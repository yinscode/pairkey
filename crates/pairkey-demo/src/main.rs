//! Loopback-bound testnet demo; hosted access uses an HTTPS reverse proxy.
mod api;
mod chain;
mod hosted;
mod messages;
mod state;
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use pairkey_sdk::{rpc::Rpc, service::Client};
use serde_json::{json, Value};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
};
use state::*;
use std::{
    path::{Path, PathBuf},
    process::{Child, Command as ProcessCommand, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

const SOLANA: &str = "https://api.devnet.solana.com";
const BASE: &str = "https://sepolia.base.org";
struct Processes(Vec<Child>);
impl Drop for Processes {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
struct App {
    root: PathBuf,
    dir: PathBuf,
    journal: Journal,
    hosted: Mutex<hosted::Store>,
    payer: Keypair,
    delegate: SigningKey,
    identities: [[u8; 32]; 2],
    controller: Pubkey,
    sol: Rpc,
    solana_rpc_url: String,
    evm: Rpc,
    sdk: Client,
    workers: [String; 2],
    stage: Mutex<Value>,
    gate: Arc<tokio::sync::Mutex<()>>,
    processes: Mutex<Processes>,
    coordinator: String,
}
fn private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn seed(path: &Path, must_exist: bool) -> Result<[u8; 32]> {
    if !path.exists() {
        ensure!(
            !must_exist,
            "missing established secret: {}",
            path.display()
        );
        private(path, &fresh())?;
    }
    ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "secret must be a regular file"
    );
    std::fs::read(path)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret length"))
}
fn port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}
impl App {
    fn stage(&self, s: &str) {
        *self.stage.lock().unwrap() = json!({"ready":false,"message":s});
        println!("{s}");
    }
    fn spawn(&self, name: &str, config: Value) -> Result<()> {
        let path = self.dir.join(format!("{name}.config.json"));
        // RPC URLs may contain credentials. Atomic storage always writes mode 0600.
        pairkey_core::local_store::LocalStore::open(&path, 64 * 1024)?
            .write(&serde_json::to_vec_pretty(&config)?)?;
        let exe = if name == "coordinator" {
            "pairkey-coordinator"
        } else {
            "pairkey-worker"
        };
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(format!("{name}.log")))?;
        let child = ProcessCommand::new(std::env::current_exe()?.with_file_name(exe))
            .arg(path)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        self.processes.lock().unwrap().0.push(child);
        Ok(())
    }
    async fn start_workers(&self) -> Result<()> {
        let s = self.journal.read();
        for (i, role) in [pairkey_types::Role::A, pairkey_types::Role::B]
            .into_iter()
            .enumerate()
        {
            self.spawn(&format!("worker-{i}"),json!({
                "dkls_binary":self.root.join("target/silence-dkls23/release/dkls-spike"),
                "role":role,"bind":self.workers[i].trim_start_matches("http://"),
                "root_file":self.dir.join(format!("root-{i}")),"identity_file":self.dir.join(format!("identity-{i}")),
                "peer_identity":self.identities[1-i],"rpc_url":self.solana_rpc_url,"provider_domain":format!("testnet-demo-{i}"),
                "network":state::GENESIS.parse::<Pubkey>()?.to_bytes(),"set_id":s.set_id,"set_governor":self.payer.pubkey().to_bytes()
            }))?;
        }
        self.spawn("coordinator",json!({"jobs_file":self.dir.join("jobs.json"),"bind":self.coordinator,"workers":self.workers,"identities":self.identities}))?;
        let relay = pairkey_coordinator::Relay::new(pairkey_coordinator::Config {
            jobs_file: None,
            bind: self.coordinator.clone(),
            workers: self.workers.clone(),
            identities: self.identities,
        })?;
        for i in 0..2 {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                if relay.health(i).await.is_ok() {
                    break;
                }
                ensure!(
                    tokio::time::Instant::now() < deadline,
                    "worker startup failed; inspect private logs"
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
        // Worker readiness does not imply the separately spawned coordinator has bound.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if tokio::net::TcpStream::connect(&self.coordinator)
                .await
                .is_ok()
            {
                break;
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "coordinator startup failed; inspect private logs"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let root = std::env::var_os("PAIRKEY_DEMO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .canonicalize()?;
    let origin = api::configured_origin(
        &std::env::var("PAIRKEY_DEMO_ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:4180".into()),
    )?;
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("usage: pairkey-demo PRIVATE_STATE_DIRECTORY")?,
    )
    .canonicalize()?;
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        std::fs::metadata(&dir)?.permissions().mode() & 0o077 == 0,
        "state directory must be mode 0700"
    );
    let payer =
        read_keypair_file(dir.join("owner.json")).map_err(|e| anyhow::anyhow!("owner key: {e}"))?;
    for (name, id) in [
        ("registry", pair_registry::id()),
        ("controller", example_controller::id()),
    ] {
        let key = read_keypair_file(dir.join(format!("{name}.json")))
            .map_err(|e| anyhow::anyhow!("program key: {e}"))?;
        ensure!(
            key.pubkey() == id,
            "program IDs differ from build; run scripts/demo-testnet.sh build"
        );
    }
    ensure!(
        !dir.join("MIGRATED_TO_DROPLET.txt").exists(),
        "this state directory is a migrated offline backup; do not start it"
    );
    let established = dir.join("state.json").exists();
    let delegate = SigningKey::from_bytes(&seed(&dir.join("delegate"), established)?);
    let mut identities = [[0; 32]; 2];
    for (i, identity) in identities.iter_mut().enumerate() {
        seed(&dir.join(format!("root-{i}")), established)?;
        *identity = SigningKey::from_bytes(&seed(&dir.join(format!("identity-{i}")), established)?)
            .verifying_key()
            .to_bytes();
    }
    let binding = format!(
        "{}:{}:{}:{}:{}:{}",
        GENESIS,
        CHAIN,
        payer.pubkey(),
        pair_registry::id(),
        example_controller::id(),
        hex(&pairkey_types::digest(
            b"pairkey/demo-identities/v1",
            &serde_json::to_vec(&(identities, delegate.verifying_key().to_bytes()))?
        ))
    );
    let journal = Journal::open(&dir.join("state.json"), binding)?;
    let controller = example_controller::authority(&example_controller::id(), &payer.pubkey()).0;
    let service_ports = match journal.read().service_ports {
        Some(ports) => ports,
        None => {
            ensure!(
                !dir.join("jobs.json").exists(),
                "existing job store requires its original service ports; reconcile before startup"
            );
            let mut ports = Vec::new();
            while ports.len() < 3 {
                let candidate = port()?;
                if candidate != 4180 && !ports.contains(&candidate) {
                    ports.push(candidate);
                }
            }
            let ports: [u16; 3] = ports.try_into().unwrap();
            journal.update(|s| {
                s.service_ports = Some(ports);
                Ok(())
            })?;
            ports
        }
    };
    ensure!(
        service_ports.iter().all(|p| *p > 0 && *p != 4180)
            && service_ports[0] != service_ports[1]
            && service_ports[0] != service_ports[2]
            && service_ports[1] != service_ports[2],
        "invalid saved service ports"
    );
    let coordinator = format!("127.0.0.1:{}", service_ports[0]);
    let workers = service_ports[1..]
        .iter()
        .map(|p| format!("http://127.0.0.1:{p}"))
        .collect::<Vec<_>>();
    let workers: [String; 2] = workers.try_into().unwrap();
    if dir.join("jobs.json").exists() {
        let store: Value = serde_json::from_slice(&std::fs::read(dir.join("jobs.json"))?)?;
        ensure!(
            store["context"]
                == json!(pairkey_types::digest(
                    b"pairkey/job-store/v2",
                    &(workers.clone(), identities)
                )),
            "saved ports/identities do not match the existing job store"
        );
    }
    let rpc_file = dir.join("solana-rpc-url");
    let solana_rpc_url = if rpc_file.exists() {
        ensure!(
            std::fs::symlink_metadata(&rpc_file)?.file_type().is_file()
                && std::fs::metadata(&rpc_file)?.permissions().mode() & 0o077 == 0,
            "RPC configuration must be a private regular file"
        );
        let url = std::fs::read_to_string(&rpc_file)?.trim().to_owned();
        ensure!(url.starts_with("https://"), "devnet RPC must use HTTPS");
        url
    } else {
        SOLANA.into()
    };
    let hosted = Mutex::new(hosted::Store::open(
        &dir.join("hosted.json"),
        pairkey_types::digest(
            b"pairkey/hosted-store/v1",
            &(identities, journal.read().set_id),
        ),
    )?);
    let app = Arc::new(App {
        hosted,
        root,
        dir,
        journal,
        payer,
        delegate,
        identities,
        controller,
        sol: Rpc::new(solana_rpc_url.clone())?,
        solana_rpc_url,
        evm: Rpc::new(BASE.into())?,
        sdk: Client::new(format!("http://{coordinator}"))?,
        workers,
        stage: Mutex::new(json!({"ready":false,"message":"Starting"})),
        gate: Arc::new(tokio::sync::Mutex::new(())),
        processes: Mutex::new(Processes(vec![])),
        coordinator,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:4180").await?;
    let boot = app.clone();
    let startup = tokio::spawn(async move {
        if let Err(e) = boot.bootstrap().await {
            boot.stage(&format!("Setup required: {e:#}"));
        }
    });
    println!("PairKey testnet demo: http://127.0.0.1:4180/demo");
    axum::serve(listener, api::router(app.clone(), origin))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    startup.abort();
    drop(std::mem::replace(
        &mut *app.processes.lock().unwrap(),
        Processes(vec![]),
    ));
    Ok(())
}
