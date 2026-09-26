//! Local-host adapter: this does not implement Phala or Oyster attestation/KMS.
use crate::wire::*;
use anyhow::{ensure, Context};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use pairkey_channel::{Channel, Envelope};
use pairkey_core::{authorize, ControlFence, Observation, ObservedAccount, Trust};
use pairkey_frost::{aggregate, register, Possession, Root, RoundOne, RoundTwo, Signer};
use pairkey_sdk::rpc::Rpc;
use pairkey_types::{derive_public, Attempt, Namespace, Role};
use rand_core::OsRng;
use serde::Deserialize;
use serde_json::{json, Value};
use solana_sdk::pubkey::Pubkey;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub role: Role,
    pub bind: String,
    pub root_file: String,
    pub identity_file: String,
    pub peer_identity: [u8; 32],
    pub rpc_url: String,
    pub provider_domain: String,
    pub network: [u8; 32],
    pub set_id: [u8; 32],
    pub set_governor: [u8; 32],
}
struct Pending {
    attempt: Attempt,
    peer_boot: [u8; 32],
    created: Instant,
}
struct Worker {
    signer: Signer,
    channel: Channel,
    rpc: Rpc,
    trust: Trust,
    pending: Mutex<BTreeMap<[u8; 32], Pending>>,
    highest_slot: AtomicU64,
    controls: ControlFence,
    incident: AtomicBool,
    capacity: Arc<tokio::sync::Semaphore>,
}
type W = Arc<Worker>;
type Failure = (StatusCode, Json<Value>);
fn failure(error: impl std::fmt::Display) -> Failure {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":error.to_string()})),
    )
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64
}
fn secret_file(path: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.len() == 32,
        "development secret must be a private 32-byte regular file"
    );
    let bytes = Zeroizing::new(std::fs::read(path)?);
    Ok(Zeroizing::new(
        bytes
            .as_slice()
            .try_into()
            .context("invalid secret length")?,
    ))
}
impl Worker {
    fn active(&self) -> anyhow::Result<()> {
        ensure!(
            !self.incident.load(Ordering::SeqCst),
            "authenticated protocol incident; worker refuses signing until operator investigation"
        );
        Ok(())
    }
    fn prune(&self) {
        let mut map = self.pending.lock().unwrap();
        map.retain(|_, p| {
            if p.created.elapsed().as_secs() >= 15 {
                self.signer.abort(&p.attempt);
                false
            } else {
                true
            }
        });
    }
    async fn observe(&self, begin: &Begin) -> anyhow::Result<u64> {
        self.active()?;
        // Capture the lower bound once; concurrent newer reads cannot invalidate this read.
        let minimum_slot = self
            .highest_slot
            .load(Ordering::SeqCst)
            .max(self.controls.minimum_slot());
        let program = pair_registry::id();
        let namespace = pair_registry::namespace_address(&program, &begin.registration).0;
        let request =
            pair_registry::request_address(&program, &namespace, &begin.attempt.commit.request_id)
                .0;
        let response = self.rpc.call("getMultipleAccounts", json!([[self.trust.enclave_set.to_string(), namespace.to_string(), request.to_string()], {"encoding":"base64", "commitment":"finalized", "minContextSlot": minimum_slot}])).await?;
        let slot = response["context"]["slot"]
            .as_u64()
            .context("invalid slot")?;
        let observed_at = now();
        let accounts = response["value"]
            .as_array()
            .context("invalid account response")?;
        ensure!(accounts.len() == 3, "missing accounts");
        let decode = |index: usize, address: Pubkey| -> anyhow::Result<ObservedAccount> {
            let value = &accounts[index];
            let owner: Pubkey = value["owner"].as_str().context("account owner")?.parse()?;
            ensure!(value["data"][1] == "base64", "invalid account encoding");
            let data = STANDARD.decode(value["data"][0].as_str().context("account bytes")?)?;
            Ok(ObservedAccount {
                address,
                owner,
                data,
            })
        };
        let block_time = self
            .rpc
            .call("getBlockTime", json!([slot]))
            .await?
            .as_i64()
            .context("missing finalized block time")?;
        let observation = Observation {
            network: self.trust.network,
            finalized: true,
            slot,
            block_time,
            observed_at,
            provider_domain: self.trust.provider_domain.clone(),
            set: decode(0, self.trust.enclave_set)?,
            namespace: decode(1, namespace)?,
            request: decode(2, request)?,
        };
        let decision = authorize(
            &self.trust,
            &observation,
            &begin.attempt,
            &begin.message,
            now(),
            minimum_slot,
        );
        let reg=match decision {
            Ok(reg)=>reg,
            Err(pairkey_core::Error::Inactive)=> {
                self.controls.observe_inactive(slot)?;
                self.highest_slot.fetch_max(slot,Ordering::SeqCst);
                return Err(pairkey_core::Error::Inactive.into());
            }
            Err(e)=>return Err(e).with_context(||format!("finalized view rejected: slot={slot}, required={minimum_slot}, block_time={block_time}, now={}",now())),
        };
        ensure!(
            reg == begin.registration,
            "delivered registration differs from chain"
        );
        self.highest_slot.fetch_max(slot, Ordering::SeqCst);
        // Also fences older reads which began before another request saw the freeze.
        self.controls.check_active(slot)?;
        Ok(slot)
    }
    fn decode_rounds(&self, request: &Finish) -> anyhow::Result<[RoundOne; 2]> {
        let b = &request.begin;
        let id = b.attempt.digest();
        ensure!(
            request.rounds[0].sender == Role::A && request.rounds[1].sender == Role::B,
            "incorrect role order"
        );
        Ok([
            self.channel.open(&b.peer, id, 1, &request.rounds[0])?,
            self.channel.open(&b.peer, id, 1, &request.rounds[1])?,
        ])
    }
}
async fn health(State(w): State<W>) -> Json<Health> {
    Json(Health {
        role: w.channel.attest([0; 32]).evidence.role,
        identity: w.channel.identity(),
        boot_id: w.channel.boot_id(),
        development: true,
        incident: w.incident.load(Ordering::SeqCst),
    })
}
async fn attest(
    State(w): State<W>,
    Json(q): Json<Challenge>,
) -> Json<pairkey_channel::Attestation> {
    Json(w.channel.attest(q.challenge))
}
async fn proof(State(w): State<W>, Json(ns): Json<Namespace>) -> Result<Json<Possession>, Failure> {
    w.active().map_err(failure)?;
    if ns.network != w.trust.network
        || ns.registry != w.trust.registry.to_bytes()
        || pair_registry::set_address(&w.trust.registry, &ns.enclave_set).0 != w.trust.enclave_set
    {
        return Err(failure("wrong namespace trust domain"));
    }
    w.signer.proof(&ns, &mut OsRng).map(Json).map_err(failure)
}
async fn ack(State(w): State<W>, Json(q): Json<Ack>) -> Result<Json<Vec<u8>>, Failure> {
    w.active().map_err(failure)?;
    let reg =
        register(q.registration.namespace.clone(), &q.proofs[0], &q.proofs[1]).map_err(failure)?;
    if reg != q.registration
        || reg.namespace.derivation_authority != q.controller
        || reg.namespace.network != w.trust.network
        || reg.namespace.registry != w.trust.registry.to_bytes()
        || pair_registry::set_address(&w.trust.registry, &reg.namespace.enclave_set).0
            != w.trust.enclave_set
    {
        return Err(failure("registration metadata mismatch"));
    }
    let own = w
        .signer
        .proof(&reg.namespace, &mut OsRng)
        .map_err(failure)?;
    if own.public_share != reg.public_shares[own.role.index()] {
        return Err(failure("own share mismatch"));
    }
    Ok(Json(w.channel.sign_public(
        &pair_registry::registration_message(&reg, &Pubkey::new_from_array(q.controller)),
    )))
}
async fn begin(State(w): State<W>, Json(q): Json<Begin>) -> Result<Json<Envelope>, Failure> {
    w.prune();
    w.channel.authenticate_peer(&q.peer).map_err(failure)?;
    w.observe(&q).await.map_err(failure)?;
    let round = w
        .signer
        .begin(&q.registration, &q.attempt, &q.message, &mut OsRng)
        .map_err(failure)?;
    let result = w
        .channel
        .seal(&q.peer, q.attempt.digest(), 1, &round)
        .map_err(failure);
    if result.is_err() {
        w.signer.abort(&q.attempt);
    } else {
        w.pending.lock().unwrap().insert(
            q.attempt.digest(),
            Pending {
                attempt: q.attempt,
                peer_boot: q.peer.evidence.boot_id,
                created: Instant::now(),
            },
        );
    }
    result.map(Json)
}
async fn finish(State(w): State<W>, Json(q): Json<Finish>) -> Result<Json<Envelope>, Failure> {
    w.prune();
    let meta = w
        .pending
        .lock()
        .unwrap()
        .remove(&q.begin.attempt.digest())
        .ok_or_else(|| failure("unknown or expired attempt"))?;
    let work = async {
        ensure!(
            meta.peer_boot == q.begin.peer.evidence.boot_id,
            "peer restarted during attempt"
        );
        w.channel.authenticate_peer(&q.begin.peer)?;
        w.observe(&q.begin).await?;
        let rounds = w.decode_rounds(&q)?;
        let share = match w.signer.finish(&q.begin.attempt, &rounds) {
            Ok(share) => share,
            Err(e @ pairkey_frost::Error::Frost(_)) => {
                w.incident.store(true, Ordering::SeqCst);
                anyhow::bail!(e);
            }
            Err(e) => anyhow::bail!(e),
        };
        Ok::<_, anyhow::Error>(w.channel.seal(
            &q.begin.peer,
            q.begin.attempt.digest(),
            2,
            &share,
        )?)
    }
    .await;
    w.signer.abort(&q.begin.attempt);
    work.map(Json).map_err(failure)
}
async fn result(
    State(w): State<W>,
    Json(q): Json<ResultRequest>,
) -> Result<Json<ResultResponse>, Failure> {
    let begin = &q.finish.begin;
    let id = begin.attempt.digest();
    w.channel.authenticate_peer(&begin.peer).map_err(failure)?;
    let slot = w.observe(begin).await.map_err(failure)?;
    let rounds = w.decode_rounds(&q.finish).map_err(failure)?;
    if q.shares[0].sender != Role::A || q.shares[1].sender != Role::B {
        return Err(failure("incorrect role order"));
    }
    let shares: [RoundTwo; 2] = [
        w.channel
            .open(&begin.peer, id, 2, &q.shares[0])
            .map_err(failure)?,
        w.channel
            .open(&begin.peer, id, 2, &q.shares[1])
            .map_err(failure)?,
    ];
    let signature = aggregate(
        &begin.registration,
        &begin.attempt,
        &begin.message,
        &rounds,
        &shares,
    )
    .map_err(|e| {
        w.incident.store(true, Ordering::SeqCst);
        failure(e)
    })?;
    let receipt = Receipt {
        version: 1,
        development: true,
        role: w.channel.attest([0; 32]).evidence.role,
        boot_id: w.channel.boot_id(),
        peer_boot: begin.peer.evidence.boot_id,
        attempt_digest: id,
        public_key: derive_public(&begin.registration, &begin.attempt.commit.account)
            .map_err(failure)?,
        message_hash: begin.attempt.commit.message_hash,
        signature: signature.to_vec(),
        finalized_slot: slot,
        provider_domain: w.trust.provider_domain.clone(),
    };
    let identity_signature = w.channel.sign_public(&receipt_message(&receipt));
    Ok(Json(ResultResponse {
        attestation: w.channel.attest(begin.peer.evidence.boot_id),
        receipt,
        identity_signature,
    }))
}
async fn abort(State(w): State<W>, Json(at): Json<Attempt>) -> StatusCode {
    w.signer.abort(&at);
    w.pending.lock().unwrap().remove(&at.digest());
    StatusCode::NO_CONTENT
}
async fn limit(
    State(w): State<W>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(_permit) = w.capacity.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"worker request capacity reached"})),
        )
            .into_response();
    };
    next.run(request).await
}
pub async fn run(path: &str) -> anyhow::Result<()> {
    let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    let bind: std::net::SocketAddr = config.bind.parse()?;
    ensure!(
        bind.ip().is_loopback(),
        "development worker must bind loopback"
    );
    let root = secret_file(&config.root_file)?;
    let identity = secret_file(&config.identity_file)?;
    let channel = Channel::development(config.role, *identity, config.peer_identity);
    let rpc = Rpc::new(config.rpc_url)?;
    let genesis: Pubkey = rpc
        .call("getGenesisHash", json!([]))
        .await?
        .as_str()
        .context("genesis hash")?
        .parse()?;
    ensure!(
        genesis.to_bytes() == config.network,
        "wrong authorization network"
    );
    let mut identities = [[0; 32]; 2];
    identities[config.role.index()] = channel.identity();
    identities[config.role.peer().index()] = config.peer_identity;
    let trust = Trust {
        registry: pair_registry::id(),
        network: config.network,
        enclave_set: pair_registry::set_address(&pair_registry::id(), &config.set_id).0,
        identity_keys: identities,
        set_governor: config.set_governor,
        provider_domain: config.provider_domain,
        allow_development: true,
        max_observation_age_secs: 3,
        max_chain_lag_secs: 30,
    };
    let worker = Arc::new(Worker {
        signer: Signer::new(Root::new(*root), config.role),
        channel,
        rpc,
        trust,
        pending: Mutex::new(BTreeMap::new()),
        highest_slot: AtomicU64::new(0),
        controls: ControlFence::default(),
        incident: AtomicBool::new(false),
        capacity: Arc::new(tokio::sync::Semaphore::new(16)),
    });
    let router = Router::new()
        .route("/health", get(health))
        .route("/attest", post(attest))
        .route("/proof", post(proof))
        .route("/ack", post(ack))
        .route("/begin", post(begin))
        .route("/finish", post(finish))
        .route("/result", post(result))
        .route("/abort", post(abort))
        .layer(DefaultBodyLimit::max(16_384))
        .layer(axum::middleware::from_fn_with_state(worker.clone(), limit))
        .with_state(worker.clone());
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            worker.prune();
        }
    });
    println!(
        "{}",
        json!({"event":"development_worker_ready", "role":config.role, "bind":bind.to_string(), "hardware_backed":false})
    );
    axum::serve(tokio::net::TcpListener::bind(bind).await?, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
