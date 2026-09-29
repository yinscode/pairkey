mod measure;
#[cfg(all(test, feature = "research-faults"))]
mod native_process_tests;
mod pool_driver;
mod pool_worker;
#[cfg(all(test, feature = "research-faults"))]
mod pooled_process_tests;
#[cfg(all(test, feature = "research-faults"))]
mod process_probe;
mod wire;
mod worker;

use anyhow::{ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    elliptic_curve::group::GroupEncoding,
};
use pairkey_dkls23_research::lifecycle::{scope_dir, Failure, FailureKind, Phase, Terminals};
use pairkey_dkls23_research::{
    digest, fresh, incident, point, Frame, Hello, Manifest, Outcome, Request, Route, MAX_FRAME,
    REVISION,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashVerifier;
use sl_mpc_mate::coord::SimpleMessageRelay;
use std::{
    collections::{BTreeSet, VecDeque},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
    time::Instant,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::mpsc,
};
use zeroize::Zeroizing;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Result<[u8; 32]> {
    ensure!(s.len() == 64, "expected 32-byte hex identifier");
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}
async fn send(stdin: &mut (impl tokio::io::AsyncWrite + Unpin), frame: &Frame) -> Result<()> {
    let mut bytes = serde_json::to_vec(frame)?;
    ensure!(bytes.len() <= MAX_FRAME, "oversized parent frame");
    bytes.push(b'\n');
    stdin.write_all(&bytes).await?;
    stdin.flush().await?;
    Ok(())
}
async fn deliver(
    inputs: &mut [Option<ChildStdin>],
    terminals: &mut Terminals,
    role: usize,
    frame: &Frame,
) -> Result<()> {
    if let Some(input) = &mut inputs[role] {
        if let Err(error) = send(input, frame).await {
            if let Some(io) = error.downcast_ref::<std::io::Error>() {
                if matches!(
                    io.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                ) {
                    terminals.pipe(role, io);
                    inputs[role].take();
                    return Ok(());
                }
            }
            return Err(error);
        }
    }
    Ok(())
}
struct ChildGroup {
    children: Vec<Child>,
    readers: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for ChildGroup {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.start_kill();
        }
        for reader in &self.readers {
            reader.abort();
        }
    }
}

#[derive(Default)]
struct Options {
    fault: Option<String>,
    reuse_entry: Option<[u8; 32]>,
    delay_ms: u64,
}
async fn attempt(
    dir: &Path,
    route: Route,
    key_id: [u8; 32],
    path: &str,
    pinned: Option<&Manifest>,
    options: Options,
) -> Result<(Manifest, Vec<Outcome>, serde_json::Value)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(40),
        attempt_inner(dir, route, key_id, path, pinned, options),
    )
    .await
    .context("parent timeout")?
}
async fn attempt_inner(
    dir: &Path,
    route: Route,
    key_id: [u8; 32],
    path: &str,
    pinned: Option<&Manifest>,
    options: Options,
) -> Result<(Manifest, Vec<Outcome>, serde_json::Value)> {
    let started = Instant::now();
    let mut group = ChildGroup {
        children: vec![],
        readers: vec![],
    };
    let mut inputs = vec![];
    let (events, mut rx) = mpsc::unbounded_channel();
    for role in 0..2u8 {
        let mut command = Command::new(std::env::current_exe()?);
        if cfg!(feature = "research-faults")
            && role == 1
            && matches!(
                options.fault.as_deref(),
                Some("migration-pprf" | "migration-pprf-abort-send")
            )
        {
            command.env("PAIRKEY_RESEARCH_BAD_MIGRATION_PPRF", "1");
        }
        let mut child = command
            .args(["worker", &role.to_string()])
            .arg(dir.join(format!("root-{role}.bin")))
            .arg(hex(&key_id))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        inputs.push(Some(child.stdin.take().context("child stdin")?));
        let mut stdout = BufReader::new(child.stdout.take().context("child stdout")?);
        let events = events.clone();
        group.readers.push(tokio::spawn(async move {
            let result: Result<()> = async {
                loop {
                    let mut bytes = Vec::new();
                    let n = (&mut stdout)
                        .take(MAX_FRAME as u64 + 1)
                        .read_until(b'\n', &mut bytes)
                        .await?;
                    if n == 0 {
                        break;
                    }
                    ensure!(
                        bytes.len() <= MAX_FRAME && bytes.last() == Some(&b'\n'),
                        "bad child frame"
                    );
                    let frame: Frame = serde_json::from_slice(&bytes)?;
                    if events.send((role as usize, frame)).is_err() {
                        break;
                    }
                }
                Ok(())
            }
            .await;
            if let Err(error) = result {
                let _ = events.send((
                    role as usize,
                    Frame::Failure(Failure::burn(
                        Phase::Transport,
                        FailureKind::Transport,
                        format!("reader: {error:#}"),
                    )),
                ));
            }
            let _ = events.send((role as usize, Frame::Closed));
        }));
        group.children.push(child);
    }
    drop(events);
    let mut hellos: [Option<Hello>; 2] = [None, None];
    while hellos.iter().any(Option::is_none) {
        let (role, frame) = rx.recv().await.context("worker exited before hello")?;
        let Frame::Hello(hello) = frame else {
            anyhow::bail!("unexpected startup frame");
        };
        hello.validate()?;
        ensure!(
            hello.role as usize == role && hellos[role].is_none(),
            "wrong/duplicate hello"
        );
        hellos[role] = Some(hello);
    }
    let hellos = hellos.map(Option::unwrap);
    let q = point(&hellos[0].contribution)? + point(&hellos[1].contribution)?;
    let manifest = Manifest {
        version: 1,
        key_id,
        identities: [hellos[0].identity, hellos[1].identity],
        additive_public: [
            hellos[0].contribution.clone(),
            hellos[1].contribution.clone(),
        ],
        public_key: q.to_bytes().to_vec(),
        chain_code: digest(
            b"pairkey/dkls-research/public-chain-code/v1",
            &(key_id, q.to_bytes().to_vec()),
        ),
    };
    manifest.validate()?;
    if let Some(pin) = pinned {
        ensure!(
            pin == &manifest,
            "restart changed public manifest/address metadata"
        );
    }
    let request = Request {
        route,
        manifest: manifest.clone(),
        hellos,
        entry: options.reuse_entry.unwrap_or_else(fresh),
        attempt: fresh(),
        path: path.into(),
        prehash: Sha256::digest(b"PairKey root-only DKLS23 research exact message").into(),
        wallet_record: None,
        fault: options.fault.clone(),
    };
    let mut byte_counts = [0usize; 2];
    let mut message_counts = [0usize; 2];
    let mut outcomes = vec![];
    let mut ready = [false; 2];
    for (role, input) in inputs.iter_mut().enumerate() {
        let mut delivered = request.clone();
        if role == 1 {
            match options.fault.as_deref() {
                Some("wrong-hash") => delivered.prehash[0] ^= 1,
                Some("wrong-chain-code") => delivered.manifest.chain_code[0] ^= 1,
                Some("wrong-key-id") => delivered.manifest.key_id[0] ^= 1,
                Some("wrong-peer") => {
                    delivered.manifest.identities[0] = delivered.manifest.identities[1]
                }
                _ => {}
            }
        }
        send(
            input.as_mut().context("missing startup pipe")?,
            &Frame::Start(Box::new(delivered)),
        )
        .await?;
    }
    let coordinator = SimpleMessageRelay::new();
    let mut relays = [coordinator.connect(), coordinator.connect()];
    let mut terminals = Terminals::default();
    let mut grace = None;
    let mut pending = VecDeque::new();
    while outcomes.len() < 2 {
        if terminals.closed.iter().all(|closed| *closed) {
            break;
        }
        if terminals.failed() && grace.is_none() {
            // EOF cancels blocked reads but leaves stdout available for the
            // originator's completed incident write and terminal diagnostic.
            for input in &mut inputs {
                input.take();
            }
            grace = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(2));
        }
        let [relay_a, relay_b] = &mut relays;
        let deadline = pending
            .front()
            .map(|p: &(tokio::time::Instant, usize, Frame)| p.0);
        let event = tokio::select! {
            event = rx.recv() => match event { Some(event)=>event, None=>break },
            _ = async { if let Some(deadline)=grace {tokio::time::sleep_until(deadline).await;} else {std::future::pending::<()>().await;} } => {terminals.drain_timed_out=true; break;},
            bytes = relay_a.next(),if !terminals.failed() => { if let Some(bytes) = bytes {pending.push_back((tokio::time::Instant::now()+std::time::Duration::from_millis(options.delay_ms),0,Frame::Relay(bytes)));} continue; },
            bytes = relay_b.next(),if !terminals.failed() => { if let Some(bytes) = bytes {pending.push_back((tokio::time::Instant::now()+std::time::Duration::from_millis(options.delay_ms),1,Frame::Relay(bytes)));} continue; },
            _ = async {if let Some(t)=deadline {tokio::time::sleep_until(t).await;}else {std::future::pending::<()>().await;}},if !terminals.failed()=>{
                let (_,role,frame)=pending.pop_front().unwrap();deliver(&mut inputs,&mut terminals,role,&frame).await?;continue;
            },
        };
        let (role, frame) = event;
        match frame {
            Frame::Setup(mut bytes) => {
                if cfg!(feature = "research-faults")
                    && options.fault.as_deref() == Some("unauthenticated-garbage")
                    && bytes.len() > 28
                {
                    bytes[28] ^= 1;
                }
                byte_counts[role] += bytes.len();
                message_counts[role] += 1;
                pending.push_back((
                    tokio::time::Instant::now()
                        + std::time::Duration::from_millis(options.delay_ms),
                    1 - role,
                    Frame::Setup(bytes),
                ));
            }
            Frame::Relay(bytes) => {
                byte_counts[role] += bytes.len();
                message_counts[role] += 1;
                relays[role]
                    .send(bytes)
                    .await
                    .map_err(|_| anyhow::anyhow!("relay refused"))?;
            }
            Frame::Ready(context) => {
                ensure!(context == request.context(), "wrong readiness context");
                ready[role] = true;
                if options.fault.as_deref() == Some("cancel-ready") && ready.iter().all(|r| *r) {
                    anyhow::bail!("injected cancellation after both setup reservations");
                }
            }
            Frame::Result(outcome) => {
                ensure!(
                    outcome.role as usize == role && outcome.context == request.context(),
                    "result context mismatch"
                );
                ensure!(
                    !outcomes.iter().any(|o: &Outcome| o.role == outcome.role),
                    "duplicate result"
                );
                outcomes.push(outcome);
            }
            Frame::Failure(error) => terminals.failure(role, error),
            Frame::Closed => {
                if !outcomes.iter().any(|o| o.role as usize == role)
                    && !terminals.failures.iter().any(|(r, _)| *r == role)
                {
                    terminals.failure(
                        role,
                        Failure::burn(
                            Phase::Transport,
                            FailureKind::Transport,
                            "worker exited without terminal diagnostic",
                        ),
                    );
                }
                terminals.closed(role);
                inputs[role].take();
            }
            _ => anyhow::bail!("unexpected worker frame"),
        }
    }
    if terminals.failed() || outcomes.len() != 2 {
        return Err(terminals.into());
    }
    outcomes.sort_by_key(|o| o.role);
    ensure!(
        outcomes[0].signature == outcomes[1].signature
            && outcomes[0].public_key == outcomes[1].public_key
            && outcomes[0].recovery_id == outcomes[1].recovery_id,
        "workers disagree on signature"
    );
    let mut derived = point(&manifest.public_key)?;
    let mut cc = manifest.chain_code;
    for child in &derivation_path::DerivationPath::from_str(path)? {
        let (_, p, code) = sl_mpc_mate::bip32::derive_child_pubkey(&derived, cc, child)?;
        derived = p;
        cc = code;
    }
    ensure!(
        derived.to_bytes().as_slice() == outcomes[0].public_key,
        "public derivation disagrees"
    );
    let key = VerifyingKey::from_affine(derived.to_affine())?;
    let signature = Signature::from_slice(&outcomes[0].signature)?;
    key.verify_prehash(&request.prehash, &signature)?;
    ensure!(signature.normalize_s().is_none(), "high-S result");
    let recovered = VerifyingKey::recover_from_prehash(
        &request.prehash,
        &signature,
        RecoveryId::from_byte(outcomes[0].recovery_id).context("invalid recovery ID")?,
    )?;
    ensure!(recovered == key, "recovery ID mismatch");
    drop(inputs); // EOF also releases Tokio's blocking stdin read in each worker.
    for child in &mut group.children {
        ensure!(child.wait().await?.success(), "worker exit failed");
    }
    let telemetry = json!({"route":route,"key_id":hex(&key_id),"path":path,"public_key":hex(&outcomes[0].public_key),
        "entry":hex(&request.entry),"attempt":hex(&request.attempt),"wall_ms":started.elapsed().as_secs_f64()*1000.0,
        "wire_messages_including_subscriptions":message_counts,"wire_bytes_including_setup":byte_counts,
        "setup_ms":[outcomes[0].setup_ms,outcomes[1].setup_ms],"signing_ms":[outcomes[0].signing_ms,outcomes[1].signing_ms],
        "setup_active_poll_ms":[outcomes[0].setup_active_poll_ms,outcomes[1].setup_active_poll_ms],"signing_active_poll_ms":[outcomes[0].signing_active_poll_ms,outcomes[1].signing_active_poll_ms],"one_way_delay_ms":options.delay_ms,
        "signature":hex(&outcomes[0].signature),"package_bytes":outcomes[0].package_bytes});
    Ok((manifest, outcomes, telemetry))
}
fn provision(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    for role in 0..2 {
        let path = dir.join(format!("root-{role}.bin"));
        if !path.exists() {
            let root = Zeroizing::new(fresh());
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(root.as_ref())?;
            file.sync_all()?;
        }
    }
    Ok(())
}
fn has_quarantine(dir: &Path, role: u8) -> bool {
    let scopes = dir.join("controls/scopes");
    std::fs::read_dir(scopes)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| entry.path().join(format!("{role}.quarantined")).exists())
}
async fn demo(dir: &Path, samples: usize) -> Result<()> {
    ensure!(
        cfg!(feature = "research-faults"),
        "demo fault suite requires --features research-faults"
    );
    ensure!(samples > 0 && samples <= 100, "sample count must be 1..100");
    provision(dir)?;
    let mut records = vec![];
    let mut signatures = BTreeSet::new();
    let mut pins = vec![];
    for wallet in 0..3u8 {
        let id = digest(b"pairkey/dkls-research/wallet/v1", &wallet);
        let mut pin = None;
        for route in [Route::Migration, Route::Direct] {
            for path in ["m", "m/7/3"] {
                for _ in 0..samples {
                    eprintln!("Research attempt: {route:?}, wallet {wallet}, path {path}");
                    let (manifest, _, record) =
                        attempt(dir, route, id, path, pin.as_ref(), Options::default()).await?;
                    ensure!(
                        signatures.insert(record["signature"].as_str().unwrap().to_owned()),
                        "repeated signature across fresh attempts"
                    );
                    if pin.is_none() {
                        pin = Some(manifest);
                    }
                    records.push(record);
                }
            }
        }
        pins.push(pin.unwrap());
    }
    let id = pins[0].key_id;
    let mut refusals = vec![];
    for fault in [
        "unauthenticated-garbage",
        "wrong-hash",
        "wrong-chain-code",
        "wrong-key-id",
        "wrong-peer",
        "bad-zero-reveal",
        "truncated-ot",
        "truncated-pprf",
        "migration-pprf",
        "migration-pprf-abort-send",
        "bad-ot",
        "corrupt-ot",
        "duplicate-party",
        "cancel-ready",
    ] {
        // Separate control domains keep deliberate faults from poisoning the baseline.
        let fault_dir = dir.join(format!("fault-{fault}"));
        provision(&fault_dir)?;
        let error = attempt(
            &fault_dir,
            if matches!(fault, "migration-pprf" | "migration-pprf-abort-send") {
                Route::Migration
            } else {
                Route::Direct
            },
            id,
            "m",
            None,
            Options {
                fault: Some(fault.into()),
                ..Default::default()
            },
        )
        .await
        .err()
        .with_context(|| format!("fault {fault} unexpectedly succeeded"))?;
        let details = error
            .downcast_ref::<Terminals>()
            .map(|report| serde_json::to_value(report).unwrap());
        if fault == "migration-pprf-abort-send" {
            let report = error
                .downcast_ref::<Terminals>()
                .context("missing combined failure report")?;
            ensure!(
                report.failures.iter().any(|(_, f)| f.abort_send_failed
                    && f.incident_persisted
                    && f.action == pairkey_dkls23_research::lifecycle::Action::QuarantinePeer),
                "original violation or abort transport failure lost"
            );
        }
        let error = format!("{error:#}");
        let expected = match fault {
            "unauthenticated-garbage" | "wrong-hash" | "wrong-chain-code" => {
                "authenticated setup context mismatch"
            }
            "wrong-key-id" => "hello/manifest mismatch",
            "wrong-peer" => "invalid manifest",
            "bad-ot" => "ProtocolViolation",
            "bad-zero-reveal" => "zero-share commitment mismatch",
            "truncated-ot" => "invalid base OT reply length",
            "truncated-pprf" => "invalid PPRF length",
            "migration-pprf" | "migration-pprf-abort-send" => "PPRF error",
            "corrupt-ot" => "ban the party",
            "duplicate-party" => "invalid message format",
            "cancel-ready" => "injected cancellation",
            _ => unreachable!(),
        };
        ensure!(
            error.contains(expected),
            "unexpected refusal cause for {fault}: {error}"
        );
        if [
            "unauthenticated-garbage",
            "wrong-hash",
            "wrong-chain-code",
            "wrong-key-id",
            "wrong-peer",
            "cancel-ready",
        ]
        .contains(&fault)
        {
            ensure!(
                !(0..2).any(|r| has_quarantine(&fault_dir, r)),
                "routing/cancellation falsely quarantined"
            );
        }
        if [
            "bad-ot",
            "corrupt-ot",
            "duplicate-party",
            "bad-zero-reveal",
            "truncated-ot",
            "truncated-pprf",
            "migration-pprf",
            "migration-pprf-abort-send",
        ]
        .contains(&fault)
        {
            ensure!(
                (0..2).any(|r| has_quarantine(&fault_dir, r)),
                "cryptographic incident was not persisted"
            );
            let retry = attempt(&fault_dir, Route::Direct, id, "m", None, Options::default())
                .await
                .err()
                .context("incident retry succeeded")?;
            ensure!(
                format!("{retry:#}").contains("research quarantine"),
                "wrong retry refusal cause"
            );
            let alternate_wallet = digest(b"incident-other-wallet/v1", &id);
            let retry = attempt(
                &fault_dir,
                Route::Migration,
                alternate_wallet,
                "m/7/3",
                None,
                Options::default(),
            )
            .await
            .err()
            .context("incident bypass through another wallet/route")?;
            ensure!(
                format!("{retry:#}").contains("research quarantine"),
                "wrong cross-wallet incident refusal"
            );
        }
        if [
            "cancel-ready",
            "unauthenticated-garbage",
            "wrong-hash",
            "wrong-chain-code",
        ]
        .contains(&fault)
        {
            attempt(&fault_dir, Route::Direct, id, "m", None, Options::default())
                .await
                .context("fresh retry after cancellation failed")?;
        }
        refusals.push(json!({"fault":fault,"refused":true,"error":error,"failure_details":details,"quarantine_persisted":(0..2).any(|r|has_quarantine(&fault_dir,r)),"retry_blocked_across_wallet_and_route":(0..2).any(|r|has_quarantine(&fault_dir,r))}));
    }
    let replay_dir = dir.join("fault-reservation-replay");
    provision(&replay_dir)?;
    let entry = fresh();
    let first = attempt(
        &replay_dir,
        Route::Direct,
        id,
        "m",
        None,
        Options {
            reuse_entry: Some(entry),
            ..Default::default()
        },
    )
    .await?;
    let replay = attempt(
        &replay_dir,
        Route::Direct,
        id,
        "m",
        Some(&first.0),
        Options {
            reuse_entry: Some(entry),
            ..Default::default()
        },
    )
    .await
    .err()
    .context("reservation replay succeeded")?;
    refusals.push(json!({"fault":"reservation-replay-after-process-restart","refused":true,"error":format!("{replay:#}")}));
    let quarantine_dir = dir.join("fault-quarantine");
    provision(&quarantine_dir)?;
    let pin = attempt(
        &quarantine_dir,
        Route::Direct,
        id,
        "m",
        None,
        Options::default(),
    )
    .await?
    .0;
    incident(
        &scope_dir(&quarantine_dir.join("controls"), &pin),
        0,
        fresh(),
    )?;
    let quarantined = attempt(
        &quarantine_dir,
        Route::Direct,
        id,
        "m",
        None,
        Options::default(),
    )
    .await
    .err()
    .context("quarantine did not survive restart")?;
    refusals.push(json!({"fault":"durable-quarantine-at-worker-start","refused":true,"error":format!("{quarantined:#}")}));
    let concurrent = futures_util::future::join_all((0..4).map(|_| {
        attempt(
            dir,
            Route::Direct,
            id,
            "m",
            Some(&pins[0]),
            Options::default(),
        )
    }))
    .await;
    let mut concurrent_signatures = BTreeSet::new();
    let mut concurrent_records = vec![];
    for result in concurrent {
        let (_, outcomes, record) = result?;
        ensure!(
            concurrent_signatures.insert(outcomes[0].signature.clone()),
            "concurrent attempts repeated a signature"
        );
        concurrent_records.push(record);
    }
    let evidence = json!({"source_revision":REVISION,"scope":"local research; mock public ledger; no TEE or production authorization",
        "dkls_spikes_executed":true,"samples_per_wallet_path_route":samples,"successful_attempts":records.len(),"wallets":pins,
        "attempts":records,"concurrent_attempts":concurrent_records,"refusals":refusals,"limitations":["VOLE 2026 parameter analysis unresolved","custom setup unaudited",
        "upstream opaque buffers and physical erasure unverified","public ledger assumes honest filesystem authority","snapshot cloning not prevented by roots or boot IDs",
        "no background OT pool or product integration"]});
    fs::write(
        dir.join("evidence.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"evidence":dir.join("evidence.json"),"successful_attempts":evidence["successful_attempts"],"refusals":evidence["refusals"].as_array().unwrap().len()})
        )?
    );
    Ok(())
}
fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let n = values.len();
    if n % 2 == 0 {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    } else {
        values[n / 2]
    }
}
async fn compare(dir: &Path, samples: usize) -> Result<()> {
    ensure!((1..=100).contains(&samples), "samples 1..100");
    provision(dir)?;
    let mut runs = vec![];
    let mut summary = vec![];
    for delay in [0u64, 10, 50] {
        let delay_dir = dir.join(format!("delay-{delay}"));
        provision(&delay_dir)?;
        let mut records = vec![];
        let mut pins = vec![];
        for wallet in 0..3u8 {
            let id = digest(b"pairkey/dkls-research/wallet/v1", &wallet);
            let mut pin = None;
            for route in [Route::Migration, Route::Direct] {
                for path in ["m", "m/7/3"] {
                    for _ in 0..samples {
                        let (manifest, _, record) = attempt(
                            &delay_dir,
                            route,
                            id,
                            path,
                            pin.as_ref(),
                            Options {
                                delay_ms: delay,
                                ..Default::default()
                            },
                        )
                        .await?;
                        if pin.is_none() {
                            pin = Some(manifest);
                        }
                        records.push(record);
                    }
                }
            }
            pins.push(pin.unwrap());
        }
        let pooled = pool_driver::benchmark(&delay_dir, samples, delay).await?;
        for record in pooled["attempts"].as_array().unwrap() {
            let id = record["key_id"].as_str().unwrap();
            let pin = pins.iter().find(|m| hex(&m.key_id) == id).unwrap();
            ensure!(
                serde_json::from_value::<Manifest>(record["manifest"].clone())? == *pin,
                "A/B/C manifest mismatch"
            );
        }
        for route in ["Migration", "Direct"] {
            let selected = records
                .iter()
                .filter(|r| r["route"] == route)
                .collect::<Vec<_>>();
            summary.push(json!({"route":route,"one_way_delay_ms":delay,"samples":selected.len(),
                "wall_median_ms":median(selected.iter().map(|r|r["wall_ms"].as_f64().unwrap()).collect()),
                "protocol_setup_median_ms":median(selected.iter().map(|r|r["setup_ms"].as_array().unwrap().iter().map(|v|v.as_f64().unwrap()).fold(0.0,f64::max)).collect()),
                "signing_median_ms":median(selected.iter().map(|r|r["signing_ms"].as_array().unwrap().iter().map(|v|v.as_f64().unwrap()).fold(0.0,f64::max)).collect()),
                "setup_active_poll_median_ms":median(selected.iter().map(|r|r["setup_active_poll_ms"].as_array().unwrap().iter().map(|v|v.as_f64().unwrap()).fold(0.0,f64::max)).collect()),
                "signing_active_poll_median_ms":median(selected.iter().map(|r|r["signing_active_poll_ms"].as_array().unwrap().iter().map(|v|v.as_f64().unwrap()).fold(0.0,f64::max)).collect())}));
        }
        let selected = pooled["attempts"].as_array().unwrap();
        let refills = pooled["refills"].as_array().unwrap();
        summary.push(json!({"route":"Pooled","one_way_delay_ms":delay,"samples":selected.len(),
            "online_wall_median_ms":median(selected.iter().map(|r|r["online_wall_ms"].as_f64().unwrap()).collect()),
            "signing_active_poll_median_ms":median(selected.iter().map(|r|r["signing_active_poll_ms"].as_array().unwrap().iter().map(|v|v.as_f64().unwrap()).fold(0.0,f64::max)).collect()),
            "idle_refill_median_ms":median(refills.iter().map(|r|r["wall_ms"].as_f64().unwrap()).collect()),
            "isolated_ot_compute_median_ms":median(refills.iter().map(|r|r["isolated_ot_compute_ms"].as_array().unwrap().iter().map(|v|v.as_f64().unwrap()).fold(0.0,f64::max)).collect()),
            "parent_framing_cpu_refill_median_ms":median(refills.iter().map(|r|r["parent_framing_probe_ms"].as_f64().unwrap()).collect())}));
        eprintln!("Compared A/B/C at {delay}ms one-way delay");
        runs.push(json!({"one_way_delay_ms":delay,"baseline_attempts":records,"pooled":pooled}));
    }
    let transport = pool_driver::transport_probe(&dir.join("transport-probe")).await?;
    let evidence = json!({"configuration":hex(&pairkey_dkls23_research::pool::configuration()),"samples_per_wallet_path":samples,"summary":summary,"runs":runs,"transport_probe":transport,
        "method":["Each logical peer delivery delayed once; both directions scheduled independently; subscriptions and policy/registration RPCs undelayed",
        "A/B wall includes worker launch/registration, C online excludes separately reported startup and wallet registration",
        "Active poll timing excludes suspended awaits, includes synchronous crypto/framing/control I/O and OS preemption; not CPU profiler data",
        "Isolated OT compute timers omit exchange awaits; parent framing timing measures actual parent serialization only",
        "Idle refill throughput is sequential two-party setup throughput; no overlapping native attempts or refill/sign multiplexing",
        "Local synthetic delay; no geographic/TEE production latency claim"],"native_parameters":"locked unchanged"});
    fs::write(
        dir.join("comparison.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"evidence":dir.join("comparison.json"),"summary":evidence["summary"]})
        )?
    );
    Ok(())
}
#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("compare") => {
            compare(
                Path::new(args.get(1).context("compare requires ignored directory")?),
                args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(3),
            )
            .await
        }
        Some("pool-worker") if args.len() == 4 => {
            pool_worker::run(args[1].parse()?, Path::new(&args[2]), unhex(&args[3])?).await
        }
        Some("pool-demo") => {
            pool_driver::demo(
                Path::new(
                    args.get(1)
                        .context("pool-demo requires ignored directory")?,
                ),
                args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(3),
            )
            .await
        }
        Some("worker") if args.len() == 4 => {
            worker::run(args[1].parse()?, Path::new(&args[2]), unhex(&args[3])?).await
        }
        Some("demo") => {
            let dir = PathBuf::from(
                args.get(1)
                    .context("demo requires an ignored output directory")?,
            );
            let samples = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(1);
            demo(&dir, samples).await
        }
        _ => anyhow::bail!("usage: dkls-spike demo <private ignored output directory> [samples]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn closed_transport_retains_originator_diagnostic() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        drop(reader);
        let error = send(&mut writer, &Frame::Ready([1; 32])).await.unwrap_err();
        let mut terminals = Terminals::default();
        terminals.pipe(1, error.downcast_ref::<std::io::Error>().unwrap());
        terminals.closed(1);
        let mut failure = Failure::violation(Phase::Signing, [2; 32], "proof failed");
        failure.incident_persisted = true;
        terminals.failure(0, failure);
        terminals.closed(0);
        assert!(terminals.diagnostic().contains("proof failed"));
        assert!(terminals.diagnostic().contains("persisted=true"));
    }
}
