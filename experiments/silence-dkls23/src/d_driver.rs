//! Trusted local orchestration and measurement. No production policy or attestation.
use super::{hex, provision, send, ChildGroup};
use anyhow::{ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use pairkey_dkls23_research::d::{Certificate, Command, Limits, Reply, Request, Wallet};
use pairkey_dkls23_research::{
    digest, fresh,
    lifecycle::{Failure, FailureKind, Phase, Terminals},
    pool::Boot,
    Frame, Root, MAX_FRAME,
};
use serde_json::{json, Value};
use signature::hazmat::PrehashVerifier;
use sl_mpc_mate::coord::{simple::MessageRelay, SimpleMessageRelay};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::{ChildStdin, Command as ProcessCommand},
    sync::mpsc,
};

struct Session {
    wallets: BTreeMap<[u8; 32], Certificate>,
    group: ChildGroup,
    inputs: Vec<Option<ChildStdin>>,
    events: mpsc::UnboundedReceiver<(usize, Frame)>,
    boots: [Boot; 2],
    relays: [MessageRelay; 2],
    delay: Duration,
    pending: VecDeque<(tokio::time::Instant, usize, Frame)>,
    wire_bytes: usize,
    wire_messages: usize,
    parent_serialization_ns: u128,
    disconnect_after_reserved: bool,
}
impl Session {
    async fn start(dir: &Path, delay_ms: u64, limits: Limits) -> Result<Self> {
        Self::start_options(dir, delay_ms, limits, None).await
    }
    async fn start_options(
        dir: &Path,
        delay_ms: u64,
        limits: Limits,
        probe: Option<(&str, u8)>,
    ) -> Result<Self> {
        provision(dir)?;
        let identities = [
            Root::load(&dir.join("root-0.bin"))?
                .identity(0)
                .verifying_key()
                .to_bytes(),
            Root::load(&dir.join("root-1.bin"))?
                .identity(1)
                .verifying_key()
                .to_bytes(),
        ];
        let mut group = ChildGroup {
            children: vec![],
            readers: vec![],
        };
        let mut inputs = vec![];
        let (events, mut rx) = mpsc::unbounded_channel();
        for role in 0..2usize {
            let mut command = ProcessCommand::new(std::env::current_exe()?);
            if cfg!(all(test, feature = "research-faults")) {
                command
                    .args([
                        "--exact",
                        "d_driver::tests::d_process_child",
                        "--ignored",
                        "--nocapture",
                        "--quiet",
                    ])
                    .env("PAIRKEY_D_CHILD_ROLE", role.to_string())
                    .env("PAIRKEY_D_CHILD_ROOT", dir.join(format!("root-{role}.bin")))
                    .env("PAIRKEY_D_CHILD_PEER", hex(&identities[1 - role]))
                    .env("PAIRKEY_D_CHILD_USES", limits.uses.to_string())
                    .env("PAIRKEY_D_CHILD_AGE", limits.age_secs.to_string());
            } else {
                command
                    .arg("d-worker")
                    .arg(role.to_string())
                    .arg(dir.join(format!("root-{role}.bin")))
                    .arg(hex(&identities[1 - role]))
                    .arg(limits.uses.to_string())
                    .arg(limits.age_secs.to_string());
            }
            if let Some((stage, victim)) = probe {
                if let Some(race) = stage.strip_prefix("race:") {
                    command
                        .env("PAIRKEY_NATIVE_RACE_DIR", dir)
                        .env("PAIRKEY_NATIVE_RACE_STAGE", race)
                        .env("PAIRKEY_NATIVE_RACE_ROLE", role.to_string())
                        .env("PAIRKEY_NATIVE_RACE_BYPASS", victim.to_string());
                    #[cfg(all(test, feature = "research-faults"))]
                    command.env("PAIRKEY_TRACE_ALL", "1");
                } else {
                    command
                        .env("PAIRKEY_D_STAGE", stage)
                        .env("PAIRKEY_D_ROLE", victim.to_string())
                        .env("PAIRKEY_D_PROBE", dir);
                    #[cfg(all(test, feature = "research-faults"))]
                    command
                        .env("PAIRKEY_NATIVE_RACE_DIR", dir)
                        .env("PAIRKEY_NATIVE_RACE_STAGE", "trace-only")
                        .env("PAIRKEY_NATIVE_RACE_ROLE", role.to_string())
                        .env("PAIRKEY_NATIVE_RACE_BYPASS", "0")
                        .env("PAIRKEY_TRACE_ALL", "1");
                }
            }
            let mut child = command
                .env("RUST_MIN_STACK", "16777216")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .kill_on_drop(true)
                .spawn()?;
            inputs.push(Some(child.stdin.take().context("pool stdin")?));
            let mut output = BufReader::new(child.stdout.take().context("pool stdout")?);
            let events = events.clone();
            group.readers.push(tokio::spawn(async move {
                let result: Result<()> = async {
                    loop {
                        let mut line = vec![];
                        if (&mut output)
                            .take(MAX_FRAME as u64 + 1)
                            .read_until(b'\n', &mut line)
                            .await?
                            == 0
                        {
                            break;
                        }
                        ensure!(
                            line.len() <= MAX_FRAME && line.last() == Some(&b'\n'),
                            "bad pool stdout frame"
                        );
                        let Some(start) = line.windows(8).position(|b| b == b"{\"kind\":") else {
                            continue;
                        };
                        events
                            .send((role, serde_json::from_slice(&line[start..])?))
                            .map_err(|_| anyhow::anyhow!("pool parent closed"))?;
                    }
                    Ok(())
                }
                .await;
                if let Err(e) = result {
                    let _ = events.send((
                        role,
                        Frame::Failure(Failure::burn(
                            Phase::Transport,
                            FailureKind::Transport,
                            format!("pool reader: {e:#}"),
                        )),
                    ));
                }
                let _ = events.send((role, Frame::Closed));
            }));
            group.children.push(child);
        }
        drop(events);
        let mut boots: [Option<Boot>; 2] = [None, None];
        tokio::time::timeout(Duration::from_secs(10), async {
            while boots.iter().any(Option::is_none) {
                let (role, frame) = rx.recv().await.context("pool startup EOF")?;
                let Frame::PoolHello(b) = frame else {
                    anyhow::bail!("unexpected pool startup");
                };
                b.validate()?;
                ensure!(
                    b.role as usize == role
                        && b.identity == identities[role]
                        && boots[role].is_none(),
                    "pool startup pin mismatch"
                );
                boots[role] = Some(b);
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        let boots = boots.map(Option::unwrap);
        ensure!(boots[0].generation != boots[1].generation, "boot collision");
        for input in &mut inputs {
            send(
                input.as_mut().unwrap(),
                &Frame::DCommand(Box::new(Command::Enroll(boots.clone()))),
            )
            .await?;
        }
        let coordinator = SimpleMessageRelay::new();
        Ok(Self {
            wallets: BTreeMap::new(),
            group,
            inputs,
            events: rx,
            boots,
            relays: [coordinator.connect(), coordinator.connect()],
            delay: Duration::from_millis(delay_ms),
            pending: VecDeque::new(),
            wire_bytes: 0,
            wire_messages: 0,
            parent_serialization_ns: 0,
            disconnect_after_reserved: false,
        })
    }
    async fn command(&mut self, commands: [Command; 2]) -> Result<Vec<(usize, Frame)>> {
        for (role, command) in commands.into_iter().enumerate() {
            self.deliver(role, Frame::DCommand(Box::new(command)))
                .await?;
        }
        tokio::time::timeout(Duration::from_secs(40), self.collect())
            .await
            .context("pool parent timeout")?
    }
    async fn deliver(&mut self, role: usize, frame: Frame) -> Result<()> {
        // Measure parent framing CPU separately from write/flush waiting.
        let t = Instant::now();
        let mut bytes = serde_json::to_vec(&frame)?;
        self.parent_serialization_ns += t.elapsed().as_nanos();
        ensure!(bytes.len() <= MAX_FRAME, "oversized pool parent frame");
        bytes.push(b'\n');
        use tokio::io::AsyncWriteExt;
        let input = self.inputs[role].as_mut().context("pool input closed")?;
        input.write_all(&bytes).await?;
        input.flush().await?;
        Ok(())
    }
    async fn collect(&mut self) -> Result<Vec<(usize, Frame)>> {
        let mut replies = vec![];
        let mut terminals = Terminals::default();
        let mut grace = None;
        let mut reserved = [false; 2];
        loop {
            if terminals.failed() && grace.is_none() {
                for i in &mut self.inputs {
                    i.take();
                }
                // Drop pending deliveries; already queued output remains released.
                self.pending.clear();
                grace = Some(tokio::time::Instant::now() + Duration::from_secs(2));
            }
            if terminals.closed.iter().all(|v| *v) {
                return Err(terminals.into());
            }
            if !terminals.failed() && replies.len() == 2 {
                return Ok(replies);
            }
            let deadline = self.pending.front().map(|p| p.0);
            let [r0, r1] = &mut self.relays;
            let event = tokio::select! {
                e=self.events.recv()=>e.context("pool events EOF")?,
                b=r0.next(),if !terminals.failed()=>{if let Some(b)=b {self.pending.push_back((tokio::time::Instant::now()+self.delay,0,Frame::Relay(b)));}continue;},
                b=r1.next(),if !terminals.failed()=>{if let Some(b)=b {self.pending.push_back((tokio::time::Instant::now()+self.delay,1,Frame::Relay(b)));}continue;},
                _=async {if let Some(t)=deadline {tokio::time::sleep_until(t).await;} else {std::future::pending::<()>().await;}},if !terminals.failed()=>{
                    let (_,role,frame)=self.pending.pop_front().unwrap();
                    if let Err(e)=self.deliver(role,frame).await {
                        terminals.failure(role,Failure::burn(Phase::Transport,FailureKind::Transport,format!("pool delivery: {e:#}")));
                    }
                    continue;
                },
                _=async {if let Some(t)=grace {tokio::time::sleep_until(t).await;} else {std::future::pending::<()>().await;}}=>{terminals.drain_timed_out=true;return Err(terminals.into());},
            };
            let (role, frame) = event;
            match frame {
                Frame::Ready(_) if self.disconnect_after_reserved => {
                    reserved[role] = true;
                    if reserved.iter().all(|r| *r) {
                        self.inputs[1].take();
                    }
                }
                Frame::Setup(bytes) if !terminals.failed() => {
                    self.wire_bytes += bytes.len();
                    self.wire_messages += 1;
                    self.pending.push_back((
                        tokio::time::Instant::now() + self.delay,
                        1 - role,
                        Frame::Setup(bytes),
                    ));
                }
                Frame::Relay(bytes) if !terminals.failed() => {
                    self.wire_bytes += bytes.len();
                    self.wire_messages += 1;
                    self.relays[role]
                        .send(bytes)
                        .await
                        .map_err(|_| anyhow::anyhow!("pool relay refused"))?;
                }
                Frame::Failure(f) => terminals.failure(role, f),
                Frame::Closed => {
                    if !terminals.failures.iter().any(|(r, _)| *r == role) {
                        terminals.failure(
                            role,
                            Failure::burn(
                                Phase::Transport,
                                FailureKind::Transport,
                                "pool worker EOF",
                            ),
                        );
                    }
                    terminals.closed(role);
                    self.inputs[role].take();
                }
                Frame::DReply(_) => {
                    ensure!(
                        !replies.iter().any(|(r, _)| *r == role),
                        "duplicate pool reply"
                    );
                    replies.push((role, frame));
                }
                _ if terminals.failed() => {}
                _ => anyhow::bail!("unexpected pool reply"),
            }
        }
    }

    fn wallet(&self, key: [u8; 32]) -> Wallet {
        Wallet {
            version: 2,
            identities: self.boots.clone().map(|b| b.identity),
            namespace: "pairkey/spike-d/research".into(),
            epoch: 0,
            key_id: key,
        }
    }
    async fn register(&mut self, key: [u8; 32], fault: Option<&str>) -> Result<Certificate> {
        let wallet = self.wallet(key);
        let attempt = fresh();
        let replies = self
            .command(std::array::from_fn(|_| Command::Register {
                wallet: wallet.clone(),
                attempt,
                fault: fault.map(str::to_owned),
            }))
            .await?;
        let certs = replies
            .into_iter()
            .map(|(_, f)| match f {
                Frame::DReply(Reply::Registered(c)) => Ok(*c),
                _ => anyhow::bail!("D registration reply"),
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            certs.len() == 2 && certs[0] == certs[1],
            "D registration disagreement"
        );
        certs[0].validate()?;
        self.wallets.insert(key, certs[0].clone());
        Ok(certs[0].clone())
    }
    async fn prepare(&mut self, fault: Option<&str>) -> Result<([u8; 32], Value)> {
        let attempt = fresh();
        let start = Instant::now();
        let frames = self
            .command(std::array::from_fn(|_| Command::Prepare {
                attempt,
                fault: fault.map(str::to_owned),
            }))
            .await?;
        let mut gens = vec![];
        let mut pubkeys = vec![];
        for (role, f) in frames {
            let Frame::DReply(Reply::Donor {
                role: r,
                generation,
                unused_public_key,
                ..
            }) = f
            else {
                anyhow::bail!("D donor reply")
            };
            ensure!(role == r as usize, "D donor role");
            gens.push(generation);
            pubkeys.push(unused_public_key);
        }
        ensure!(
            gens.len() == 2 && gens[0] == gens[1] && pubkeys[0] == pubkeys[1],
            "D donor generation mismatch"
        );
        Ok((
            gens[0],
            json!({"generation":hex(&gens[0]),"unused_public_key":hex(&pubkeys[0]),"wall_ms":start.elapsed().as_secs_f64()*1000.0}),
        ))
    }
    fn request(
        &self,
        key: [u8; 32],
        generation: [u8; 32],
        fault: Option<&str>,
        index: usize,
    ) -> Result<Request> {
        let cert = self.wallets.get(&key).context("D wallet not registered")?;
        Ok(Request {
            wallet: cert.record.wallet.clone(),
            record: cert.record.digest(),
            generation,
            path: if index % 2 == 0 { "m" } else { "m/7/3" }.into(),
            prehash: digest(b"pairkey/d/demo-message", &(key, index)),
            attempt: fresh(),
            fault: fault.map(str::to_owned),
        })
    }
    async fn sign_request(&mut self, requests: [Request; 2]) -> Result<Value> {
        let start = Instant::now();
        let instance = requests[0].instance();
        let hash = requests[0].prehash;
        let generation = requests[0].generation;
        let frames = self.command(requests.map(Command::Sign)).await?;
        let mut results = vec![];
        for (role, f) in frames {
            let Frame::DReply(Reply::Signed {
                role: r,
                instance: i,
                generation: g,
                final_session,
                signature,
                public_key,
                recovery_id,
                uses,
                ..
            }) = f
            else {
                anyhow::bail!("D signing reply")
            };
            ensure!(
                role == r as usize && i == instance && g == generation,
                "D output binding"
            );
            let sig = Signature::from_slice(&signature)?;
            let key = VerifyingKey::from_sec1_bytes(&public_key)?;
            key.verify_prehash(&hash, &sig)?;
            ensure!(sig.normalize_s().is_none(), "D high S");
            ensure!(
                VerifyingKey::recover_from_prehash(
                    &hash,
                    &sig,
                    RecoveryId::from_byte(recovery_id).context("D recovery id")?
                )? == key,
                "D recovered key"
            );
            results.push((signature, public_key, final_session, recovery_id, uses));
        }
        ensure!(
            results.len() == 2 && results[0] == results[1],
            "D results disagree"
        );
        Ok(
            json!({"instance":hex(&instance),"generation":hex(&generation),"final_session":hex(&results[0].2),"signature":hex(&results[0].0),"public_key":hex(&results[0].1),"uses":results[0].4,"wall_ms":start.elapsed().as_secs_f64()*1000.0}),
        )
    }
    async fn stop(mut self) -> Result<()> {
        for i in self.inputs.iter_mut().flatten() {
            send(i, &Frame::DCommand(Box::new(Command::Stop))).await?;
        }
        self.inputs.clear();
        for child in &mut self.group.children {
            ensure!(
                tokio::time::timeout(Duration::from_secs(5), child.wait())
                    .await??
                    .success(),
                "D worker exit"
            );
        }
        for reader in &mut self.group.readers {
            reader.await?;
        }
        Ok(())
    }
}
fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}
pub async fn demo(dir: &Path, samples: usize) -> Result<()> {
    ensure!(
        cfg!(feature = "research-faults"),
        "D driver is a co-located test fixture; enable research-faults"
    );
    ensure!((1..=1000).contains(&samples), "D samples 1..1000");
    let mut s = Session::start(dir, 0, Limits::default()).await?;
    let mut records = vec![];
    for index in 0..3 {
        records.push(s.register(digest(b"D/demo-wallet", &index), None).await?);
    }
    let (mut generation, donor) = s.prepare(None).await?;
    let mut rotations = vec![];
    let mut attempts = vec![];
    let mut instances = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    let mut rs = BTreeSet::new();
    for i in 0..samples {
        if i > 0 && i % Limits::default().uses as usize == 0 {
            let (next, rotation) = s.prepare(None).await?;
            ensure!(next != generation, "D donor rotation unchanged");
            generation = next;
            rotations.push(rotation);
        }
        let key = records[i % 3].record.wallet.key_id;
        let r = s.request(key, generation, Some("repeat-entropy"), i)?;
        let other = r.clone();
        let result = s.sign_request([r, other]).await?;
        ensure!(
            instances.insert(result["instance"].as_str().unwrap().to_owned()),
            "D repeated instance"
        );
        ensure!(
            sessions.insert(result["final_session"].as_str().unwrap().to_owned()),
            "D repeated native final session"
        );
        ensure!(
            rs.insert(result["signature"].as_str().unwrap()[..64].to_owned()),
            "D repeated aggregate r"
        );
        attempts.push(result);
    }
    let (next, rotation) = s.prepare(None).await?;
    ensure!(next != generation, "D donor rotation unchanged");
    let r = s.request(records[0].record.wallet.key_id, next, None, samples)?;
    let after = s.sign_request([r.clone(), r]).await?;
    s.stop().await?;
    let report = json!({"route":"D/donor-base","fixture":"two root files on one research host only","signatures":samples,"wallets":records,"limits":Limits::default(),"donor":donor,"bounded_rotations":rotations,"rotation":rotation,"after_rotation":after,"attempts":attempts,"instance_ids_unique":true,"observed_native_final_sids_unique":true,"aggregate_r_unique":true,"deliberately_repeated_os_entropy":"hedged with distinct context/counter; uniqueness test, not protected entropy","warm_sign_median_ms":median(attempts.iter().map(|r|r["wall_ms"].as_f64().unwrap()).collect()),"native_parameters":"unchanged","wallet_package_cache":false});
    std::fs::write(
        dir.join("spike-d.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"evidence":dir.join("spike-d.json"),"signatures":samples,"warm_sign_median_ms":report["warm_sign_median_ms"]})
        )?
    );
    Ok(())
}

#[cfg(all(test, feature = "research-faults"))]
#[path = "d/process_tests.rs"]
mod tests;

pub async fn bench(dir: &Path) -> Result<()> {
    ensure!(
        cfg!(feature = "research-faults"),
        "D benchmark is a research fixture"
    );
    let mut rows = vec![];
    for delay in [0u64, 50] {
        let run = dir.join(format!("delay-{delay}"));
        let mut s = Session::start(&run, delay, Limits::default()).await?;
        let start = Instant::now();
        let registration = Instant::now();
        let cert = s.register([7; 32], None).await?;
        let registration_ms = registration.elapsed().as_secs_f64() * 1000.0;
        let (g, donor) = s.prepare(None).await?;
        let request = s.request([7; 32], g, None, 0)?;
        let first = s.sign_request([request.clone(), request]).await?;
        let cold_ms = start.elapsed().as_secs_f64() * 1000.0;
        let mut warm = vec![];
        for i in 1..=5 {
            let r = s.request([7; 32], g, None, i)?;
            warm.push(s.sign_request([r.clone(), r]).await?);
        }
        let (_, rotation) = s.prepare(None).await?;
        let wire_bytes = s.wire_bytes;
        let wire_frames = s.wire_messages;
        let framing_ms = s.parent_serialization_ns as f64 / 1e6;
        s.stop().await?;
        rows.push(json!({"one_way_delay_ms":delay,"registration_ms":registration_ms,"donor_dkg":donor,"cold_registration_donor_first_signature_ms":cold_ms,"first_signature":first,"warm_median_ms":median(warm.iter().map(|r|r["wall_ms"].as_f64().unwrap()).collect()),"warm_attempts":warm,"fresh_dkg_rotation":rotation,"wire_bytes":wire_bytes,"wire_frames":wire_frames,"parent_framing_cpu_ms":framing_ms,"public_record":hex(&cert.record.digest())}));
    }
    let report = json!({"route":"D/shared-donor-base","rows":rows,"delay_model":"applied to each peer-directed native/setup frame; excludes Internet/provider costs","clock":"host monotonic elapsed","signing_flights":"two authenticated context exchanges before four native signing rounds","cache":"donor OT only; no native wallet package cache"});
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("latency.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn finish_failed(session: &mut Session) -> Result<()> {
    session.inputs.clear();
    for child in &mut session.group.children {
        ensure!(
            tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await??
                .success(),
            "D failed worker did not shut down cleanly"
        );
    }
    for reader in &mut session.group.readers {
        reader.await?;
    }
    Ok(())
}
fn expected_hygiene_refusal(error: &anyhow::Error) -> Result<Value> {
    let t = error
        .downcast_ref::<Terminals>()
        .context("D missing structured refusal")?;
    ensure!(
        !t.drain_timed_out,
        "D refusal diagnostics not fully drained"
    );
    ensure!(
        t.failures.iter().all(|(_, f)| f.action
            == pairkey_dkls23_research::lifecycle::Action::Burn
            && !f.incident_attempted),
        "D unexpected quarantine/freeze: {error:#}"
    );
    ensure!(
        t.failures
            .iter()
            .any(|(_, f)| f.kind == FailureKind::Context
                && f.detail.contains("generation/bound mismatch")),
        "D missing hygiene refusal: {error:#}"
    );
    Ok(
        json!({"expected":true,"reason":"generation absent/exhausted/expired","failures":t.failures,"diagnostic":t.to_string()}),
    )
}
fn no_incident(dir: &Path, peers: [[u8; 32]; 2]) -> Result<()> {
    let scope = pairkey_dkls23_research::lifecycle::pair_scope_dir(&dir.join("controls"), peers, 1);
    ensure!(
        !scope.join("0.quarantined").exists() && !scope.join("1.quarantined").exists(),
        "D hygiene refusal must not quarantine pairing"
    );
    Ok(())
}
pub async fn stress(dir: &Path, batches: usize) -> Result<()> {
    ensure!(
        cfg!(feature = "research-faults"),
        "D stress is a research fixture"
    );
    ensure!((1..=100).contains(&batches), "D batches 1..100");
    let limits = Limits::default();
    let mut session = Session::start(dir, 0, limits.clone()).await?;
    let mut certs = BTreeMap::new();
    for i in 0..10usize {
        let key = digest(b"D/stress-wallet", &i);
        certs.insert(key, session.register(key, None).await?);
    }
    let keys = certs.keys().copied().collect::<Vec<_>>();
    let peers = session.boots.clone().map(|b| b.identity);
    let mut rows = vec![];
    let mut instances = BTreeSet::new();
    let mut finals = BTreeSet::new();
    let mut rs = BTreeSet::new();
    let mut pubkeys = BTreeMap::new();
    let mut generations = BTreeSet::new();
    for batch in 0..batches {
        // Alternate normal in-process rotation and restart. Deliberate failed
        // attempts are separate from this throughput schedule: the collector
        // closes both inputs on a failure, which legitimately accounts a peer
        // disconnect and can trigger the unchanged transport rate limiter.
        if batch > 0 && batch % 2 == 0 {
            session.stop().await?;
            session = Session::start(dir, 0, limits.clone()).await?;
            session.wallets = certs.clone();
        }
        let (generation, donor) = session.prepare(None).await?;
        ensure!(generations.insert(generation), "D repeated generation");
        let mut attempts = vec![];
        for index in 0..limits.uses as usize {
            let key = keys[(index + batch) % keys.len()];
            let r = session.request(key, generation, None, batch * limits.uses as usize + index)?;
            let path = r.path.clone();
            let result = match session.sign_request([r.clone(), r]).await {
                Ok(v) => v,
                Err(e) => {
                    std::fs::write(
                        dir.join("stress-failure.json"),
                        serde_json::to_vec_pretty(
                            &json!({"batch":batch,"index":index,"unexpected":true,"detail":format!("{e:#}"),"completed_batches":rows}),
                        )?,
                    )?;
                    return Err(e);
                }
            };
            ensure!(
                result["uses"].as_u64() == Some(index as u64 + 1),
                "D count disagreement"
            );
            ensure!(
                instances.insert(result["instance"].as_str().unwrap().to_owned()),
                "D repeated instance"
            );
            ensure!(
                finals.insert(result["final_session"].as_str().unwrap().to_owned()),
                "D repeated native final session"
            );
            ensure!(
                rs.insert(result["signature"].as_str().unwrap()[..64].to_owned()),
                "D repeated aggregate r"
            );
            let public = result["public_key"].as_str().unwrap().to_owned();
            if let Some(old) = pubkeys.insert((key, path), public.clone()) {
                ensure!(old == public, "D address changed across rotation");
            }
            attempts.push(result);
        }
        let refusal = if batch + 1 == batches {
            let r = session.request(
                keys[batch % keys.len()],
                generation,
                None,
                (batch + 1) * limits.uses as usize,
            )?;
            let error = session
                .sign_request([r.clone(), r])
                .await
                .err()
                .context("D attempt 101 unexpectedly succeeded")?;
            let refusal = expected_hygiene_refusal(&error)?;
            finish_failed(&mut session).await?;
            Some(refusal)
        } else {
            None
        };
        no_incident(dir, peers)?;
        // Both workers must have retired this generation before reuse/restart.
        let retired = dir
            .join("controls/d")
            .join(hex(&pairkey_dkls23_research::d::pairing(peers)))
            .join("retired-generations");
        for role in 0..2 {
            ensure!(
                std::fs::read(retired.join(format!("{role}-{}.retired", hex(&generation))))?
                    == generation,
                "D generation not durably retired"
            );
        }
        rows.push(json!({"batch":batch+1,"donor":donor,"attempts":attempts,"successes":attempts.len(),"warm_median_ms":median(attempts.iter().map(|a|a["wall_ms"].as_f64().unwrap()).collect()),"both_roles_retired_at_100":true,"attempt_101":refusal,"establishment":if batch==0 {"initial"} else if batch%2==0 {"restart"} else {"in-process rotation"}}));
        std::fs::write(
            dir.join("stress-progress.json"),
            serde_json::to_vec_pretty(
                &json!({"completed_batches":rows.len(),"limits":limits,"batches":rows}),
            )?,
        )?;
        println!(
            "D stress: batch {}/{}: {} signatures, both donors retired{}",
            batch + 1,
            batches,
            limits.uses,
            if refusal.is_some() {
                "; expected attempt-101 burn"
            } else {
                ""
            }
        );
    }
    let report = json!({"limits":limits,"wallets":certs.values().collect::<Vec<_>>(),"signatures":instances.len(),"batches":rows,"generations_distinct":generations.len(),"instance_ids_unique":true,"observed_native_final_sessions_unique":true,"aggregate_r_unique":true,"addresses_stable_across_rotations":true,"expected_limit_refusals":1,"unexpected_failures":0,"entropy":"fresh OS entropy for every native setup/signing attempt"});
    std::fs::write(dir.join("stress.json"), serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
pub async fn expiry_probe(dir: &Path) -> Result<()> {
    ensure!(
        cfg!(feature = "research-faults"),
        "D expiry probe is a research fixture"
    );
    let limits = Limits::default();
    let mut s = Session::start(dir, 0, limits.clone()).await?;
    let key = [7; 32];
    let cert = s.register(key, None).await?;
    let (g, donor) = s.prepare(None).await?;
    let start = Instant::now();
    let r = s.request(key, g, None, 0)?;
    let before = s.sign_request([r.clone(), r]).await?;
    println!(
        "D age probe: valid initial signature; waiting {} seconds for real expiry",
        limits.age_secs + 2
    );
    tokio::time::sleep(Duration::from_secs(limits.age_secs + 2)).await;
    let r = s.request(key, g, None, 1)?;
    let error = s
        .sign_request([r.clone(), r])
        .await
        .err()
        .context("D expired donor unexpectedly signed")?;
    let refusal = expected_hygiene_refusal(&error)?;
    finish_failed(&mut s).await?;
    no_incident(dir, cert.record.wallet.identities)?;
    let mut replacement = Session::start(dir, 0, limits.clone()).await?;
    replacement.wallets.insert(key, cert.clone());
    let (next, rotation) = replacement.prepare(None).await?;
    ensure!(next != g, "D age rotation reused generation");
    let r = replacement.request(key, next, None, 2)?;
    let after = replacement.sign_request([r.clone(), r]).await?;
    ensure!(
        before["public_key"] == after["public_key"],
        "D expiry recovery changed address"
    );
    replacement.stop().await?;
    let report = json!({"limits":limits,"real_elapsed_secs":start.elapsed().as_secs_f64(),"donor":donor,"initial_signature":before,"expiry_refusal":refusal,"rotation":rotation,"signature_after_rotation":after,"unexpected_failures":0});
    std::fs::write(dir.join("expiry.json"), serde_json::to_vec_pretty(&report)?)?;
    println!("D age probe: expected expiry burn, fresh rotation signed successfully");
    Ok(())
}
