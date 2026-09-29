//! Trusted local orchestration and measurement. No production policy or attestation.
use super::{hex, provision, send, ChildGroup};
use anyhow::{ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    elliptic_curve::group::GroupEncoding,
};
use pairkey_dkls23_research::{
    digest, fresh,
    lifecycle::{Failure, FailureKind, Phase, Terminals},
    point,
    pool::{self, Boot, Command, Consumption, SetupInput, Status},
    Frame, Hello, Manifest, Request, Root, Route, MAX_FRAME,
};
use serde_json::{json, Value};
use signature::hazmat::PrehashVerifier;
use sl_mpc_mate::coord::{simple::MessageRelay, SimpleMessageRelay};
use std::{
    collections::{BTreeSet, VecDeque},
    path::Path,
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::{ChildStdin, Command as ProcessCommand},
    sync::mpsc,
};

struct Session {
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
    async fn start(dir: &Path, delay_ms: u64) -> Result<Self> {
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
            let mut child = ProcessCommand::new(std::env::current_exe()?)
                .arg("pool-worker")
                .arg(role.to_string())
                .arg(dir.join(format!("root-{role}.bin")))
                .arg(hex(&identities[1 - role]))
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
                        events
                            .send((role, serde_json::from_slice(&line)?))
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
                &Frame::PoolCommand(Box::new(Command::Enroll(boots.clone()))),
            )
            .await?;
        }
        let coordinator = SimpleMessageRelay::new();
        Ok(Self {
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
            self.deliver(role, Frame::PoolCommand(Box::new(command)))
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
                Frame::Hello(_) | Frame::PoolStatus(_) | Frame::Result(_) => {
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
    fn input(&self) -> SetupInput {
        SetupInput {
            version: 1,
            recipe: 1,
            peers: self.boots.clone().map(|b| b.identity),
            boots: self.boots.clone().map(|b| b.generation),
            configuration: pool::configuration(),
            entry: fresh(),
        }
    }
    async fn refill(&mut self, fault: Option<&str>) -> Result<(SetupInput, Vec<Status>, Value)> {
        let input = self.input();
        let start = Instant::now();
        let bytes = self.wire_bytes;
        let cpu = self.parent_serialization_ns;
        let frames = self
            .command([
                Command::Setup {
                    input: input.clone(),
                    fault: fault.map(str::to_owned),
                },
                Command::Setup {
                    input: input.clone(),
                    fault: fault.map(str::to_owned),
                },
            ])
            .await?;
        let mut statuses = vec![];
        for (_, f) in frames {
            let Frame::PoolStatus(s) = f else {
                anyhow::bail!("expected refill status");
            };
            statuses.push(s);
        }
        ensure!(
            statuses[0].completed == statuses[1].completed
                && statuses
                    .iter()
                    .all(|s| s.entry == input.entry && s.input == input.digest()),
            "refill provenance disagreement"
        );
        let wall = start.elapsed().as_secs_f64() * 1000.0;
        let record = json!({"entry":hex(&input.entry),"completed":hex(&statuses[0].completed),"wall_ms":wall,"worker_elapsed_ms":statuses.iter().map(|s|s.elapsed_ms).collect::<Vec<_>>(),
            "isolated_ot_compute_ms":statuses.iter().map(|s|s.compute_ms).collect::<Vec<_>>(),"parent_framing_probe_ms":(self.parent_serialization_ns-cpu) as f64/1e6,"wire_bytes":self.wire_bytes-bytes,"entries_per_second":1000.0/wall});
        Ok((input, statuses, record))
    }
    async fn describe(&mut self, key: [u8; 32]) -> Result<(Manifest, [Hello; 2])> {
        let mut frames = self
            .command([Command::Describe(key), Command::Describe(key)])
            .await?;
        frames.sort_by_key(|(r, _)| *r);
        let hellos: Vec<_> = frames
            .into_iter()
            .map(|(role, f)| {
                let Frame::Hello(h) = f else {
                    anyhow::bail!("expected wallet hello");
                };
                h.validate()?;
                ensure!(
                    h.role as usize == role
                        && h.key_id == key
                        && h.identity == self.boots[role].identity
                        && h.ephemeral == self.boots[role].ephemeral,
                    "wallet hello/pool enrollment mismatch"
                );
                Ok(h)
            })
            .collect::<Result<_>>()?;
        let hellos: [Hello; 2] = hellos
            .try_into()
            .map_err(|_| anyhow::anyhow!("hello count"))?;
        let q = point(&hellos[0].contribution)? + point(&hellos[1].contribution)?;
        let manifest = Manifest {
            version: 1,
            key_id: key,
            identities: self.boots.clone().map(|b| b.identity),
            additive_public: [
                hellos[0].contribution.clone(),
                hellos[1].contribution.clone(),
            ],
            public_key: q.to_bytes().to_vec(),
            chain_code: digest(
                b"pairkey/dkls-research/public-chain-code/v1",
                &(key, q.to_bytes().to_vec()),
            ),
        };
        manifest.validate()?;
        Ok((manifest, hellos))
    }
    async fn sign(
        &mut self,
        input: &SetupInput,
        completed: [u8; 32],
        key: [u8; 32],
        path: &str,
        fault: Option<&str>,
    ) -> Result<Value> {
        let (manifest, hellos) = self.describe(key).await?;
        let request = Request {
            route: Route::Pooled,
            manifest: manifest.clone(),
            hellos,
            entry: input.entry,
            attempt: fresh(),
            path: path.into(),
            prehash: pool::hash("mock-exact-message", &[&key, path.as_bytes()]),
            fault: fault.map(str::to_owned),
        };
        let c = Consumption::new(
            input,
            completed,
            &request,
            pool::hash("mock-policy-receipt", &[&request.prehash]),
            1,
        );
        let mut commands = [
            Command::Sign {
                request: Box::new(request.clone()),
                consumption: c.clone(),
            },
            Command::Sign {
                request: Box::new(request.clone()),
                consumption: c.clone(),
            },
        ];
        if cfg!(feature = "research-faults") {
            if let Command::Sign { consumption, .. } = &mut commands[1] {
                match fault {
                    Some("wrong-consumption") => consumption.receipt[0] ^= 1,
                    Some("wrong-provenance") => consumption.completed[0] ^= 1,
                    _ => {}
                }
            }
        }
        let bytes = self.wire_bytes;
        let messages = self.wire_messages;
        let cpu = self.parent_serialization_ns;
        let start = Instant::now();
        self.disconnect_after_reserved = fault == Some("disconnect");
        let mut frames = self.command(commands).await?;
        frames.sort_by_key(|(r, _)| *r);
        let mut outcomes = vec![];
        for (role, f) in frames {
            let Frame::Result(o) = f else {
                anyhow::bail!("expected pool signature");
            };
            ensure!(
                o.role as usize == role && o.context == c.digest(),
                "pooled result binding mismatch"
            );
            outcomes.push(o);
        }
        ensure!(
            outcomes[0].signature == outcomes[1].signature
                && outcomes[0].public_key == outcomes[1].public_key
                && outcomes[0].recovery_id == outcomes[1].recovery_id,
            "pool signature disagreement"
        );
        let mut derived = point(&manifest.public_key)?;
        let mut cc = manifest.chain_code;
        for child in &derivation_path::DerivationPath::from_str(path)? {
            let (_, p, code) = sl_mpc_mate::bip32::derive_child_pubkey(&derived, cc, child)?;
            derived = p;
            cc = code;
        }
        let vk = VerifyingKey::from_affine(derived.to_affine())?;
        let sig = Signature::from_slice(&outcomes[0].signature)?;
        vk.verify_prehash(&request.prehash, &sig)?;
        ensure!(
            sig.normalize_s().is_none() && derived.to_bytes().as_slice() == outcomes[0].public_key,
            "pooled derivation/low-S failed"
        );
        ensure!(
            VerifyingKey::recover_from_prehash(
                &request.prehash,
                &sig,
                RecoveryId::from_byte(outcomes[0].recovery_id).context("recovery ID")?
            )? == vk,
            "pooled recovery mismatch"
        );
        Ok(
            json!({"route":"Pooled","key_id":hex(&key),"path":path,"entry":hex(&input.entry),"consumption":hex(&c.digest()),"public_key":hex(&outcomes[0].public_key),"signature":hex(&outcomes[0].signature),
            "online_wall_ms":start.elapsed().as_secs_f64()*1000.0,"online_setup_ms":outcomes.iter().map(|o|o.setup_ms).collect::<Vec<_>>(),"signing_and_verification_ms":outcomes.iter().map(|o|o.signing_ms).collect::<Vec<_>>(),
            "wire_bytes":self.wire_bytes-bytes,"wire_messages_including_subscriptions":self.wire_messages-messages,"parent_framing_probe_ms":(self.parent_serialization_ns-cpu) as f64/1e6,
            "signing_active_poll_ms":outcomes.iter().map(|o|o.signing_active_poll_ms).collect::<Vec<_>>(),"package_bytes":outcomes[0].package_bytes,"manifest":manifest}),
        )
    }
    async fn stop(mut self) -> Result<()> {
        for i in self.inputs.iter_mut().flatten() {
            send(i, &Frame::PoolCommand(Box::new(Command::Stop))).await?;
        }
        self.inputs.clear();
        for child in &mut self.group.children {
            ensure!(
                tokio::time::timeout(Duration::from_secs(5), child.wait())
                    .await??
                    .success(),
                "pool worker stop failed"
            );
        }
        Ok(())
    }
}

pub async fn benchmark(dir: &Path, samples: usize, delay_ms: u64) -> Result<Value> {
    ensure!((1..=100).contains(&samples), "samples 1..100");
    let start = Instant::now();
    let mut session = Session::start(dir, delay_ms).await?;
    let startup_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut signatures = BTreeSet::new();
    let mut refills = vec![];
    let mut records = vec![];
    // Two slots are prepared while idle BEFORE wallet/message selection.
    let mut available = VecDeque::new();
    for _ in 0..2 {
        let (input, s, record) = session.refill(None).await?;
        refills.push(record);
        available.push_back((input, s[0].completed));
    }
    for wallet in 0..3u8 {
        for path in ["m", "m/7/3"] {
            for _ in 0..samples {
                let (input, completed) = available.pop_front().unwrap();
                let key = digest(b"pairkey/dkls-research/wallet/v1", &wallet);
                let record = session.sign(&input, completed, key, path, None).await?;
                ensure!(
                    signatures.insert(record["signature"].as_str().unwrap().to_owned()),
                    "pool repeated signature"
                );
                records.push(record);
                // Idle refill is explicit and separately measured, never hidden on a miss.
                let (input, s, record) = session.refill(None).await?;
                refills.push(record);
                available.push_back((input, s[0].completed));
            }
        }
    }
    session.stop().await?;
    Ok(
        json!({"route":"Pooled","one_way_delay_ms":delay_ms,"startup_ms":startup_ms,"successful_signatures":records.len(),"refills":refills,"attempts":records,
        "scope":"two long-lived local workers; sequential native signing; idle two-slot refill; no real TEE","remaining_unused_entries_discarded":2}),
    )
}

pub async fn demo(dir: &Path, samples: usize) -> Result<()> {
    ensure!(
        cfg!(feature = "research-faults"),
        "pool-demo fault suite requires research-faults"
    );
    let baseline = benchmark(dir, samples, 0).await?;
    let mut refusals = vec![];
    for fault in [
        "bad-zero-reveal",
        "truncated-ot",
        "truncated-pprf",
        "completed-mismatch",
        "setup-timeout",
        "wrong-consumption",
        "wrong-provenance",
        "cancel-reserved",
        "sign-timeout",
        "empty-pool",
        "disconnect",
        "generation-substitution",
        "incident",
        "corrupt-ot",
        "full-pool",
        "repeat-setup",
        "repeat-consumption",
    ] {
        let fault_dir = dir.join(format!("pool-fault-{fault}"));
        let mut s = Session::start(&fault_dir, 0).await?;
        let mut affected = None;
        let result: Result<()> = async {
            if [
                "bad-zero-reveal",
                "truncated-ot",
                "truncated-pprf",
                "completed-mismatch",
                "setup-timeout",
            ]
            .contains(&fault)
            {
                s.refill(Some(fault)).await?;
                return Ok(());
            }
            if fault == "generation-substitution" {
                let mut input = s.input();
                input.boots[1][0] ^= 1;
                s.command([
                    Command::Setup {
                        input: input.clone(),
                        fault: None,
                    },
                    Command::Setup { input, fault: None },
                ])
                .await?;
                return Ok(());
            }
            if fault == "empty-pool" {
                let input = s.input();
                s.sign(&input, [5; 32], [7; 32], "m", None).await?;
                return Ok(());
            }
            let (input, status, _) = s
                .refill(if fault == "corrupt-ot" {
                    Some(fault)
                } else {
                    None
                })
                .await?;
            affected = Some(input.clone());
            // A second unused entry exists when incident/cancellation closes the generation.
            s.refill(None).await?;
            if fault == "full-pool" {
                s.refill(None).await?;
                return Ok(());
            }
            if fault == "repeat-setup" {
                // Consume one slot first, so refusal comes from the setup tombstone.
                s.sign(&input, status[0].completed, [7; 32], "m", None)
                    .await?;
                s.command([
                    Command::Setup {
                        input: input.clone(),
                        fault: None,
                    },
                    Command::Setup {
                        input: input.clone(),
                        fault: None,
                    },
                ])
                .await?;
                return Ok(());
            }
            if fault == "repeat-consumption" {
                s.sign(&input, status[0].completed, [7; 32], "m", None)
                    .await?;
            }
            if fault == "incident" {
                s.command([Command::Incident([9; 32]), Command::Incident([9; 32])])
                    .await?;
                return Ok(());
            }
            s.sign(&input, status[0].completed, [7; 32], "m", Some(fault))
                .await?;
            Ok(())
        }
        .await;
        let error = result
            .err()
            .with_context(|| format!("pool fault {fault} succeeded"))?;
        let terminals = error
            .downcast_ref::<Terminals>()
            .map(|t| serde_json::to_value(t).unwrap());
        let report = error
            .downcast_ref::<Terminals>()
            .context("missing pool terminal report")?;
        ensure!(
            !report.drain_timed_out && report.closed.iter().all(|c| *c),
            "incomplete pool failure drain"
        );
        // Do not count an outer timeout as a refusal. Originating expected error required.
        let expected = match fault {
            "bad-zero-reveal" => "pool zero commitment mismatch",
            "truncated-ot" => "invalid pool OT msg2 length",
            "truncated-pprf" => "invalid pool PPRF length",
            "completed-mismatch" => "pool completed digest disagreement",
            "setup-timeout" | "sign-timeout" => "pool command timeout",
            "wrong-consumption" => "authenticated setup context mismatch",
            "wrong-provenance" => "pool provenance mismatch",
            "cancel-reserved" => "injected cancellation",
            "empty-pool" => "pool empty",
            "disconnect" => "peer disconnected",
            "generation-substitution" => "pool setup enrollment/boot mismatch",
            "incident" => "explicit research incident",
            "corrupt-ot" => "ban the party",
            "full-pool" => "pool full",
            "repeat-setup" => "entry already reserved",
            "repeat-consumption" => "pool empty or entry unavailable",
            _ => unreachable!(),
        };
        if fault == "disconnect" {
            ensure!(
                report
                    .failures
                    .iter()
                    .any(|(_, f)| f.kind == FailureKind::Transport
                        && f.action == pairkey_dkls23_research::lifecycle::Action::Burn),
                "disconnect did not produce a typed transport refusal"
            );
        } else {
            ensure!(
                format!("{error:#}").contains(expected),
                "wrong pool failure {fault}: {error:#}"
            );
        }
        drop(s); // ambiguous command or closed transport discards the other process too
        let quarantined = (0..2).any(|r| super::has_quarantine(&fault_dir, r));
        let expect_incident = [
            "bad-zero-reveal",
            "truncated-ot",
            "truncated-pprf",
            "completed-mismatch",
            "incident",
            "corrupt-ot",
        ]
        .contains(&fault);
        ensure!(
            quarantined == expect_incident,
            "pool fault {fault} incident classification mismatch"
        );
        if expect_incident {
            ensure!(
                report
                    .failures
                    .iter()
                    .any(|(_, f)| f.incident_attempted && f.incident_persisted),
                "missing durable incident evidence"
            );
        }
        let reservations_retired = affected
            .as_ref()
            .map(|input| {
                (0..2).all(|r| {
                    fault_dir
                        .join("controls/entries")
                        .join(format!("{r}-{}.retired", hex(&input.entry)))
                        .exists()
                })
            })
            .unwrap_or(false);
        if [
            "wrong-consumption",
            "wrong-provenance",
            "cancel-reserved",
            "sign-timeout",
            "disconnect",
            "repeat-consumption",
        ]
        .contains(&fault)
        {
            ensure!(
                reservations_retired,
                "both workers did not durably retire the reserved pool entry"
            );
        }
        let mut replacement = Session::start(&fault_dir, 0).await?;
        // Old setup generation is refused even if it was unused; root pins stay stable.
        let retry = if expect_incident {
            replacement.refill(None).await.map(|_| ())
        } else {
            let (input, status, _) = replacement.refill(None).await?;
            replacement
                .sign(&input, status[0].completed, [8; 32], "m/7/3", None)
                .await
                .map(|_| ())
        };
        ensure!(
            retry.is_err() == expect_incident,
            "replacement retry policy failed for {fault}"
        );
        if !expect_incident {
            replacement.stop().await?;
        } else {
            drop(replacement);
        }
        refusals.push(json!({"fault":fault,"diagnostic":format!("{error:#}"),"terminals":terminals,"quarantine":quarantined,"replacement_retry_succeeded":!expect_incident,"affected_setup":affected,"both_reservations_retired":reservations_retired}));
    }
    // Old RAM entry and generation are unavailable after a clean restart.
    let restart_dir = dir.join("pool-fault-restart");
    let mut old = Session::start(&restart_dir, 0).await?;
    let (input, status, _) = old.refill(None).await?;
    old.stop().await?;
    let mut new = Session::start(&restart_dir, 0).await?;
    let error = new
        .sign(&input, status[0].completed, [7; 32], "m", None)
        .await
        .unwrap_err();
    ensure!(
        format!("{error:#}").contains("pool empty"),
        "restart did not discard pool"
    );
    drop(new);
    refusals.push(
        json!({"fault":"restart discards unused material","diagnostic":format!("{error:#}")}),
    );
    let evidence = json!({"configuration":hex(&pool::configuration()),"baseline":baseline,"refusals":refusals,"native_parameters":"locked unchanged","limitations":["custom composition unaudited","cooperating local processes share OS-lock authority; no cross-host/replica fencing","snapshot/rollback protection absent","idle refill scheduled by trusted driver; no overlapping sign/refill wire multiplexing","no TEE, production authorization or adoption"]});
    std::fs::write(
        dir.join("pool-evidence.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!(
        "{}",
        json!({"evidence":dir.join("pool-evidence.json"),"successful_signatures":evidence["baseline"]["successful_signatures"],"refusals":evidence["refusals"].as_array().unwrap().len()})
    );
    Ok(())
}

/// Actual two-worker pipe round trip with no curve/OT work. Includes framing,
/// scheduling and gate filesystem checks; not a raw kernel pipe benchmark.
pub async fn transport_probe(dir: &Path) -> Result<Value> {
    let mut session = Session::start(dir, 0).await?;
    let mut records = vec![];
    for i in 0..102 {
        let nonce = fresh();
        let before = session.parent_serialization_ns;
        let t = Instant::now();
        let frames = session
            .command([Command::Ping(nonce), Command::Ping(nonce)])
            .await?;
        for (_, frame) in frames {
            let Frame::PoolStatus(s) = frame else {
                anyhow::bail!("expected pong");
            };
            ensure!(s.operation == "pong" && s.entry == nonce, "pong mismatch");
        }
        if i >= 2 {
            records.push(json!({"two_worker_roundtrip_ms":t.elapsed().as_secs_f64()*1000.0,"parent_serialization_ms":(session.parent_serialization_ns-before) as f64/1e6}));
        }
    }
    session.stop().await?;
    Ok(
        json!({"samples":100,"two_worker_roundtrip_median_ms":super::median(records.iter().map(|r|r["two_worker_roundtrip_ms"].as_f64().unwrap()).collect()),
        "parent_serialization_median_ms":super::median(records.iter().map(|r|r["parent_serialization_ms"].as_f64().unwrap()).collect()),"records":records,
        "scope":"stdio JSON serialization, pipe writes/reads, runtime scheduling and release-gate metadata checks; no curve/OT computation"}),
    )
}
