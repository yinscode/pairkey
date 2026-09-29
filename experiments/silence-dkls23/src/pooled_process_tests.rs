//! Actual pooled adapter processes. Queue observations are independent of worker
//! cancellation and send results. Test helpers/bypasses never enter a normal build.
use super::{send, ChildGroup};
use anyhow::{ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use k256::elliptic_curve::group::GroupEncoding;
use pairkey_dkls23_research::{
    digest, fresh, incident,
    lifecycle::pair_scope_dir,
    point,
    pool::{self, Boot, Command as Operation, Consumption, SetupInput},
    registration::{Endorsement, RegisteredWallet, WalletRecord},
    Frame, Hello, Manifest, Request, Root, Route, MAX_FRAME,
};
use sl_mpc_mate::coord::{simple::MessageRelay, SimpleMessageRelay};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::{ChildStdin, Command},
    sync::mpsc,
};

const CHILD: &str = "pooled_process_tests::pooled_process_child";
#[test]
#[ignore = "explicit pooled subprocess fixture"]
fn pooled_process_child() {
    let dir = PathBuf::from(std::env::var_os("PAIRKEY_NATIVE_RACE_DIR").expect("parent fixture"));
    let storage = std::env::var_os("PAIRKEY_ACTOR_STORAGE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.clone());
    let direct = std::env::var("PAIRKEY_ACTOR_ROUTE").ok().as_deref() == Some("direct");
    let role: u8 = std::env::var("PAIRKEY_NATIVE_RACE_ROLE")
        .unwrap()
        .parse()
        .unwrap();
    fs::write(
        dir.join(format!("{role}.pid")),
        std::process::id().to_string(),
    )
    .unwrap();
    if role == 2 {
        if std::env::var("PAIRKEY_POOLED_PUBLISH").unwrap() == "1" {
            let peers = serde_json::from_slice(&fs::read(dir.join("peers.json")).unwrap()).unwrap();
            let publisher_role = std::env::var("PAIRKEY_POOLED_PUBLISHER_ROLE")
                .unwrap()
                .parse()
                .unwrap();
            // Exercise the public API, including role-1 publication.
            let scope = pair_scope_dir(&storage.join("controls"), peers, 1);
            if std::env::var("PAIRKEY_PUBLISH_API").ok().as_deref() == Some("gate") {
                pairkey_dkls23_research::lifecycle::ReleaseGate::new(scope, publisher_role)
                    .publish([9; 32])
                    .unwrap();
            } else {
                incident(&scope, publisher_role, [9; 32]).unwrap();
            }
            fs::write(dir.join("published"), []).unwrap();
        }
        fs::write(dir.join("publisher.done"), []).unwrap();
    } else {
        let peers: [[u8; 32]; 2] =
            serde_json::from_slice(&fs::read(dir.join("peers.json")).unwrap()).unwrap();
        let peer = peers[(1 - role) as usize];
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(3)
            .thread_stack_size(16 * 1024 * 1024)
            .enable_all()
            .build()
            .unwrap();
        let result = if direct {
            let key = super::unhex(&std::env::var("PAIRKEY_ACTOR_KEY").unwrap()).unwrap();
            runtime.block_on(super::worker::run(
                role,
                &storage.join(format!("root-{role}.bin")),
                key,
            ))
        } else {
            runtime.block_on(super::pool_worker::run(
                role,
                &storage.join(format!("root-{role}.bin")),
                peer,
            ))
        };
        fs::write(dir.join(format!("{role}.done")), format!("{result:?}")).unwrap();
        if direct && result.is_err() {
            // Direct run returns a gate refusal on its final Result send. Require
            // a persisted incident; every other unexpected error fails the fixture.
            let gate = pairkey_dkls23_research::lifecycle::ReleaseGate::new(
                pair_scope_dir(&storage.join("controls"), peers, 1),
                role,
            );
            assert!(
                gate.release(|| Ok(())).is_err(),
                "unexpected Direct worker error: {result:?}"
            );
        } else {
            result.expect("non-killed pooled fixture worker failed");
        }
    }
}
fn command(
    dir: &Path,
    role: u8,
    stage: &str,
    publish: bool,
    bypass: bool,
    publisher_role: u8,
) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--ignored", "--exact", CHILD, "--nocapture", "--quiet"])
        .env("RUST_MIN_STACK", "16777216")
        .env("PAIRKEY_NATIVE_RACE_DIR", dir)
        .env("PAIRKEY_NATIVE_RACE_ROLE", role.to_string())
        .env("PAIRKEY_NATIVE_RACE_STAGE", stage)
        .env("PAIRKEY_NATIVE_RACE_BYPASS", if bypass { "1" } else { "0" })
        .env("PAIRKEY_POOLED_PUBLISH", if publish { "1" } else { "0" })
        .env("PAIRKEY_POOLED_PUBLISHER_ROLE", publisher_role.to_string())
        .kill_on_drop(true);
    c
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        if self.0.join("passed").exists() {
            let _ = fs::remove_dir_all(&self.0);
        } else {
            eprintln!("pooled fixture retained: {}", self.0.display());
        }
    }
}
struct Actors {
    group: ChildGroup,
    inputs: Vec<Option<ChildStdin>>,
    events: mpsc::UnboundedReceiver<(usize, Frame)>,
    relays: [MessageRelay; 2],
    boots: Option<[Boot; 2]>,
    direct_hellos: Option<[Hello; 2]>,
    probe_dir: PathBuf,
}
impl Actors {
    async fn start(dir: &Path, stage: &str, bypass: bool) -> Result<Self> {
        Self::start_variant(dir, dir, stage, bypass, None).await
    }
    fn boots(&self) -> &[Boot; 2] {
        self.boots.as_ref().expect("pooled boot pair")
    }
    async fn start_variant(
        dir: &Path,
        storage: &Path,
        stage: &str,
        bypass: bool,
        direct_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        Self::start_options(dir, storage, stage, bypass, direct_key, None).await
    }
    async fn start_options(
        dir: &Path,
        storage: &Path,
        stage: &str,
        bypass: bool,
        direct_key: Option<[u8; 32]>,
        single_role: Option<u8>,
    ) -> Result<Self> {
        let peers = [
            Root::load(&storage.join("root-0.bin"))?
                .identity(0)
                .verifying_key()
                .to_bytes(),
            Root::load(&storage.join("root-1.bin"))?
                .identity(1)
                .verifying_key()
                .to_bytes(),
        ];
        fs::write(dir.join("peers.json"), serde_json::to_vec(&peers)?)?;
        let mut group = ChildGroup {
            children: vec![],
            readers: vec![],
        };
        let mut inputs = vec![];
        let (tx, mut events) = mpsc::unbounded_channel();
        for role in 0..2 {
            let mut process = command(dir, role, stage, false, bypass, 0);
            process
                .env("PAIRKEY_ACTOR_STORAGE_DIR", storage)
                .env("PAIRKEY_TRACE_ALL", "1");
            if let Some(role) = single_role {
                process.env("PAIRKEY_PROBE_ROLE", role.to_string());
            }
            if let Some(key) = direct_key {
                process
                    .env("PAIRKEY_ACTOR_ROUTE", "direct")
                    .env("PAIRKEY_ACTOR_KEY", super::hex(&key));
            }
            let mut child = process
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .spawn()?;
            inputs.push(child.stdin.take());
            let mut output = BufReader::new(child.stdout.take().context("stdout")?);
            let tx = tx.clone();
            group.readers.push(tokio::spawn(async move {
                loop {
                    let mut line = vec![];
                    if (&mut output)
                        .take(MAX_FRAME as u64 + 1)
                        .read_until(b'\n', &mut line)
                        .await
                        .unwrap()
                        == 0
                    {
                        break;
                    }
                    assert!(line.len() <= MAX_FRAME);
                    if let Some(start) = line.windows(8).position(|w| w == b"{\"kind\":") {
                        tx.send((
                            role as usize,
                            serde_json::from_slice(&line[start..]).unwrap(),
                        ))
                        .unwrap();
                    }
                }
                let _ = tx.send((role as usize, Frame::Closed));
            }));
            group.children.push(child);
        }
        drop(tx);
        let mut boots: [Option<Boot>; 2] = [None, None];
        let mut hellos: [Option<Hello>; 2] = [None, None];
        let mut seen = [false; 2];
        while !seen.iter().all(|v| *v) {
            let (role, frame) = events.recv().await.context("startup closed")?;
            ensure!(role < 2 && !seen[role], "startup role/duplicate");
            if let Some(key) = direct_key {
                let Frame::Hello(h) = frame else {
                    anyhow::bail!("unexpected Direct startup");
                };
                h.validate()?;
                ensure!(
                    h.role as usize == role && h.identity == peers[role] && h.key_id == key,
                    "Direct startup pin"
                );
                hellos[role] = Some(h);
            } else {
                let Frame::PoolHello(b) = frame else {
                    anyhow::bail!("unexpected pooled startup");
                };
                b.validate()?;
                ensure!(
                    b.role as usize == role && b.identity == peers[role],
                    "pool startup pin"
                );
                boots[role] = Some(b);
            }
            seen[role] = true;
        }
        let boots = if direct_key.is_none() {
            Some(boots.map(Option::unwrap))
        } else {
            None
        };
        if let Some(boots) = &boots {
            for input in &mut inputs {
                send(
                    input.as_mut().unwrap(),
                    &Frame::PoolCommand(Box::new(Operation::Enroll(boots.clone()))),
                )
                .await?;
            }
        }
        let relay = SimpleMessageRelay::new();
        Ok(Self {
            group,
            inputs,
            events,
            relays: [relay.connect(), relay.connect()],
            boots,
            direct_hellos: direct_key.map(|_| hellos.map(Option::unwrap)),
            probe_dir: dir.to_path_buf(),
        })
    }
    async fn call(&mut self, ops: [Operation; 2]) -> Result<Vec<(usize, Frame)>> {
        for (role, op) in ops.into_iter().enumerate() {
            send(
                self.inputs[role].as_mut().context("input closed")?,
                &Frame::PoolCommand(Box::new(op)),
            )
            .await?;
        }
        self.collect().await
    }
    async fn start_direct(&mut self, request: Request) -> Result<Vec<(usize, Frame)>> {
        for input in &mut self.inputs {
            send(
                input.as_mut().context("input closed")?,
                &Frame::Start(Box::new(request.clone())),
            )
            .await?;
        }
        self.collect().await
    }
    async fn collect(&mut self) -> Result<Vec<(usize, Frame)>> {
        let mut replies = vec![];
        let mut closed = [false; 2];
        let mut failed = false;
        let mut poll = tokio::time::interval(Duration::from_millis(5));
        loop {
            if closed.iter().all(|v| *v) || (!failed && replies.len() == 2) {
                return Ok(replies);
            }
            let [r0, r1] = &mut self.relays;
            let event = tokio::select! {
                e=self.events.recv()=>e.context("events closed")?,
                _=poll.tick()=>{for (role,input) in self.inputs.iter_mut().enumerate() {if self.probe_dir.join(format!("{role}.done")).exists() {input.take();}}continue;},
                b=r0.next(),if !failed=>{if let (Some(b),Some(input))=(b,&mut self.inputs[0]) {let _=send(input,&Frame::Relay(b)).await;}continue;},
                b=r1.next(),if !failed=>{if let (Some(b),Some(input))=(b,&mut self.inputs[1]) {let _=send(input,&Frame::Relay(b)).await;}continue;},
            };
            match event {
                (role, Frame::Setup(b)) if !failed => {
                    if let Some(input) = &mut self.inputs[1 - role] {
                        let _ = send(input, &Frame::Setup(b)).await;
                    }
                }
                (role, Frame::Relay(b)) if !failed => {
                    let _ = self.relays[role].send(b).await;
                }
                (role, Frame::Closed) => {
                    closed[role] = true;
                    self.inputs[role].take();
                    if !replies.iter().any(|(r, _)| *r == role) {
                        failed = true;
                        for input in &mut self.inputs {
                            input.take();
                        }
                    }
                }
                (role, Frame::Failure(f)) => {
                    // After a deliberate result bypass, a pooled worker can
                    // emit its unfenced incident-shutdown control frame before
                    // the other role's completed result reaches this reader.
                    // The result already received is this command's terminal
                    // reply; the later control frame must not replace/count it.
                    if self.probe_dir.join("published").exists()
                        && replies
                            .iter()
                            .any(|(r, frame)| *r == role && matches!(frame, Frame::Result(_)))
                    {
                        continue;
                    }
                    replies.push((role, Frame::Failure(f)));
                    failed = true;
                    for input in &mut self.inputs {
                        input.take();
                    }
                }
                (_, Frame::Ready(_)) => {}
                (_, Frame::Setup(_) | Frame::Relay(_)) => {}
                (role, frame) => {
                    ensure!(!replies.iter().any(|(r, _)| *r == role), "duplicate reply");
                    replies.push((role, frame));
                }
            }
        }
    }
    async fn describe(&mut self, key: [u8; 32]) -> Result<(WalletRecord, [Hello; 2])> {
        let mut frames = self
            .call([Operation::Describe(key), Operation::Describe(key)])
            .await?;
        frames.sort_by_key(|(r, _)| *r);
        let hellos: Vec<_> = frames
            .into_iter()
            .map(|(_, f)| {
                let Frame::Hello(h) = f else {
                    anyhow::bail!("expected hello");
                };
                h.validate()?;
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
            identities: self.boots().clone().map(|b| b.identity),
            additive_public: hellos.clone().map(|h| h.contribution),
            public_key: q.to_bytes().to_vec(),
            chain_code: digest(
                b"pairkey/dkls-research/public-chain-code/v1",
                &(key, q.to_bytes().to_vec()),
            ),
        };
        let record = WalletRecord::new(manifest)?;
        record.validate_hellos(&hellos)?;
        Ok((record, hellos))
    }
    async fn endorse(
        &mut self,
        record: &WalletRecord,
        hellos: &[Hello; 2],
    ) -> Result<Vec<(usize, Frame)>> {
        self.call(std::array::from_fn(|_| Operation::Register {
            record: Box::new(record.clone()),
            hellos: Box::new(hellos.clone()),
        }))
        .await
    }
    async fn commit(&mut self, wallet: &RegisteredWallet) -> Result<Vec<(usize, Frame)>> {
        self.call(std::array::from_fn(|_| {
            Operation::CommitWallet(Box::new(wallet.clone()))
        }))
        .await
    }
    async fn finish(mut self) -> Result<()> {
        for input in &mut self.inputs {
            if let Some(input) = input {
                let _ = send(input, &Frame::PoolCommand(Box::new(Operation::Stop))).await;
            }
            input.take();
        }
        for child in &mut self.group.children {
            ensure!(child.wait().await?.success(), "worker failed");
        }
        for reader in &mut self.group.readers {
            reader.await?;
        }
        Ok(())
    }
}
/// Require observed ACKs from both transport roles, exactly once, before a
/// schedule can claim successful registration. An empty reply list is failure.
fn commit_ack_roles(frames: &[(usize, Frame)], digest: [u8; 32]) -> Result<[usize; 2]> {
    ensure!(
        frames.len() == 2,
        "expected exactly two commit acknowledgments"
    );
    let mut roles = [0; 2];
    for (role, frame) in frames {
        ensure!(*role < roles.len(), "invalid commit acknowledgment role");
        ensure!(
            matches!(frame, Frame::WalletRegistered(d) if *d == digest),
            "commit acknowledgment mismatch"
        );
        roles[*role] += 1;
    }
    ensure!(
        roles == [1, 1],
        "expected one commit acknowledgment from each role"
    );
    Ok(roles)
}
fn wallet(record: WalletRecord, mut frames: Vec<(usize, Frame)>) -> Result<RegisteredWallet> {
    frames.sort_by_key(|(r, _)| *r);
    let endorsements: Vec<Endorsement> = frames
        .into_iter()
        .map(|(_, f)| {
            let Frame::WalletEndorsement(e) = f else {
                anyhow::bail!("expected endorsement");
            };
            Ok(e)
        })
        .collect::<Result<_>>()?;
    let w = RegisteredWallet {
        record,
        endorsements: endorsements
            .try_into()
            .map_err(|_| anyhow::anyhow!("endorsement count"))?,
    };
    w.validate()?;
    Ok(w)
}
async fn barrier(
    dir: PathBuf,
    stage: String,
    publish: bool,
    bypass: bool,
    publisher_role: u8,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !(0..2).all(|r| dir.join(format!("{r}.reached")).exists()) {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "pooled barrier not reached"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    ensure!(
        (0..2).all(|r| !dir.join(format!("{r}.queued")).exists()),
        "target already queued"
    );
    let mut publisher = command(&dir, 2, &stage, publish, bypass, publisher_role)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;
    ensure!(publisher.wait().await?.success(), "publisher failure");
    ensure!(
        dir.join("publisher.done").exists(),
        "no publication acknowledgment"
    );
    fs::write(dir.join("resume"), [])?;
    Ok(())
}
async fn case(stage: &str, publish: bool, bypass: bool, publisher_role: u8) -> Result<()> {
    let dir = Directory(std::env::temp_dir().join(format!("dkls-pooled-process-{:?}", fresh())));
    fs::create_dir(&dir.0)?;
    for role in 0..2 {
        fs::write(
            dir.0.join(format!("root-{role}.bin")),
            [11 + role as u8; 32],
        )?;
    }
    let mut actors = Actors::start(&dir.0, stage, bypass).await?;
    let (record, hellos) = actors.describe([7; 32]).await?;
    let target = tokio::spawn(barrier(
        dir.0.clone(),
        stage.to_owned(),
        publish,
        bypass,
        publisher_role,
    ));
    let first = actors.endorse(&record, &hellos).await?;
    let mut outcomes = vec![];
    if stage != "endorsement" || !publish {
        let w = wallet(record.clone(), first)?;
        let commits = actors.commit(&w).await?;
        if stage != "commit" || !publish {
            commit_ack_roles(&commits, record.digest())?;
            let input = SetupInput {
                version: 1,
                recipe: 1,
                peers: actors.boots().clone().map(|b| b.identity),
                boots: actors.boots().clone().map(|b| b.generation),
                configuration: pool::configuration(),
                entry: fresh(),
            };
            let setup = actors
                .call(std::array::from_fn(|_| Operation::Setup {
                    input: input.clone(),
                    fault: None,
                }))
                .await?;
            let completed = match &setup[0].1 {
                Frame::PoolStatus(s) => s.completed,
                _ => anyhow::bail!("missing refill"),
            };
            ensure!(setup.iter().all(|(_,f)|matches!(f,Frame::PoolStatus(s) if s.completed==completed && s.entry==input.entry && s.input==input.digest())),"setup disagreement");
            let request = Request {
                route: Route::Pooled,
                manifest: record.manifest.clone(),
                hellos,
                entry: input.entry,
                attempt: fresh(),
                path: "m".into(),
                prehash: [6; 32],
                fault: None,
                wallet_record: Some(record.digest()),
            };
            let consumption = Consumption::new(&input, completed, &request, fresh(), 1);
            outcomes = actors
                .call(std::array::from_fn(|_| Operation::Sign {
                    request: Box::new(request.clone()),
                    consumption: consumption.clone(),
                }))
                .await?;
            if !publish || stage == "result" && bypass {
                use signature::hazmat::PrehashVerifier;
                ensure!(outcomes.len() == 2, "result count");
                for (_, frame) in &outcomes {
                    let Frame::Result(out) = frame else {
                        anyhow::bail!("expected signature");
                    };
                    let signature = k256::ecdsa::Signature::from_slice(&out.signature)?;
                    k256::ecdsa::VerifyingKey::from_sec1_bytes(&record.manifest.public_key)?
                        .verify_prehash(&request.prehash, &signature)?;
                    ensure!(signature.normalize_s().is_none(), "high-S");
                }
            }
        }
    }
    target.await??;
    actors.finish().await?;
    let pids = (0..3)
        .map(|r| fs::read_to_string(dir.0.join(format!("{r}.pid"))))
        .collect::<std::io::Result<std::collections::BTreeSet<_>>>()?;
    ensure!(pids.len() == 3, "actors must be distinct processes");
    let queued = (0..2)
        .filter(|r| dir.0.join(format!("{r}.queued")).exists())
        .count();
    ensure!(
        queued == if publish && !bypass { 0 } else { 2 },
        "pooled queue oracle failed for {stage}"
    );
    for role in 0..2 {
        if queued == 2 {
            ensure!(
                fs::read_to_string(dir.0.join(format!("{role}.queued")))?
                    == if publish { "late" } else { "ordinary" },
                "incorrect observation"
            );
        }
    }
    if publish {
        // Route/wallet changes cannot escape the same pair authority; another
        // pair authority sharing the filesystem remains usable.
        let scope = pair_scope_dir(&dir.0.join("controls"), record.manifest.identities, 1);
        for role in 0..2 {
            ensure!(
                pairkey_dkls23_research::lifecycle::ReleaseGate::new(scope.clone(), role)
                    .release(|| Ok(()))
                    .is_err(),
                "scope escaped"
            );
        }
        let mut other = record.manifest.identities;
        other[0][0] ^= 1;
        pairkey_dkls23_research::lifecycle::ReleaseGate::new(
            pair_scope_dir(&dir.0.join("controls"), other, 1),
            0,
        )
        .release(|| Ok(()))?;
    }
    if let Some(output) = std::env::var_os("PAIRKEY_ASSURANCE_EVIDENCE_DIR") {
        let output = PathBuf::from(output);
        fs::create_dir_all(&output)?;
        fs::write(
            output.join(format!(
                "pooled-{stage}-{publish}-{bypass}-{publisher_role}.json"
            )),
            serde_json::to_vec_pretty(
                &serde_json::json!({"stage":stage,"publish":publish,"bypass":bypass,"publisher_role":publisher_role,"publication_api":"incident","distinct_processes":pids.len(),"both_actual_targets_reached":true,"queue_handoffs":queued,"verified_result_frames":outcomes.iter().filter(|(_,f)|matches!(f,Frame::Result(_))).count(),"passed":true}),
            )?,
        )?;
    }
    fs::write(dir.0.join("passed"), [])?;
    Ok(())
}
async fn cases(publish: bool, bypass: bool, publisher_role: u8) {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for stage in ["endorsement", "commit", "consume", "r4", "result"] {
        tokio::time::timeout(
            Duration::from_secs(25),
            case(stage, publish, bypass, publisher_role),
        )
        .await
        .unwrap()
        .unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_process_handoffs_refuse_after_public_incident() {
    cases(true, false, 0).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_process_positive_controls_complete() {
    cases(false, false, 0).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_process_queue_observer_detects_bypasses() {
    cases(true, true, 0).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_process_role_one_publication_fences_both_roles() {
    cases(true, false, 1).await;
}

async fn registration_release_death_case(stage: &str, after_release: bool) -> Result<()> {
    let dir =
        Directory(std::env::temp_dir().join(format!("dkls-registration-release-{:?}", fresh())));
    fs::create_dir(&dir.0)?;
    for role in 0..2 {
        fs::write(
            dir.0.join(format!("root-{role}.bin")),
            [11 + role as u8; 32],
        )?;
    }
    let mut actors = Actors::start(&dir.0, stage, false).await?;
    let (record, hellos) = actors.describe([7; 32]).await?;
    let prepared_prefix = super::hex(&record.manifest.key_id);
    let (operation, candidate) = if stage == "endorsement" {
        (
            std::array::from_fn(|_| Operation::Register {
                record: Box::new(record.clone()),
                hellos: Box::new(hellos.clone()),
            }),
            None,
        )
    } else {
        let w = wallet(record.clone(), actors.endorse(&record, &hellos).await?)?;
        (
            std::array::from_fn(|_| Operation::CommitWallet(Box::new(w.clone()))),
            Some(w),
        )
    };
    let interruption = tokio::spawn({
        let dir = dir.0.clone();
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while !(0..2).all(|r| dir.join(format!("{r}.reached")).exists()) {
                ensure!(
                    tokio::time::Instant::now() < deadline,
                    "release targets missing"
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            ensure!(
                (0..2).all(|r| !dir.join(format!("{r}.queued")).exists()),
                "target already queued"
            );
            if after_release {
                fs::write(dir.join("resume"), [])?;
            }
            Ok::<_, anyhow::Error>(())
        }
    });
    let mut released_endorsements: [Option<Endorsement>; 2] = [None, None];
    // Keep driving stdio while the workers reach their actual gated releases.
    if after_release {
        let frames = actors.call(operation).await?;
        ensure!(frames.len() == 2, "both releases required");
        if stage == "commit" {
            commit_ack_roles(&frames, record.digest())?;
        }
        for (role, frame) in frames {
            match frame {
                Frame::WalletEndorsement(e) if stage == "endorsement" => {
                    ensure!(role < 2 && e.role as usize == role, "role");
                    ensure!(
                        released_endorsements[role].is_none(),
                        "duplicate endorsement release"
                    );
                    e.validate(&record)?;
                    released_endorsements[role] = Some(e);
                }
                Frame::WalletRegistered(d) if stage == "commit" => {
                    ensure!(d == record.digest(), "commit ACK")
                }
                _ => anyhow::bail!("unexpected release"),
            }
        }
        interruption.await??;
    } else {
        for (role, op) in operation.into_iter().enumerate() {
            send(
                actors.inputs[role].as_mut().unwrap(),
                &Frame::PoolCommand(Box::new(op)),
            )
            .await?;
        }
        interruption.await??;
    }
    let original = (0..2)
        .map(|role| {
            fs::read(
                dir.0
                    .join("controls/wallets")
                    .join(format!("{prepared_prefix}-{role}.prepared")),
            )
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let expected: Vec<Endorsement> = original
        .iter()
        .map(|bytes| {
            let v: serde_json::Value = serde_json::from_slice(bytes)?;
            Ok(serde_json::from_value(v["endorsement"].clone())?)
        })
        .collect::<Result<_>>()?;
    if stage == "endorsement" && after_release {
        for (role, saved) in expected.iter().enumerate() {
            ensure!(
                released_endorsements[role].as_ref() == Some(saved),
                "released endorsement differs from saved journal"
            );
        }
    }
    let committed_path = dir
        .0
        .join("controls/wallets")
        .join(format!("{prepared_prefix}.wallet"));
    let committed = fs::read(&committed_path).ok();
    ensure!(
        committed.is_some() == (stage == "commit"),
        "unexpected commit state before interruption"
    );
    for child in &mut actors.group.children {
        child.start_kill()?;
        child.wait().await?;
    }
    for input in &mut actors.inputs {
        input.take();
    }
    for reader in &mut actors.group.readers {
        reader.await?;
    }
    let queued = (0..2)
        .filter(|role| dir.0.join(format!("{role}.queued")).exists())
        .count();
    ensure!(
        queued == if after_release { 2 } else { 0 },
        "independent release observation"
    );
    drop(actors);
    // A replacement process gets fresh boot entropy, but must recover the exact
    // persisted proof/endorsement, rather than silently generating a new one.
    let mut replacement = Actors::start(&dir.0, "", false).await?;
    let (same_record, new_hellos) = replacement.describe([7; 32]).await?;
    ensure!(same_record == record, "root/address changed");
    let recovered = wallet(
        same_record,
        replacement.endorse(&record, &new_hellos).await?,
    )?;
    ensure!(
        recovered.endorsements.as_slice() == expected.as_slice(),
        "replacement changed endorsements"
    );
    for (role, released) in released_endorsements.iter().enumerate() {
        if let Some(released) = released {
            ensure!(
                *released == recovered.endorsements[role],
                "released endorsement differs from replacement endorsement"
            );
        }
    }
    if let Some(candidate) = candidate {
        ensure!(candidate == recovered, "commit candidate changed");
    }
    let acknowledgments = replacement.commit(&recovered).await?;
    let acknowledgment_roles = commit_ack_roles(&acknowledgments, record.digest())?;
    let acknowledgment_count: usize = acknowledgment_roles.iter().sum();
    let released_endorsement_count = released_endorsements.iter().flatten().count();
    for (role, bytes) in original.iter().enumerate() {
        ensure!(
            fs::read(
                dir.0
                    .join("controls/wallets")
                    .join(format!("{prepared_prefix}-{role}.prepared"))
            )? == *bytes,
            "prepare journal changed"
        );
    }
    if let Some(committed) = committed {
        ensure!(
            fs::read(committed_path)? == committed,
            "committed record changed"
        );
    }
    replacement.finish().await?;
    if let Some(output) = std::env::var_os("PAIRKEY_ASSURANCE_EVIDENCE_DIR") {
        let output = PathBuf::from(output);
        fs::create_dir_all(&output)?;
        fs::write(
            output.join(format!("registration-release-{stage}-{after_release}.json")),
            serde_json::to_vec_pretty(
                &serde_json::json!({"stage":stage,"death_after_queue_handoff":after_release,"observed_queue_handoffs":queued,"both_workers_killed":true,"replacement_endorsements_identical":true,"existing_bytes_unchanged":true,"replacement_commit_acknowledgments":acknowledgment_count,"replacement_commit_acknowledgment_roles":acknowledgment_roles,"observed_released_endorsements":released_endorsement_count,"released_journal_replacement_match":if released_endorsement_count > 0 {Some(true)} else {None},"replacement_workers_completed_successfully":true,"passed":true}),
            )?,
        )?;
    }
    fs::write(dir.0.join("passed"), [])?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_registration_process_death_before_and_after_release_recovers_exact_record() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for stage in ["endorsement", "commit"] {
        for after_release in [false, true] {
            tokio::time::timeout(
                Duration::from_secs(25),
                registration_release_death_case(stage, after_release),
            )
            .await
            .unwrap()
            .unwrap();
        }
    }
}

#[test]
fn commit_acknowledgment_validation_rejects_empty_missing_duplicate_and_invalid_replies() {
    let digest = [9; 32];
    let ack = |role| (role, Frame::WalletRegistered(digest));
    assert_eq!(commit_ack_roles(&[ack(1), ack(0)], digest).unwrap(), [1, 1]);
    for frames in [
        vec![],
        vec![ack(0)],
        vec![ack(0), ack(0)],
        vec![ack(1), ack(1)],
        vec![ack(0), ack(2)],
        vec![ack(0), (1, Frame::WalletRegistered([8; 32]))],
        vec![ack(0), (1, Frame::Closed)],
        vec![ack(0), ack(1), ack(1)],
    ] {
        assert!(commit_ack_roles(&frames, digest).is_err());
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_fixture_worker_error_exits_unsuccessfully() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    let dir =
        Directory(std::env::temp_dir().join(format!("dkls-pooled-worker-error-{:?}", fresh())));
    fs::create_dir(&dir.0).unwrap();
    fs::write(
        dir.0.join("peers.json"),
        serde_json::to_vec(&[[1u8; 32], [2u8; 32]]).unwrap(),
    )
    .unwrap();
    // Missing own root makes run() return Err before stdio starts. The child
    // helper must fail, even though it can publish a diagnostic completion file.
    let mut child = command(&dir.0, 0, "", false, false, 0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success(), "fixture hid pool_worker::run failure");
    assert!(fs::read_to_string(dir.0.join("0.done"))
        .unwrap()
        .starts_with("Err("));
    fs::write(dir.0.join("passed"), []).unwrap();
}

#[path = "extended_process_tests.rs"]
mod extended;

#[tokio::test]
async fn collector_preserves_completed_results_before_incident_shutdown_control() {
    // Synthetic frames test ordering only. Actual native signatures and queues
    // are independently verified by the process matrix.
    for published in [false, true] {
        let dir =
            Directory(std::env::temp_dir().join(format!("dkls-terminal-reply-{:?}", fresh())));
        fs::create_dir(&dir.0).unwrap();
        if published {
            fs::write(dir.0.join("published"), []).unwrap();
        }
        let result = |role| {
            Frame::Result(pairkey_dkls23_research::Outcome {
                role,
                route: Route::Pooled,
                context: [1; 32],
                public_key: vec![],
                signature: vec![],
                recovery_id: 0,
                setup_ms: 0.0,
                signing_ms: 0.0,
                setup_active_poll_ms: None,
                signing_active_poll_ms: 0.0,
                package_bytes: 0,
                setup_id: vec![],
            })
        };
        let (tx, events) = mpsc::unbounded_channel();
        tx.send((0, result(0))).unwrap();
        tx.send((
            0,
            Frame::Failure(pairkey_dkls23_research::lifecycle::Failure::burn(
                pairkey_dkls23_research::lifecycle::Phase::Control,
                pairkey_dkls23_research::lifecycle::FailureKind::Quarantined,
                "post-result incident shutdown",
            )),
        ))
        .unwrap();
        tx.send((1, result(1))).unwrap();
        tx.send((0, Frame::Closed)).unwrap();
        tx.send((1, Frame::Closed)).unwrap();
        let relay = SimpleMessageRelay::new();
        let mut actors = Actors {
            group: ChildGroup {
                children: vec![],
                readers: vec![],
            },
            inputs: vec![None, None],
            events,
            relays: [relay.connect(), relay.connect()],
            boots: None,
            direct_hellos: None,
            probe_dir: dir.0.clone(),
        };
        let replies = tokio::time::timeout(Duration::from_secs(2), actors.collect())
            .await
            .unwrap()
            .unwrap();
        if published {
            assert_eq!(replies.len(), 2);
            assert!(replies
                .iter()
                .enumerate()
                .all(|(role, (r, f))| role == *r && matches!(f, Frame::Result(_))));
        } else {
            assert!(replies.iter().any(|(_, f)| matches!(f, Frame::Failure(_))));
            assert_ne!(
                replies.len(),
                2,
                "unexpected failure hidden without publication"
            );
        }
        fs::write(dir.0.join("passed"), []).unwrap();
    }
}
