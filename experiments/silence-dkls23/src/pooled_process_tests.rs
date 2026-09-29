//! Actual pooled adapter processes. Queue observations are independent of worker
//! cancellation and send results. Test helpers/bypasses never enter a normal build.
use super::{send, ChildGroup};
use anyhow::{ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use k256::elliptic_curve::group::GroupEncoding;
use pairkey_dkls23_research::{
    digest, fresh, incident,
    lifecycle::{pair_scope_dir, Failure},
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
#[derive(serde::Serialize, serde::Deserialize)]
struct PublicationAck {
    peers: [[u8; 32]; 2],
    run: [u8; 32],
    publisher: u8,
    context: [u8; 32],
}
#[derive(Clone)]
struct PublicationExpectation {
    dir: PathBuf,
    scope: PathBuf,
    peers: [[u8; 32]; 2],
    run: [u8; 32],
    publisher: u8,
}
impl PublicationExpectation {
    fn confirmed(&self) -> bool {
        let check = || -> Result<()> {
            ensure!(
                self.dir.join("publisher.done").exists(),
                "publisher not acknowledged"
            );
            let ack: PublicationAck =
                serde_json::from_slice(&fs::read(self.dir.join("publication-ack.json"))?)?;
            ensure!(
                ack.peers == self.peers
                    && ack.run == self.run
                    && ack.publisher == self.publisher
                    && ack.context == [9; 32],
                "wrong publication"
            );
            ensure!(
                fs::read(self.scope.join(format!("{}.quarantined", self.publisher)))?
                    == ack.context,
                "wrong or incomplete authority record"
            );
            Ok(())
        };
        check().is_ok()
    }
}
fn direct_cutoff(error: &anyhow::Error, publication: &PublicationExpectation) -> bool {
    error
        .downcast_ref::<Failure>()
        .is_some_and(Failure::is_incident_cutoff)
        && publication.confirmed()
}
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
            let ack = PublicationAck {
                peers,
                run: serde_json::from_slice(&fs::read(dir.join("run.json")).unwrap()).unwrap(),
                publisher: publisher_role,
                context: [9; 32],
            };
            fs::write(
                dir.join("publication-ack.json"),
                serde_json::to_vec(&ack).unwrap(),
            )
            .unwrap();
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
            // Only the original typed cutoff is acceptable, never an unrelated
            // error followed by a failed re-check of the gate.
            let run = serde_json::from_slice(&fs::read(dir.join("run.json")).unwrap()).unwrap();
            assert!(
                (0..2).any(|publisher| direct_cutoff(
                    result.as_ref().unwrap_err(),
                    &PublicationExpectation {
                        dir: dir.clone(),
                        scope: pair_scope_dir(&storage.join("controls"), peers, 1),
                        peers,
                        run,
                        publisher,
                    }
                )),
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
    publication: PublicationExpectation,
    expected_publication: Option<PublicationExpectation>,
    closed: [bool; 2],
    replied: [bool; 2],
    diagnostics: Vec<(usize, Failure)>,
    unexpected: Vec<String>,
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
        let run = fresh();
        fs::write(dir.join("run.json"), serde_json::to_vec(&run)?)?;
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
            publication: PublicationExpectation {
                dir: dir.to_path_buf(),
                scope: pair_scope_dir(&storage.join("controls"), peers, 1),
                peers,
                run,
                publisher: 0,
            },
            expected_publication: None,
            closed: [false; 2],
            replied: [false; 2],
            diagnostics: vec![],
            unexpected: vec![],
        })
    }
    fn expect_publication(&mut self, publisher: u8) {
        let mut publication = self.publication.clone();
        publication.publisher = publisher;
        self.expected_publication = Some(publication);
    }
    fn expected_cutoff(&self, failure: &Failure) -> bool {
        failure.is_incident_cutoff()
            && self
                .expected_publication
                .as_ref()
                .is_some_and(PublicationExpectation::confirmed)
    }
    fn check_diagnostics(&self) -> Result<()> {
        ensure!(
            self.unexpected.is_empty(),
            "unexpected worker events: {:?}; diagnostics: {:?}",
            self.unexpected,
            self.diagnostics
        );
        Ok(())
    }
    async fn stop_inputs(&mut self) {
        for input in &mut self.inputs {
            // Stop is queued before EOF even if a survivor's completed reply
            // has not reached the collector yet. Dropping stdin alone would
            // manufacture a post-reply transport failure in its idle loop.
            if self.boots.is_some() {
                if let Some(input) = input {
                    let _ = send(input, &Frame::PoolCommand(Box::new(Operation::Stop))).await;
                }
            }
            input.take();
        }
    }
    async fn call(&mut self, ops: [Operation; 2]) -> Result<Vec<(usize, Frame)>> {
        self.check_diagnostics()?;
        self.replied = [false; 2];
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
        self.replied = [false; 2];
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
        let mut failed = false;
        let mut poll = tokio::time::interval(Duration::from_millis(5));
        loop {
            if self.closed.iter().all(|v| *v) || (!failed && self.replied.iter().all(|v| *v)) {
                self.check_diagnostics()?;
                return Ok(replies);
            }
            let [r0, r1] = &mut self.relays;
            let event = tokio::select! {
                e=self.events.recv()=>e.context("events closed")?,
                _=poll.tick()=>{for (role,input) in self.inputs.iter_mut().enumerate() {if self.probe_dir.join(format!("{role}.done")).exists() {input.take();}}continue;},
                b=r0.next(),if !failed=>{if let (Some(b),Some(input))=(b,&mut self.inputs[0]) {let _=send(input,&Frame::Relay(b)).await;}continue;},
                b=r1.next(),if !failed=>{if let (Some(b),Some(input))=(b,&mut self.inputs[1]) {let _=send(input,&Frame::Relay(b)).await;}continue;},
            };
            ensure!(event.0 < 2, "invalid worker role");
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
                    self.closed[role] = true;
                    self.inputs[role].take();
                    if !self.replied[role] {
                        failed = true;
                        self.stop_inputs().await;
                    }
                }
                (role, Frame::Failure(f)) => {
                    self.diagnostics.push((role, f.clone()));
                    if self.replied[role] {
                        if !self.expected_cutoff(&f) {
                            self.unexpected
                                .push(format!("role {role} failure after reply: {f:?}"));
                        }
                        continue;
                    }
                    self.replied[role] = true;
                    replies.push((role, Frame::Failure(f)));
                    failed = true;
                    self.stop_inputs().await;
                }
                (_, Frame::Ready(_)) => {}
                (_, Frame::Setup(_) | Frame::Relay(_)) => {}
                (role, frame) => {
                    if self.replied[role] {
                        self.unexpected.push(format!("role {role} duplicate reply"));
                        self.check_diagnostics()?;
                    }
                    self.replied[role] = true;
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
    async fn finish(self) -> Result<()> {
        self.finish_except(&[]).await
    }
    async fn finish_except(mut self, killed: &[usize]) -> Result<()> {
        self.finish_with_timeout(killed, Duration::from_secs(10))
            .await
    }
    async fn finish_with_timeout(&mut self, killed: &[usize], timeout: Duration) -> Result<()> {
        let result = tokio::time::timeout(timeout, self.drain_workers(killed)).await;
        if result.is_err() {
            self.unexpected.push("worker/reader drain timed out".into());
        } else if let Err(error) = result.unwrap() {
            self.unexpected
                .push(format!("worker completion: {error:#}"));
        }
        if let Some(output) = std::env::var_os("PAIRKEY_ASSURANCE_EVIDENCE_DIR") {
            let output = PathBuf::from(output).join("terminals");
            fs::create_dir_all(&output)?;
            fs::write(
                output.join(format!("{}.json", super::hex(&self.publication.run))),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "run": self.publication.run, "closed": self.closed,
                    "diagnostics": self.diagnostics, "unexpected": self.unexpected,
                    "planned_killed_roles": killed,
                }))?,
            )?;
        }
        self.check_diagnostics()
    }
    async fn drain_workers(&mut self, killed: &[usize]) -> Result<()> {
        self.stop_inputs().await;
        for (role, child) in self.group.children.iter_mut().enumerate() {
            let status = child.wait().await?;
            use std::os::unix::process::ExitStatusExt;
            if if killed.contains(&role) {
                status.signal() != Some(libc::SIGKILL)
            } else {
                !status.success()
            } {
                self.unexpected
                    .push(format!("role {role} unexpected worker exit: {status}"));
            }
        }
        for reader in &mut self.group.readers {
            if let Err(error) = reader.await {
                self.unexpected.push(format!("reader failed: {error}"));
            }
        }
        while let Some((role, frame)) = self.events.recv().await {
            ensure!(role < 2, "invalid residual worker role");
            match frame {
                Frame::Closed => self.closed[role] = true,
                Frame::Failure(f) => {
                    if !self.expected_cutoff(&f) {
                        self.unexpected
                            .push(format!("role {role} residual failure: {f:?}"));
                    }
                    self.diagnostics.push((role, f));
                }
                // Queued native traffic may precede a cutoff; the independent
                // queue oracle determines its ordering relative to publication.
                Frame::Relay(_) | Frame::Setup(_) | Frame::Ready(_) => {}
                _ => self
                    .unexpected
                    .push(format!("role {role} unexpected residual terminal reply")),
            }
        }
        ensure!(
            self.closed.iter().all(|v| *v),
            "worker output ended without EOF event"
        );
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
    if publish {
        actors.expect_publication(publisher_role);
    }
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

fn synthetic_result(role: u8) -> Frame {
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
}
fn synthetic_actors() -> (Directory, Actors, mpsc::UnboundedSender<(usize, Frame)>) {
    let dir = Directory(std::env::temp_dir().join(format!("dkls-collector-{:?}", fresh())));
    fs::create_dir(&dir.0).unwrap();
    let (tx, events) = mpsc::unbounded_channel();
    let relay = SimpleMessageRelay::new();
    let actors = Actors {
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
        publication: PublicationExpectation {
            dir: dir.0.clone(),
            scope: dir.0.join("authority"),
            peers: [[1; 32], [2; 32]],
            run: fresh(),
            publisher: 1,
        },
        expected_publication: None,
        closed: [false; 2],
        replied: [false; 2],
        diagnostics: vec![],
        unexpected: vec![],
    };
    (dir, actors, tx)
}
fn acknowledge(publication: &PublicationExpectation) {
    incident(&publication.scope, publication.publisher, [9; 32]).unwrap();
    let ack = PublicationAck {
        peers: publication.peers,
        run: publication.run,
        publisher: publication.publisher,
        context: [9; 32],
    };
    fs::write(
        publication.dir.join("publication-ack.json"),
        serde_json::to_vec(&ack).unwrap(),
    )
    .unwrap();
    fs::write(publication.dir.join("publisher.done"), []).unwrap();
    fs::write(publication.dir.join("published"), []).unwrap();
}
fn close_events(tx: mpsc::UnboundedSender<(usize, Frame)>) {
    tx.send((0, Frame::Closed)).unwrap();
    tx.send((1, Frame::Closed)).unwrap();
}

#[tokio::test]
async fn collector_preserves_completed_results_before_incident_shutdown_control() {
    for after_both in [false, true] {
        let (dir, mut actors, tx) = synthetic_actors();
        actors.expect_publication(1);
        acknowledge(actors.expected_publication.as_ref().unwrap());
        tx.send((0, synthetic_result(0))).unwrap();
        if after_both {
            tx.send((1, synthetic_result(1))).unwrap();
        }
        tx.send((0, Frame::Failure(Failure::incident_cutoff())))
            .unwrap();
        if !after_both {
            tx.send((1, synthetic_result(1))).unwrap();
        }
        close_events(tx);
        let replies = actors.collect().await.unwrap();
        assert_eq!(replies.len(), 2);
        assert!(replies.iter().all(|(_, f)| matches!(f, Frame::Result(_))));
        actors
            .finish_with_timeout(&[], Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(actors.diagnostics.len(), 1);
        assert!(actors.diagnostics[0].1.is_incident_cutoff());
        assert!(!actors.diagnostics[0].1.incident_persisted);
        fs::write(dir.0.join("passed"), []).unwrap();
    }
}

#[tokio::test]
async fn collector_never_suppresses_unexpected_post_result_failures() {
    use pairkey_dkls23_research::lifecycle::{Action, FailureKind, Phase};
    let mut persistence = Failure::violation(Phase::Signing, [7; 32], "persistence failed");
    persistence.incident_attempted = true;
    let mut freeze = Failure::burn(Phase::Control, FailureKind::Local, "freeze");
    freeze.action = Action::FreezeConfiguration;
    let mut cutoff_with_failure = Failure::incident_cutoff();
    cutoff_with_failure.abort_send_failed = true;
    let failures = [
        Failure::violation(Phase::Signing, [7; 32], "unexpected protocol violation"),
        persistence,
        freeze,
        cutoff_with_failure,
        Failure::burn(Phase::Transport, FailureKind::Transport, "transport"),
        Failure::burn(Phase::Control, FailureKind::Timeout, "timeout"),
        Failure::burn(Phase::Control, FailureKind::Local, "local"),
    ];
    for failure in failures {
        for after_both in [false, true] {
            let (dir, mut actors, tx) = synthetic_actors();
            actors.expect_publication(1);
            acknowledge(actors.expected_publication.as_ref().unwrap());
            tx.send((0, synthetic_result(0))).unwrap();
            if after_both {
                tx.send((1, synthetic_result(1))).unwrap();
            }
            tx.send((0, Frame::Failure(failure.clone()))).unwrap();
            if !after_both {
                tx.send((1, synthetic_result(1))).unwrap();
            }
            close_events(tx);
            assert_eq!(actors.collect().await.is_ok(), after_both);
            assert!(actors
                .finish_with_timeout(&[], Duration::from_secs(1))
                .await
                .is_err());
            assert_eq!(actors.diagnostics.len(), 1);
            assert_eq!(actors.diagnostics[0].1.detail, failure.detail);
            assert_eq!(
                actors.diagnostics[0].1.incident_attempted,
                failure.incident_attempted
            );
            assert_eq!(
                actors.diagnostics[0].1.incident_persisted,
                failure.incident_persisted
            );
            fs::write(dir.0.join("passed"), []).unwrap();
        }
    }
}

#[tokio::test]
async fn collector_requires_scoped_acknowledgment_for_late_cutoff() {
    for invalid in [
        "no-expectation",
        "no-ack",
        "no-done",
        "wrong-role",
        "old-run",
        "wrong-peers",
        "wrong-scope",
        "partial-record",
    ] {
        let (dir, mut actors, tx) = synthetic_actors();
        actors.expect_publication(1);
        acknowledge(actors.expected_publication.as_ref().unwrap());
        let p = actors.expected_publication.as_mut().unwrap();
        match invalid {
            "no-expectation" => actors.expected_publication = None,
            "no-ack" => fs::remove_file(p.dir.join("publication-ack.json")).unwrap(),
            "no-done" => fs::remove_file(p.dir.join("publisher.done")).unwrap(),
            "wrong-role" => p.publisher = 0,
            "old-run" => p.run = fresh(),
            "wrong-peers" => p.peers.swap(0, 1),
            "wrong-scope" => p.scope = p.dir.join("unrelated"),
            "partial-record" => fs::write(p.scope.join("1.quarantined"), [0; 7]).unwrap(),
            _ => unreachable!(),
        }
        tx.send((0, synthetic_result(0))).unwrap();
        tx.send((0, Frame::Failure(Failure::incident_cutoff())))
            .unwrap();
        tx.send((1, synthetic_result(1))).unwrap();
        close_events(tx);
        assert!(actors.collect().await.is_err(), "{invalid}");
        assert_eq!(actors.diagnostics.len(), 1);
        assert!(actors
            .finish_with_timeout(&[], Duration::from_secs(1))
            .await
            .is_err());
        fs::write(dir.0.join("passed"), []).unwrap();
    }
}

#[tokio::test]
async fn collector_returns_failures_before_that_roles_result() {
    for failing_role in 0..2 {
        let (dir, mut actors, tx) = synthetic_actors();
        actors.expect_publication(1);
        acknowledge(actors.expected_publication.as_ref().unwrap());
        let other = 1 - failing_role;
        // A peer's result never turns this role's first failure into shutdown.
        tx.send((other, synthetic_result(other as u8))).unwrap();
        tx.send((failing_role, Frame::Failure(Failure::incident_cutoff())))
            .unwrap();
        close_events(tx);
        let replies = actors.collect().await.unwrap();
        assert!(replies
            .iter()
            .any(|(role, frame)| *role == failing_role && matches!(frame, Frame::Failure(_))));
        assert_eq!(actors.diagnostics.len(), 1);
        actors
            .finish_with_timeout(&[], Duration::from_secs(1))
            .await
            .unwrap();
        fs::write(dir.0.join("passed"), []).unwrap();
    }
}

#[tokio::test]
async fn collector_rejects_duplicate_replies_reader_errors_and_drain_timeout() {
    for mode in [
        "duplicate",
        "residual-duplicate",
        "reader-error",
        "timeout",
        "missing-eof",
        "bad-exit",
    ] {
        let (dir, mut actors, tx) = synthetic_actors();
        tx.send((0, synthetic_result(0))).unwrap();
        if mode == "duplicate" {
            tx.send((0, synthetic_result(0))).unwrap();
        }
        tx.send((1, synthetic_result(1))).unwrap();
        if mode == "residual-duplicate" {
            tx.send((1, synthetic_result(1))).unwrap();
        }
        if mode == "reader-error" {
            actors
                .group
                .readers
                .push(tokio::spawn(async { panic!("injected reader failure") }));
        }
        if mode == "bad-exit" {
            actors.group.children.push(
                Command::new("/bin/sh")
                    .args(["-c", "exit 7"])
                    .spawn()
                    .unwrap(),
            );
        }
        let held = if mode == "timeout" {
            Some(tx)
        } else {
            if mode == "missing-eof" {
                drop(tx);
            } else {
                close_events(tx);
            }
            None
        };
        assert_eq!(actors.collect().await.is_ok(), mode != "duplicate");
        // A collection failure must remain a failure at completion as well.
        let finish = actors
            .finish_with_timeout(&[], Duration::from_millis(250))
            .await;
        assert!(finish.is_err(), "{mode}");
        drop(held);
        fs::write(dir.0.join("passed"), []).unwrap();
    }
}

#[test]
fn direct_fixture_requires_original_cutoff_not_a_later_closed_gate() {
    use pairkey_dkls23_research::lifecycle::{FailureKind, Phase};
    let (dir, actors, _tx) = synthetic_actors();
    let p = &actors.publication;
    acknowledge(p);
    assert!(direct_cutoff(&Failure::incident_cutoff().into(), p));
    for error in [
        anyhow::anyhow!("original I/O failure"),
        Failure::burn(Phase::Control, FailureKind::Local, "lock timeout").into(),
        Failure::violation(Phase::Signing, [7; 32], "protocol violation").into(),
    ] {
        assert!(!direct_cutoff(&error, p));
    }
    fs::remove_file(p.dir.join("publisher.done")).unwrap();
    assert!(!direct_cutoff(&Failure::incident_cutoff().into(), p));
    fs::write(dir.0.join("passed"), []).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_idle_and_active_cutoffs_emit_typed_observer_failures() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for active in [false, true] {
        let dir = Directory(std::env::temp_dir().join(format!("dkls-cutoff-{:?}", fresh())));
        extended::provision(&dir.0, 11).unwrap();
        let mut actors = Actors::start(&dir.0, if active { "setup" } else { "" }, false)
            .await
            .unwrap();
        actors.expect_publication(1);
        // Confirm enrollment and an ordinary command completed before testing
        // the idle loop, rather than racing initial admission.
        actors.describe([7; 32]).await.unwrap();
        if active {
            let input = SetupInput {
                version: 1,
                recipe: 1,
                peers: actors.boots().clone().map(|b| b.identity),
                boots: actors.boots().clone().map(|b| b.generation),
                configuration: pool::configuration(),
                entry: fresh(),
            };
            let publisher = tokio::spawn(barrier(dir.0.clone(), "setup".into(), true, false, 1));
            let replies = actors
                .call(std::array::from_fn(|_| Operation::Setup {
                    input: input.clone(),
                    fault: None,
                }))
                .await
                .unwrap();
            publisher.await.unwrap().unwrap();
            assert_eq!(replies.len(), 2);
            assert!(replies
                .iter()
                .all(|(_, f)| matches!(f, Frame::Failure(f) if f.is_incident_cutoff())));
        } else {
            extended::publish(&dir.0, &dir.0, 1, "incident")
                .await
                .unwrap();
            // Observe shutdown before sending Stop, so this exercises idle
            // cancellation rather than the ordinary Stop command.
            tokio::time::timeout(Duration::from_secs(5), async {
                while !(0..2).all(|r| dir.0.join(format!("{r}.done")).exists()) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
        actors
            .finish_with_timeout(&[], Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(actors.diagnostics.len(), 2);
        assert!(actors
            .diagnostics
            .iter()
            .all(|(_, f)| f.is_incident_cutoff() && !f.incident_persisted));
        fs::write(dir.0.join("passed"), []).unwrap();
    }
}
