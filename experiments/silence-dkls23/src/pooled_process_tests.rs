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
            incident(
                &pair_scope_dir(&dir.join("controls"), peers, 1),
                publisher_role,
                [9; 32],
            )
            .unwrap();
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
        let result = runtime.block_on(super::pool_worker::run(
            role,
            &dir.join(format!("root-{role}.bin")),
            peer,
        ));
        fs::write(dir.join(format!("{role}.done")), format!("{result:?}")).unwrap();
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
    boots: [Boot; 2],
}
impl Actors {
    async fn start(dir: &Path, stage: &str, bypass: bool) -> Result<Self> {
        let peers = [
            Root::load(&dir.join("root-0.bin"))?
                .identity(0)
                .verifying_key()
                .to_bytes(),
            Root::load(&dir.join("root-1.bin"))?
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
            let mut child = command(dir, role, stage, false, bypass, 0)
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
        while boots.iter().any(Option::is_none) {
            let (role, Frame::PoolHello(boot)) = events.recv().await.context("startup closed")?
            else {
                anyhow::bail!("unexpected startup");
            };
            boot.validate()?;
            let root = Root::load(&dir.join(format!("root-{role}.bin")))?;
            ensure!(
                boot.role as usize == role
                    && boot.identity == root.identity(role as u8).verifying_key().to_bytes(),
                "startup pin"
            );
            boots[role] = Some(boot);
        }
        let boots = boots.map(Option::unwrap);
        fs::write(
            dir.join("peers.json"),
            serde_json::to_vec(&boots.clone().map(|b| b.identity))?,
        )?;
        for input in &mut inputs {
            send(
                input.as_mut().unwrap(),
                &Frame::PoolCommand(Box::new(Operation::Enroll(boots.clone()))),
            )
            .await?;
        }
        let relay = SimpleMessageRelay::new();
        Ok(Self {
            group,
            inputs,
            events,
            relays: [relay.connect(), relay.connect()],
            boots,
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
        let mut replies = vec![];
        let mut closed = [false; 2];
        let mut failed = false;
        loop {
            if closed.iter().all(|v| *v) || (!failed && replies.len() == 2) {
                return Ok(replies);
            }
            let [r0, r1] = &mut self.relays;
            let event = tokio::select! {
                e=self.events.recv()=>e.context("events closed")?,
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
                }
                (role, Frame::Failure(f)) => {
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
            identities: self.boots.clone().map(|b| b.identity),
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
            ensure!(
                commits
                    .iter()
                    .all(|(_, f)| matches!(f,Frame::WalletRegistered(d) if *d==record.digest())),
                "commit ACK mismatch"
            );
            let input = SetupInput {
                version: 1,
                recipe: 1,
                peers: actors.boots.clone().map(|b| b.identity),
                boots: actors.boots.clone().map(|b| b.generation),
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
    // Keep driving stdio while the workers reach their actual gated releases.
    if after_release {
        let frames = actors.call(operation).await?;
        ensure!(frames.len() == 2, "both releases required");
        for (role, frame) in frames {
            match frame {
                Frame::WalletEndorsement(e) if stage == "endorsement" => {
                    ensure!(e.role as usize == role, "role");
                    e.validate(&record)?;
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
    if let Some(candidate) = candidate {
        ensure!(candidate == recovered, "commit candidate changed");
    }
    let acknowledgments = replacement.commit(&recovered).await?;
    ensure!(
        acknowledgments
            .iter()
            .all(|(_, f)| matches!(f,Frame::WalletRegistered(d) if *d==record.digest())),
        "replacement commit ACK mismatch"
    );
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
                &serde_json::json!({"stage":stage,"death_after_queue_handoff":after_release,"observed_queue_handoffs":queued,"both_workers_killed":true,"replacement_endorsements_identical":true,"existing_bytes_unchanged":true,"replacement_commit_acknowledgments":2,"passed":true}),
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
