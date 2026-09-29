//! Actual native base OT/signing in two actor processes; a third process publishes.
use super::{send, ChildGroup};
use anyhow::{ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use k256::elliptic_curve::group::GroupEncoding;
use pairkey_dkls23_research::{
    fresh,
    lifecycle::{scope_dir, ReleaseGate},
    point, Frame, Hello, Manifest, Request, Route, MAX_FRAME,
};
use sl_mpc_mate::coord::SimpleMessageRelay;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Command,
    sync::mpsc,
};

const CHILD: &str = "native_process_tests::native_process_child";
#[test]
#[ignore = "explicit subprocess fixture"]
fn native_process_child() {
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
        if std::env::var("PAIRKEY_NATIVE_RACE_PUBLISH").unwrap() == "1" {
            let manifest: Manifest =
                serde_json::from_slice(&fs::read(dir.join("manifest.json")).unwrap()).unwrap();
            ReleaseGate::new(scope_dir(&dir.join("controls"), &manifest), 0)
                .publish([9; 32])
                .unwrap();
            fs::write(dir.join("published"), []).unwrap();
        }
        fs::write(dir.join("publisher.done"), []).unwrap();
    } else {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(3)
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(super::worker::run(
            role,
            &dir.join(format!("root-{role}.bin")),
            [7; 32],
        ));
        // A fenced final-result send can return directly; that is not the queue oracle.
        fs::write(dir.join(format!("{role}.done")), format!("{result:?}")).unwrap();
    }
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        if self.0.join("passed").exists() {
            let _ = fs::remove_dir_all(&self.0);
        } else {
            eprintln!("native fixture retained: {}", self.0.display());
        }
    }
}
fn command(dir: &Path, role: u8, stage: &str, publish: bool, bypass: bool) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--ignored", "--exact", CHILD, "--nocapture", "--quiet"])
        .env("PAIRKEY_NATIVE_RACE_DIR", dir)
        .env("PAIRKEY_NATIVE_RACE_ROLE", role.to_string())
        .env("PAIRKEY_NATIVE_RACE_STAGE", stage)
        .env(
            "PAIRKEY_NATIVE_RACE_PUBLISH",
            if publish { "1" } else { "0" },
        )
        .env("PAIRKEY_NATIVE_RACE_BYPASS", if bypass { "1" } else { "0" })
        .kill_on_drop(true);
    c
}
async fn case(stage: &str, publish: bool, bypass: bool) -> Result<()> {
    let dir = Directory(std::env::temp_dir().join(format!("dkls-native-process-{:?}", fresh())));
    fs::create_dir(&dir.0)?;
    eprintln!(
        "native stage {stage} publish={publish} bypass={bypass}: {}",
        dir.0.display()
    );
    for role in 0..2 {
        fs::write(
            dir.0.join(format!("root-{role}.bin")),
            [11 + role as u8; 32],
        )?;
    }
    let mut group = ChildGroup {
        children: vec![],
        readers: vec![],
    };
    let mut inputs = vec![];
    let (tx, mut events) = mpsc::unbounded_channel();
    for role in 0..2 {
        let mut child = command(&dir.0, role, stage, publish, bypass)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;
        inputs.push(child.stdin.take());
        let mut out = BufReader::new(child.stdout.take().context("stdout")?);
        let tx = tx.clone();
        group.readers.push(tokio::spawn(async move {
            let result: Result<()> = async {
                loop {
                    let mut line = vec![];
                    if (&mut out)
                        .take(MAX_FRAME as u64 + 1)
                        .read_until(b'\n', &mut line)
                        .await?
                        == 0
                    {
                        break;
                    }
                    ensure!(line.len() <= MAX_FRAME, "oversized native fixture stdout");
                    // The test harness adds banners/dots around actual stdio frames.
                    if let Some(start) = line.windows(8).position(|w| w == b"{\"kind\":") {
                        let frame: Frame = serde_json::from_slice(&line[start..])?;
                        tx.send((role as usize, Some(frame)))?;
                    }
                }
                tx.send((role as usize, None))?;
                Ok(())
            }
            .await;
            result.unwrap();
        }));
        group.children.push(child);
    }
    drop(tx);
    let mut hellos: [Option<Hello>; 2] = [None, None];
    while hellos.iter().any(Option::is_none) {
        let (role, frame) = events.recv().await.context("startup closed")?;
        let Some(Frame::Hello(hello)) = frame else {
            anyhow::bail!("unexpected native startup");
        };
        hello.validate()?;
        ensure!(hello.role as usize == role, "startup role");
        hellos[role] = Some(hello);
    }
    let hellos = hellos.map(Option::unwrap);
    let q = point(&hellos[0].contribution)? + point(&hellos[1].contribution)?;
    let manifest = Manifest {
        version: 1,
        key_id: [7; 32],
        identities: [hellos[0].identity, hellos[1].identity],
        additive_public: [
            hellos[0].contribution.clone(),
            hellos[1].contribution.clone(),
        ],
        public_key: q.to_bytes().to_vec(),
        chain_code: [8; 32],
    };
    manifest.validate()?;
    fs::write(dir.0.join("manifest.json"), serde_json::to_vec(&manifest)?)?;
    let request = Request {
        route: Route::Direct,
        manifest: manifest.clone(),
        hellos,
        entry: fresh(),
        attempt: fresh(),
        path: "m".into(),
        prehash: [6; 32],
        fault: None,
        wallet_record: None,
    };
    for input in &mut inputs {
        send(
            input.as_mut().unwrap(),
            &Frame::Start(Box::new(request.clone())),
        )
        .await?;
    }
    let coordinator = SimpleMessageRelay::new();
    let mut relays = [coordinator.connect(), coordinator.connect()];
    let mut closed = [false; 2];
    let mut advanced = false;
    let mut outcomes = vec![];
    let mut poll = tokio::time::interval(Duration::from_millis(5));
    while !closed.iter().all(|c| *c) {
        let [r0, r1] = &mut relays;
        let event = tokio::select! {
            e=events.recv()=>e.context("native events closed")?,
            bytes=r0.next()=>{if let Some(bytes)=bytes {if let Some(input)=&mut inputs[0] {let _=send(input,&Frame::Relay(bytes)).await;}}continue;},
            bytes=r1.next()=>{if let Some(bytes)=bytes {if let Some(input)=&mut inputs[1] {let _=send(input,&Frame::Relay(bytes)).await;}}continue;},
            _=poll.tick()=>{
                // Tokio's blocking stdin read needs EOF even when a fenced
                // final send returns directly without a terminal frame.
                for (role,input) in inputs.iter_mut().enumerate() {if dir.0.join(format!("{role}.done")).exists() {input.take();}}
                if !advanced && (0..2).all(|r|dir.0.join(format!("{r}.reached")).exists()) {
                    // Both actual native targets exist, still held before handoff.
                    ensure!((0..2).all(|r|!dir.0.join(format!("{r}.queued")).exists()),"target queued before release barrier");
                    let mut publisher=command(&dir.0,2,stage,publish,bypass).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::inherit()).spawn()?;
                    ensure!(publisher.wait().await?.success(),"publisher failed");
                    group.children.push(publisher);
                    ensure!(dir.0.join("publisher.done").exists(),"publisher did not acknowledge");
                    fs::write(dir.0.join("resume"),[])?;advanced=true;
                }
                continue;
            },
        };
        let (role, frame) = event;
        match frame {
            Some(Frame::Setup(bytes)) => {
                if let Some(input) = &mut inputs[1 - role] {
                    let _ = send(input, &Frame::Setup(bytes)).await;
                }
            }
            Some(Frame::Relay(bytes)) => {
                let _ = relays[role].send(bytes).await;
            }
            Some(Frame::Result(out)) => {
                outcomes.push(out);
                inputs[role].take();
            }
            Some(Frame::Failure(_)) => {
                inputs[role].take();
            }
            Some(Frame::Ready(context)) => {
                ensure!(context == request.context(), "incorrect readiness context")
            }
            None => {
                closed[role] = true;
                inputs[role].take();
            }
            _ => anyhow::bail!("unexpected native frame"),
        }
    }
    for reader in &mut group.readers {
        reader.await?;
    }
    for child in &mut group.children {
        ensure!(child.wait().await?.success(), "actor fixture failed");
    }
    ensure!(advanced, "both actors did not reach requested native stage");
    let pids = (0..3)
        .map(|r| fs::read_to_string(dir.0.join(format!("{r}.pid"))))
        .collect::<std::io::Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        pids.len() == 3,
        "actors/publisher must be distinct processes"
    );
    let queued = (0..2)
        .filter(|r| dir.0.join(format!("{r}.queued")).exists())
        .count();
    let result_count = outcomes.len();
    if publish && !bypass {
        ensure!(queued == 0, "native target escaped after publication");
    } else {
        ensure!(
            queued == 2,
            "positive/bypass control did not observe both targets"
        );
        for role in 0..2 {
            ensure!(
                fs::read_to_string(dir.0.join(format!("{role}.queued")))?
                    == if publish { "late" } else { "ordinary" },
                "incorrect queue observation"
            );
        }
    }
    if !publish || stage == "result" && bypass {
        ensure!(
            outcomes.len() == 2,
            "successful native executions lacked results"
        );
        use signature::hazmat::PrehashVerifier;
        let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&manifest.public_key)?;
        for out in outcomes {
            let signature = k256::ecdsa::Signature::from_slice(&out.signature)?;
            key.verify_prehash(&request.prehash, &signature)?;
            ensure!(signature.normalize_s().is_none(), "high-S");
        }
    }
    if let Some(output) = std::env::var_os("PAIRKEY_ASSURANCE_EVIDENCE_DIR") {
        let output = PathBuf::from(output);
        fs::create_dir_all(&output)?;
        fs::write(
            output.join(format!("native-{stage}-{publish}-{bypass}.json")),
            serde_json::to_vec_pretty(
                &serde_json::json!({"stage":stage,"publish":publish,"bypass":bypass,"distinct_processes":pids.len(),"both_actual_targets_reached":true,"queue_handoffs":queued,"result_frames":result_count,"independent_signature_verification":!publish || stage=="result" && bypass,"passed":true}),
            )?,
        )?;
    }
    fs::write(dir.0.join("passed"), [])?;
    Ok(())
}
async fn cases(publish: bool, bypass: bool) {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for stage in ["setup", "r4", "result"] {
        tokio::time::timeout(Duration::from_secs(25), case(stage, publish, bypass))
            .await
            .unwrap()
            .unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_native_process_targets_refuse_after_third_process_publication() {
    cases(true, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_native_process_positive_controls_complete_and_release_targets() {
    cases(false, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_native_process_queue_oracle_detects_deliberate_bypasses() {
    cases(true, true).await;
}
