//! Two processes already own duplicate synthetic RAM entries. These tests cover
//! filesystem ownership transitions, not native OT correlations or power loss.
use crate::{
    fresh, lifecycle::ReleaseGate, point, pool, public, Hello, Manifest, Request, ReserveStep,
    Root, Route,
};
use k256::elliptic_curve::group::GroupEncoding;
use sl_oblivious::soft_spoken::{ReceiverOTSeed, SenderOTSeed};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const STEPS: [ReserveStep; 12] = [
    ReserveStep::BeforeRemove,
    ReserveStep::Removed,
    ReserveStep::BeforeCreate,
    ReserveStep::Created,
    ReserveStep::PartiallyWritten,
    ReserveStep::Written,
    ReserveStep::BeforeFileSync,
    ReserveStep::FileSynced,
    ReserveStep::BeforeDirectorySync,
    ReserveStep::DirectorySynced,
    ReserveStep::BeforeProvenance,
    ReserveStep::Validated,
];
fn wait(dir: &Path, name: &str) {
    let end = Instant::now() + Duration::from_secs(10);
    while !dir.join(name).exists() {
        assert!(Instant::now() < end, "missing reservation event {name}");
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn fixture(dir: &Path) -> (pool::RamPool, pool::Consumption) {
    let roots = [
        Root::load(&dir.join("a")).unwrap(),
        Root::load(&dir.join("b")).unwrap(),
    ];
    let key = [7; 32];
    let peers = [
        roots[0].identity(0).verifying_key().to_bytes(),
        roots[1].identity(1).verifying_key().to_bytes(),
    ];
    let shares = [
        public(&roots[0].derive(0, key).unwrap()),
        public(&roots[1].derive(1, key).unwrap()),
    ];
    let m = Manifest {
        version: 1,
        key_id: key,
        identities: peers,
        public_key: (point(&shares[0]).unwrap() + point(&shares[1]).unwrap())
            .to_bytes()
            .to_vec(),
        additive_public: shares,
        chain_code: [8; 32],
    };
    let r = Request {
        route: Route::Pooled,
        manifest: m,
        hellos: [
            Hello::new(&roots[0], 0, key, [31; 32]).unwrap(),
            Hello::new(&roots[1], 1, key, [32; 32]).unwrap(),
        ],
        entry: [9; 32],
        attempt: [10; 32],
        path: "m".into(),
        prehash: [6; 32],
        fault: None,
        wallet_record: None,
    };
    let input = pool::SetupInput {
        version: 1,
        recipe: 1,
        peers,
        boots: [[31; 32], [32; 32]],
        configuration: pool::configuration(),
        entry: r.entry,
    };
    let c = pool::Consumption::new(&input, [8; 32], &r, [11; 32], 1);
    let p = pool::RamPool::new(
        ReleaseGate::new(dir.join("scope"), 0),
        dir.join("entries"),
        0,
        peers,
        input.boots,
        2,
    )
    .unwrap();
    p.insert(
        pool::AvailableEntry::agreed(
            input,
            [8; 32],
            pool::Material::new(SenderOTSeed::default(), ReceiverOTSeed::default(), [3; 32]),
            Duration::from_secs(300),
        )
        .unwrap(),
    )
    .unwrap();
    (p, c)
}
#[test]
#[ignore = "explicit reservation subprocess fixture"]
fn reservation_child() {
    let dir = PathBuf::from(std::env::var_os("PAIRKEY_RESERVATION_DIR").expect("parent fixture"));
    let role = std::env::var("PAIRKEY_RESERVATION_ACTOR").unwrap();
    let mode = std::env::var("PAIRKEY_RESERVATION_MODE").unwrap();
    let target: usize = std::env::var("PAIRKEY_RESERVATION_STEP")
        .unwrap()
        .parse()
        .unwrap();
    let (pool, c) = fixture(&dir);
    fs::write(dir.join(format!("{role}.ready")), []).unwrap();
    wait(&dir, &format!("{role}.go"));
    fs::write(dir.join(format!("{role}.attempting")), []).unwrap();
    let result = if role == "first" {
        pool.reserve_checkpoint(&c, |step| {
            if step == STEPS[target] {
                fs::write(dir.join("first.paused"), []).unwrap();
                wait(&dir, "first.resume");
                if mode == "fail" {
                    anyhow::bail!("injected reservation I/O failure at {step:?}");
                }
            }
            Ok(())
        })
    } else {
        pool.reserve(&c)
    };
    fs::write(
        dir.join(format!("{role}.result")),
        if result.is_ok() {
            b"owned".as_slice()
        } else {
            b"refused".as_slice()
        },
    )
    .unwrap();
    drop(result);
    pool.invalidate();
    assert_eq!(pool.available(), 0);
}
struct Actor(Child);
impl Drop for Actor {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Actor {
    fn finish(&mut self) {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < end, "reservation actor did not exit");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
fn spawn(dir: &Path, actor: &str, mode: &str, index: usize) -> Actor {
    Actor(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "reservation_tests::reservation_child",
                "--ignored",
                "--nocapture",
                "--quiet",
            ])
            .env("PAIRKEY_RESERVATION_DIR", dir)
            .env("PAIRKEY_RESERVATION_ACTOR", actor)
            .env("PAIRKEY_RESERVATION_MODE", mode)
            .env("PAIRKEY_RESERVATION_STEP", index.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}
fn schedules(mode: &str) {
    for (i, step) in STEPS.iter().enumerate() {
        let dir = std::env::temp_dir().join(format!("dkls-reservation-schedule-{:?}", fresh()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("a"), [11; 32]).unwrap();
        fs::write(dir.join("b"), [22; 32]).unwrap();
        let mut first = spawn(&dir, "first", mode, i);
        let mut second = spawn(&dir, "second", mode, i);
        wait(&dir, "first.ready");
        wait(&dir, "second.ready");
        fs::write(dir.join("first.go"), []).unwrap();
        wait(&dir, "first.paused");
        fs::write(dir.join("second.go"), []).unwrap();
        wait(&dir, "second.attempting");
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            !dir.join("second.result").exists(),
            "competitor bypassed active authority at {step:?}"
        );
        if mode == "crash" {
            first.0.kill().unwrap();
            first.0.wait().unwrap();
        } else {
            fs::write(dir.join("first.resume"), []).unwrap();
            first.finish();
            assert_eq!(fs::read(dir.join("first.result")).unwrap(), b"refused");
        }
        second.finish();
        let before_marker = matches!(
            step,
            ReserveStep::BeforeRemove | ReserveStep::Removed | ReserveStep::BeforeCreate
        );
        assert_eq!(
            fs::read(dir.join("second.result")).unwrap(),
            if before_marker {
                b"owned".as_slice()
            } else {
                b"refused".as_slice()
            },
            "incorrect competitor outcome at {step:?}"
        );
        let (_, c) = fixture(&dir); // Loading duplicate ownership still cannot reserve it again.
        let (retry, _) = fixture(&dir);
        assert!(retry.reserve(&c).is_err());
        let bytes = fs::read(dir.join("entries").join(
            format!("0-{}.retired",[9u8;32].iter().map(|b|format!("{b:02x}")).collect::<String>()),
        ))
        .unwrap();
        let expected = match step {
            ReserveStep::Created => 0,
            ReserveStep::PartiallyWritten => 16,
            _ => 32,
        };
        assert_eq!(
            bytes.len(),
            expected,
            "unexpected tombstone shape at {step:?}"
        );
        if let Some(output) = std::env::var_os("PAIRKEY_ASSURANCE_EVIDENCE_DIR") {
            let output = PathBuf::from(output);
            fs::create_dir_all(&output).unwrap();
            fs::write(output.join(format!("reservation-{mode}-{i}.json")),serde_json::to_vec_pretty(&serde_json::json!({"transition":format!("{step:?}"),"mode":mode,"competitor_preloaded_same_entry":true,"competitor_blocked_while_first_owned_authority":true,"competitor_acquired_after_failure":before_marker,"tombstone_bytes":bytes.len(),"replacement_reuse_refused":true,"passed":true})).unwrap()).unwrap();
        }
        drop(first);
        drop(second);
        fs::remove_dir_all(dir).unwrap();
    }
}
#[test]
fn every_reservation_transition_refuses_or_transfers_once_after_injected_io_failure() {
    schedules("fail");
}
#[test]
fn every_reservation_transition_refuses_or_transfers_once_after_process_death() {
    schedules("crash");
}
