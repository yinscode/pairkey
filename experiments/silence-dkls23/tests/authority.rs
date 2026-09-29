//! Real-process authority tests. Synthetic seed/queue fixtures are not evidence
//! of cryptographic composition security or of a cross-host release authority.
use k256::elliptic_curve::group::GroupEncoding;
use pairkey_dkls23_research::registration::{WalletRecord, WalletStore};
use pairkey_dkls23_research::{
    fresh, lifecycle::ReleaseGate, pool, public, reserve, Hello, Manifest, Request, Root, Route,
};
use sl_oblivious::soft_spoken::{ReceiverOTSeed, SenderOTSeed};
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("dkls-process-authority-{:?}", fresh()));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("a"), [11; 32]).unwrap();
        fs::write(path.join("b"), [22; 32]).unwrap();
        Self(path)
    }
    fn scope(&self) -> PathBuf {
        self.0.join("scope")
    }
    fn spawn(&self, mode: &str, label: &str, role: u8) -> Process {
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "authority_child", "--nocapture"])
            .env("PAIRKEY_AUTHORITY_TEST_DIR", &self.0)
            .env("PAIRKEY_AUTHORITY_TEST_MODE", mode)
            .env("PAIRKEY_AUTHORITY_TEST_LABEL", label)
            .env("PAIRKEY_AUTHORITY_TEST_ROLE", role.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        Process(child)
    }
    fn signal(&self, name: &str) {
        fs::write(self.0.join(name), []).unwrap();
    }
    fn wait(&self, name: &str) {
        let deadline = Instant::now() + Duration::from_secs(8);
        while !self.0.join(name).exists() {
            assert!(Instant::now() < deadline, "missing child event {name}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.0.join(name)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Process {
    fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "child did not exit");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn kill(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn synthetic_pool(f: &Fixture, gate: ReleaseGate, role: u8) -> (pool::RamPool, pool::Consumption) {
    let roots = [
        Root::load(&f.0.join("a")).unwrap(),
        Root::load(&f.0.join("b")).unwrap(),
    ];
    let key = [7; 32];
    let shares = [
        public(&roots[0].derive(0, key).unwrap()),
        public(&roots[1].derive(1, key).unwrap()),
    ];
    let q = pairkey_dkls23_research::point(&shares[0]).unwrap()
        + pairkey_dkls23_research::point(&shares[1]).unwrap();
    let peers = [
        roots[0].identity(0).verifying_key().to_bytes(),
        roots[1].identity(1).verifying_key().to_bytes(),
    ];
    let input = pool::SetupInput {
        version: 1,
        recipe: 1,
        peers,
        boots: [[31; 32], [32; 32]],
        configuration: pool::configuration(),
        entry: [9; 32],
    };
    let r = Request {
        route: Route::Pooled,
        manifest: Manifest {
            version: 1,
            key_id: key,
            identities: peers,
            additive_public: shares,
            public_key: q.to_bytes().to_vec(),
            chain_code: [8; 32],
        },
        hellos: [
            Hello::new(&roots[0], 0, key, [31; 32]).unwrap(),
            Hello::new(&roots[1], 1, key, [32; 32]).unwrap(),
        ],
        entry: input.entry,
        attempt: [12; 32],
        path: "m".into(),
        prehash: [6; 32],
        wallet_record: None,
        fault: None,
    };
    let c = pool::Consumption::new(&input, [10; 32], &r, [11; 32], 1);
    let p = pool::RamPool::new(gate, f.0.join("entries"), role, peers, input.boots, 2).unwrap();
    p.insert(
        pool::AvailableEntry::agreed(
            input,
            [10; 32],
            pool::Material::new(SenderOTSeed::default(), ReceiverOTSeed::default(), [3; 32]),
            Duration::from_secs(300),
        )
        .unwrap(),
    )
    .unwrap();
    (p, c)
}

#[test]
#[ignore = "subprocess fixture, invoked explicitly by parent tests"]
fn authority_child() {
    let f = Fixture(PathBuf::from(
        std::env::var_os("PAIRKEY_AUTHORITY_TEST_DIR").expect("parent fixture"),
    ));
    // Parent alone owns directory cleanup, including killed child fixtures.
    let f = std::mem::ManuallyDrop::new(f);
    let mode = std::env::var("PAIRKEY_AUTHORITY_TEST_MODE").unwrap();
    let label = std::env::var("PAIRKEY_AUTHORITY_TEST_LABEL").unwrap();
    let role = std::env::var("PAIRKEY_AUTHORITY_TEST_ROLE")
        .unwrap()
        .parse()
        .unwrap();
    let gate = ReleaseGate::new(f.scope(), role);
    let event = |s: &str| f.signal(&format!("{label}.{s}"));
    let report = |s: &str| fs::write(f.0.join(format!("{label}.result")), s).unwrap();
    match mode.as_str() {
        "register" | "register-fork" => {
            let roots = [
                Root::load(&f.0.join("a")).unwrap(),
                Root::load(&f.0.join("b")).unwrap(),
            ];
            let key = [7; 32];
            let mut public_shares = [
                public(&roots[0].derive(0, key).unwrap()),
                public(&roots[1].derive(1, key).unwrap()),
            ];
            if mode == "register-fork" {
                public_shares[1] = (pairkey_dkls23_research::point(&public_shares[1]).unwrap()
                    + k256::ProjectivePoint::GENERATOR)
                    .to_bytes()
                    .to_vec();
            }
            let q = (pairkey_dkls23_research::point(&public_shares[0]).unwrap()
                + pairkey_dkls23_research::point(&public_shares[1]).unwrap())
            .to_bytes()
            .to_vec();
            let m = Manifest {
                version: 1,
                key_id: key,
                identities: [
                    roots[0].identity(0).verifying_key().to_bytes(),
                    roots[1].identity(1).verifying_key().to_bytes(),
                ],
                additive_public: public_shares,
                public_key: q.clone(),
                chain_code: pairkey_dkls23_research::digest(
                    b"pairkey/dkls-research/public-chain-code/v1",
                    &(key, q),
                ),
            };
            let r = WalletRecord::new(m).unwrap();
            event("ready");
            f.wait("go");
            let e =
                gate.release(|| WalletStore::new(f.0.join("wallets")).endorse(&r, &roots[0], 0));
            match e {
                Ok(e) => report(&serde_json::to_string(&e).unwrap()),
                Err(_) => report("conflict"),
            }
        }
        "reserve" => {
            let (p, c) = synthetic_pool(&f, gate, role);
            event("ready");
            f.wait("go");
            report(if p.reserve(&c).is_ok() {
                "won"
            } else {
                "burned"
            });
        }
        "publish" | "publish-direct" => {
            event("attempting");
            if mode == "publish-direct" {
                pairkey_dkls23_research::incident(&f.scope(), role, [4; 32]).unwrap();
            } else {
                gate.publish([4; 32]).unwrap();
            }
            event("published");
        }
        "release" | "release-bypass" | "contend" => {
            // Observe the actual queue independently of the gate's return value.
            let (tx, rx) = mpsc::channel();
            event("ready");
            let handoff = || {
                tx.send([4; 32])?;
                Ok(())
            };
            let first: anyhow::Result<()> = if mode == "release-bypass" {
                handoff() // Deliberate test-only bypass validates the queue oracle.
            } else {
                gate.release(handoff)
            };
            if mode == "contend" {
                assert!(format!("{:#}", first.as_ref().unwrap_err()).contains("lock timed out"));
                event("first");
                f.wait("retry");
                assert!(gate
                    .release(|| {
                        tx.send([5; 32])?;
                        Ok(())
                    })
                    .is_err());
            }
            let count = rx.try_iter().count();
            report(&format!(
                "{}:{count}",
                if first.is_ok() { "released" } else { "fenced" }
            ));
        }
        "hold" | "hold-reserved" | "hold-partial" | "hold-release" => {
            let (tx, rx) = mpsc::channel();
            gate.release(|| {
                if mode == "hold-reserved" {
                    reserve(&f.0.join("entries"), role, [9; 32], [10; 32])?;
                }
                if mode == "hold-partial" {
                    fs::write(f.scope().join(format!("{role}.quarantined")), [])?;
                }
                event("held");
                f.wait("release");
                if mode == "hold-release" {
                    tx.send([4; 32])?;
                }
                Ok(())
            })
            .unwrap();
            report(&format!("queued:{}", rx.try_iter().count()));
        }
        "cancel" => {
            event("ready");
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                tokio::time::timeout(Duration::from_secs(5), gate.cancelled())
                    .await
                    .unwrap();
            });
            event("cancelled");
        }
        _ => panic!("unknown child mode"),
    }
}

#[test]
fn replicated_ram_entries_have_one_cross_process_reservation_winner() {
    let f = Fixture::new();
    let mut children: Vec<_> = (0..4)
        .map(|i| f.spawn("reserve", &format!("r{i}"), 0))
        .collect();
    for i in 0..4 {
        f.wait(&format!("r{i}.ready"));
    }
    f.signal("go");
    for p in &mut children {
        p.finish();
    }
    assert_eq!(
        (0..4)
            .filter(|i| f.read(&format!("r{i}.result")) == "won")
            .count(),
        1
    );
    assert_eq!(
        fs::read_dir(f.0.join("entries"))
            .unwrap()
            .filter(|e| e
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "retired"))
            .count(),
        1
    );
    let mut replacement = f.spawn("reserve", "replacement", 0);
    replacement.finish();
    assert_eq!(f.read("replacement.result"), "burned");
}

#[test]
fn publication_orders_with_handoff_and_fences_both_roles_after_cutoff() {
    let f = Fixture::new();
    let mut sender = f.spawn("hold-release", "sender", 0);
    f.wait("sender.held");
    let mut publisher = f.spawn("publish-direct", "publisher", 1);
    f.wait("publisher.attempting");
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !f.0.join("publisher.published").exists(),
        "publication bypassed active handoff lock"
    );
    f.signal("release");
    sender.finish();
    publisher.finish();
    assert_eq!(
        f.read("sender.result"),
        "queued:1",
        "positive control did not release"
    );
    for role in 0..2 {
        let label = format!("late{role}");
        let mut late = f.spawn("release", &label, role);
        late.finish();
        assert_eq!(f.read(&format!("{label}.result")), "fenced:0");
    }
    let mut bypass = f.spawn("release-bypass", "bypass", 0);
    bypass.finish();
    assert_eq!(
        f.read("bypass.result"),
        "released:1",
        "queue oracle missed deliberate bypass"
    );
    // Another pairing's authority remains independent.
    ReleaseGate::new(f.0.join("other-scope"), 0)
        .release(|| Ok(()))
        .unwrap();
}

#[test]
fn killing_a_lock_holder_releases_authority_without_inventing_an_incident() {
    let f = Fixture::new();
    let mut holder = f.spawn("hold", "holder", 0);
    f.wait("holder.held");
    holder.kill();
    let mut next = f.spawn("release", "next", 0);
    next.finish();
    assert_eq!(f.read("next.result"), "released:1");
}

#[test]
fn killing_after_retirement_never_restores_reservation_availability() {
    let f = Fixture::new();
    let mut holder = f.spawn("hold-reserved", "holder", 0);
    f.wait("holder.held");
    holder.kill();
    let mut next = f.spawn("reserve", "next", 0);
    f.wait("next.ready");
    f.signal("go");
    next.finish();
    assert_eq!(f.read("next.result"), "burned");
}

#[test]
fn incomplete_marker_after_creator_death_fences_all_roles_without_confirming_durability() {
    let f = Fixture::new();
    let mut holder = f.spawn("hold-partial", "holder", 0);
    f.wait("holder.held");
    holder.kill();
    assert!(ReleaseGate::new(f.scope(), 1).publish([5; 32]).is_ok());
    assert!(ReleaseGate::new(f.scope(), 0).publish([5; 32]).is_err());
    assert!(fs::read(f.scope().join("0.quarantined"))
        .unwrap()
        .is_empty());
    let mut next = f.spawn("release", "next", 1);
    next.finish();
    assert_eq!(f.read("next.result"), "fenced:0");
}

#[test]
fn idle_process_observes_remote_incident_cancellation() {
    let f = Fixture::new();
    let mut idle = f.spawn("cancel", "idle", 0);
    f.wait("idle.ready");
    let mut publisher = f.spawn("publish", "publisher", 1);
    publisher.finish();
    idle.finish();
    f.wait("idle.cancelled");
}

#[test]
fn authority_contention_times_out_without_release_and_keeps_local_gate_closed() {
    let f = Fixture::new();
    let mut holder = f.spawn("hold", "holder", 0);
    f.wait("holder.held");
    let mut contender = f.spawn("contend", "contender", 0);
    f.wait("contender.first");
    holder.kill();
    f.signal("retry");
    contender.finish();
    assert_eq!(f.read("contender.result"), "fenced:0");
    let mut replacement = f.spawn("release", "replacement", 0);
    replacement.finish();
    assert_eq!(f.read("replacement.result"), "released:1");
}

#[test]
fn conflicting_registration_across_processes_endorses_only_one_candidate() {
    let f = Fixture::new();
    let mut children: Vec<_> = (0..4)
        .map(|i| {
            f.spawn(
                if i % 2 == 0 {
                    "register"
                } else {
                    "register-fork"
                },
                &format!("r{i}"),
                0,
            )
        })
        .collect();
    for i in 0..4 {
        f.wait(&format!("r{i}.ready"));
    }
    f.signal("go");
    for c in &mut children {
        c.finish();
    }
    let records: Vec<_> = (0..4).map(|i| f.read(&format!("r{i}.result"))).collect();
    let success: Vec<_> = records
        .iter()
        .filter(|r| r.as_str() != "conflict")
        .collect();
    assert_eq!(success.len(), 2);
    assert_eq!(success[0], success[1]);
}
