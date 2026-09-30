//! Actual two-worker donor route. Process death is distinct from storage loss.
use super::*;
use pairkey_dkls23_research::{
    d::{self, Journal},
    lifecycle::{pair_scope_dir, Action},
};
use std::{fs, path::PathBuf};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("pairkey-d-process-{}", hex(&fresh())));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
#[ignore = "explicit donor worker subprocess"]
fn d_process_child() {
    let role = std::env::var("PAIRKEY_D_CHILD_ROLE")
        .unwrap()
        .parse()
        .unwrap();
    if role == 2 {
        let dir = PathBuf::from(std::env::var_os("PAIRKEY_D_PUBLISH_DIR").unwrap());
        let peers: [[u8; 32]; 2] =
            serde_json::from_slice(&fs::read(dir.join("peers.json")).unwrap()).unwrap();
        let publisher = std::env::var("PAIRKEY_D_PUBLISH_ROLE")
            .unwrap()
            .parse()
            .unwrap();
        let scope = pair_scope_dir(&dir.join("controls"), peers, 1);
        pairkey_dkls23_research::incident(&scope, publisher, [9; 32]).unwrap();
        fs::write(dir.join("published"), []).unwrap();
        return;
    }
    let root = PathBuf::from(std::env::var_os("PAIRKEY_D_CHILD_ROOT").unwrap());
    let peer = crate::unhex(&std::env::var("PAIRKEY_D_CHILD_PEER").unwrap()).unwrap();
    let limits = Limits {
        uses: std::env::var("PAIRKEY_D_CHILD_USES")
            .unwrap()
            .parse()
            .unwrap(),
        age_secs: std::env::var("PAIRKEY_D_CHILD_AGE")
            .unwrap()
            .parse()
            .unwrap(),
        ..Limits::default()
    };
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(crate::d_worker::run(role, &root, peer, limits))
        .unwrap();
}
fn failure(error: &anyhow::Error, action: Action) -> bool {
    error
        .downcast_ref::<Terminals>()
        .is_some_and(|t| t.failures.iter().any(|(_, f)| f.action == action))
}
async fn setup(f: &Fixture, limits: Limits) -> (Session, [u8; 32], [u8; 32]) {
    let mut s = Session::start(&f.0, 0, limits).await.unwrap();
    let key = [7; 32];
    s.register(key, None).await.unwrap();
    let (g, _) = s.prepare(None).await.unwrap();
    (s, key, g)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_donor_multiwallet_rotation_and_use_bounds() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    let f = Fixture::new();
    let (mut s, key, g) = setup(
        &f,
        Limits {
            uses: 2,
            ..Limits::default()
        },
    )
    .await;
    let c = s.register([8; 32], None).await.unwrap();
    let a = s.request(key, g, None, 0).unwrap();
    let b = s.request([8; 32], g, None, 1).unwrap();
    let first = s.sign_request([a.clone(), a]).await.unwrap();
    let second = s.sign_request([b.clone(), b]).await.unwrap();
    assert_ne!(first["final_session"], second["final_session"]);
    assert_ne!(first["signature"], second["signature"]);
    let r = s.request(key, g, None, 2).unwrap();
    let e = s.sign_request([r.clone(), r]).await.unwrap_err();
    assert!(failure(&e, Action::Burn), "{e:#}");
    drop(s);
    let mut replacement = Session::start(&f.0, 0, Limits::default()).await.unwrap();
    assert_eq!(replacement.register([8; 32], None).await.unwrap(), c);
    replacement.register(key, None).await.unwrap();
    let (next, _) = replacement.prepare(None).await.unwrap();
    assert_ne!(g, next);
    let r = replacement.request(key, next, None, 3).unwrap();
    replacement.sign_request([r.clone(), r]).await.unwrap();
    replacement.stop().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn age_generation_and_replay_refuse_before_native_freeze() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for kind in [
        "age",
        "missing-donor",
        "instance-replay",
        "repeat-native-seed",
    ] {
        let f = Fixture::new();
        let (mut s, key, g) = setup(
            &f,
            Limits {
                age_secs: if kind == "age" { 1 } else { 600 },
                ..Limits::default()
            },
        )
        .await;
        let fault = matches!(kind, "missing-donor" | "repeat-native-seed").then_some(kind);
        let r = s.request(key, g, fault, 0).unwrap();
        let request = if matches!(kind, "instance-replay" | "repeat-native-seed") {
            s.sign_request([r.clone(), r.clone()]).await.unwrap();
            if kind == "instance-replay" {
                r
            } else {
                s.request(key, g, fault, 1).unwrap()
            }
        } else {
            r
        };
        if kind == "age" {
            tokio::time::sleep(Duration::from_millis(1100)).await;
            // Expiry must dispose the idle donor without needing a request.
            let retired =
                f.0.join("controls/d")
                    .join(hex(&d::pairing(s.boots.clone().map(|b| b.identity))))
                    .join("retired-generations");
            for role in 0..2 {
                assert_eq!(
                    fs::read(retired.join(format!("{role}-{}.retired", hex(&g)))).unwrap(),
                    g
                );
            }
        }
        let e = s
            .sign_request([request.clone(), request])
            .await
            .unwrap_err();
        assert!(failure(&e, Action::Burn), "{kind}: {e:#}");
        let scope = pair_scope_dir(
            &f.0.join("controls"),
            s.boots.clone().map(|b| b.identity),
            1,
        );
        assert!(
            !scope.join("0.quarantined").exists() && !scope.join("1.quarantined").exists(),
            "{kind}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn age_expiry_cancels_inflight_attempt_and_fresh_rotation_preserves_wallet() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    let f = Fixture::new();
    let limits = Limits {
        age_secs: 1,
        ..Limits::default()
    };
    let (mut s, key, g) = setup(&f, limits.clone()).await;
    let cert = s.wallets[&key].clone();
    let first = s.request(key, g, None, 0).unwrap();
    let before = s.sign_request([first.clone(), first]).await.unwrap();
    // Real one-second age with delayed peer flights: no mocked clock and no
    // alteration of native cryptographic parameters.
    s.delay = Duration::from_millis(350);
    let request = s.request(key, g, None, 2).unwrap();
    let error = s
        .sign_request([request.clone(), request])
        .await
        .unwrap_err();
    let terminals = error.downcast_ref::<Terminals>().unwrap();
    assert!(!terminals.drain_timed_out, "{error:#}");
    assert!(
        terminals
            .failures
            .iter()
            .any(|(_, f)| f.kind == FailureKind::Context
                && f.detail == "D donor age bound expired during attempt"),
        "{error:#}"
    );
    assert!(
        terminals
            .failures
            .iter()
            .all(|(_, f)| f.action == Action::Burn && !f.incident_attempted),
        "{error:#}"
    );
    finish_failed(&mut s).await.unwrap();
    no_incident(&f.0, cert.record.wallet.identities).unwrap();
    let mut next = Session::start(&f.0, 0, limits).await.unwrap();
    next.wallets.insert(key, cert);
    let (generation, _) = next.prepare(None).await.unwrap();
    assert_ne!(generation, g);
    let request = next.request(key, generation, None, 2).unwrap();
    let after = next.sign_request([request.clone(), request]).await.unwrap();
    assert_eq!(before["public_key"], after["public_key"]);
    assert_ne!(before["final_session"], after["final_session"]);
    next.stop().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_donor_violation_and_aggregate_failure_matrix() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for kind in [
        "donor-pprf",
        "donor-abort-send",
        "reveal-mismatch",
        "mismatched-zero",
        "native-r1-commit",
    ] {
        let f = Fixture::new();
        let mut s = Session::start(&f.0, 0, Limits::default()).await.unwrap();
        let e = if kind == "reveal-mismatch" {
            s.register([7; 32], Some(kind)).await.unwrap_err()
        } else {
            s.register([7; 32], None).await.unwrap();
            if matches!(kind, "mismatched-zero" | "native-r1-commit") {
                let (g, _) = s.prepare(None).await.unwrap();
                let r = s.request([7; 32], g, Some(kind), 0).unwrap();
                s.sign_request([r.clone(), r]).await.unwrap_err()
            } else {
                s.prepare(Some(kind)).await.unwrap_err()
            }
        };
        let expected = if kind == "mismatched-zero" {
            Action::FreezeConfiguration
        } else {
            Action::QuarantinePeer
        };
        assert!(failure(&e, expected), "{kind}: {e:#}");
        let t = e.downcast_ref::<Terminals>().unwrap();
        assert!(
            t.failures
                .iter()
                .any(|(_, f)| f.action == expected && f.incident_persisted),
            "{kind}: {e:#}"
        );
        if kind == "donor-abort-send" {
            assert!(
                t.failures
                    .iter()
                    .any(|(_, f)| f.action == Action::QuarantinePeer && f.abort_send_failed),
                "{e:#}"
            );
        }
    }
}
async fn reached(dir: &Path) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !dir.join("reached").exists() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_one_sided_process_death_preserves_or_retires_exact_records() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for stage in [
        "before-reserved",
        "reserved",
        "before-commit",
        "commit",
        "before-peer-commit",
        "peer-commit",
        "before-reveal-release",
        "reveal-release",
        "before-prepared",
        "prepared",
        "before-active",
        "active",
    ] {
        for victim in 0..2u8 {
            let f = Fixture::new();
            let s = Session::start_options(&f.0, 0, Limits::default(), Some((stage, victim)))
                .await
                .unwrap();
            let wallet = s.wallet([7; 32]);
            let pid = s.group.children[victim as usize].id().unwrap();
            let task = tokio::spawn(async move {
                let mut s = s;
                let result = s.register([7; 32], None).await;
                (s, result)
            });
            reached(&f.0).await;
            assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGKILL) }, 0);
            let (old, result) = task.await.unwrap();
            assert!(result.is_err(), "{stage}/{victim} unexpectedly completed");
            drop(old);
            let base =
                f.0.join("controls/d")
                    .join(hex(&d::pairing(wallet.identities)))
                    .join("wallets");
            let js = [
                Journal::new(&base, &wallet, 0).unwrap(),
                Journal::new(&base, &wallet, 1).unwrap(),
            ];
            let prepared = js
                .iter()
                .map(|j| fs::read(j.path("prepared")).ok())
                .collect::<Vec<_>>();
            let active = js
                .iter()
                .map(|j| fs::read(j.path("active")).ok())
                .collect::<Vec<_>>();
            let complete = prepared.iter().all(Option::is_some);
            let mut replacement = Session::start(&f.0, 0, Limits::default()).await.unwrap();
            let result = replacement.register([7; 32], None).await;
            assert_eq!(result.is_ok(), complete, "{stage}/{victim}: {result:?}");
            for i in 0..2 {
                if let Some(ref before) = prepared[i] {
                    assert_eq!(&fs::read(js[i].path("prepared")).unwrap(), before);
                }
                if let Some(ref before) = active[i] {
                    assert_eq!(&fs::read(js[i].path("active")).unwrap(), before);
                }
            }
            if let Ok(c) = result {
                for j in &js {
                    let saved: (d::Record, d::Endorsement) = j.read("prepared").unwrap();
                    assert_eq!(saved.0, c.record);
                    assert_eq!(saved.1, c.endorsements[j.role as usize]);
                }
                replacement.stop().await.unwrap();
            }
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn donor_route_actual_setup_r4_result_cutoff_with_positive_and_bypass_controls() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for stage in ["setup", "r4", "result"] {
        for mode in ["positive", "protected", "bypass"] {
            for publisher in 0..2u8 {
                let f = Fixture::new();
                let name = format!("race:{stage}");
                let mut s = Session::start_options(
                    &f.0,
                    0,
                    Limits::default(),
                    Some((&name, u8::from(mode == "bypass"))),
                )
                .await
                .unwrap();
                let cert = s.register([7; 32], None).await.unwrap();
                let (g, _) = s.prepare(None).await.unwrap();
                let request = s.request([7; 32], g, None, 0).unwrap();
                fs::write(
                    f.0.join("peers.json"),
                    serde_json::to_vec(&cert.record.wallet.identities).unwrap(),
                )
                .unwrap();
                let task = tokio::spawn(async move {
                    let result = s.sign_request([request.clone(), request]).await;
                    (s, result)
                });
                tokio::time::timeout(Duration::from_secs(10), async {
                    while !(f.0.join("0.reached").exists() && f.0.join("1.reached").exists()) {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                })
                .await
                .unwrap();
                if mode != "positive" {
                    let mut child = ProcessCommand::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "d_driver::tests::d_process_child",
                            "--ignored",
                            "--nocapture",
                            "--quiet",
                        ])
                        .env("PAIRKEY_D_CHILD_ROLE", "2")
                        .env("PAIRKEY_D_PUBLISH_DIR", &f.0)
                        .env("PAIRKEY_D_PUBLISH_ROLE", publisher.to_string())
                        .stdout(std::process::Stdio::null())
                        .spawn()
                        .unwrap();
                    assert!(child.wait().await.unwrap().success());
                    let scope =
                        pair_scope_dir(&f.0.join("controls"), cert.record.wallet.identities, 1);
                    assert_eq!(
                        fs::read(scope.join(format!("{publisher}.quarantined"))).unwrap(),
                        [9; 32]
                    );
                }
                fs::write(f.0.join("resume"), []).unwrap();
                let (mut session, result) = task.await.unwrap();
                if mode == "positive" {
                    result.unwrap();
                    for input in session.inputs.iter_mut().flatten() {
                        send(input, &Frame::DCommand(Box::new(Command::Stop)))
                            .await
                            .unwrap();
                    }
                    session.inputs.clear();
                } else if !(mode == "bypass" && stage == "result") {
                    assert!(result.is_err(), "{stage}/{mode}");
                }
                session.inputs.clear(); // Tokio stdin blocking reads require EOF even after reader abort.
                for child in &mut session.group.children {
                    assert!(tokio::time::timeout(Duration::from_secs(5), child.wait())
                        .await
                        .unwrap()
                        .unwrap()
                        .success());
                }
                for reader in &mut session.group.readers {
                    reader.await.unwrap();
                }
                for role in 0..2 {
                    let observed = fs::read(f.0.join(format!("{role}.queued"))).ok();
                    assert_eq!(
                        observed,
                        match mode {
                            "positive" => Some(b"ordinary".to_vec()),
                            "bypass" => Some(b"late".to_vec()),
                            _ => None,
                        },
                        "{stage}/{mode}/{publisher}/{role}"
                    );
                }
            }
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_donor_retirement_marker_cannot_report_success() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    let f = Fixture::new();
    let (mut s, _, g) = setup(&f, Limits::default()).await;
    let dir =
        f.0.join("controls/d")
            .join(hex(&d::pairing(s.boots.clone().map(|b| b.identity))))
            .join("retired-generations");
    fs::create_dir_all(&dir).unwrap();
    let marker = dir.join(format!("0-{}.retired", hex(&g)));
    fs::write(&marker, []).unwrap();
    let error = s
        .command([Command::Discard, Command::Discard])
        .await
        .err()
        .expect("incomplete retirement must refuse");
    assert!(failure(&error, Action::Burn), "{error:#}");
    assert!(format!("{error:#}").contains("already reserved or ledger unavailable"));
    assert!(fs::read(marker).unwrap().is_empty());
}

async fn finish_workers(session: &mut Session) {
    session.inputs.clear();
    for child in &mut session.group.children {
        assert!(tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success());
    }
    for reader in &mut session.group.readers {
        reader.await.unwrap();
    }
}
fn observed_handoffs(dir: &Path) -> [Vec<u8>; 2] {
    std::array::from_fn(|role| fs::read(dir.join(format!("{role}.handoffs"))).unwrap_or_default())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_incident_fences_other_registered_wallet_across_worker_restarts() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for publisher in 0..2u8 {
        let f = Fixture::new();
        let mut s = Session::start_options(&f.0, 0, Limits::default(), Some(("race:r4", 0)))
            .await
            .unwrap();
        let first = s.register([7; 32], None).await.unwrap();
        let second = s.register([8; 32], None).await.unwrap();
        let (generation, _) = s.prepare(None).await.unwrap();
        // Positive control: the second wallet actually signs with this same donor.
        // Resume initially so this control does not stop at the R4 race barrier.
        fs::write(f.0.join("resume"), []).unwrap();
        let r = s.request([8; 32], generation, None, 0).unwrap();
        s.sign_request([r.clone(), r]).await.unwrap();
        fs::remove_file(f.0.join("resume")).unwrap();
        for role in 0..2 {
            fs::remove_file(f.0.join(format!("{role}.reached"))).unwrap();
            fs::remove_file(f.0.join(format!("{role}.queued"))).unwrap();
        }
        let request = s.request([7; 32], generation, None, 1).unwrap();
        let pending = tokio::spawn(async move {
            let result = s.sign_request([request.clone(), request]).await;
            (s, result)
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            while !(f.0.join("0.reached").exists() && f.0.join("1.reached").exists()) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        fs::write(
            f.0.join("peers.json"),
            serde_json::to_vec(&first.record.wallet.identities).unwrap(),
        )
        .unwrap();
        let mut child = ProcessCommand::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "d_driver::tests::d_process_child",
                "--ignored",
                "--nocapture",
                "--quiet",
            ])
            .env("PAIRKEY_D_CHILD_ROLE", "2")
            .env("PAIRKEY_D_PUBLISH_DIR", &f.0)
            .env("PAIRKEY_D_PUBLISH_ROLE", publisher.to_string())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        assert!(child.wait().await.unwrap().success());
        let scope = pair_scope_dir(&f.0.join("controls"), first.record.wallet.identities, 1);
        assert_eq!(
            fs::read(scope.join(format!("{publisher}.quarantined"))).unwrap(),
            [9; 32]
        );
        fs::write(f.0.join("resume"), []).unwrap();
        let (mut old, result) = pending.await.unwrap();
        let error = result.unwrap_err();
        let terminals = error.downcast_ref::<Terminals>().unwrap();
        // A native queue refusal is returned as SendMessage; do not infer
        // incident persistence from it. The independently synced marker and
        // actual queue oracle establish this cutoff.
        for role in 0..2 {
            assert!(
                terminals.failures.iter().any(|(r, f)| *r == role
                    && f.action == Action::Burn
                    && (f.is_incident_cutoff()
                        || matches!(f.kind, FailureKind::Transport | FailureKind::PeerAbort))),
                "{error:#}"
            );
        }
        finish_workers(&mut old).await;
        for role in 0..2 {
            assert!(!f.0.join(format!("{role}.queued")).exists());
        }
        let base =
            f.0.join("controls/d")
                .join(hex(&d::pairing(second.record.wallet.identities)))
                .join("wallets");
        let journals = std::array::from_fn::<_, 2, _>(|role| {
            Journal::new(&base, &second.record.wallet, role as u8).unwrap()
        });
        let saved = journals
            .each_ref()
            .map(|j| fs::read(j.path("active")).unwrap());
        // Restart twice, keeping roots/public authority/records, but fresh boots.
        for _ in 0..2 {
            let before = observed_handoffs(&f.0);
            let mut replacement =
                Session::start_options(&f.0, 0, Limits::default(), Some(("race:none", 0)))
                    .await
                    .unwrap();
            assert_ne!(old.boots[0].generation, replacement.boots[0].generation);
            assert_ne!(old.boots[1].generation, replacement.boots[1].generation);
            replacement.wallets.insert([8; 32], second.clone());
            let r = replacement.request([8; 32], generation, None, 2).unwrap();
            // Gate may close stdin before delivery; drain authenticated worker
            // diagnostics independently rather than accepting a broken pipe.
            for role in 0..2 {
                let _ = replacement
                    .deliver(role, Frame::DCommand(Box::new(Command::Sign(r.clone()))))
                    .await;
            }
            let error = tokio::time::timeout(Duration::from_secs(10), replacement.collect())
                .await
                .unwrap()
                .err()
                .expect("other wallet must be fenced");
            let t = error.downcast_ref::<Terminals>().unwrap();
            assert!(t.closed.iter().all(|closed| *closed));
            assert!(!t.drain_timed_out);
            for role in 0..2 {
                assert!(
                    t.failures
                        .iter()
                        .any(|(r, f)| *r == role && f.is_incident_cutoff()),
                    "{error:#}"
                );
            }
            finish_workers(&mut replacement).await;
            assert_eq!(
                observed_handoffs(&f.0),
                before,
                "no setup/native/result handoff allowed after restart"
            );
            for role in 0..2 {
                assert_eq!(
                    fs::read(journals[role].path("active")).unwrap(),
                    saved[role]
                );
            }
        }
        // Negative scope control: another identity pairing remains usable.
        let independent = Fixture::new();
        let (mut other, key, g) = setup(&independent, Limits::default()).await;
        let r = other.request(key, g, None, 0).unwrap();
        other.sign_request([r.clone(), r]).await.unwrap();
        other.stop().await.unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_abort_after_reveal_cannot_return_with_a_new_commitment() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    let f = Fixture::new();
    let s = Session::start_options(&f.0, 0, Limits::default(), Some(("before-prepared", 1)))
        .await
        .unwrap();
    let wallet = s.wallet([7; 32]);
    let pid = s.group.children[1].id().unwrap();
    let task = tokio::spawn(async move {
        let mut s = s;
        let result = s.register([7; 32], None).await;
        (s, result)
    });
    reached(&f.0).await;
    assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGKILL) }, 0);
    let (mut old, result) = task.await.unwrap();
    assert!(result.is_err());
    old.inputs.clear();
    for (role, child) in old.group.children.iter_mut().enumerate() {
        assert_eq!(child.wait().await.unwrap().success(), role == 0);
    }
    for reader in &mut old.group.readers {
        reader.await.unwrap();
    }
    let base =
        f.0.join("controls/d")
            .join(hex(&d::pairing(wallet.identities)))
            .join("wallets");
    let journals =
        std::array::from_fn::<_, 2, _>(|r| Journal::new(&base, &wallet, r as u8).unwrap());
    let commitments = journals
        .each_ref()
        .map(|j| fs::read(j.path("commit")).unwrap());
    let peer_commitments = journals
        .each_ref()
        .map(|j| fs::read(j.path("peer-commit")).unwrap());
    let before = observed_handoffs(&f.0);
    let mut replacement =
        Session::start_options(&f.0, 0, Limits::default(), Some(("race:trace-only", 0)))
            .await
            .unwrap();
    assert!(replacement.register([7; 32], None).await.is_err());
    finish_workers(&mut replacement).await;
    assert!(journals[1].retired());
    for role in 0..2 {
        assert_eq!(
            fs::read(journals[role].path("commit")).unwrap(),
            commitments[role]
        );
        assert_eq!(
            fs::read(journals[role].path("peer-commit")).unwrap(),
            peer_commitments[role]
        );
        assert!(!journals[role].exists("active"));
    }
    // Exactly one authenticated public-state exchange per side is released by
    // the retry; a new commitment/reveal/endorsement must never be queued.
    for (role, bytes) in observed_handoffs(&f.0).into_iter().enumerate() {
        assert!(bytes.starts_with(&before[role]));
        let bytes = &bytes[before[role].len()..];
        let frames = bytes
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(|b| serde_json::from_slice::<Value>(b).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["kind"], "setup");
    }
}
