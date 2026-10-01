use super::*;
use std::{fs, path::PathBuf};
struct Fixture {
    dir: PathBuf,
    roots: [Root; 2],
    wallet: Wallet,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("pairkey-D-{:?}", crate::fresh()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("0"), [11; 32]).unwrap();
        fs::write(dir.join("1"), [22; 32]).unwrap();
        let roots = [
            Root::load(&dir.join("0")).unwrap(),
            Root::load(&dir.join("1")).unwrap(),
        ];
        let wallet = Wallet {
            version: 2,
            identities: std::array::from_fn(|i| {
                roots[i].identity(i as u8).verifying_key().to_bytes()
            }),
            namespace: "test".into(),
            epoch: 0,
            key_id: [7; 32],
        };
        Self { dir, roots, wallet }
    }
    fn record(&self) -> Record {
        let openings = std::array::from_fn(|i| Opening {
            point: public(&self.roots[i].derive_v2(i as u8, &self.wallet).unwrap()),
            salt: [31 + i as u8; 32],
        });
        let commits = std::array::from_fn(|i| openings[i].commitment(&self.wallet, i as u8));
        Record::new(self.wallet.clone(), commits, openings).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
#[test]
fn derivation_v2_binds_pair_namespace_epoch_wallet_and_preserves_v1() {
    let f = Fixture::new();
    let old = f.roots[0].derive(0, f.wallet.key_id).unwrap();
    let x = f.roots[0].derive_v2(0, &f.wallet).unwrap();
    assert_eq!(*x, *f.roots[0].derive_v2(0, &f.wallet).unwrap());
    for kind in 0..4 {
        let mut w = f.wallet.clone();
        match kind {
            0 => w.namespace.push('x'),
            1 => w.epoch += 1,
            2 => w.key_id[0] ^= 1,
            3 => {
                w.identities[1] = ed25519_dalek::SigningKey::from_bytes(&[99; 32])
                    .verifying_key()
                    .to_bytes()
            }
            _ => unreachable!(),
        };
        assert_ne!(*x, *f.roots[0].derive_v2(0, &w).unwrap());
    }
    assert_eq!(*old, *f.roots[0].derive(0, f.wallet.key_id).unwrap());
    assert!(f.roots[1].derive_v2(0, &f.wallet).is_err());
}
#[test]
fn commitment_and_record_mutations_refuse() {
    let f = Fixture::new();
    let record = f.record();
    record.validate().unwrap();
    for kind in 0..6 {
        let mut r = record.clone();
        match kind {
            0 => r.openings[0].salt[0] ^= 1,
            1 => r.commitments.swap(0, 1),
            2 => r.wallet.key_id[0] ^= 1,
            3 => r.wallet.identities.swap(0, 1),
            4 => r.chain_code[0] ^= 1,
            5 => r.public_key = r.openings[0].point.clone(),
            _ => unreachable!(),
        };
        assert!(r.validate().is_err());
    }
}
#[test]
fn only_exact_prepared_certificate_can_activate() {
    let f = Fixture::new();
    let r = f.record();
    let js = std::array::from_fn::<_, 2, _>(|i| {
        Journal::new(&f.dir.join("journals"), &f.wallet, i as u8).unwrap()
    });
    for (i, j) in js.iter().enumerate() {
        j.reserve(&f.wallet, [8; 32]).unwrap();
        assert!(j.reserve(&f.wallet, [8; 32]).is_err());
        j.prepare(&r, &f.roots[i]).unwrap();
    }
    let cert = Certificate {
        record: r.clone(),
        endorsements: std::array::from_fn(|i| js[i].prepare(&r, &f.roots[i]).unwrap()),
    };
    for (i, j) in js.iter().enumerate() {
        j.commit(&cert, &f.roots[i]).unwrap();
        assert_eq!(j.active(&f.roots[i]).unwrap(), cert);
        let mut wrong = cert.clone();
        wrong.endorsements.swap(0, 1);
        assert!(j.commit(&wrong, &f.roots[i]).is_err());
    }
}
#[test]
fn incomplete_or_conflicting_journals_refuse_and_retirement_is_permanent() {
    let f = Fixture::new();
    let j = Journal::new(&f.dir.join("j"), &f.wallet, 0).unwrap();
    j.reserve(&f.wallet, [8; 32]).unwrap();
    j.write("commit", &[1; 32]).unwrap();
    assert!(j.write("commit", &[2; 32]).is_err());
    fs::write(j.path("prepared"), b"{").unwrap();
    assert!(j.read::<(Record, Endorsement)>("prepared").is_err());
    j.retire().unwrap();
    assert!(j.reserve(&f.wallet, [9; 32]).is_err());
    assert!(j.prepare(&f.record(), &f.roots[0]).is_err());
}
#[test]
fn public_journal_checkpoint_errors_only_resync_complete_exact_records() {
    use WriteStep::*;
    let steps = [
        BeforeCreate,
        Created,
        Partial,
        Written,
        BeforeFileSync,
        FileSynced,
        BeforeDirectorySync,
        DirectorySynced,
    ];
    for stage in [
        "commit",
        "peer-commit",
        "reveal-release",
        "prepared",
        "active",
    ] {
        for failed in steps {
            let f = Fixture::new();
            let j = Journal::new(&f.dir.join("j"), &f.wallet, 0).unwrap();
            assert!(j
                .write_checkpoint(stage, &[7; 32], |s| {
                    if s == failed {
                        anyhow::bail!("injected I/O failure")
                    };
                    Ok(())
                })
                .is_err());
            let incomplete = matches!(failed, Created | Partial);
            assert_eq!(j.write(stage, &[7; 32]).is_err(), incomplete);
            if incomplete {
                let before = fs::read(j.path(stage)).unwrap();
                assert!(j.write(stage, &[8; 32]).is_err());
                assert_eq!(before, fs::read(j.path(stage)).unwrap());
            }
        }
    }
}
#[test]
fn seed_hedge_keeps_entropy_and_separates_context_role_counter_operation() {
    let e = [8; 32];
    let c = [9; 32];
    let s = hedged_seed(&e, c, 1, 0, "sign");
    assert_ne!(*s, *hedged_seed(&[7; 32], c, 1, 0, "sign"));
    assert_ne!(*s, *hedged_seed(&e, [10; 32], 1, 0, "sign"));
    assert_ne!(*s, *hedged_seed(&e, c, 2, 0, "sign"));
    assert_ne!(*s, *hedged_seed(&e, c, 1, 1, "sign"));
    assert_ne!(*s, *hedged_seed(&e, c, 1, 0, "donor-dkg"));
}
#[test]
fn counter_regression_and_partial_issuance_fail_closed() {
    let f = Fixture::new();
    let dir = f.dir.join("c");
    let mut c = Counter::new(dir.clone(), 0);
    assert_eq!(c.issue().unwrap(), 1);
    assert_eq!(c.issue().unwrap(), 2);
    fs::write(dir.join("0-counter"), 1u64.to_be_bytes()).unwrap();
    assert!(c.issue().is_err());
    assert!(Counter::new(dir.clone(), 0).issue().is_err());
    fs::write(dir.join("0-counter"), 2u64.to_be_bytes()).unwrap();
    fs::write(dir.join("0-issued-3"), []).unwrap();
    assert!(c.issue().is_err());
}
#[test]
fn authenticated_r1_replay_journal_and_native_final_sid_observer() {
    use sl_mpc_mate::message::MESSAGE_HEADER_SIZE;
    let f = Fixture::new();
    let ids = [[1; 32], [2; 32]];
    let guard = R1Guard::new(ids, [3; 32], 0, f.wallet.identities, f.dir.join("sid"));
    let packet = |role: usize| {
        let mut b = vec![0; MESSAGE_HEADER_SIZE + 97];
        b[..32].copy_from_slice(&ids[role]);
        b[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + 32].copy_from_slice(&[8 + role as u8; 32]);
        let sig = f.roots[role].identity(role as u8).sign(&b);
        b.extend(sig.to_bytes());
        b
    };
    let a = packet(0);
    let b = packet(1);
    guard.observe(&a, true).unwrap();
    guard.observe(&b, false).unwrap();
    guard.final_session().unwrap();
    let replacement = R1Guard::new(ids, [3; 32], 0, f.wallet.identities, f.dir.join("sid"));
    assert!(replacement.observe(&b, false).is_err());
    assert!(replacement.failure().is_some());
    let mut bad = packet(1);
    *bad.last_mut().unwrap() ^= 1;
    let untrusted = R1Guard::new(
        ids,
        [3; 32],
        0,
        f.wallet.identities,
        f.dir.join("untrusted"),
    );
    untrusted.observe(&bad, false).unwrap();
    assert!(untrusted.final_session().is_err());
}
#[test]
fn possession_proof_is_authenticated_and_bound_to_entire_record() {
    let f = Fixture::new();
    let r = f.record();
    let e = Endorsement::new(&r, &f.roots[0], 0).unwrap();
    e.validate(&r).unwrap();
    let mut bad = e.clone();
    bad.response[0] ^= 1;
    bad.signature = f.roots[0]
        .identity(0)
        .sign(&bad.message())
        .to_bytes()
        .to_vec();
    let err = bad.validate(&r).unwrap_err();
    assert_eq!(
        err.downcast_ref::<crate::lifecycle::Failure>()
            .unwrap()
            .action,
        crate::lifecycle::Action::QuarantinePeer
    );
    let mut other = r.clone();
    other.wallet.epoch += 1;
    assert!(e.validate(&other).is_err());
}
#[test]
fn transport_rate_journal_survives_restart_and_refuses_clock_regression() {
    let f = Fixture::new();
    let dir = f.dir.join("rate");
    let c = Counter::new(dir.clone(), 0);
    for i in 0..3 {
        c.check_rate(100, 60, 3).unwrap();
        c.transport(100, [i; 32]).unwrap();
    }
    let restarted = Counter::new(dir, 0);
    assert!(restarted.check_rate(100, 60, 3).is_err());
    assert!(restarted.check_rate(99, 60, 3).is_err());
    restarted.check_rate(161, 60, 3).unwrap();
}
#[test]
#[ignore = "explicit public-journal subprocess"]
fn journal_process_child() {
    let dir = PathBuf::from(std::env::var_os("PAIRKEY_D_JOURNAL_DIR").unwrap());
    let wallet: Wallet =
        serde_json::from_slice(&fs::read(dir.join("wallet.json")).unwrap()).unwrap();
    let stage = std::env::var("PAIRKEY_D_JOURNAL_STAGE").unwrap();
    let target: usize = std::env::var("PAIRKEY_D_JOURNAL_STEP")
        .unwrap()
        .parse()
        .unwrap();
    let steps = [
        WriteStep::BeforeCreate,
        WriteStep::Created,
        WriteStep::Partial,
        WriteStep::Written,
        WriteStep::BeforeFileSync,
        WriteStep::FileSynced,
        WriteStep::BeforeDirectorySync,
        WriteStep::DirectorySynced,
    ];
    let j = Journal::new(&dir.join("journal"), &wallet, 0).unwrap();
    let checkpoint = |s| {
        if s == steps[target] {
            fs::write(dir.join("paused"), []).unwrap();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        Ok(())
    };
    if stage == "reserved" {
        j.reserve_checkpoint(&wallet, [7; 32], checkpoint).unwrap()
    } else {
        j.write_checkpoint(&stage, &[7u8; 32], checkpoint).unwrap()
    }
}
#[test]
fn public_journal_process_death_at_every_write_sync_checkpoint() {
    for stage in [
        "reserved",
        "commit",
        "peer-commit",
        "reveal-release",
        "prepared",
        "active",
    ] {
        for step in 0..8 {
            let f = Fixture::new();
            fs::write(
                f.dir.join("wallet.json"),
                serde_json::to_vec(&f.wallet).unwrap(),
            )
            .unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "d::tests::journal_process_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("PAIRKEY_D_JOURNAL_DIR", &f.dir)
                .env("PAIRKEY_D_JOURNAL_STAGE", stage)
                .env("PAIRKEY_D_JOURNAL_STEP", step.to_string())
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !f.dir.join("paused").exists() {
                assert!(std::time::Instant::now() < end);
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            let j = Journal::new(&f.dir.join("journal"), &f.wallet, 0).unwrap();
            let error = if stage == "reserved" {
                j.reserve(&f.wallet, [7; 32]).is_err()
            } else {
                j.write(stage, &[7u8; 32]).is_err()
            };
            assert_eq!(
                error,
                if stage == "reserved" {
                    step != 0
                } else {
                    matches!(step, 1 | 2)
                },
                "{stage}/{step}"
            );
        }
    }
}
#[derive(Clone)]
struct TestIdentity(VerifyingKey);
impl AsRef<[u8]> for TestIdentity {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl signature::Verifier<Signature> for TestIdentity {
    fn verify(&self, m: &[u8], s: &Signature) -> std::result::Result<(), signature::Error> {
        self.0.verify_strict(m, s)
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_donor_extraction_reuses_exact_material_with_concurrent_transient_wallets() {
    use sl_dkls23::{keygen, sign};
    use sl_mpc_mate::{coord::SimpleMessageRelay, message::InstanceId};
    use std::{str::FromStr, sync::Arc};
    let f = Fixture::new();
    let identities = f
        .wallet
        .identities
        .map(|b| TestIdentity(VerifyingKey::from_bytes(&b).unwrap()))
        .to_vec();
    let relay = SimpleMessageRelay::new();
    let id = crate::fresh();
    let setup = |role: usize| {
        sl_dkls23::setup::keygen::SetupMessage::<_, _, Signature>::new(
            InstanceId::new(id),
            f.roots[role].identity(role as u8),
            role,
            identities.clone(),
            &[0, 0],
            2,
        )
    };
    let (a, b) = tokio::join!(
        keygen::run(setup(0), crate::fresh(), relay.connect()),
        keygen::run(setup(1), crate::fresh(), relay.connect())
    );
    let mut donors = [
        Donor::extract(a.unwrap(), f.wallet.identities, 0, Limits::default()).unwrap(),
        Donor::extract(b.unwrap(), f.wallet.identities, 1, Limits::default()).unwrap(),
    ];
    assert_eq!(donors[0].generation, donors[1].generation);
    let original = donors.each_ref().map(Donor::fingerprint);
    let mut jobs = vec![];
    for i in 0..8usize {
        let mut record = f.record();
        record.wallet.key_id[0] += i as u8;
        record.openings = std::array::from_fn(|r| Opening {
            point: public(&f.roots[r].derive_v2(r as u8, &record.wallet).unwrap()),
            salt: crate::fresh(),
        });
        record.commitments =
            std::array::from_fn(|r| record.openings[r].commitment(&record.wallet, r as u8));
        record = Record::new(record.wallet, record.commitments, record.openings).unwrap();
        let instance = crate::fresh();
        let hash = crate::fresh();
        let packages = std::array::from_fn::<_, 2, _>(|r| {
            donors[r].reserve().unwrap();
            Arc::new(donors[r].package(&f.roots[r], &record, instance).unwrap())
        });
        let relay = SimpleMessageRelay::new();
        let path =
            derivation_path::DerivationPath::from_str(if i % 2 == 0 { "m" } else { "m/7/3" })
                .unwrap();
        let expected = packages[0].derive_with_offset(&path).unwrap().1;
        let setups = std::array::from_fn::<_, 2, _>(|r| {
            sl_dkls23::setup::sign::SetupMessage::<_, _, Signature>::new(
                InstanceId::new(instance),
                f.roots[r].identity(r as u8),
                r,
                identities.clone(),
                packages[r].clone(),
            )
            .with_hash(hash)
            .with_chain_path(path.clone())
        });
        let mut iter = setups.into_iter();
        let left = iter.next().unwrap();
        let right = iter.next().unwrap();
        jobs.push(async move {
            let (a, b) = tokio::join!(
                sign::run(left, crate::fresh(), relay.connect()),
                sign::run(right, crate::fresh(), relay.connect())
            );
            let a = a.unwrap();
            assert_eq!(a, b.unwrap());
            use signature::hazmat::PrehashVerifier;
            k256::ecdsa::VerifyingKey::from_affine(expected.to_affine())
                .unwrap()
                .verify_prehash(&hash, &a.0)
                .unwrap();
            a.0.to_bytes().to_vec()
        });
    }
    let signatures = futures_util::future::join_all(jobs).await;
    let unique: std::collections::BTreeSet<_> = signatures.iter().map(|s| &s[..32]).collect();
    assert_eq!(unique.len(), 8);
    assert_eq!(original, donors.each_ref().map(Donor::fingerprint));
    let mut forbidden = f.record();
    forbidden.public_key = donors[0].unused_public_key.clone();
    assert!(donors[0].package(&f.roots[0], &forbidden, [7; 32]).is_err());
}
#[test]
fn strict_reservation_checkpoint_errors_never_reopen_created_slots() {
    let steps = [
        WriteStep::BeforeCreate,
        WriteStep::Created,
        WriteStep::Partial,
        WriteStep::Written,
        WriteStep::BeforeFileSync,
        WriteStep::FileSynced,
        WriteStep::BeforeDirectorySync,
        WriteStep::DirectorySynced,
    ];
    for target in steps {
        let f = Fixture::new();
        let j = Journal::new(&f.dir.join("r"), &f.wallet, 0).unwrap();
        assert!(j
            .reserve_checkpoint(&f.wallet, [7; 32], |s| {
                if s == target {
                    anyhow::bail!("injected reserve error")
                };
                Ok(())
            })
            .is_err());
        assert_eq!(
            j.reserve(&f.wallet, [8; 32]).is_err(),
            target != WriteStep::BeforeCreate
        );
    }
}

#[test]
fn registration_commitments_do_not_replay_across_wallet_role_pairing_or_epoch() {
    let f = Fixture::new();
    let r = f.record();
    let opening = r.openings[0].clone();
    let original = opening.commitment(&f.wallet, 0);
    assert_ne!(original, opening.commitment(&f.wallet, 1));
    for field in 0..4 {
        let mut w = f.wallet.clone();
        match field {
            0 => w.key_id[0] ^= 1,
            1 => w.namespace.push('x'),
            2 => w.epoch += 1,
            _ => {
                w.identities[1] = ed25519_dalek::SigningKey::from_bytes(&[99; 32])
                    .verifying_key()
                    .to_bytes()
            }
        };
        assert_ne!(original, opening.commitment(&w, 0));
        let mut wrong = r.clone();
        wrong.wallet = w;
        assert!(wrong.validate().is_err());
    }
    let mut swapped = r;
    swapped.openings.swap(0, 1);
    assert!(swapped.validate().is_err());
}
#[test]
fn competing_ceremonies_have_one_reservation_winner_per_role() {
    let f = Fixture::new();
    for role in 0..2 {
        let j = Journal::new(&f.dir.join("race"), &f.wallet, role).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let handles = (0..2)
                .map(|i| {
                    let b = barrier.clone();
                    let j = j.clone();
                    let w = f.wallet.clone();
                    scope.spawn(move || {
                        b.wait();
                        (i, j.reserve(&w, [i; 32]).is_ok())
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|(_, ok)| *ok).count(), 1);
        let (w, attempt): (Wallet, Hash) = j.read("reserved").unwrap();
        assert_eq!(w, f.wallet);
        assert_eq!(attempt, [results.iter().find(|(_, ok)| *ok).unwrap().0; 32]);
        assert!(j.reserve(&f.wallet, [9; 32]).is_err());
    }
}
#[path = "native_review_tests.rs"]
mod native_review;
