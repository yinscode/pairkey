use super::*;
use crate::{public, reserve, Hello, Route};
use k256::elliptic_curve::group::GroupEncoding;
use std::{
    fs,
    sync::{Arc, Barrier},
};
struct Fixture {
    dir: PathBuf,
    root: Root,
    input: SetupInput,
    request: Request,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("dkls-pool-{:?}", fresh()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("a"), [11; 32]).unwrap();
        fs::write(dir.join("b"), [22; 32]).unwrap();
        let root = Root::load(&dir.join("a")).unwrap();
        let other = Root::load(&dir.join("b")).unwrap();
        let key = [7; 32];
        let shares = [
            public(&root.derive(0, key).unwrap()),
            public(&other.derive(1, key).unwrap()),
        ];
        let q = point(&shares[0]).unwrap() + point(&shares[1]).unwrap();
        let peers = [
            root.identity(0).verifying_key().to_bytes(),
            other.identity(1).verifying_key().to_bytes(),
        ];
        let input = SetupInput {
            version: 1,
            recipe: 1,
            peers,
            boots: [[31; 32], [32; 32]],
            configuration: configuration(),
            entry: fresh(),
        };
        let manifest = Manifest {
            version: 1,
            key_id: key,
            identities: peers,
            additive_public: shares,
            public_key: q.to_bytes().to_vec(),
            chain_code: [9; 32],
        };
        let request = Request {
            route: Route::Pooled,
            manifest,
            hellos: [
                Hello::new(&root, 0, key, [31; 32]).unwrap(),
                Hello::new(&other, 1, key, [32; 32]).unwrap(),
            ],
            entry: input.entry,
            attempt: fresh(),
            path: "m".into(),
            prehash: [6; 32],
            wallet_record: None,
            fault: None,
        };
        Self {
            dir,
            root,
            input,
            request,
        }
    }
    fn gate(&self) -> ReleaseGate {
        ReleaseGate::new(self.dir.join("incidents"), 0)
    }
    fn pool(&self) -> RamPool {
        RamPool::new(
            self.gate(),
            self.dir.join("entries"),
            0,
            self.input.peers,
            self.input.boots,
            2,
        )
        .unwrap()
    }
    fn entry(&self) -> AvailableEntry {
        self.entry_for(self.input.clone(), Duration::from_secs(300))
    }
    fn entry_for(&self, input: SetupInput, ttl: Duration) -> AvailableEntry {
        // Synthetic seeds for ownership/constructor tests, not signing evidence.
        AvailableEntry::agreed(
            input,
            [8; 32],
            Material::new(SenderOTSeed::default(), ReceiverOTSeed::default(), [3; 32]),
            ttl,
        )
        .unwrap()
    }
    fn consumption(&self) -> Consumption {
        Consumption::new(&self.input, [8; 32], &self.request, [10; 32], 1)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
#[test]
fn canonical_encoding_vector_and_domain_boundaries() {
    // Independent explicit byte vector fixes version, BE lengths and labels.
    let actual = hash("x", &[b"ab", b"c"]);
    let expected = Sha256::digest(
        [
            vec![0, 1],
            1u64.to_be_bytes().to_vec(),
            b"x".to_vec(),
            2u64.to_be_bytes().to_vec(),
            b"ab".to_vec(),
            1u64.to_be_bytes().to_vec(),
            b"c".to_vec(),
        ]
        .concat(),
    );
    assert_eq!(actual.as_slice(), expected.as_slice());
    assert_ne!(actual, hash("x", &[b"a", b"bc"]));
    assert_ne!(actual, hash("y", &[b"ab", b"c"]));
}
#[test]
fn setup_inputs_exclude_wallet_and_payload_and_bind_roles_generation_config() {
    let f = Fixture::new();
    let expected = f.input.digest();
    let mut r = f.request.clone();
    r.manifest.key_id[0] ^= 1;
    r.prehash[0] ^= 1;
    r.path = "m/7/3".into();
    assert_eq!(f.input.digest(), expected); // no request field exists in SetupInput
    let mut input = f.input.clone();
    input.peers.swap(0, 1);
    assert_ne!(input.digest(), expected);
    let mut input = f.input.clone();
    input.boots[0][0] ^= 1;
    assert_ne!(input.digest(), expected);
    let mut input = f.input.clone();
    input.configuration[0] ^= 1;
    assert_ne!(input.digest(), expected);
    assert!(input.validate().is_err());
    let mut input = f.input.clone();
    input.entry[0] ^= 1;
    assert_ne!(input.digest(), expected);
    assert_ne!(f.input.sid("base", 0, 1), f.input.sid("base", 1, 0));
    assert_ne!(f.input.sid("base", 0, 1), f.input.sid("pprf", 0, 1));
}
#[test]
fn transcript_is_arrival_independent_and_rejects_duplicates_missing_and_substitution() {
    let f = Fixture::new();
    let mut forward = Transcript::new(f.input.digest());
    let mut reverse = Transcript::new(f.input.digest());
    for stage in 0..4 {
        for role in 0..2 {
            forward.record(stage, role, &[stage, role]).unwrap();
        }
    }
    for stage in (0..4).rev() {
        for role in (0..2).rev() {
            reverse.record(stage, role, &[stage, role]).unwrap();
        }
    }
    let digest = forward.completed().unwrap();
    assert_eq!(digest, reverse.completed().unwrap());
    assert!(forward.record(0, 0, &[0, 0]).is_err());
    assert!(forward.record(0, 0, &[9]).is_err());
    assert!(Transcript::new(f.input.digest()).completed().is_err());
    let mut other = Transcript::new([9; 32]);
    for stage in 0..4 {
        for role in 0..2 {
            other.record(stage, role, &[stage, role]).unwrap();
        }
    }
    assert_ne!(digest, other.completed().unwrap());
    let mut changed = Transcript::new(f.input.digest());
    for stage in 0..4 {
        for role in 0..2 {
            changed.record(stage, role, &[stage, role, 99]).unwrap();
        }
    }
    assert_ne!(digest, changed.completed().unwrap());
    // Completion ACKs cannot be added to the transcript (no circular digest).
    assert!(forward.record(4, 0, &digest).is_err());
}
#[test]
fn consumption_binds_provenance_wallet_path_prehash_receipt_policy_attempt() {
    let f = Fixture::new();
    let c = f.consumption();
    c.validate_request(&f.request).unwrap();
    let original = c.digest();
    for field in 0..11 {
        let mut c = c.clone();
        match field {
            0 => c.input[0] ^= 1,
            1 => c.completed[0] ^= 1,
            2 => c.entry[0] ^= 1,
            3 => c.wallet[0] ^= 1,
            4 => c.scheme.push('x'),
            5 => c.path = "m/7/3".into(),
            6 => c.prehash[0] ^= 1,
            7 => c.receipt[0] ^= 1,
            8 => c.policy_version += 1,
            9 => c.attempt[0] ^= 1,
            10 => c.version += 1,
            _ => unreachable!(),
        }
        assert_ne!(original, c.digest());
        assert_ne!(f.consumption().package_sid(), c.package_sid());
    }
    let mut r = f.request.clone();
    r.manifest.chain_code[0] ^= 1;
    assert!(c.validate_request(&r).is_err());
}
#[test]
fn pool_consumption_moves_seeds_into_one_bound_native_package() {
    let f = Fixture::new();
    let pool = f.pool();
    pool.insert(f.entry()).unwrap();
    let c = f.consumption();
    let reserved = pool.reserve(&c).unwrap();
    assert_eq!(pool.available(), 0);
    assert!(pool.reserve(&c).is_err());
    let package = reserved.into_package(&f.request, &f.root, 0).unwrap();
    assert_eq!(package.final_session_id, c.package_sid());
    assert_eq!(package.extra_data(), c.digest());
    assert_eq!(
        package.public_key(),
        point(&f.request.manifest.public_key).unwrap()
    );
    assert!(pool.insert(f.entry()).is_err()); // cannot replenish an already admitted ID
}
#[test]
fn concurrent_reservation_has_one_winner_and_cancellation_stays_retired() {
    let f = Fixture::new();
    let pool = Arc::new(f.pool());
    pool.insert(f.entry()).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let c = f.consumption();
    let threads = (0..8)
        .map(|_| {
            let pool = pool.clone();
            let barrier = barrier.clone();
            let c = c.clone();
            std::thread::spawn(move || {
                barrier.wait();
                pool.reserve(&c).is_ok() // drops reserved ownership, modeling cancellation
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        threads
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|b| *b)
            .count(),
        1
    );
    assert_eq!(pool.available(), 0);
    let replacement = f.pool();
    replacement.insert(f.entry()).unwrap();
    assert!(replacement.reserve(&c).is_err());
    assert_eq!(replacement.available(), 0);
}
#[test]
fn provenance_and_consumption_mismatches_burn_without_unreserve() {
    for wrong in ["input", "completed", "path"] {
        let f = Fixture::new();
        let pool = f.pool();
        pool.insert(f.entry()).unwrap();
        let mut c = f.consumption();
        match wrong {
            "input" => c.input[0] ^= 1,
            "completed" => c.completed[0] ^= 1,
            "path" => c.path = "m/7/3".into(),
            _ => unreachable!(),
        }
        match pool.reserve(&c) {
            Err(_) => {}
            Ok(r) => assert!(r.into_package(&f.request, &f.root, 0).is_err()),
        }
        assert_eq!(pool.available(), 0);
        assert!(reserve(&f.dir.join("entries"), 0, c.entry, c.digest()).is_err());
    }
}
#[test]
fn bounded_pool_expiry_empty_and_wrong_generation_fail_closed() {
    let f = Fixture::new();
    let pool = f.pool();
    assert!(pool.reserve(&f.consumption()).is_err());
    let mut wrong = f.input.clone();
    wrong.boots[0][0] ^= 1;
    wrong.entry = fresh();
    assert!(pool
        .insert(f.entry_for(wrong, Duration::from_secs(1)))
        .is_err());
    pool.insert(f.entry_for(f.input.clone(), Duration::from_millis(1)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(3));
    assert_eq!(pool.available(), 0);
    assert!(pool.reserve(&f.consumption()).is_err());
    for _ in 0..2 {
        let mut input = f.input.clone();
        input.entry = fresh();
        pool.insert(f.entry_for(input, Duration::from_secs(1)))
            .unwrap();
    }
    let mut input = f.input.clone();
    input.entry = fresh();
    assert!(pool
        .insert(f.entry_for(input, Duration::from_secs(1)))
        .is_err());
    assert_eq!(pool.available(), 2);
}
#[test]
fn incident_fences_reserved_packages_and_discards_available_material() {
    let f = Fixture::new();
    let pool = f.pool();
    pool.insert(f.entry()).unwrap();
    let mut second = f.input.clone();
    second.entry = fresh();
    pool.insert(f.entry_for(second, Duration::from_secs(1)))
        .unwrap();
    let reserved = pool.reserve(&f.consumption()).unwrap();
    assert_eq!(pool.available(), 1);
    f.gate().publish([9; 32]).unwrap();
    assert!(reserved.into_package(&f.request, &f.root, 0).is_err());
    assert_eq!(pool.available(), 0);
    assert!(pool.insert(f.entry()).is_err());
    assert!(pool.reserve(&f.consumption()).is_err());
}
#[test]
fn concurrent_refill_incident_and_reservation_share_release_cutoff() {
    let f = Fixture::new();
    let pool = Arc::new(f.pool());
    pool.insert(f.entry()).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let c = f.consumption();
    let entry = fresh();
    let mut input = f.input.clone();
    input.entry = entry;
    let refill = f.entry_for(input, Duration::from_secs(10));
    let reserve_thread = {
        let pool = pool.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            pool.reserve(&c).ok()
        })
    };
    let refill_thread = {
        let pool = pool.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            pool.insert(refill).is_ok()
        })
    };
    f.gate().publish([9; 32]).unwrap(); // deterministic cutoff before racing operations
    barrier.wait();
    assert!(reserve_thread.join().unwrap().is_none());
    assert!(!refill_thread.join().unwrap());
    assert_eq!(pool.available(), 0);
}
#[test]
fn restart_discards_unused_pool_and_setup_ids_remain_burned() {
    let f = Fixture::new();
    let pool = f.pool();
    pool.insert(f.entry()).unwrap();
    drop(pool);
    assert_eq!(f.pool().available(), 0);
    let ledger = f.dir.join("pool-setups");
    reserve(&ledger, 0, f.input.entry, f.input.digest()).unwrap();
    assert!(reserve(&ledger, 0, f.input.entry, f.input.digest()).is_err());
    // This assertion does not claim host rollback/snapshots are prevented.
}
