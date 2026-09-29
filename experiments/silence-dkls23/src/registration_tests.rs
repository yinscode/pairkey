use super::*;
use crate::{fresh, public, Route};
use k256::elliptic_curve::group::GroupEncoding;
use std::sync::{Arc, Barrier};

struct Fixture {
    dir: PathBuf,
    roots: [Root; 2],
    record: WalletRecord,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("dkls-registration-{:?}", fresh()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("a"), [11; 32]).unwrap();
        fs::write(dir.join("b"), [22; 32]).unwrap();
        let roots = [
            Root::load(&dir.join("a")).unwrap(),
            Root::load(&dir.join("b")).unwrap(),
        ];
        let key = [7; 32];
        let contributions = [
            public(&roots[0].derive(0, key).unwrap()),
            public(&roots[1].derive(1, key).unwrap()),
        ];
        let q = (point(&contributions[0]).unwrap() + point(&contributions[1]).unwrap())
            .to_bytes()
            .to_vec();
        let manifest = Manifest {
            version: 1,
            key_id: key,
            identities: [
                roots[0].identity(0).verifying_key().to_bytes(),
                roots[1].identity(1).verifying_key().to_bytes(),
            ],
            additive_public: contributions,
            public_key: q.clone(),
            chain_code: digest(b"pairkey/dkls-research/public-chain-code/v1", &(key, q)),
        };
        Self {
            dir,
            roots,
            record: WalletRecord::new(manifest).unwrap(),
        }
    }
    fn store(&self) -> WalletStore {
        WalletStore::new(self.dir.join("wallets"))
    }
    fn wallet(&self) -> RegisteredWallet {
        RegisteredWallet {
            record: self.record.clone(),
            endorsements: [
                self.store()
                    .endorse(&self.record, &self.roots[0], 0)
                    .unwrap(),
                self.store()
                    .endorse(&self.record, &self.roots[1], 1)
                    .unwrap(),
            ],
        }
    }
    fn request(&self) -> Request {
        Request {
            route: Route::Pooled,
            manifest: self.record.manifest.clone(),
            hellos: [
                Hello::new(&self.roots[0], 0, [7; 32], [31; 32]).unwrap(),
                Hello::new(&self.roots[1], 1, [7; 32], [32; 32]).unwrap(),
            ],
            entry: fresh(),
            attempt: fresh(),
            path: "m".into(),
            prehash: [4; 32],
            fault: None,
            wallet_record: Some(self.record.digest()),
        }
    }
    fn fork(&self) -> WalletRecord {
        let mut r = self.record.clone();
        r.manifest.additive_public[1] = (point(&r.manifest.additive_public[1]).unwrap()
            + k256::ProjectivePoint::GENERATOR)
            .to_bytes()
            .to_vec();
        r.manifest.public_key = (point(&r.manifest.additive_public[0]).unwrap()
            + point(&r.manifest.additive_public[1]).unwrap())
        .to_bytes()
        .to_vec();
        r.manifest.chain_code = digest(
            b"pairkey/dkls-research/public-chain-code/v1",
            &(r.manifest.key_id, r.manifest.public_key.clone()),
        );
        r.validate().unwrap();
        r
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn record_digest_binds_all_metadata_and_supported_versions_are_enforced() {
    let f = Fixture::new();
    let r = &f.record;
    let encoded = json_order_independent_digest(r);
    assert_eq!(r.digest(), encoded);
    let changes: [fn(&mut WalletRecord); 13] = [
        |r| r.version += 1,
        |r| r.namespace.push('x'),
        |r| r.configuration[0] ^= 1,
        |r| r.curve.push('x'),
        |r| r.kdf_version += 1,
        |r| r.chain_code_version += 1,
        |r| r.derivation_version += 1,
        |r| r.share_version += 1,
        |r| r.party_ids.swap(0, 1),
        |r| r.coordinates.swap(0, 1),
        |r| r.ranks[0] = 1,
        |r| r.threshold = 1,
        |r| r.manifest.chain_code[0] ^= 1,
    ];
    for change in changes {
        let mut altered = r.clone();
        change(&mut altered);
        assert_ne!(altered.digest(), r.digest());
        assert!(altered.validate().is_err());
    }
    assert_ne!(f.fork().digest(), r.digest());
}
fn json_order_independent_digest(r: &WalletRecord) -> [u8; 32] {
    let value = serde_json::to_value(r).unwrap();
    let parsed: WalletRecord = serde_json::from_value(value).unwrap();
    parsed.digest()
}
#[test]
fn endorsements_bind_final_record_role_and_proof_in_addition_to_identity_signature() {
    let f = Fixture::new();
    let w = f.wallet();
    w.validate().unwrap();
    let mut altered = w.clone();
    altered.record = f.fork();
    assert!(altered.validate().is_err());
    let mut altered = w.clone();
    altered.endorsements.swap(0, 1);
    assert!(altered.validate().is_err());
    let mut altered = w.clone();
    let e = &mut altered.endorsements[1];
    let z = Option::<Scalar>::from(Scalar::from_repr(e.response.into())).unwrap() + Scalar::ONE;
    e.response = z.to_bytes().into();
    e.signature = f.roots[1]
        .identity(1)
        .sign(&e.message())
        .to_bytes()
        .to_vec();
    assert!(altered
        .validate()
        .unwrap_err()
        .to_string()
        .contains("possession proof"));
}
#[test]
fn only_authenticated_invalid_registration_proofs_quarantine_the_peer() {
    let f = Fixture::new();
    let w = f.wallet();
    let mut bad = w.endorsements[1].clone();
    bad.signature[0] ^= 1;
    assert!(bad
        .validate(&f.record)
        .unwrap_err()
        .downcast_ref::<crate::lifecycle::Failure>()
        .is_none());
    bad = w.endorsements[1].clone();
    bad.response = [255; 32];
    bad.signature = f.roots[1]
        .identity(1)
        .sign(&bad.message())
        .to_bytes()
        .to_vec();
    let failure = bad
        .validate(&f.record)
        .unwrap_err()
        .downcast::<crate::lifecycle::Failure>()
        .unwrap();
    assert_eq!(failure.peer, Some(f.record.manifest.identities[1]));
    assert_eq!(failure.action, crate::lifecycle::Action::QuarantinePeer);
    let local = failure
        .clone()
        .registration_perspective(f.record.manifest.identities[1]);
    assert_eq!(local.action, crate::lifecycle::Action::FreezeConfiguration);
    assert_eq!(local.peer, None);
    assert_eq!(
        failure
            .clone()
            .registration_perspective(f.record.manifest.identities[0])
            .peer,
        Some(f.record.manifest.identities[1])
    );
    let dir = f.dir.join("scope");
    let gate = crate::lifecycle::ReleaseGate::new(dir.clone(), 0);
    assert!(gate.apply(failure, f.record.digest()).incident_persisted);
    assert!(crate::lifecycle::ReleaseGate::new(dir, 1)
        .release(|| Ok(()))
        .is_err());
}
#[test]
fn registration_is_idempotent_across_reload_and_never_reissues_a_proof_for_another_record() {
    let f = Fixture::new();
    let w = f.wallet();
    let root = Root::load(&f.dir.join("a")).unwrap();
    assert_eq!(
        f.store().endorse(&f.record, &root, 0).unwrap(),
        w.endorsements[0]
    );
    for role in 0..2 {
        assert_eq!(
            f.store().commit(&w, &f.roots[role], role as u8).unwrap(),
            f.record.digest()
        );
    }
    assert_eq!(f.store().load([7; 32]).unwrap(), w);
    assert!(f.store().endorse(&f.fork(), &root, 0).is_err());
}
#[test]
fn prepared_only_and_missing_or_wrong_endorsements_do_not_commit_or_authorize_signing() {
    let f = Fixture::new();
    let e = f.store().endorse(&f.record, &f.roots[0], 0).unwrap();
    assert!(f.store().load([7; 32]).is_err());
    let mut w = RegisteredWallet {
        record: f.record.clone(),
        endorsements: [e.clone(), e],
    };
    assert!(f.store().commit(&w, &f.roots[0], 0).is_err());
    w.endorsements[1] = Endorsement::new(&f.record, &f.roots[1], 1).unwrap();
    assert!(f.store().commit(&w, &f.roots[1], 1).is_err());
    assert!(!f.store().record_path([7; 32]).exists());
}
#[test]
fn signing_requires_committed_identity_and_rejects_internally_consistent_fork_or_missing_digest() {
    let f = Fixture::new();
    let w = f.wallet();
    f.store().commit(&w, &f.roots[0], 0).unwrap();
    let mut r = f.request();
    w.validate_request(&r, &f.roots[0], 0).unwrap();
    r.manifest = f.fork().manifest;
    assert!(w.validate_request(&r, &f.roots[0], 0).is_err());
    r = f.request();
    r.wallet_record = None;
    assert!(w.validate_request(&r, &f.roots[0], 0).is_err());
    r = f.request();
    r.wallet_record = Some([8; 32]);
    assert!(w.validate_request(&r, &f.roots[0], 0).is_err());
}
#[test]
fn concurrent_conflicting_candidates_publish_endorsements_for_only_one_record() {
    let f = Fixture::new();
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let b = barrier.clone();
            let record = if i % 2 == 0 {
                f.record.clone()
            } else {
                f.fork()
            };
            let dir = f.dir.clone();
            std::thread::spawn(move || {
                let root = Root::load(&dir.join("a")).unwrap();
                b.wait();
                WalletStore::new(dir.join("wallets"))
                    .endorse(&record, &root, 0)
                    .ok()
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .filter_map(|h| h.join().unwrap())
        .collect();
    assert_eq!(results.len(), 4);
    assert!(results.iter().all(|r| *r == results[0]));
}
#[test]
fn partial_journal_and_partial_final_record_fail_closed_without_repair() {
    let f = Fixture::new();
    let store = f.store();
    fs::create_dir_all(&store.dir).unwrap();
    fs::write(store.prepared_path([7; 32], 0), []).unwrap();
    assert!(store.endorse(&f.record, &f.roots[0], 0).is_err());
    assert!(fs::read(store.prepared_path([7; 32], 0))
        .unwrap()
        .is_empty());
    let g = Fixture::new();
    let w = g.wallet();
    fs::write(g.store().record_path([7; 32]), b"{").unwrap();
    assert!(g.store().commit(&w, &g.roots[0], 0).is_err());
    assert!(g.store().load([7; 32]).is_err());
    assert!(g.store().endorse(&g.record, &g.roots[0], 0).is_err());
    assert_eq!(fs::read(g.store().record_path([7; 32])).unwrap(), b"{");
}
#[test]
fn write_failures_at_durability_steps_allow_only_complete_valid_resynced_records() {
    for failed in [
        WriteStep::Created,
        WriteStep::Written,
        WriteStep::FileSynced,
        WriteStep::DirectorySynced,
    ] {
        let f = Fixture::new();
        let store = f.store();
        fs::create_dir_all(&store.dir).unwrap();
        let e = Endorsement::new(&f.record, &f.roots[0], 0).unwrap();
        let prepared = Prepared {
            record: f.record.clone(),
            endorsement: e.clone(),
        };
        assert!(write_checkpoint(
            &store.prepared_path([7; 32], 0),
            &store.dir,
            &prepared,
            |step| {
                if step == failed {
                    anyhow::bail!("injected sync/write failure");
                }
                Ok(())
            }
        )
        .is_err());
        let retry = store.endorse(&f.record, &f.roots[0], 0);
        if failed == WriteStep::Created {
            assert!(retry.is_err());
        } else {
            assert_eq!(retry.unwrap(), e);
        }
        let g = Fixture::new();
        let w = g.wallet();
        let store = g.store();
        assert!(
            write_checkpoint(&store.record_path([7; 32]), &store.dir, &w, |step| {
                if step == failed {
                    anyhow::bail!("injected final commit failure");
                }
                Ok(())
            })
            .is_err()
        );
        let retry = store.commit(&w, &g.roots[0], 0);
        if failed == WriteStep::Created {
            assert!(retry.is_err());
            assert!(store.load([7; 32]).is_err());
        } else {
            assert_eq!(retry.unwrap(), g.record.digest());
            assert_eq!(store.load([7; 32]).unwrap(), w);
        }
    }
}
#[test]
fn changed_record_filename_and_oversized_or_unknown_fields_are_refused() {
    let f = Fixture::new();
    let w = f.wallet();
    f.store().commit(&w, &f.roots[0], 0).unwrap();
    fs::copy(
        f.store().record_path([7; 32]),
        f.store().record_path([8; 32]),
    )
    .unwrap();
    assert!(f.store().load([8; 32]).is_err());
    let mut value = serde_json::to_value(&w).unwrap();
    value["unknown"] = true.into();
    fs::write(
        f.store().record_path([7; 32]),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(f.store().load([7; 32]).is_err());
    fs::write(
        f.store().record_path([7; 32]),
        vec![0; MAX_RECORD as usize + 1],
    )
    .unwrap();
    assert!(f.store().load([7; 32]).is_err());
}
