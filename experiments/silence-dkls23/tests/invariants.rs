use k256::{elliptic_curve::group::GroupEncoding, Scalar};
use pairkey_dkls23_research::{
    check_incident, digest, fresh, incident, point, public, reserve, Hello, Manifest, Request,
    Root, Route,
};
use sl_dkls23::keygen::Keyshare;
use sl_oblivious::soft_spoken::{ReceiverOTSeed, SenderOTSeed};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Barrier},
};

struct Fixture {
    dir: PathBuf,
    a: Root,
    b: Root,
    manifest: Manifest,
}
impl Fixture {
    fn new() -> Self {
        let name = fresh()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let dir = std::env::temp_dir().join(format!("pairkey-dkls-research-{name}"));
        fs::create_dir(&dir).unwrap();
        // Public synthetic roots, never product secrets.
        fs::write(dir.join("a"), [11; 32]).unwrap();
        fs::write(dir.join("b"), [22; 32]).unwrap();
        let a = Root::load(&dir.join("a")).unwrap();
        let b = Root::load(&dir.join("b")).unwrap();
        let id = [7; 32];
        let sa = a.derive(0, id).unwrap();
        let sb = b.derive(1, id).unwrap();
        let additive = [public(&sa), public(&sb)];
        let q = point(&additive[0]).unwrap() + point(&additive[1]).unwrap();
        let manifest = Manifest {
            version: 1,
            key_id: id,
            identities: [
                a.identity(0).verifying_key().to_bytes(),
                b.identity(1).verifying_key().to_bytes(),
            ],
            additive_public: additive,
            public_key: q.to_bytes().to_vec(),
            chain_code: [9; 32],
        };
        Self {
            dir,
            a,
            b,
            manifest,
        }
    }
    fn request(&self) -> Request {
        Request {
            route: Route::Direct,
            manifest: self.manifest.clone(),
            hellos: [
                Hello::new(&self.a, 0, self.manifest.key_id, [31; 32]).unwrap(),
                Hello::new(&self.b, 1, self.manifest.key_id, [32; 32]).unwrap(),
            ],
            entry: fresh(),
            attempt: fresh(),
            path: "m".into(),
            prehash: [6; 32],
            fault: None,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn deterministic_reconstruction_and_weighted_conversion_preserve_the_public_key() {
    let f = Fixture::new();
    f.manifest.validate().unwrap();
    let shares = f.manifest.stored_public().unwrap();
    assert_eq!(
        shares[0] * Scalar::from(2u64) - shares[1],
        point(&f.manifest.public_key).unwrap()
    );
    let again = Root::load(&f.dir.join("a")).unwrap();
    assert_eq!(
        public(&again.derive(0, f.manifest.key_id).unwrap()),
        f.manifest.additive_public[0]
    );
    assert_ne!(
        public(&again.derive(0, [8; 32]).unwrap()),
        f.manifest.additive_public[0]
    );
    assert!(f.manifest.check_local(&f.b, 0).is_err());
}
#[test]
fn invalid_points_aggregate_and_constant_polynomial_are_rejected() {
    let f = Fixture::new();
    let mut m = f.manifest.clone();
    m.public_key = vec![0; 33];
    assert!(m.validate().is_err());
    let mut m = f.manifest.clone();
    m.public_key = m.additive_public[0].clone();
    assert!(m.validate().is_err());
    let mut m = f.manifest.clone();
    let a = point(&m.additive_public[0]).unwrap();
    m.additive_public[1] = (-a * Scalar::from(2u64).invert().unwrap())
        .to_bytes()
        .to_vec();
    m.public_key = (a + point(&m.additive_public[1]).unwrap())
        .to_bytes()
        .to_vec();
    assert!(m.validate().is_err());
}
#[test]
fn boot_proofs_and_identity_signatures_reject_substitution() {
    let f = Fixture::new();
    let request = f.request();
    request.validate().unwrap();
    let mut hello = request.hellos[1].clone();
    hello.contribution = request.hellos[0].contribution.clone();
    assert!(hello.validate().is_err());
    let mut hello = request.hellos[0].clone();
    hello.ephemeral[0] ^= 1;
    assert!(hello.validate().is_err());
    let mut hello = request.hellos[0].clone();
    hello.proof_response[0] ^= 1;
    assert!(hello.validate().is_err());
    let mut r = request;
    r.hellos.swap(0, 1);
    assert!(r.validate().is_err());
}
#[test]
fn attempt_binding_includes_key_chain_code_payload_path_boot_and_entry() {
    let f = Fixture::new();
    let request = f.request();
    let expected = request.context();
    let mut r = request.clone();
    r.prehash[0] ^= 1;
    assert_ne!(r.context(), expected);
    let mut r = request.clone();
    r.path = "m/7/3".into();
    assert_ne!(r.context(), expected);
    let mut r = request.clone();
    r.manifest.chain_code[0] ^= 1;
    assert_ne!(r.context(), expected);
    let mut r = request.clone();
    r.manifest.key_id[0] ^= 1;
    assert!(r.validate().is_err());
    assert_ne!(r.context(), expected);
    let mut r = request.clone();
    r.hellos[0].boot[0] ^= 1;
    assert_ne!(r.context(), expected);
    let mut r = request;
    r.entry[0] ^= 1;
    assert_ne!(r.context(), expected);
}
#[test]
fn typed_constructor_rejects_wrong_secret_mapping_and_aggregate() {
    let f = Fixture::new();
    let contribution = f.a.derive(0, f.manifest.key_id).unwrap();
    let s = *contribution * Scalar::from(2u64).invert().unwrap();
    let shares = f.manifest.stored_public().unwrap();
    let q = point(&f.manifest.public_key).unwrap();
    let sender = SenderOTSeed::default();
    let receiver = ReceiverOTSeed::default();
    let build = |party, secret, points, key| {
        Keyshare::pairkey_research_two_party(
            party,
            secret,
            points,
            key,
            f.manifest.key_id,
            f.manifest.chain_code,
            [1; 32],
            &[2; 32],
            &sender,
            &receiver,
            &f.manifest.digest(),
        )
    };
    assert!(build(2, s, shares, q).is_none());
    assert!(build(0, s + Scalar::ONE, shares, q).is_none());
    assert!(build(0, s, shares, shares[0] + shares[1]).is_none());
    let package = build(0, s, shares, q).unwrap();
    assert_eq!(
        package.x_i_list().iter().map(|s| **s).collect::<Vec<_>>(),
        vec![Scalar::ONE, Scalar::from(2u64)]
    );
    assert_eq!(package.root_chain_code(), f.manifest.chain_code);
    // This intentionally demonstrates the boundary: byte-local validation
    // cannot establish remote OT correlations, even with zero seed fixtures.
    assert_eq!(package.public_key(), q);
}
#[test]
fn reservation_race_and_restart_allow_exactly_one_owner() {
    let f = Fixture::new();
    let dir = f.dir.join("entries");
    fs::create_dir(&dir).unwrap();
    let entry = fresh();
    let barrier = Arc::new(Barrier::new(8));
    let threads = (0..8)
        .map(|_| {
            let dir = dir.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                reserve(&dir, 0, entry, [1; 32]).is_ok()
            })
        })
        .collect::<Vec<_>>();
    let successes = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .filter(|b| *b)
        .count();
    assert_eq!(successes, 1);
    assert!(reserve(&dir, 0, entry, [2; 32]).is_err());
    reserve(&dir, 1, entry, [1; 32]).unwrap(); // matching peer has its own one-use lease
    reserve(&dir, 0, fresh(), [1; 32]).unwrap(); // fresh retry gets new material
}
#[test]
fn quarantine_is_durable_and_not_cleared_by_new_attempts() {
    let f = Fixture::new();
    let controls = f.dir.join("controls");
    check_incident(&controls, 0).unwrap();
    incident(&controls, 0, [1; 32]).unwrap();
    incident(&controls, 0, [2; 32]).unwrap();
    assert!(check_incident(&controls, 0).is_err());
    check_incident(&controls, 1).unwrap();
    assert_eq!(fs::read(controls.join("0.quarantined")).unwrap(), [1; 32]);
}
#[test]
fn external_ledger_detects_volatile_replay_but_ledger_rollback_is_not_prevented() {
    let f = Fixture::new();
    let dir = f.dir.join("snapshot-test");
    let entry = fresh();
    reserve(&dir, 0, entry, [1; 32]).unwrap();
    assert!(reserve(&dir, 0, entry, [1; 32]).is_err());
    // Deliberately model a hostile rewind of the public authority. This test
    // establishes a limitation, not a snapshot-resistance claim.
    fs::remove_dir_all(&dir).unwrap();
    reserve(&dir, 0, entry, [1; 32]).unwrap();
}
#[test]
fn manifest_chain_code_is_part_of_the_stable_public_pin() {
    let f = Fixture::new();
    let mut changed = f.manifest.clone();
    changed.chain_code[0] ^= 1;
    changed.validate().unwrap();
    assert_ne!(changed, f.manifest);
    assert_ne!(changed.digest(), f.manifest.digest());
    assert_ne!(
        digest(b"public-pin", &changed),
        digest(b"public-pin", &f.manifest)
    );
}

#[test]
fn failure_policy_covers_every_native_error_without_accusing_transport() {
    use pairkey_dkls23_research::lifecycle::{Action, Failure, FailureKind};
    use sl_dkls23::{keygen::KeygenError as K, sign::SignError as S};
    let peer = [19; 32];
    for error in [
        S::InvalidCommitment,
        S::InvalidDigest,
        S::InvalidMessage,
        S::AbortProtocolAndBanParty(1),
    ] {
        let f = Failure::native_sign(&error, peer);
        assert_eq!(f.action, Action::QuarantinePeer);
        assert_eq!(f.peer, Some(peer));
    }
    for error in [S::FailedCheck("fixture"), S::K256Error, S::InvalidPreSign] {
        let f = Failure::native_sign(&error, peer);
        assert_eq!(f.action, Action::FreezeConfiguration);
        assert!(f.peer.is_none());
    }
    for error in [
        S::MissingMessage,
        S::SendMessage,
        S::InvalidFinalSessionID,
        S::AbortProtocol(1),
    ] {
        assert_eq!(Failure::native_sign(&error, peer).action, Action::Burn);
    }
    for error in [
        K::InvalidMessage,
        K::InvalidCommitmentHash,
        K::InvalidDLogProof,
        K::InvalidPolynomialPoint,
        K::BigFVecMismatch,
        K::PPRFError("fixture"),
    ] {
        assert_eq!(
            Failure::native_migration(&error, peer).action,
            Action::QuarantinePeer
        );
    }
    for error in [
        K::InvalidKeyRefresh,
        K::InvalidQuorumChange,
        K::NotUniqueXiValues,
        K::FailedFelmanVerify,
        K::PublicKeyMismatch,
        K::BigSMismatch,
    ] {
        assert_eq!(
            Failure::native_migration(&error, peer).action,
            Action::FreezeConfiguration
        );
    }
    for error in [K::MissingMessage, K::SendMessage, K::AbortProtocol(1)] {
        assert_eq!(Failure::native_migration(&error, peer).action, Action::Burn);
    }
    assert_eq!(
        Failure::native_sign(&S::AbortProtocol(1), peer).kind,
        FailureKind::PeerAbort
    );
}
#[test]
fn diagnostics_survive_exit_closed_pipe_and_reversed_abort_order() {
    use pairkey_dkls23_research::lifecycle::{Failure, FailureKind, Phase, Terminals};
    for reversed in [false, true] {
        let abort = Failure::burn(Phase::Signing, FailureKind::PeerAbort, "peer abort");
        let mut origin = Failure::violation(Phase::Signing, [5; 32], "originator proof failure");
        origin.incident_persisted = true;
        let mut t = Terminals::default();
        t.closed(1);
        t.pipe(1, &std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        if reversed {
            t.failure(0, origin);
            t.failure(1, abort);
        } else {
            t.failure(1, abort);
            t.failure(0, origin);
        }
        t.closed(0);
        assert!(t.closed.iter().all(|b| *b));
        assert!(t.diagnostic().contains("originator proof failure"));
        assert!(t.diagnostic().contains("persisted=true"));
    }
}
#[test]
fn scope_spans_wallets_and_shared_gate_stops_active_and_unused_entries() {
    use pairkey_dkls23_research::lifecycle::{scope, scope_dir, ReleaseGate};
    let f = Fixture::new();
    let mut other = f.manifest.clone();
    other.key_id = [8; 32];
    other.chain_code = [3; 32];
    assert_eq!(scope(&f.manifest), scope(&other));
    other.identities.swap(0, 1);
    assert_ne!(scope(&f.manifest), scope(&other));
    let dir = scope_dir(&f.dir.join("controls"), &f.manifest);
    let gate = ReleaseGate::new(dir.clone(), 0);
    let active = ReleaseGate::new(dir.clone(), 0); // independently acquired same-process authority
    let unused = gate.clone();
    active.release(|| Ok(())).unwrap();
    gate.publish([3; 32]).unwrap();
    assert!(active.release(|| Ok(())).is_err());
    assert!(unused.release(|| Ok(())).is_err());
    assert!(ReleaseGate::new(dir, 0).release(|| Ok(())).is_err());
}
#[test]
fn publication_failure_keeps_local_gate_closed() {
    use pairkey_dkls23_research::lifecycle::ReleaseGate;
    let f = Fixture::new();
    let file = f.dir.join("not-a-directory");
    fs::write(&file, []).unwrap();
    let gate = ReleaseGate::new(file, 0);
    assert!(gate.publish([3; 32]).is_err());
    assert!(gate.release(|| Ok(())).is_err());
}
#[test]
fn pool_spec_ownership_rejects_substitution_and_restart_reuse() {
    use pairkey_dkls23_research::lifecycle::ReservedEntry;
    let f = Fixture::new();
    let dir = f.dir.join("pool-spec");
    let p = [4; 32];
    let c = [5; 32];
    let e = [6; 32];
    ReservedEntry::reserve(&dir, 0, e, p, c)
        .unwrap()
        .consume(e, p, c)
        .unwrap();
    assert!(ReservedEntry::reserve(&dir, 0, e, p, c).is_err());
    for (entry, pre, consume) in [([7; 32], p, c), (e, [8; 32], c), (e, p, [9; 32])] {
        let fresh_entry = fresh();
        let reserved = ReservedEntry::reserve(&dir, 0, fresh_entry, p, c).unwrap();
        assert!(reserved
            .consume(if entry == e { fresh_entry } else { entry }, pre, consume)
            .is_err());
        assert!(ReservedEntry::reserve(&dir, 0, fresh_entry, p, c).is_err());
    }
    let fresh_entry = fresh();
    {
        let _cancelled = ReservedEntry::reserve(&dir, 0, fresh_entry, p, c).unwrap();
    }
    assert!(ReservedEntry::reserve(&dir, 0, fresh_entry, p, c).is_err()); // cancellation burns
}

#[cfg(not(feature = "research-faults"))]
#[test]
fn default_build_rejects_fault_injection() {
    let f = Fixture::new();
    let mut request = f.request();
    request.fault = Some("bad-ot".into());
    let error = request.validate().unwrap_err();
    assert!(error.to_string().contains("requires research-faults"));
}
