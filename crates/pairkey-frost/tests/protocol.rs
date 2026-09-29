use ed25519_dalek::{Signature, VerifyingKey};
use pairkey_frost::{aggregate, register, verify_proof, Root, Signer};
use pairkey_types::{
    derive_public, AccountPath, Attempt, Commit, Namespace, Registration, Role, Scheme,
};
use rand_core::{OsRng, RngCore};
use std::sync::Arc;

fn namespace(id: u8) -> Namespace {
    Namespace {
        version: 1,
        scheme: Scheme::FrostEd25519,
        network: [1; 32],
        registry: [2; 32],
        derivation_authority: [3; 32],
        namespace_id: [id; 32],
        enclave_set: [5; 32],
    }
}
fn setup(id: u8) -> (Signer, Signer, Registration) {
    let a = Signer::new(Root::new([11; 32]), Role::A);
    let b = Signer::new(Root::new([22; 32]), Role::B);
    let ns = namespace(id);
    let reg = register(
        ns.clone(),
        &a.proof(&ns, &mut OsRng).unwrap(),
        &b.proof(&ns, &mut OsRng).unwrap(),
    )
    .unwrap();
    (a, b, reg)
}
fn attempt(reg: &Registration, path: u32, msg: &[u8]) -> Attempt {
    let mut random_id = [0; 32];
    OsRng.fill_bytes(&mut random_id);
    Attempt {
        authorization: Default::default(),
        commit: Commit::new(
            reg,
            [9; 32],
            AccountPath {
                destination: [8; 32],
                path: vec![path],
            },
            msg,
        )
        .unwrap(),
        random_id,
    }
}

#[test]
fn native_ed25519_many_namespaces_and_paths_fresh_repeat_signing() {
    for id in 0..3 {
        let (a, b, reg) = setup(id);
        for path in 0..3 {
            let msg = b"original message bytes, not their hash";
            let mut signatures = Vec::new();
            for _ in 0..2 {
                let at = attempt(&reg, path, msg);
                let rounds = [
                    a.begin(&reg, &at, msg, &mut OsRng).unwrap(),
                    b.begin(&reg, &at, msg, &mut OsRng).unwrap(),
                ];
                let responses = [
                    a.finish(&at, &rounds).unwrap(),
                    b.finish(&at, &rounds).unwrap(),
                ];
                let sig = aggregate(&reg, &at, msg, &rounds, &responses).unwrap();
                let vk =
                    VerifyingKey::from_bytes(&derive_public(&reg, &at.commit.account).unwrap())
                        .unwrap();
                vk.verify_strict(msg, &Signature::from_bytes(&sig)).unwrap();
                assert!(vk
                    .verify_strict(&at.commit.message_hash, &Signature::from_bytes(&sig))
                    .is_err());
                signatures.push(sig);
                assert!(a.finish(&at, &rounds).is_err());
            }
            assert_ne!(signatures[0], signatures[1]);
        }
    }
}

#[test]
fn altered_messages_proofs_roles_metadata_and_points_fail() {
    let (a, b, reg) = setup(8);
    let at = attempt(&reg, 1, b"approved");
    assert!(a.begin(&reg, &at, b"altered", &mut OsRng).is_err());
    let mut p = b.proof(&reg.namespace, &mut OsRng).unwrap();
    p.role = Role::A;
    assert!(verify_proof(&reg.namespace, &p).is_err());
    let mut p = b.proof(&reg.namespace, &mut OsRng).unwrap();
    p.response[0] ^= 1;
    assert!(verify_proof(&reg.namespace, &p).is_err());
    for bytes in [[0; 32], [255; 32], {
        let mut v = [0; 32];
        v[0] = 1;
        v
    }] {
        let mut bad = reg.clone();
        bad.public_shares[1] = bytes;
        assert!(bad.validate().is_err());
    }
    let (_, _, other) = setup(9);
    assert!(a.begin(&other, &at, b"approved", &mut OsRng).is_err());
    let impostor = Signer::new(Root::new([44; 32]), Role::A);
    assert!(impostor.begin(&reg, &at, b"approved", &mut OsRng).is_err());
    let mut bad = reg.clone();
    bad.public_key = other.public_key;
    assert!(bad.validate().is_err());
    let mut degenerate = reg.clone();
    degenerate.public_shares[1] = degenerate.public_shares[0];
    degenerate.public_key = degenerate.public_shares[0];
    assert!(degenerate.validate().is_err());
    assert!(a.begin(&degenerate, &at, b"approved", &mut OsRng).is_err());
}

#[test]
fn nonce_burns_on_invalid_transcript_and_only_one_concurrent_finish_succeeds() {
    let (a, b, reg) = setup(8);
    let a = Arc::new(a);
    let at = attempt(&reg, 1, b"approved");
    let rounds = [
        a.begin(&reg, &at, b"approved", &mut OsRng).unwrap(),
        b.begin(&reg, &at, b"approved", &mut OsRng).unwrap(),
    ];
    assert!(a.begin(&reg, &at, b"approved", &mut OsRng).is_err());
    let mut bad = rounds.clone();
    bad[1].attempt_digest[0] ^= 1;
    assert!(a.finish(&at, &bad).is_err());
    assert!(a.finish(&at, &rounds).is_err());
    let at = attempt(&reg, 1, b"approved");
    let rounds = [
        a.begin(&reg, &at, b"approved", &mut OsRng).unwrap(),
        b.begin(&reg, &at, b"approved", &mut OsRng).unwrap(),
    ];
    let joins: Vec<_> = (0..8)
        .map(|_| {
            let a = Arc::clone(&a);
            let at = at.clone();
            let rounds = rounds.clone();
            std::thread::spawn(move || a.finish(&at, &rounds).is_ok())
        })
        .collect();
    assert_eq!(
        joins
            .into_iter()
            .map(|j| usize::from(j.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

#[test]
fn restart_preserves_public_keys_and_aborts_nonce_state() {
    let (a, b, reg) = setup(7);
    let msg = b"approved";
    let at = attempt(&reg, 1, msg);
    let rounds = [
        a.begin(&reg, &at, msg, &mut OsRng).unwrap(),
        b.begin(&reg, &at, msg, &mut OsRng).unwrap(),
    ];
    drop(a);
    let replacement = Signer::new(Root::new([11; 32]), Role::A);
    assert!(replacement.finish(&at, &rounds).is_err());
    assert_eq!(
        replacement
            .proof(&reg.namespace, &mut OsRng)
            .unwrap()
            .public_share,
        reg.public_shares[0]
    );
    b.abort(&at);
    let at2 = attempt(&reg, 1, msg);
    let rounds = [
        replacement.begin(&reg, &at2, msg, &mut OsRng).unwrap(),
        b.begin(&reg, &at2, msg, &mut OsRng).unwrap(),
    ];
    let responses = [
        replacement.finish(&at2, &rounds).unwrap(),
        b.finish(&at2, &rounds).unwrap(),
    ];
    aggregate(&reg, &at2, msg, &rounds, &responses).unwrap();
}

#[test]
fn peer_cannot_fake_signature_share() {
    let (a, b, reg) = setup(1);
    let msg = b"approved";
    let at = attempt(&reg, 1, msg);
    let rounds = [
        a.begin(&reg, &at, msg, &mut OsRng).unwrap(),
        b.begin(&reg, &at, msg, &mut OsRng).unwrap(),
    ];
    let mut responses = [
        a.finish(&at, &rounds).unwrap(),
        b.finish(&at, &rounds).unwrap(),
    ];
    responses[1].share = vec![0; 32];
    assert!(aggregate(&reg, &at, msg, &rounds, &responses).is_err());
}

#[test]
fn canonical_derivation_vectors() {
    let (_, _, reg) = setup(1);
    let path = AccountPath {
        destination: [8; 32],
        path: vec![0, 1, 42],
    };
    let original = derive_public(&reg, &path).unwrap();
    let mut other = path.clone();
    other.destination[0] ^= 1;
    assert_ne!(original, derive_public(&reg, &other).unwrap());
    other = path.clone();
    other.path.push(0);
    assert_ne!(original, derive_public(&reg, &other).unwrap());
    // Fixed public vectors are checked independently of proof randomness.
    assert_eq!(
        reg.public_key,
        [
            160, 239, 72, 36, 150, 55, 113, 41, 193, 91, 31, 58, 217, 241, 2, 142, 149, 30, 144,
            104, 56, 28, 43, 196, 68, 187, 31, 58, 47, 28, 152, 2
        ]
    );
    assert_eq!(
        original,
        [
            6, 34, 113, 73, 35, 180, 169, 94, 95, 7, 243, 24, 218, 64, 212, 232, 78, 190, 48, 155,
            255, 111, 167, 31, 178, 28, 82, 67, 99, 206, 1, 84
        ]
    );
}

#[test]
fn reused_attempt_generations_are_distinguished_before_share_verification() {
    let (a, b, reg) = setup(1);
    let msg = b"approved";
    let at = attempt(&reg, 1, msg);
    let first = [
        a.begin(&reg, &at, msg, &mut OsRng).unwrap(),
        b.begin(&reg, &at, msg, &mut OsRng).unwrap(),
    ];
    let old_shares = [
        a.finish(&at, &first).unwrap(),
        b.finish(&at, &first).unwrap(),
    ];
    let second = [
        a.begin(&reg, &at, msg, &mut OsRng).unwrap(),
        b.begin(&reg, &at, msg, &mut OsRng).unwrap(),
    ];
    assert!(matches!(
        aggregate(&reg, &at, msg, &second, &old_shares),
        Err(pairkey_frost::Error::Attempt)
    ));
    let new_shares = [
        a.finish(&at, &second).unwrap(),
        b.finish(&at, &second).unwrap(),
    ];
    let mixed = [old_shares[0].clone(), new_shares[1].clone()];
    assert!(matches!(
        aggregate(&reg, &at, msg, &second, &mixed),
        Err(pairkey_frost::Error::Attempt)
    ));
    aggregate(&reg, &at, msg, &first, &old_shares).unwrap();
    aggregate(&reg, &at, msg, &second, &new_shares).unwrap();
    // There is no compatibility fallback for an unbound, old-format share.
    let mut old_wire = serde_json::to_value(&new_shares[0]).unwrap();
    old_wire
        .as_object_mut()
        .unwrap()
        .remove("transcript_digest");
    assert!(serde_json::from_value::<pairkey_frost::RoundTwo>(old_wire).is_err());
}

#[test]
fn duplicate_and_full_admission_reject_before_secret_reconstruction() {
    let (a, _, reg) = setup(1);
    let msg = b"approved";
    let mut attempts = Vec::new();
    for i in 0..64 {
        let at = attempt(&reg, i, msg);
        a.begin(&reg, &at, msg, &mut OsRng).unwrap();
        attempts.push(at);
    }
    // Invalid registration would fail validation/reconstruction if admission
    // reached that code. Neither refusal may construct a throwaway key package.
    let mut invalid = reg.clone();
    invalid.public_key = [0; 32];
    assert!(matches!(
        a.begin(&invalid, &attempts[0], msg, &mut OsRng),
        Err(pairkey_frost::Error::Attempt)
    ));
    let fresh = attempt(&reg, 65, msg);
    assert!(matches!(
        a.begin(&invalid, &fresh, msg, &mut OsRng),
        Err(pairkey_frost::Error::Capacity)
    ));
    a.abort(&attempts[0]);
    a.begin(&reg, &fresh, msg, &mut OsRng).unwrap();
}
