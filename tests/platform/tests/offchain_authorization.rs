mod support;
use ed25519_dalek::{Signer, SigningKey};
use pairkey_core::{Observation, ObservedAccount, Trust};
use pairkey_types::{approval::*, policy::Authorization, Attempt, Commit, Registration};

fn fixture() -> (Trust, Observation, Registration, Attempt, Proof, Vec<u8>) {
    let (trust, mut observation, old, payload) = support::fixture();
    let ns: pair_registry::NamespaceRecord =
        borsh::from_slice(&observation.namespace.data).unwrap();
    let mut reg = ns.registration;
    let owner = SigningKey::from_bytes(&[42; 32]);
    reg.namespace.derivation_authority = owner.verifying_key().to_bytes();
    let commit = Commit::new(&reg, old.commit.request_id, old.commit.account, &payload).unwrap();
    observation.namespace = ObservedAccount {
        address: pair_registry::namespace_address(&trust.registry, &reg).0,
        owner: solana_sdk::system_program::id(),
        data: vec![],
    };
    observation.request.data.clear();
    let request = Request {
        version: APPROVAL_VERSION,
        identity: Identity::Account {
            public_key: reg.namespace.derivation_authority,
        },
        commit: commit.clone(),
        policy_revision: 0,
        policy_digest: Rules::default().digest(),
        issued_at: 1000,
        expires_at: 1100,
    };
    let proof = Proof::Account {
        signature: owner.sign(&request.signing_message()).to_bytes().to_vec(),
    };
    let authorization = Authorization::offchain(&Approval {
        request,
        proof: proof.clone(),
    });
    (
        trust,
        observation,
        reg,
        Attempt {
            commit,
            authorization,
            random_id: [6; 32],
        },
        proof,
        payload,
    )
}
fn rules(trust: &Trust, observation: &mut Observation, reg: &Registration, rules: Rules) {
    observation.rules = Some(ObservedAccount {
        address: pair_registry::approval::rules_address(&trust.registry, &reg.namespace.digest()).0,
        owner: trust.registry,
        data: borsh::to_vec(&pair_registry::approval::RulesRecord {
            namespace_digest: reg.namespace.digest(),
            rules,
        })
        .unwrap(),
    });
}
fn check(
    t: &Trust,
    o: &Observation,
    r: &Registration,
    a: &Attempt,
    p: &Proof,
    m: &[u8],
) -> Result<(), pairkey_core::Error> {
    pairkey_core::approval::authorize(t, o, r, a, m, p, None, 1000, 100)
}

#[test]
fn both_signers_require_authentication_and_fresh_chain_state_without_registration() {
    let (t, mut o, r, a, p, m) = fixture();
    check(&t, &o, &r, &a, &p, &m).unwrap();
    let mut other = t;
    other.provider_domain = "B-local".into();
    assert!(check(&other, &o, &r, &a, &p, &m).is_err());
    o.provider_domain = "B-local".into();
    check(&other, &o, &r, &a, &p, &m).unwrap();
    let mut bad = p.clone();
    if let Proof::Account { signature } = &mut bad {
        signature[0] ^= 1;
    }
    assert!(check(&other, &o, &r, &a, &bad, &m).is_err());
    let mut changed = a.clone();
    changed.commit.request_id[0] ^= 1;
    assert!(check(&other, &o, &r, &changed, &p, &m).is_err());
    o.block_time = 900;
    assert!(check(&other, &o, &r, &a, &p, &m).is_err());
    o.block_time = 999;
    o.finalized = false;
    assert!(check(&other, &o, &r, &a, &p, &m).is_err());
    o.finalized = true;
    o.namespace.owner = other.registry;
    assert!(check(&other, &o, &r, &a, &p, &m).is_err());
}

#[test]
fn existing_freeze_and_retirement_still_apply_to_owner_signed_approvals() {
    let (t, mut o, r, a, p, m) = fixture();
    o.namespace.owner = t.registry;
    let mut ns = pair_registry::NamespaceRecord {
        registration: r.clone(),
        controller: r.namespace.derivation_authority,
        frozen: false,
    };
    o.namespace.data = borsh::to_vec(&ns).unwrap();
    check(&t, &o, &r, &a, &p, &m).unwrap();
    ns.frozen = true;
    o.namespace.data = borsh::to_vec(&ns).unwrap();
    assert!(matches!(
        check(&t, &o, &r, &a, &p, &m),
        Err(pairkey_core::Error::Inactive)
    ));
    ns.frozen = false;
    o.namespace.data = borsh::to_vec(&ns).unwrap();
    let mut set: pair_registry::EnclaveSet = borsh::from_slice(&o.set.data).unwrap();
    set.retired = true;
    o.set.data = borsh::to_vec(&set).unwrap();
    assert!(matches!(
        check(&t, &o, &r, &a, &p, &m),
        Err(pairkey_core::Error::Inactive)
    ));
}

#[test]
fn old_custom_policy_needs_explicit_owner_rules_and_stale_approvals_cannot_opt_in() {
    let (t, mut o, r, mut a, mut p, m) = fixture();
    o.policy = Some(ObservedAccount {
        address: pair_registry::policy_address(&t.registry, &o.namespace.address).0,
        owner: t.registry,
        data: borsh::to_vec(&pair_registry::PolicyRecord {
            namespace_address: o.namespace.address.to_bytes(),
            policy: pairkey_types::policy::Policy {
                version: 1,
                ..Default::default()
            },
        })
        .unwrap(),
    });
    assert!(check(&t, &o, &r, &a, &p, &m).is_err());
    let current = Rules {
        revision: 1,
        ..Default::default()
    };
    rules(&t, &mut o, &r, current.clone());
    assert!(check(&t, &o, &r, &a, &p, &m).is_err());
    let mut request = a.authorization.offchain_request().unwrap().clone();
    request.policy_revision = 1;
    request.policy_digest = current.digest();
    p = Proof::Account {
        signature: SigningKey::from_bytes(&[42; 32])
            .sign(&request.signing_message())
            .to_bytes()
            .to_vec(),
    };
    a.authorization = Authorization::offchain(&Approval {
        request,
        proof: p.clone(),
    });
    check(&t, &o, &r, &a, &p, &m).unwrap();
    o.rules.as_mut().unwrap().address = solana_sdk::pubkey::Pubkey::new_unique();
    assert!(check(&t, &o, &r, &a, &p, &m).is_err());
}

#[test]
fn legacy_commit_cannot_bypass_new_persistent_restrictions() {
    let (t, mut o, a, m) = support::fixture();
    pairkey_core::authorize(&t, &o, &a, &m, 1000, 100).unwrap();
    let ns: pair_registry::NamespaceRecord = borsh::from_slice(&o.namespace.data).unwrap();
    rules(
        &t,
        &mut o,
        &ns.registration,
        Rules {
            revision: 1,
            disabled: true,
            ..Default::default()
        },
    );
    assert!(pairkey_core::authorize(&t, &o, &a, &m, 1000, 100).is_err());
}
