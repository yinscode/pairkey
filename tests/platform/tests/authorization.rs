use pair_registry::{
    namespace_address, request_address, set_address, EnclaveSet, NamespaceRecord, RequestRecord,
};
use pairkey_core::{authorize, Observation, ObservedAccount, Trust};
use pairkey_frost::{register, Root, Signer};
use pairkey_types::{derive_public, AccountPath, Attempt, Commit, Namespace, Role, Scheme};
use rand_core::OsRng;
use solana_sdk::pubkey::Pubkey;

fn fixture() -> (Trust, Observation, Attempt, Vec<u8>) {
    let program = pair_registry::id();
    let ns = Namespace {
        version: 1,
        scheme: Scheme::FrostEd25519,
        network: [1; 32],
        registry: program.to_bytes(),
        derivation_authority: [3; 32],
        namespace_id: [4; 32],
        enclave_set: [5; 32],
    };
    let a = Signer::new(Root::new([11; 32]), Role::A);
    let b = Signer::new(Root::new([22; 32]), Role::B);
    let reg = register(
        ns.clone(),
        &a.proof(&ns, &mut OsRng).unwrap(),
        &b.proof(&ns, &mut OsRng).unwrap(),
    )
    .unwrap();
    let message = b"original approved bytes".to_vec();
    let commit = Commit::new(
        &reg,
        [7; 32],
        AccountPath {
            destination: [8; 32],
            path: vec![1],
        },
        &message,
    )
    .unwrap();
    let namespace = namespace_address(&program, &reg).0;
    let set = set_address(&program, &ns.enclave_set).0;
    let request = request_address(&program, &namespace, &commit.request_id).0;
    let identities = [[31; 32], [32; 32]];
    let observation = Observation {
        network: ns.network,
        finalized: true,
        slot: 100,
        block_time: 999,
        observed_at: 1000,
        provider_domain: "A-local".into(),
        set: ObservedAccount {
            address: set,
            owner: program,
            data: borsh::to_vec(&EnclaveSet {
                version: 1,
                set_id: ns.enclave_set,
                governor: [9; 32],
                identities,
                retired: false,
                development: true,
            })
            .unwrap(),
        },
        namespace: ObservedAccount {
            address: namespace,
            owner: program,
            data: borsh::to_vec(&NamespaceRecord {
                registration: reg.clone(),
                controller: [3; 32],
                frozen: false,
            })
            .unwrap(),
        },
        request: ObservedAccount {
            address: request,
            owner: program,
            data: borsh::to_vec(&RequestRecord {
                namespace_address: namespace.to_bytes(),
                commit: commit.clone(),
                derived_key: derive_public(&reg, &commit.account).unwrap(),
            })
            .unwrap(),
        },
    };
    let trust = Trust {
        registry: program,
        network: ns.network,
        enclave_set: set,
        identity_keys: identities,
        set_governor: [9; 32],
        provider_domain: "A-local".into(),
        allow_development: true,
        max_observation_age_secs: 3,
        max_chain_lag_secs: 30,
    };
    (
        trust,
        observation,
        Attempt {
            commit,
            random_id: [6; 32],
        },
        message,
    )
}

#[test]
fn independent_authorization_rejects_forgery_staleness_and_invalid_identity() {
    let (mut trust, mut o, at, bytes) = fixture();
    authorize(&trust, &o, &at, &bytes, 1000, 100).unwrap();
    assert!(authorize(&trust, &o, &at, b"altered", 1000, 100).is_err());
    o.request.owner = Pubkey::new_unique();
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
    o.request.owner = trust.registry;
    o.request.address = Pubkey::new_unique();
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
    o.request.address =
        request_address(&trust.registry, &o.namespace.address, &at.commit.request_id).0;
    o.finalized = false;
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
    o.finalized = true;
    assert!(authorize(&trust, &o, &at, &bytes, 1004, 100).is_err());
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 101).is_err());
    o.block_time = 900;
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
    o.block_time = 999;
    o.provider_domain = "B-local".into();
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
    o.provider_domain = "A-local".into();
    trust.allow_development = false;
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
}

#[test]
fn freeze_and_retirement_refuse_then_finalized_resumption_works() {
    let (trust, mut o, at, bytes) = fixture();
    let mut ns: NamespaceRecord = borsh::from_slice(&o.namespace.data).unwrap();
    ns.frozen = true;
    o.namespace.data = borsh::to_vec(&ns).unwrap();
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
    ns.frozen = false;
    o.namespace.data = borsh::to_vec(&ns).unwrap();
    let mut set: EnclaveSet = borsh::from_slice(&o.set.data).unwrap();
    set.retired = true;
    o.set.data = borsh::to_vec(&set).unwrap();
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
    set.retired = false;
    o.set.data = borsh::to_vec(&set).unwrap();
    o.slot += 1;
    authorize(&trust, &o, &at, &bytes, 1000, 101).unwrap();
}

#[test]
fn altered_chain_records_and_unbounded_encodings_fail_closed() {
    let (trust, mut o, at, bytes) = fixture();
    let original = o.request.data.clone();
    let mut req: RequestRecord = borsh::from_slice(&original).unwrap();
    req.derived_key[0] ^= 1;
    o.request.data = borsh::to_vec(&req).unwrap();
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
    o.request.data = original;
    o.request.data.push(0);
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
    o.request.data.resize(2000, 0);
    assert!(authorize(&trust, &o, &at, &bytes, 1000, 100).is_err());
}

#[test]
fn confirmed_negative_control_blocks_old_and_concurrently_started_views() {
    let (trust, mut observation, attempt, message) = fixture();
    let fence = pairkey_core::ControlFence::default();
    let started_slot = observation.slot;
    authorize(&trust, &observation, &attempt, &message, 1000, 0).unwrap();
    let mut ns: NamespaceRecord = borsh::from_slice(&observation.namespace.data).unwrap();
    ns.frozen = true;
    observation.namespace.data = borsh::to_vec(&ns).unwrap();
    observation.slot = started_slot + 1;
    assert!(matches!(
        authorize(&trust, &observation, &attempt, &message, 1000, 0),
        Err(pairkey_core::Error::Inactive)
    ));
    fence.observe_inactive(observation.slot).unwrap();
    // A read started before the freeze cannot finish using its old active view.
    assert!(fence.check_active(started_slot).is_err());
    ns.frozen = false;
    observation.namespace.data = borsh::to_vec(&ns).unwrap();
    // Conflicting active data at the same finalized slot is not resumption.
    assert!(authorize(
        &trust,
        &observation,
        &attempt,
        &message,
        1000,
        fence.minimum_slot()
    )
    .is_err());
    assert!(fence.check_active(observation.slot).is_err());
    observation.slot += 1;
    authorize(
        &trust,
        &observation,
        &attempt,
        &message,
        1000,
        fence.minimum_slot(),
    )
    .unwrap();
    fence.check_active(observation.slot).unwrap();
    // A still older negative report cannot move the fence backwards.
    fence.observe_inactive(started_slot).unwrap();
    assert!(fence.check_active(started_slot + 1).is_err());
}

#[test]
fn malformed_negative_record_is_not_a_confirmed_control_and_slot_overflow_refuses() {
    let (trust, mut observation, attempt, message) = fixture();
    let mut ns: NamespaceRecord = borsh::from_slice(&observation.namespace.data).unwrap();
    ns.frozen = true;
    observation.namespace.data = borsh::to_vec(&ns).unwrap();
    observation.request.address = Pubkey::new_unique();
    assert!(matches!(
        authorize(&trust, &observation, &attempt, &message, 1000, 0),
        Err(pairkey_core::Error::Authorization)
    ));
    let fence = pairkey_core::ControlFence::default();
    assert!(fence.observe_inactive(u64::MAX).is_err());
}
