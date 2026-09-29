use pair_registry::{request_address, EnclaveSet, NamespaceRecord, RequestRecord};
use pairkey_core::authorize;
use solana_sdk::pubkey::Pubkey;

mod support;
use support::fixture;

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
