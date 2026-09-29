//! COMMIT, SESSION, credential and SIMULATE authorization over an injected chain observation.
//! RPC correctness and the observation's authenticated clock are adapter assumptions.
use borsh::BorshDeserialize;
use pair_registry::{
    namespace_address, request_address, set_address, EnclaveSet, NamespaceRecord, RequestRecord,
};
use pairkey_types::{derive_public, Attempt, Registration, VERSION};
use solana_program::pubkey::Pubkey;
use std::sync::atomic::{AtomicU64, Ordering};

/// Public in-memory fence, not signing-key state. A verified negative control
/// requires a strictly later finalized observation before active service resumes.
#[derive(Default)]
pub struct ControlFence {
    minimum_active_slot: AtomicU64,
}
impl ControlFence {
    pub fn minimum_slot(&self) -> u64 {
        self.minimum_active_slot.load(Ordering::SeqCst)
    }
    pub fn observe_inactive(&self, slot: u64) -> Result<(), Error> {
        let next = slot.checked_add(1).ok_or(Error::State)?;
        self.minimum_active_slot.fetch_max(next, Ordering::SeqCst);
        Ok(())
    }
    pub fn check_active(&self, slot: u64) -> Result<(), Error> {
        if slot < self.minimum_slot() {
            Err(Error::State)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("incorrect account owner, PDA, record, or payload")]
    Authorization,
    #[error("inactive namespace or enclave set")]
    Inactive,
    #[error("untrusted, nonfinalized, or stale observation")]
    State,
}
#[derive(Clone)]
pub struct ObservedAccount {
    pub address: Pubkey,
    pub owner: Pubkey,
    pub data: Vec<u8>,
}
pub mod access;
pub mod operation;
mod policy;
pub use policy::{
    code_hash, immutable_loader, simulation_input, ExecutableObservation, Freshness,
    SimulationObservation,
};

pub struct Observation {
    pub policy: Option<ObservedAccount>,
    pub session: Option<ObservedAccount>,
    pub simulation: Option<SimulationObservation>,
    pub network: [u8; 32],
    pub finalized: bool,
    pub slot: u64,
    pub block_time: i64,
    pub observed_at: i64,
    pub provider_domain: String,
    pub set: ObservedAccount,
    pub namespace: ObservedAccount,
    pub request: ObservedAccount,
}
pub struct Trust {
    pub registry: Pubkey,
    pub network: [u8; 32],
    pub enclave_set: Pubkey,
    pub identity_keys: [[u8; 32]; 2],
    pub set_governor: [u8; 32],
    pub provider_domain: String,
    pub allow_development: bool,
    pub max_observation_age_secs: i64,
    pub max_chain_lag_secs: i64,
}
pub trait ChainView {
    fn observe(&self, request: Pubkey) -> Result<Observation, Error>;
}
pub trait Clock {
    fn now(&self) -> i64;
}
/// Optional encrypted setup is reserved for later backends; FROST requires none.
pub struct BackendSetup {
    pub public_registration: Registration,
    pub encrypted_setup: Option<Vec<u8>>,
}
fn decode<T: BorshDeserialize>(account: &ObservedAccount, owner: &Pubkey) -> Result<T, Error> {
    if account.owner != *owner || account.data.len() > 1600 {
        return Err(Error::Authorization);
    }
    T::try_from_slice(&account.data).map_err(|_| Error::Authorization)
}
fn authorize_impl(
    trust: &Trust,
    observation: &Observation,
    attempt: &Attempt,
    message: &[u8],
    now: i64,
    minimum_slot: u64,
    check_simulation: bool,
) -> Result<Registration, Error> {
    if trust.max_observation_age_secs <= 0
        || trust.max_chain_lag_secs <= 0
        || !observation.finalized
        || observation.network != trust.network
        || observation.provider_domain != trust.provider_domain
        || observation.slot < minimum_slot
        || observation.observed_at > now
        || now.saturating_sub(observation.observed_at) > trust.max_observation_age_secs
        || observation.block_time > now.saturating_add(5)
        || now.saturating_sub(observation.block_time) > trust.max_chain_lag_secs
    {
        return Err(Error::State);
    }
    let set: EnclaveSet = decode(&observation.set, &trust.registry)?;
    let ns: NamespaceRecord = decode(&observation.namespace, &trust.registry)?;

    if observation.set.address != trust.enclave_set
        || observation.set.address
            != set_address(&trust.registry, &ns.registration.namespace.enclave_set).0
        || set.set_id != ns.registration.namespace.enclave_set
        || set.identities != trust.identity_keys
        || set.version != VERSION
        || set.governor != trust.set_governor
        || set.development != trust.allow_development
    {
        return Err(Error::Authorization);
    }
    if ns.registration.namespace.registry != trust.registry.to_bytes()
        || ns.registration.namespace.network != trust.network
        || observation.namespace.address != namespace_address(&trust.registry, &ns.registration).0
    {
        return Err(Error::Authorization);
    }
    attempt
        .commit
        .authorize(&ns.registration, message)
        .map_err(|_| Error::Authorization)?;
    policy::authorize_policy(
        trust,
        observation,
        attempt,
        message,
        now,
        &ns,
        check_simulation,
    )?;
    // Only well-formed, correctly bound records may advance a negative-control fence.
    if set.retired || ns.frozen {
        return Err(Error::Inactive);
    }
    Ok(ns.registration)
}

/// Prepare verifies all authority before a worker constructs its own simulation call.
pub fn prepare(
    trust: &Trust,
    observation: &Observation,
    attempt: &Attempt,
    message: &[u8],
    now: i64,
    minimum_slot: u64,
) -> Result<Registration, Error> {
    authorize_impl(
        trust,
        observation,
        attempt,
        message,
        now,
        minimum_slot,
        false,
    )
}
pub fn authorize(
    trust: &Trust,
    observation: &Observation,
    attempt: &Attempt,
    message: &[u8],
    now: i64,
    minimum_slot: u64,
) -> Result<Registration, Error> {
    authorize_impl(
        trust,
        observation,
        attempt,
        message,
        now,
        minimum_slot,
        true,
    )
}
