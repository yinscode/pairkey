use super::*;
use pair_registry::{policy_address, session_address, PolicyRecord, SessionRecord};
use pairkey_types::{
    digest,
    policy::{simulation_state, Policy, SimulationInput, SimulationOutput},
};
use std::sync::Mutex;

/// Monotonic progress lease. Re-reading a stalled slot cannot extend its lease.
#[derive(Default)]
pub struct Freshness(Mutex<Option<(u64, i64, u64)>>);
impl Freshness {
    pub fn check(
        &self,
        slot: u64,
        block_time: i64,
        monotonic_ms: u64,
        lease_ms: u64,
    ) -> Result<(), Error> {
        if lease_ms == 0 {
            return Err(Error::State);
        }
        let mut previous = self.0.lock().map_err(|_| Error::State)?;
        match *previous {
            Some((old_slot, old_time, first_seen)) => {
                if monotonic_ms < first_seen {
                    return Err(Error::State);
                }
                if slot <= old_slot {
                    if (slot == old_slot && block_time != old_time)
                        || (slot < old_slot && block_time > old_time)
                        || monotonic_ms.saturating_sub(first_seen) >= lease_ms
                    {
                        return Err(Error::State);
                    }
                    // An overlapping earlier view is permitted within the same lease;
                    // it never extends progress and is still subject to control/version fences.
                } else {
                    if block_time < old_time {
                        return Err(Error::State);
                    }
                    *previous = Some((slot, block_time, monotonic_ms));
                }
            }
            None => *previous = Some((slot, block_time, monotonic_ms)),
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct ExecutableObservation {
    pub program: Pubkey,
    pub owner: Pubkey,
    pub executable: bool,
    pub code: Vec<u8>,
    pub program_data: Option<ObservedAccount>,
}
impl ExecutableObservation {
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        use solana_sdk::bpf_loader_upgradeable::{self, UpgradeableLoaderState};
        if !self.executable {
            return Err(Error::Authorization);
        }
        if immutable_loader(self.owner) {
            if self.program_data.is_some() || self.code.is_empty() {
                return Err(Error::Authorization);
            }
            return Ok(code_hash(&self.code));
        }
        if self.owner != bpf_loader_upgradeable::id()
            || self.code.len() != UpgradeableLoaderState::size_of_program()
        {
            return Err(Error::Authorization);
        }
        let state: UpgradeableLoaderState =
            bincode::deserialize(&self.code).map_err(|_| Error::Authorization)?;
        let UpgradeableLoaderState::Program {
            programdata_address,
        } = state
        else {
            return Err(Error::Authorization);
        };
        let data = self.program_data.as_ref().ok_or(Error::Authorization)?;
        let expected =
            Pubkey::find_program_address(&[self.program.as_ref()], &bpf_loader_upgradeable::id()).0;
        if data.address != programdata_address
            || data.address != expected
            || data.owner != bpf_loader_upgradeable::id()
            || data.data.len() <= UpgradeableLoaderState::size_of_programdata_metadata()
        {
            return Err(Error::Authorization);
        }
        let metadata: UpgradeableLoaderState = bincode::deserialize(
            &data.data[..UpgradeableLoaderState::size_of_programdata_metadata()],
        )
        .map_err(|_| Error::Authorization)?;
        if !matches!(
            metadata,
            UpgradeableLoaderState::ProgramData {
                upgrade_authority_address: None,
                ..
            }
        ) {
            return Err(Error::Authorization);
        }
        Ok(code_hash(&data.data))
    }
}
#[derive(Clone)]
pub struct SimulationObservation {
    pub slot: u64,
    pub program: ExecutableObservation,
    pub output: SimulationOutput,
}
pub fn immutable_loader(owner: Pubkey) -> bool {
    owner == solana_program::bpf_loader::id()
        || owner == solana_program::bpf_loader_deprecated::id()
}
pub fn code_hash(bytes: &[u8]) -> [u8; 32] {
    digest(b"pairkey/immutable-program/v1", &bytes)
}
fn policy(o: &Observation, registry: &Pubkey) -> Result<Policy, Error> {
    match &o.policy {
        Some(info) => {
            let record: PolicyRecord = decode(info, registry)?;
            if info.address != policy_address(registry, &o.namespace.address).0
                || record.namespace_address != o.namespace.address.to_bytes()
            {
                return Err(Error::Authorization);
            }
            record.policy.validate().map_err(|_| Error::Authorization)?;
            Ok(record.policy)
        }
        None => Ok(Policy::default()),
    }
}
pub fn simulation_input(
    o: &Observation,
    attempt: &Attempt,
    message: &[u8],
) -> Result<Option<SimulationInput>, Error> {
    let ns: NamespaceRecord = decode(&o.namespace, &o.namespace.owner)?;
    let p = policy(o, &o.namespace.owner)?;
    if p.simulation.is_none() {
        return Ok(None);
    }
    let transfer = operation::parse(&ns.registration, &attempt.commit.account, message)?;
    Ok(Some(SimulationInput {
        commit_digest: attempt.commit.digest(),
        policy_digest: p.digest(),
        authorization_digest: digest(b"pairkey/authorization/v1", &attempt.authorization),
        state_digest: simulation_state(
            &o.set.data,
            &o.namespace.data,
            &o.policy.as_ref().ok_or(Error::Authorization)?.data,
        ),
        recipient: transfer.recipient,
        lamports: transfer.lamports,
    }))
}
pub(super) fn authorize_policy(
    trust: &Trust,
    o: &Observation,
    attempt: &Attempt,
    message: &[u8],
    now: i64,
    ns: &NamespaceRecord,
    check_simulation: bool,
) -> Result<(), Error> {
    let p = policy(o, &trust.registry)?;
    let auth = &attempt.authorization;
    if auth.policy_version != p.version {
        return Err(Error::State);
    }
    if p.require_commit || auth.session_id.is_none() {
        let req: RequestRecord = decode(&o.request, &trust.registry)?;
        if o.request.address
            != request_address(
                &trust.registry,
                &o.namespace.address,
                &attempt.commit.request_id,
            )
            .0
            || req.namespace_address != o.namespace.address.to_bytes()
            || req.commit != attempt.commit
            || req.derived_key
                != derive_public(&ns.registration, &req.commit.account)
                    .map_err(|_| Error::Authorization)?
        {
            return Err(Error::Authorization);
        }
    }
    if p.require_session && auth.session_id.is_none() {
        return Err(Error::Authorization);
    }
    if let Some(id) = auth.session_id {
        if !p.allow_session {
            return Err(Error::Authorization);
        }
        let info = o.session.as_ref().ok_or(Error::Authorization)?;
        let record: SessionRecord = decode(info, &trust.registry)?;
        let g = &record.grant;
        g.validate().map_err(|_| Error::Authorization)?;
        if info.address != session_address(&trust.registry, &o.namespace.address, &id).0
            || record.namespace_address != o.namespace.address.to_bytes()
            || g.session_id != id
            || g.policy_version != p.version
            || g.account != attempt.commit.account
        {
            return Err(Error::Authorization);
        }
        let proof = auth.session_proof.as_ref().ok_or(Error::Authorization)?;
        access::verify(
            &g.credential,
            proof,
            auth.challenge(&attempt.commit, Some(g), b"pairkey/session-request/v1"),
        )?;
        let transfer = operation::parse(&ns.registration, &g.account, message)?;
        if transfer.recipient != g.recipient || transfer.lamports > g.max_lamports_per_operation {
            return Err(Error::Authorization);
        }
        // Expiry is conservative against either local time or finalized chain time.
        if now < g.not_before
            || o.block_time < g.not_before
            || now >= g.expires_at
            || o.block_time >= g.expires_at
        {
            return Err(Error::State);
        }
        if record.revoked {
            return Err(Error::Inactive);
        }
    } else if auth.session_proof.is_some() || o.session.is_some() {
        return Err(Error::Authorization);
    }
    match (&p.access, &auth.access_proof) {
        (Some(credential), Some(proof)) => access::verify(
            credential,
            proof,
            auth.challenge(&attempt.commit, None, b"pairkey/access-request/v1"),
        )?,
        (None, None) => {}
        _ => return Err(Error::Authorization),
    }
    if let Some(config) = &p.simulation {
        let transfer = operation::parse(&ns.registration, &attempt.commit.account, message)?;
        if transfer.lamports > config.max_lamports {
            return Err(Error::Authorization);
        }
        if check_simulation {
            let observed = o.simulation.as_ref().ok_or(Error::Authorization)?;
            let input = simulation_input(o, attempt, message)?.ok_or(Error::Authorization)?;
            if observed.slot < o.slot
                || observed.program.program.to_bytes() != config.program
                || observed.program.hash()? != config.code_hash
                || observed.output
                    != (SimulationOutput {
                        input_digest: input.digest(),
                        allowed: true,
                    })
            {
                return Err(Error::Authorization);
            }
        }
    } else if o.simulation.is_some() {
        return Err(Error::Authorization);
    }
    Ok(())
}
