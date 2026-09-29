//! Constrained SIMULATE evaluator. Caller identity is proved by the native precompile.
#![allow(unexpected_cfgs)]
use borsh::BorshDeserialize;
use pair_registry::{EnclaveSet, NamespaceRecord, PolicyRecord};
use pairkey_types::policy::{
    simulation_message, simulation_state, SimulationInput, SimulationOutput,
};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::instructions::load_current_index_checked,
};
solana_program::declare_id!("79cu2QNvp92chEmBhBgcUfERDT9KHnUcr8eiJb5WzKML");
#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);
fn bad() -> ProgramError {
    ProgramError::InvalidArgument
}
pub fn process_instruction(
    program: &Pubkey,
    accounts: &[AccountInfo],
    bytes: &[u8],
) -> ProgramResult {
    if bytes.len() > 512 || accounts.len() != 4 {
        return Err(bad());
    }
    let input = SimulationInput::try_from_slice(bytes).map_err(|_| bad())?;
    let mut iter = accounts.iter();
    let set_info = next_account_info(&mut iter)?;
    let ns_info = next_account_info(&mut iter)?;
    let policy_info = next_account_info(&mut iter)?;
    let instructions = next_account_info(&mut iter)?;
    if accounts.iter().any(|a| a.is_writable) || load_current_index_checked(instructions)? != 1 {
        return Err(bad());
    }
    let registry = pair_registry::id();
    let set: EnclaveSet = pair_registry::read(set_info, &registry)?;
    let ns: NamespaceRecord = pair_registry::read(ns_info, &registry)?;
    let policy: PolicyRecord = pair_registry::read(policy_info, &registry)?;
    let config = policy.policy.simulation.as_ref().ok_or_else(bad)?;
    if *set_info.key
        != pair_registry::set_address(&registry, &ns.registration.namespace.enclave_set).0
        || *ns_info.key != pair_registry::namespace_address(&registry, &ns.registration).0
        || *policy_info.key != pair_registry::policy_address(&registry, ns_info.key).0
        || policy.namespace_address != ns_info.key.to_bytes()
        || set.set_id != ns.registration.namespace.enclave_set
        || set.retired
        || ns.frozen
        || config.program != program.to_bytes()
        || policy.policy.digest() != input.policy_digest
        || simulation_state(
            &set_info.try_borrow_data()?,
            &ns_info.try_borrow_data()?,
            &policy_info.try_borrow_data()?,
        ) != input.state_digest
    {
        return Err(bad());
    }
    let challenge = simulation_message(&input);
    if !set.identities.iter().any(|identity| {
        pair_registry::ed_verified(instructions, identity, &challenge, None).is_ok()
    }) {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let output = SimulationOutput {
        input_digest: input.digest(),
        allowed: input.lamports > 0 && input.lamports <= config.max_lamports,
    };
    solana_program::program::set_return_data(&borsh::to_vec(&output).map_err(|_| bad())?);
    Ok(())
}
