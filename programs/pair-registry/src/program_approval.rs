//! Registration-free program approvals and reusable helpers for custom policy programs.
use super::*;
use pairkey_types::program_approval::{AccountState, CommitApproval, Input, Source};

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ProgramApprovalRecord {
    pub namespace_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub expires_at: i64,
}
pub fn approval_address(
    registry: &Pubkey,
    namespace: &[u8; 32],
    request: &[u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"program-approval", namespace, request], registry)
}
pub fn validate_source(source: &Source) -> Result<Pubkey, ProgramError> {
    source.validate().map_err(|_| bad())?;
    let seeds: Vec<_> = source.seeds.iter().map(Vec::as_slice).collect();
    let (authority, _) =
        Pubkey::try_find_program_address(&seeds, &Pubkey::new_from_array(source.program))
            .ok_or_else(bad)?;
    if authority.to_bytes() != source.authority {
        return Err(bad());
    }
    Ok(authority)
}
pub fn account_state(account: &AccountInfo) -> Result<AccountState, ProgramError> {
    Ok(AccountState {
        address: account.key.to_bytes(),
        owner: account.owner.to_bytes(),
        lamports: account.lamports(),
        executable: account.executable,
        data: account.try_borrow_data()?.to_vec(),
    })
}
/// A worker attests the exact caller-authenticated input, including application state.
/// Programs still apply their own rules and check their own expected PDA/accounts.
/// Layout: [enclave set, instructions sysvar, ordered application accounts...].
pub fn authenticate_input(
    accounts: &[AccountInfo],
    input: &Input,
    expected_set: &Pubkey,
) -> ProgramResult {
    input.validate().map_err(|_| bad())?;
    if accounts.len() < 2
        || accounts.len() > 2 + pairkey_types::program_approval::MAX_PROGRAM_ACCOUNTS
        || accounts.iter().any(|a| a.is_writable || a.is_signer)
    {
        return Err(bad());
    }
    let set_info = &accounts[0];
    address(set_info, *expected_set)?;
    let instructions = &accounts[1];
    address(instructions, solana_program::sysvar::instructions::id())?;
    if load_current_index_checked(instructions)? != 1
        || input.expires_at <= solana_program::clock::Clock::get()?.unix_timestamp
    {
        return Err(bad());
    }
    let registry = id();
    let set: EnclaveSet = read(set_info, &registry)?;
    address(set_info, set_address(&registry, &set.set_id).0)?;
    if set.version != VERSION || set.retired || set.identities[0] == set.identities[1] {
        return Err(bad());
    }
    let mut states = vec![account_state(set_info)?];
    for account in &accounts[2..] {
        states.push(account_state(account)?);
    }
    if pairkey_types::program_approval::state_digest(&states) != input.state_digest {
        return Err(bad());
    }
    if !set.identities.iter().any(|identity| {
        ed_verified(instructions, identity, &input.attestation_message(), None).is_ok()
    }) {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}
pub(super) fn approve(
    program: &Pubkey,
    accounts: &[AccountInfo],
    approval: CommitApproval,
) -> ProgramResult {
    if accounts.len() != 6 {
        return Err(bad());
    }
    let [payer, authority, set_info, namespace_info, target, system] = accounts else {
        return Err(bad());
    };
    signer(authority)?;
    // Transaction keys cannot sign for a PDA. The application must invoke_signed.
    if pairkey_types::is_edwards_point(authority.key.to_bytes())
        || authority.key.to_bytes() != approval.namespace.derivation_authority
        || approval.namespace.registry != program.to_bytes()
    {
        return Err(bad());
    }
    approval.namespace.validate().map_err(|_| bad())?;
    let now = solana_program::clock::Clock::get()?.unix_timestamp;
    if approval.request_id == [0; 32]
        || approval.request_digest == [0; 32]
        || approval.expires_at <= now
        || approval.expires_at.saturating_sub(now) > pairkey_types::approval::MAX_APPROVAL_LIFETIME
    {
        return Err(bad());
    }
    let set: EnclaveSet = read(set_info, program)?;
    address(
        set_info,
        set_address(program, &approval.namespace.enclave_set).0,
    )?;
    if set.version != VERSION || set.set_id != approval.namespace.enclave_set || set.retired {
        return Err(bad());
    }
    let ns = approval.namespace.digest();
    address(
        namespace_info,
        Pubkey::find_program_address(&[b"namespace", &ns], program).0,
    )?;
    if namespace_info.owner == program {
        let record: NamespaceRecord = read(namespace_info, program)?;
        if record.registration.namespace != approval.namespace
            || record.frozen
            || record.controller != authority.key.to_bytes()
        {
            return Err(bad());
        }
    } else if namespace_info.owner != &solana_program::system_program::id()
        || !namespace_info.data_is_empty()
    {
        return Err(bad());
    }
    let (pda, bump) = approval_address(program, &ns, &approval.request_id);
    address(target, pda)?;
    create(
        payer,
        target,
        system,
        program,
        &[b"program-approval", &ns, &approval.request_id, &[bump]],
        &ProgramApprovalRecord {
            namespace_digest: ns,
            request_digest: approval.request_digest,
            expires_at: approval.expires_at,
        },
    )
}
