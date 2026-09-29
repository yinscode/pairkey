use super::*;
use pairkey_types::policy::{Policy, SessionGrant};

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct PolicyRecord {
    pub namespace_address: [u8; 32],
    pub policy: Policy,
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SessionRecord {
    pub namespace_address: [u8; 32],
    pub grant: SessionGrant,
    pub revoked: bool,
}
pub fn policy_address(program: &Pubkey, namespace: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"policy", namespace.as_ref()], program)
}
pub fn session_address(program: &Pubkey, namespace: &Pubkey, id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"session", namespace.as_ref(), id], program)
}
fn controlled_namespace(
    program: &Pubkey,
    controller: &AccountInfo,
    info: &AccountInfo,
) -> Result<NamespaceRecord, ProgramError> {
    signer(controller)?;
    let ns: NamespaceRecord = read(info, program)?;
    address(info, namespace_address(program, &ns.registration).0)?;
    if ns.controller != controller.key.to_bytes() {
        return Err(bad());
    }
    Ok(ns)
}
pub(super) fn process(
    program: &Pubkey,
    accounts: &[AccountInfo],
    ix: RegistryInstruction,
) -> ProgramResult {
    let mut iter = accounts.iter();
    match ix {
        RegistryInstruction::SetPolicy { policy } => {
            let payer = next_account_info(&mut iter)?;
            let controller = next_account_info(&mut iter)?;
            let ns_info = next_account_info(&mut iter)?;
            let target = next_account_info(&mut iter)?;
            let system = next_account_info(&mut iter)?;
            controlled_namespace(program, controller, ns_info)?;
            signer(payer)?;
            policy.validate().map_err(|_| bad())?;
            let (pda, bump) = policy_address(program, ns_info.key);
            address(target, pda)?;
            let record = PolicyRecord {
                namespace_address: ns_info.key.to_bytes(),
                policy,
            };
            if target.owner == program {
                let old: PolicyRecord = read(target, program)?;
                if old.namespace_address != record.namespace_address
                    || record.policy.version != old.policy.version.checked_add(1).ok_or_else(bad)?
                {
                    return Err(bad());
                }
                let bytes = borsh::to_vec(&record).map_err(|_| bad())?;
                let rent = Rent::get()?.minimum_balance(bytes.len());
                if target.lamports() < rent {
                    solana_program::program::invoke(
                        &system_instruction::transfer(
                            payer.key,
                            target.key,
                            rent - target.lamports(),
                        ),
                        &[payer.clone(), target.clone(), system.clone()],
                    )?;
                }
                target.realloc(bytes.len(), false)?;
                write(target, &record)
            } else {
                if record.policy.version != 1 {
                    return Err(bad());
                }
                create(
                    payer,
                    target,
                    system,
                    program,
                    &[b"policy", ns_info.key.as_ref(), &[bump]],
                    &record,
                )
            }
        }
        RegistryInstruction::GrantSession { grant } => {
            let payer = next_account_info(&mut iter)?;
            let controller = next_account_info(&mut iter)?;
            let ns_info = next_account_info(&mut iter)?;
            let policy_info = next_account_info(&mut iter)?;
            let set_info = next_account_info(&mut iter)?;
            let target = next_account_info(&mut iter)?;
            let system = next_account_info(&mut iter)?;
            let ns = controlled_namespace(program, controller, ns_info)?;
            address(policy_info, policy_address(program, ns_info.key).0)?;
            let policy: PolicyRecord = read(policy_info, program)?;
            address(
                set_info,
                set_address(program, &ns.registration.namespace.enclave_set).0,
            )?;
            let set: EnclaveSet = read(set_info, program)?;
            grant.validate().map_err(|_| bad())?;
            if ns.frozen
                || set.retired
                || policy.namespace_address != ns_info.key.to_bytes()
                || !policy.policy.allow_session
                || grant.policy_version != policy.policy.version
                || grant.expires_at <= solana_program::clock::Clock::get()?.unix_timestamp
            {
                return Err(bad());
            }
            derive_public(&ns.registration, &grant.account).map_err(|_| bad())?;
            let (pda, bump) = session_address(program, ns_info.key, &grant.session_id);
            address(target, pda)?;
            let id = grant.session_id;
            let record = SessionRecord {
                namespace_address: ns_info.key.to_bytes(),
                grant,
                revoked: false,
            };
            create(
                payer,
                target,
                system,
                program,
                &[b"session", ns_info.key.as_ref(), &id, &[bump]],
                &record,
            )
        }
        RegistryInstruction::RevokeSession { session_id } => {
            let controller = next_account_info(&mut iter)?;
            let ns_info = next_account_info(&mut iter)?;
            let target = next_account_info(&mut iter)?;
            controlled_namespace(program, controller, ns_info)?;
            address(target, session_address(program, ns_info.key, &session_id).0)?;
            let mut record: SessionRecord = read(target, program)?;
            if record.namespace_address != ns_info.key.to_bytes()
                || record.grant.session_id != session_id
            {
                return Err(bad());
            }
            record.revoked = true;
            write(target, &record)
        }
        _ => Err(bad()),
    }
}
