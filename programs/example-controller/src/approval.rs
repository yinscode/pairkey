//! Example application rules: designated caller, destination/path scope and an optional
//! persistent approval counter. Developers can replace these rules with their own logic.
use super::*;
use pairkey_types::program_approval::{CommitCall, Input, Output, APPROVE_PREFIX, COMMIT_PREFIX};
use solana_program::{program::set_return_data, rent::Rent, sysvar::Sysvar};
pub const POLICY_PREFIX: &[u8] = b"pairkey_policy/v1\0";
pub const SCOPED_POLICY_PREFIX: &[u8] = b"pairkey_policy/v2\0";
pub const POLICY_SEED: &[u8] = b"pairkey-policy";
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct AppPolicy {
    pub owner: [u8; 32],
    pub enclave_set: [u8; 32],
    pub revision: u64,
    pub enabled: bool,
    pub destination: [u8; 32],
    pub path_prefix: Vec<u32>,
    pub max_payload_bytes: u16,
    pub require_commit: bool,
    pub remaining_approvals: u64,
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ScopedPolicyUpdate {
    pub namespace_scope: Option<[u8; 32]>,
    pub policy: AppPolicy,
}
pub fn policy_address(program: &Pubkey, owner: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[POLICY_SEED, owner.as_ref()], program)
}
pub fn scoped_policy_address(
    program: &Pubkey,
    owner: &Pubkey,
    namespace_digest: &[u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[POLICY_SEED, owner.as_ref(), namespace_digest], program)
}
fn selected_policy_address(
    program: &Pubkey,
    owner: &Pubkey,
    scope: Option<&[u8; 32]>,
) -> (Pubkey, u8) {
    scope.map_or_else(
        || policy_address(program, owner),
        |digest| scoped_policy_address(program, owner, digest),
    )
}
fn bad() -> ProgramError {
    ProgramError::InvalidArgument
}
fn policy(
    program: &Pubkey,
    info: &AccountInfo,
    namespace_digest: &[u8; 32],
) -> Result<AppPolicy, ProgramError> {
    let p: AppPolicy = pair_registry::read(info, program)?;
    let owner = Pubkey::new_from_array(p.owner);
    if policy_address(program, &owner).0 != *info.key
        && scoped_policy_address(program, &owner, namespace_digest).0 != *info.key
    {
        return Err(bad());
    }
    Ok(p)
}
impl AppPolicy {
    fn validate(&self) -> ProgramResult {
        if self.owner == [0; 32]
            || self.revision == 0
            || self.path_prefix.len() > pairkey_types::MAX_PATH
            || self.max_payload_bytes == 0
            || self.max_payload_bytes as usize > pairkey_types::MAX_MESSAGE
        {
            return Err(bad());
        }
        Ok(())
    }
    fn allows(
        &self,
        caller: [u8; 32],
        account: &pairkey_types::AccountPath,
        payload: &[u8],
    ) -> bool {
        self.enabled
            && self.owner == caller
            && account.destination == self.destination
            && account.path.starts_with(&self.path_prefix)
            && !payload.is_empty()
            && payload.len() <= self.max_payload_bytes as usize
    }
}
pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if let Some(bytes) = data.strip_prefix(SCOPED_POLICY_PREFIX) {
        let update = ScopedPolicyUpdate::try_from_slice(bytes).map_err(|_| bad())?;
        let scope = update.namespace_scope.ok_or_else(bad)?;
        return set_policy(program, accounts, update.policy, Some(scope));
    }
    if let Some(bytes) = data.strip_prefix(POLICY_PREFIX) {
        let policy = AppPolicy::try_from_slice(bytes).map_err(|_| bad())?;
        return set_policy(program, accounts, policy, None);
    }
    if let Some(bytes) = data.strip_prefix(APPROVE_PREFIX) {
        let input = Input::try_from_slice(bytes).map_err(|_| bad())?;
        if accounts.len() != 3 {
            return Err(bad());
        }
        let p = policy(program, &accounts[2], &input.namespace_digest)?;
        pair_registry::program_approval::authenticate_input(
            accounts,
            &input,
            &pair_registry::set_address(&pair_registry::id(), &p.enclave_set).0,
        )?;
        let allowed = input.authority
            == authority(program, &Pubkey::new_from_array(p.owner))
                .0
                .to_bytes()
            && !p.require_commit
            && p.allows(input.caller, &input.account, &input.payload);
        set_return_data(
            &borsh::to_vec(&Output {
                input_digest: input.digest(),
                allowed,
            })
            .map_err(|_| bad())?,
        );
        return Ok(());
    }
    let bytes = data.strip_prefix(COMMIT_PREFIX).ok_or_else(bad)?;
    let call = CommitCall::try_from_slice(bytes).map_err(|_| bad())?;
    let source = call
        .validate(solana_program::clock::Clock::get()?.unix_timestamp)
        .map_err(|_| bad())?;
    if accounts.len() != 8 {
        return Err(bad());
    }
    let [owner, authority_info, policy_info, registry, set, namespace, target, system] = accounts
    else {
        return Err(bad());
    };
    if !owner.is_signer || *registry.key != pair_registry::id() || !registry.executable {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (pda, bump) = authority(program, owner.key);
    if source.program != program.to_bytes()
        || source.authority != pda.to_bytes()
        || pair_registry::program_approval::validate_source(source)? != pda
        || *authority_info.key != pda
        || source.accounts != vec![policy_info.key.to_bytes()]
    {
        return Err(bad());
    }
    let mut p = policy(program, policy_info, &call.namespace.digest())?;
    if p.enclave_set != call.namespace.enclave_set {
        return Err(bad());
    }
    if !p.allows(
        owner.key.to_bytes(),
        &call.request.commit.account,
        &call.payload,
    ) || p.remaining_approvals == 0
    {
        return Err(bad());
    }
    p.remaining_approvals -= 1;
    let bytes = borsh::to_vec(&p).map_err(|_| bad())?;
    policy_info.try_borrow_mut_data()?.copy_from_slice(&bytes);
    let ix = instruction(
        *registry.key,
        vec![
            AccountMeta::new(*owner.key, true),
            AccountMeta::new_readonly(pda, true),
            AccountMeta::new_readonly(*set.key, false),
            AccountMeta::new_readonly(*namespace.key, false),
            AccountMeta::new(*target.key, false),
            AccountMeta::new_readonly(*system.key, false),
        ],
        RegistryInstruction::ApproveProgram {
            approval: call.approval(),
        },
    );
    invoke_signed(
        &ix,
        &[
            owner.clone(),
            authority_info.clone(),
            set.clone(),
            namespace.clone(),
            target.clone(),
            system.clone(),
            registry.clone(),
        ],
        &[&[AUTHORITY_SEED, owner.key.as_ref(), &[bump]]],
    )
}
fn set_policy(
    program: &Pubkey,
    accounts: &[AccountInfo],
    p: AppPolicy,
    namespace_scope: Option<[u8; 32]>,
) -> ProgramResult {
    p.validate()?;
    if namespace_scope == Some([0; 32]) {
        return Err(bad());
    }
    let [owner, target, system] = accounts else {
        return Err(bad());
    };
    let (pda, bump) = selected_policy_address(program, owner.key, namespace_scope.as_ref());
    if !owner.is_signer
        || p.owner != owner.key.to_bytes()
        || *target.key != pda
        || *system.key != solana_program::system_program::id()
    {
        return Err(bad());
    }
    let encoded = borsh::to_vec(&p).map_err(|_| bad())?;
    let rent = Rent::get()?.minimum_balance(encoded.len());
    if target.owner == program {
        let old: AppPolicy = pair_registry::read(target, program)?;
        if old.owner != p.owner || old.revision.checked_add(1) != Some(p.revision) {
            return Err(bad());
        }
        if target.lamports() < rent {
            solana_program::program::invoke(
                &solana_program::system_instruction::transfer(
                    owner.key,
                    target.key,
                    rent - target.lamports(),
                ),
                &[owner.clone(), target.clone(), system.clone()],
            )?;
        }
        target.realloc(encoded.len(), false)?;
    } else {
        if p.revision != 1
            || target.owner != &solana_program::system_program::id()
            || !target.data_is_empty()
        {
            return Err(bad());
        }
        let bump_seed = [bump];
        let mut seeds: Vec<&[u8]> = vec![POLICY_SEED, owner.key.as_ref()];
        if let Some(scope) = namespace_scope.as_ref() {
            seeds.push(scope);
        }
        seeds.push(&bump_seed);
        if target.lamports() == 0 {
            invoke_signed(
                &solana_program::system_instruction::create_account(
                    owner.key,
                    target.key,
                    rent,
                    encoded.len() as u64,
                    program,
                ),
                &[owner.clone(), target.clone(), system.clone()],
                &[&seeds],
            )?;
        } else {
            if target.lamports() < rent {
                solana_program::program::invoke(
                    &solana_program::system_instruction::transfer(
                        owner.key,
                        target.key,
                        rent - target.lamports(),
                    ),
                    &[owner.clone(), target.clone(), system.clone()],
                )?;
            }
            invoke_signed(
                &solana_program::system_instruction::allocate(target.key, encoded.len() as u64),
                &[target.clone(), system.clone()],
                &[&seeds],
            )?;
            invoke_signed(
                &solana_program::system_instruction::assign(target.key, program),
                &[target.clone(), system.clone()],
                &[&seeds],
            )?;
        }
    }
    target.try_borrow_mut_data()?.copy_from_slice(&encoded);
    Ok(())
}
