//! Sample controller: a designated owner authorizes a PDA, which signs registry CPI.
#![allow(unexpected_cfgs)]
use borsh::{BorshDeserialize, BorshSerialize};
use pair_registry::{instruction, RegistryInstruction};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::AccountMeta,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
};

solana_program::declare_id!("9xQeWvG816bUx9EPfEZhGkGFdKsPZkiSvRfNbm9V2C4Z");
#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);
pub const AUTHORITY_SEED: &[u8] = b"controller";

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ControllerInstruction {
    pub registry_instruction: RegistryInstruction,
}
pub fn authority(program: &Pubkey, owner: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[AUTHORITY_SEED, owner.as_ref()], program)
}

pub fn process_instruction(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() > 1600 {
        return Err(ProgramError::InvalidArgument);
    }
    let call = ControllerInstruction::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut iter = accounts.iter();
    let owner = next_account_info(&mut iter)?;
    let authority_info = next_account_info(&mut iter)?;
    let registry = next_account_info(&mut iter)?;
    if !owner.is_signer || *registry.key != pair_registry::id() || !registry.executable {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (pda, bump) = authority(program, owner.key);
    if *authority_info.key != pda {
        return Err(ProgramError::InvalidArgument);
    }
    let mut metas = vec![
        AccountMeta::new(*owner.key, true),
        AccountMeta::new_readonly(pda, true),
    ];
    let rest: Vec<_> = iter.cloned().collect();
    match call.registry_instruction {
        RegistryInstruction::Register { .. } | RegistryInstruction::Commit { .. } => {}
        RegistryInstruction::Freeze { .. } => {
            metas = vec![AccountMeta::new_readonly(pda, true)];
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }
    metas.extend(rest.iter().map(|a| {
        if a.is_writable {
            AccountMeta::new(*a.key, false)
        } else {
            AccountMeta::new_readonly(*a.key, false)
        }
    }));
    let ix = instruction(*registry.key, metas, call.registry_instruction);
    let mut infos = vec![owner.clone(), authority_info.clone(), registry.clone()];
    infos.extend(rest);
    invoke_signed(
        &ix,
        &infos,
        &[&[AUTHORITY_SEED, owner.key.as_ref(), &[bump]]],
    )
}
