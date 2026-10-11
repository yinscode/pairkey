//! Minimal developer-owned controller for PairKey's hosted devnet gateway.
//! Each wallet controls a separate PDA. Replace the owner check with your app's rules.
#![allow(unexpected_cfgs, deprecated)]
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
};
solana_program::entrypoint!(process_instruction);
// Pin the intended gateway. Verify this against https://pairkey.com/api/v1/config.
const GATEWAY: Pubkey = solana_program::pubkey!("rsYu5jyioN9YjWcj58houJ4AYnWKWwjTtpG8hSMw1QZ");
pub fn process_instruction(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Gateway v1 Borsh instruction tags: Register=1, Commit=2.
    if !matches!(data.first(), Some(1 | 2)) || data.len() > 1600 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut iter = accounts.iter();
    let owner = next_account_info(&mut iter)?;
    let authority = next_account_info(&mut iter)?;
    let gateway = next_account_info(&mut iter)?;
    // APPLICATION LOGIC: the wallet that scopes this PDA must approve every call.
    if !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (expected, bump) =
        Pubkey::find_program_address(&[b"controller", owner.key.as_ref()], program);
    if *authority.key != expected || *gateway.key != GATEWAY || !gateway.executable {
        return Err(ProgramError::InvalidArgument);
    }
    let rest: Vec<_> = iter.cloned().collect();
    let mut metas = vec![
        AccountMeta::new(*owner.key, true),
        AccountMeta::new_readonly(expected, true),
    ];
    metas.extend(rest.iter().map(|a| {
        if a.is_writable {
            AccountMeta::new(*a.key, false)
        } else {
            AccountMeta::new_readonly(*a.key, false)
        }
    }));
    let ix = Instruction {
        program_id: GATEWAY,
        accounts: metas,
        data: data.to_vec(),
    };
    let mut infos = vec![owner.clone(), authority.clone(), gateway.clone()];
    infos.extend(rest);
    invoke_signed(
        &ix,
        &infos,
        &[&[b"controller", owner.key.as_ref(), &[bump]]],
    )
}
