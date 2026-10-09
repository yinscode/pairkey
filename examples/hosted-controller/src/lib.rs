//! Developer-owned application program for hosted PairKey v2.
//! The downloadable bundle includes the exact typed gateway ABI and tested
//! application rules in vendor/programs/example-controller/src/approval.rs.
//! Edit AppPolicy::allows there to add application-specific rules. Its caller
//! authentication, exact-request binding and commit CPI must remain intact.
#![allow(unexpected_cfgs)]
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
solana_program::entrypoint!(process_instruction);
pub fn process_instruction(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Expose v2 approval and policy management only. Legacy Register/Commit
    // forwarding must not become an alternate route around application rules.
    let application = data.starts_with(b"pairkey_approve/v1\0")
        || data.starts_with(b"pairkey_approve_commit/v1\0")
        || data.starts_with(example_controller::approval::POLICY_PREFIX);
    // The typed shared dispatcher validates the complete SetRules (tag 11) ABI
    // and requires the owner before allowing PDA CPI.
    if !application && data.first() != Some(&11) {
        return Err(solana_program::program_error::ProgramError::InvalidInstructionData);
    }
    example_controller::process_instruction(program, accounts, data)
}
