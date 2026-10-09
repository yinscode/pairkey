//! Custom program approval ABI and example-controller helpers.
use anyhow::{ensure, Result};
use pairkey_types::{
    approval::{Identity, Request},
    program_approval::{CommitCall, Input, Mode, APPROVE_PREFIX, COMMIT_PREFIX},
    Namespace,
};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    transaction::Transaction,
};

/// Signer-authenticated context follows one native Ed25519 precompile instruction.
/// The payer must be funded for RPC simulation but no transaction is broadcast.
pub fn simulation_transaction(
    program: Pubkey,
    payer: Pubkey,
    set: Pubkey,
    accounts: &[[u8; 32]],
    identity: [u8; 32],
    signature: [u8; 64],
    input: &Input,
) -> Result<Transaction> {
    input.validate()?;
    ensure!(
        accounts.len() <= pairkey_types::program_approval::MAX_PROGRAM_ACCOUNTS,
        "program account bound"
    );
    let mut metas = vec![
        AccountMeta::new_readonly(set, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
    ];
    metas.extend(
        accounts
            .iter()
            .map(|key| AccountMeta::new_readonly(Pubkey::new_from_array(*key), false)),
    );
    let mut data = APPROVE_PREFIX.to_vec();
    data.extend(borsh::to_vec(input)?);
    let tx = Transaction::new_with_payer(
        &[
            crate::ed25519_instruction(identity, signature, &input.attestation_message()),
            Instruction {
                program_id: program,
                accounts: metas,
                data,
            },
        ],
        Some(&payer),
    );
    ensure!(bincode::serialized_size(&tx)?<=1232,"program simulation exceeds Solana transaction size; use a shorter message or fewer accounts");
    Ok(tx)
}
pub fn commit_instruction(
    payer: Pubkey,
    authority: Pubkey,
    approval: pairkey_types::program_approval::CommitApproval,
) -> Instruction {
    let registry = Pubkey::new_from_array(approval.namespace.registry);
    let ns = approval.namespace.digest();
    let metas = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new_readonly(
            pair_registry::set_address(&registry, &approval.namespace.enclave_set).0,
            false,
        ),
        AccountMeta::new_readonly(
            Pubkey::find_program_address(&[b"namespace", &ns], &registry).0,
            false,
        ),
        AccountMeta::new(
            pair_registry::program_approval::approval_address(&registry, &ns, &approval.request_id)
                .0,
            false,
        ),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ];
    pair_registry::instruction(
        registry,
        metas,
        pair_registry::RegistryInstruction::ApproveProgram { approval },
    )
}
pub fn example_policy(
    program: Pubkey,
    policy: example_controller::approval::AppPolicy,
) -> Instruction {
    let owner = Pubkey::new_from_array(policy.owner);
    let mut data = example_controller::approval::POLICY_PREFIX.to_vec();
    data.extend(borsh::to_vec(&policy).unwrap());
    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(owner, true),
            AccountMeta::new(
                example_controller::approval::policy_address(&program, &owner).0,
                false,
            ),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}
pub fn example_commit(
    owner: Pubkey,
    namespace: Namespace,
    request: Request,
    payload: Vec<u8>,
) -> Result<Instruction> {
    let Identity::Program(source) = &request.identity else {
        anyhow::bail!("program source required")
    };
    ensure!(source.mode == Mode::Onchain, "on-chain approval required");
    let program = Pubkey::new_from_array(source.program);
    let authority = example_controller::authority(&program, &owner).0;
    ensure!(
        source.authority == authority.to_bytes()
            && source.accounts
                == vec![
                    example_controller::approval::policy_address(&program, &owner)
                        .0
                        .to_bytes()
                ],
        "example program source mismatch"
    );
    let call = CommitCall {
        namespace,
        request,
        payload,
    };
    let gateway = commit_instruction(owner, authority, call.approval());
    let mut accounts = vec![
        AccountMeta::new(owner, true),
        AccountMeta::new_readonly(authority, false),
        AccountMeta::new(
            example_controller::approval::policy_address(&program, &owner).0,
            false,
        ),
        AccountMeta::new_readonly(gateway.program_id, false),
    ];
    accounts.extend(gateway.accounts[2..].iter().cloned());
    let mut data = COMMIT_PREFIX.to_vec();
    data.extend(borsh::to_vec(&call)?);
    Ok(Instruction {
        program_id: program,
        accounts,
        data,
    })
}
