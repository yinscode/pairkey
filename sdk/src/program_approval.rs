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
    example_policy_for_scope(program, policy, None)
}
pub fn example_policy_for_scope(
    program: Pubkey,
    policy: example_controller::approval::AppPolicy,
    namespace_scope: Option<[u8; 32]>,
) -> Instruction {
    let owner = Pubkey::new_from_array(policy.owner);
    let mut data = if namespace_scope.is_some() {
        example_controller::approval::SCOPED_POLICY_PREFIX.to_vec()
    } else {
        example_controller::approval::POLICY_PREFIX.to_vec()
    };
    if namespace_scope.is_some() {
        data.extend(
            borsh::to_vec(&example_controller::approval::ScopedPolicyUpdate {
                namespace_scope,
                policy,
            })
            .unwrap(),
        );
    } else {
        data.extend(borsh::to_vec(&policy).unwrap());
    }
    let policy_address = namespace_scope.map_or_else(
        || example_controller::approval::policy_address(&program, &owner).0,
        |scope| example_controller::approval::scoped_policy_address(&program, &owner, &scope).0,
    );
    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(owner, true),
            AccountMeta::new(policy_address, false),
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
    let shared = example_controller::approval::policy_address(&program, &owner).0;
    let scoped =
        example_controller::approval::scoped_policy_address(&program, &owner, &namespace.digest())
            .0;
    let policy = source
        .accounts
        .first()
        .map(|key| Pubkey::new_from_array(*key))
        .filter(|key| *key == shared || *key == scoped)
        .ok_or_else(|| anyhow::anyhow!("example program policy scope mismatch"))?;
    ensure!(
        source.authority == authority.to_bytes() && source.accounts == vec![policy.to_bytes()],
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
        AccountMeta::new(policy, false),
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

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize;

    fn policy(owner: Pubkey) -> example_controller::approval::AppPolicy {
        example_controller::approval::AppPolicy {
            owner: owner.to_bytes(),
            enclave_set: [3; 32],
            revision: 1,
            enabled: true,
            destination: [4; 32],
            path_prefix: vec![0],
            max_payload_bytes: 256,
            require_commit: false,
            remaining_approvals: 0,
        }
    }

    #[test]
    fn example_policy_selects_shared_or_namespace_pda() {
        let program = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let shared = example_policy_for_scope(program, policy(owner), None);
        assert!(shared
            .data
            .starts_with(example_controller::approval::POLICY_PREFIX));
        assert_eq!(
            shared.accounts[1].pubkey,
            example_controller::approval::policy_address(&program, &owner).0
        );

        let scope = [9; 32];
        let scoped = example_policy_for_scope(program, policy(owner), Some(scope));
        assert!(scoped
            .data
            .starts_with(example_controller::approval::SCOPED_POLICY_PREFIX));
        assert_eq!(
            scoped.accounts[1].pubkey,
            example_controller::approval::scoped_policy_address(&program, &owner, &scope).0
        );
        let update = example_controller::approval::ScopedPolicyUpdate::try_from_slice(
            &scoped.data[example_controller::approval::SCOPED_POLICY_PREFIX.len()..],
        )
        .unwrap();
        assert_eq!(update.namespace_scope, Some(scope));
        assert_eq!(update.policy.owner, owner.to_bytes());
    }
}
