//! Public derivation and Solana request helpers; no provider-root access.
pub mod approval;
pub mod hosted;
pub mod http;
pub mod policy;
pub mod rpc;
pub mod service;
use pair_registry::{
    instruction, namespace_address, request_address, response_address, set_address,
    RegistryInstruction,
};
use pairkey_types::{AccountPath, Commit, Registration};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

pub use pairkey_types::derive_public;
pub fn derived_address(
    reg: &Registration,
    path: &AccountPath,
) -> Result<Pubkey, pairkey_types::Error> {
    Ok(Pubkey::new_from_array(derive_public(reg, path)?))
}
pub fn verify_signature(
    reg: &Registration,
    commit: &Commit,
    bytes: &[u8],
    signature: &[u8; 64],
) -> bool {
    if commit.authorize(reg, bytes).is_err() {
        return false;
    }
    let Ok(public) = derive_public(reg, &commit.account) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&public) else {
        return false;
    };
    key.verify_strict(bytes, &ed25519_dalek::Signature::from_bytes(signature))
        .is_ok()
}
pub fn ed25519_instruction(key: [u8; 32], signature: [u8; 64], message: &[u8]) -> Instruction {
    assert!(message.len() <= u16::MAX as usize);
    let mut data = vec![1, 0];
    for value in [
        16u16,
        u16::MAX,
        80,
        u16::MAX,
        112,
        message.len() as u16,
        u16::MAX,
    ] {
        data.extend_from_slice(&value.to_le_bytes());
    }
    data.extend_from_slice(&signature);
    data.extend_from_slice(&key);
    data.extend_from_slice(message);
    Instruction {
        program_id: solana_sdk::ed25519_program::id(),
        accounts: vec![],
        data,
    }
}
pub fn create_set(
    payer: Pubkey,
    set_id: [u8; 32],
    identities: [[u8; 32]; 2],
    development: bool,
) -> Instruction {
    instruction(
        pair_registry::id(),
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(set_address(&pair_registry::id(), &set_id).0, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        RegistryInstruction::CreateSet {
            set_id,
            identities,
            development,
        },
    )
}
pub fn register(payer: Pubkey, controller: Pubkey, reg: Registration) -> Instruction {
    instruction(
        pair_registry::id(),
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(controller, true),
            AccountMeta::new_readonly(
                set_address(&pair_registry::id(), &reg.namespace.enclave_set).0,
                false,
            ),
            AccountMeta::new(namespace_address(&pair_registry::id(), &reg).0, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        RegistryInstruction::Register { registration: reg },
    )
}
pub fn commit(
    payer: Pubkey,
    controller: Pubkey,
    reg: &Registration,
    commit: Commit,
) -> Instruction {
    let ns = namespace_address(&pair_registry::id(), reg).0;
    instruction(
        pair_registry::id(),
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(controller, true),
            AccountMeta::new_readonly(ns, false),
            AccountMeta::new_readonly(
                set_address(&pair_registry::id(), &reg.namespace.enclave_set).0,
                false,
            ),
            AccountMeta::new(
                request_address(&pair_registry::id(), &ns, &commit.request_id).0,
                false,
            ),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        RegistryInstruction::Commit { commit },
    )
}
pub fn through_controller(owner: Pubkey, registry_ix: Instruction) -> Instruction {
    let authority = example_controller::authority(&example_controller::id(), &owner).0;
    assert_eq!(registry_ix.program_id, pair_registry::id());
    let registry_instruction = borsh::from_slice::<RegistryInstruction>(&registry_ix.data).unwrap();
    let start = if matches!(
        registry_instruction,
        RegistryInstruction::Freeze { .. }
            | RegistryInstruction::RevokeSession { .. }
            | RegistryInstruction::RevokeEvmSession { .. }
    ) {
        assert_eq!(registry_ix.accounts[0].pubkey, authority);
        1
    } else {
        assert_eq!(registry_ix.accounts[1].pubkey, authority);
        2
    };
    let mut accounts = vec![
        AccountMeta::new(owner, true),
        AccountMeta::new_readonly(authority, false),
        AccountMeta::new_readonly(pair_registry::id(), false),
    ];
    accounts.extend_from_slice(&registry_ix.accounts[start..]);
    Instruction {
        program_id: example_controller::id(),
        accounts,
        data: borsh::to_vec(&example_controller::ControllerInstruction {
            registry_instruction,
        })
        .unwrap(),
    }
}

pub fn freeze(controller: Pubkey, reg: &Registration, frozen: bool) -> Instruction {
    instruction(
        pair_registry::id(),
        vec![
            AccountMeta::new_readonly(controller, true),
            AccountMeta::new(namespace_address(&pair_registry::id(), reg).0, false),
        ],
        RegistryInstruction::Freeze { frozen },
    )
}
pub fn retire(governor: Pubkey, set_id: [u8; 32], retired: bool) -> Instruction {
    instruction(
        pair_registry::id(),
        vec![
            AccountMeta::new_readonly(governor, true),
            AccountMeta::new(set_address(&pair_registry::id(), &set_id).0, false),
        ],
        RegistryInstruction::Retire { retired },
    )
}
pub fn respond(
    payer: Pubkey,
    reg: &Registration,
    commit: &Commit,
    message: Vec<u8>,
    signature: [u8; 64],
) -> Vec<Instruction> {
    let ns = namespace_address(&pair_registry::id(), reg).0;
    let request = request_address(&pair_registry::id(), &ns, &commit.request_id).0;
    vec![
        ed25519_instruction(
            derive_public(reg, &commit.account).unwrap(),
            signature,
            &message,
        ),
        instruction(
            pair_registry::id(),
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(ns, false),
                AccountMeta::new_readonly(request, false),
                AccountMeta::new(response_address(&pair_registry::id(), &request).0, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
            RegistryInstruction::Respond { message, signature },
        ),
    ]
}

pub fn set_policy(
    payer: Pubkey,
    controller: Pubkey,
    reg: &Registration,
    policy: pairkey_types::policy::Policy,
) -> Instruction {
    let ns = namespace_address(&pair_registry::id(), reg).0;
    instruction(
        pair_registry::id(),
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(controller, true),
            AccountMeta::new_readonly(ns, false),
            AccountMeta::new(
                pair_registry::policy_address(&pair_registry::id(), &ns).0,
                false,
            ),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        RegistryInstruction::SetPolicy { policy },
    )
}
pub fn grant_session(
    payer: Pubkey,
    controller: Pubkey,
    reg: &Registration,
    grant: pairkey_types::policy::SessionGrant,
) -> Instruction {
    let ns = namespace_address(&pair_registry::id(), reg).0;
    instruction(
        pair_registry::id(),
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(controller, true),
            AccountMeta::new_readonly(ns, false),
            AccountMeta::new_readonly(
                pair_registry::policy_address(&pair_registry::id(), &ns).0,
                false,
            ),
            AccountMeta::new_readonly(
                set_address(&pair_registry::id(), &reg.namespace.enclave_set).0,
                false,
            ),
            AccountMeta::new(
                pair_registry::session_address(&pair_registry::id(), &ns, &grant.session_id).0,
                false,
            ),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        RegistryInstruction::GrantSession { grant },
    )
}
pub fn revoke_session(controller: Pubkey, reg: &Registration, session_id: [u8; 32]) -> Instruction {
    let ns = namespace_address(&pair_registry::id(), reg).0;
    instruction(
        pair_registry::id(),
        vec![
            AccountMeta::new_readonly(controller, true),
            AccountMeta::new_readonly(ns, false),
            AccountMeta::new(
                pair_registry::session_address(&pair_registry::id(), &ns, &session_id).0,
                false,
            ),
        ],
        RegistryInstruction::RevokeSession { session_id },
    )
}

pub fn grant_evm_session(
    payer: Pubkey,
    controller: Pubkey,
    reg: &Registration,
    grant: pairkey_types::policy::EvmSessionGrant,
) -> Instruction {
    let ns = namespace_address(&pair_registry::id(), reg).0;
    instruction(
        pair_registry::id(),
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(controller, true),
            AccountMeta::new_readonly(ns, false),
            AccountMeta::new_readonly(
                pair_registry::policy_address(&pair_registry::id(), &ns).0,
                false,
            ),
            AccountMeta::new_readonly(
                set_address(&pair_registry::id(), &reg.namespace.enclave_set).0,
                false,
            ),
            AccountMeta::new(
                pair_registry::evm_session_address(&pair_registry::id(), &ns, &grant.session_id).0,
                false,
            ),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        RegistryInstruction::GrantEvmSession { grant },
    )
}
pub fn revoke_evm_session(
    controller: Pubkey,
    reg: &Registration,
    session_id: [u8; 32],
) -> Instruction {
    let ns = namespace_address(&pair_registry::id(), reg).0;
    instruction(
        pair_registry::id(),
        vec![
            AccountMeta::new_readonly(controller, true),
            AccountMeta::new_readonly(ns, false),
            AccountMeta::new(
                pair_registry::evm_session_address(&pair_registry::id(), &ns, &session_id).0,
                false,
            ),
        ],
        RegistryInstruction::RevokeEvmSession { session_id },
    )
}

/// Only these two instructions are ever simulated; no client transaction is replayed.
pub fn simulation_transaction(
    program: Pubkey,
    payer: Pubkey,
    reg: &Registration,
    identity: [u8; 32],
    signature: [u8; 64],
    input: pairkey_types::policy::SimulationInput,
) -> solana_sdk::transaction::Transaction {
    let ns = namespace_address(&pair_registry::id(), reg).0;
    let challenge = pairkey_types::policy::simulation_message(&input);
    let instructions = vec![
        ed25519_instruction(identity, signature, &challenge),
        Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new_readonly(
                    set_address(&pair_registry::id(), &reg.namespace.enclave_set).0,
                    false,
                ),
                AccountMeta::new_readonly(ns, false),
                AccountMeta::new_readonly(
                    pair_registry::policy_address(&pair_registry::id(), &ns).0,
                    false,
                ),
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
            ],
            data: borsh::to_vec(&input).unwrap(),
        },
    ];
    solana_sdk::transaction::Transaction::new_unsigned(solana_sdk::message::Message::new(
        &instructions,
        Some(&payer),
    ))
}

pub mod multi;

pub mod program_approval;
