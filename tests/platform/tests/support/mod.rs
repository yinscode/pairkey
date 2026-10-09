use pair_registry::{
    namespace_address, request_address, set_address, EnclaveSet, NamespaceRecord, RequestRecord,
};
use pairkey_core::{Observation, ObservedAccount, Trust};
use pairkey_frost::{register, Root, Signer};
use pairkey_types::{derive_public, AccountPath, Attempt, Commit, Namespace, Role, Scheme};
use rand_core::OsRng;

pub fn fixture() -> (Trust, Observation, Attempt, Vec<u8>) {
    let program = pair_registry::id();
    let ns = Namespace {
        version: 1,
        scheme: Scheme::FrostEd25519,
        network: [1; 32],
        registry: program.to_bytes(),
        derivation_authority: [3; 32],
        namespace_id: [4; 32],
        enclave_set: [5; 32],
    };
    let a = Signer::new(Root::new([11; 32]), Role::A);
    let b = Signer::new(Root::new([22; 32]), Role::B);
    let reg = register(
        ns.clone(),
        &a.proof(&ns, &mut OsRng).unwrap(),
        &b.proof(&ns, &mut OsRng).unwrap(),
    )
    .unwrap();
    let message = b"original approved bytes".to_vec();
    let commit = Commit::new(
        &reg,
        [7; 32],
        AccountPath {
            destination: [8; 32],
            path: vec![1],
        },
        &message,
    )
    .unwrap();
    let namespace = namespace_address(&program, &reg).0;
    let set = set_address(&program, &ns.enclave_set).0;
    let request = request_address(&program, &namespace, &commit.request_id).0;
    let identities = [[31; 32], [32; 32]];
    let observation = Observation {
        rules: None,
        policy: None,
        session: None,
        simulation: None,
        network: ns.network,
        finalized: true,
        slot: 100,
        block_time: 999,
        observed_at: 1000,
        provider_domain: "A-local".into(),
        set: ObservedAccount {
            address: set,
            owner: program,
            data: borsh::to_vec(&EnclaveSet {
                version: 1,
                set_id: ns.enclave_set,
                governor: [9; 32],
                identities,
                retired: false,
                development: true,
            })
            .unwrap(),
        },
        namespace: ObservedAccount {
            address: namespace,
            owner: program,
            data: borsh::to_vec(&NamespaceRecord {
                registration: reg.clone(),
                controller: [3; 32],
                frozen: false,
            })
            .unwrap(),
        },
        request: ObservedAccount {
            address: request,
            owner: program,
            data: borsh::to_vec(&RequestRecord {
                namespace_address: namespace.to_bytes(),
                commit: commit.clone(),
                derived_key: derive_public(&reg, &commit.account).unwrap(),
            })
            .unwrap(),
        },
    };
    let trust = Trust {
        registry: program,
        network: ns.network,
        enclave_set: set,
        identity_keys: identities,
        set_governor: [9; 32],
        provider_domain: "A-local".into(),
        allow_development: true,
        max_observation_age_secs: 3,
        max_chain_lag_secs: 30,
    };
    (
        trust,
        observation,
        Attempt {
            authorization: Default::default(),
            commit,
            random_id: [6; 32],
        },
        message,
    )
}
