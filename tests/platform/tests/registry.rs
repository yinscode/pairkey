use litesvm::LiteSVM;
use pair_registry::{NamespaceRecord, RequestRecord, ResponseRecord};
use pairkey_frost::{aggregate, register, Root, Signer as ThresholdSigner};
use pairkey_types::{AccountPath, Attempt, Commit, Namespace, Registration, Role, Scheme};
use rand_core::{OsRng, RngCore};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
    transaction::Transaction,
};

struct Fixture {
    svm: LiteSVM,
    payer: Keypair,
    identities: [Keypair; 2],
    a: ThresholdSigner,
    b: ThresholdSigner,
}
impl Fixture {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let root = std::env::var_os("PAIRKEY_PROGRAM_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy")
            });
        svm.add_program_from_file(pair_registry::id(), root.join("pair_registry.so"))
            .unwrap();
        svm.add_program_from_file(example_controller::id(), root.join("example_controller.so"))
            .unwrap();
        svm.add_program_from_file(example_policy::id(), root.join("example_policy.so"))
            .unwrap();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();
        let identities = [Keypair::new(), Keypair::new()];
        let mut f = Self {
            svm,
            payer,
            identities,
            a: ThresholdSigner::new(Root::new([11; 32]), Role::A),
            b: ThresholdSigner::new(Root::new([22; 32]), Role::B),
        };
        let ix = pairkey_sdk::create_set(
            f.payer.pubkey(),
            [5; 32],
            [
                f.identities[0].pubkey().to_bytes(),
                f.identities[1].pubkey().to_bytes(),
            ],
            true,
        );
        f.send(vec![ix]).unwrap();
        f
    }
    fn send(&mut self, mut instructions: Vec<Instruction>) -> Result<(), String> {
        instructions.insert(
            0,
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        );
        let tx = Transaction::new_signed_with_payer(
            &instructions,
            Some(&self.payer.pubkey()),
            &[&self.payer],
            self.svm.latest_blockhash(),
        );
        self.svm
            .send_transaction(tx)
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }
    fn registration(&mut self, controller: Pubkey, id: u8, cpi: bool) -> Registration {
        let ns = Namespace {
            version: 1,
            scheme: Scheme::FrostEd25519,
            network: [1; 32],
            registry: pair_registry::id().to_bytes(),
            derivation_authority: controller.to_bytes(),
            namespace_id: [id; 32],
            enclave_set: [5; 32],
        };
        let reg = register(
            ns.clone(),
            &self.a.proof(&ns, &mut OsRng).unwrap(),
            &self.b.proof(&ns, &mut OsRng).unwrap(),
        )
        .unwrap();
        let manifest = pair_registry::registration_message(&reg, &controller);
        let mut ixs: Vec<_> = self
            .identities
            .iter()
            .map(|key| {
                pairkey_sdk::ed25519_instruction(
                    key.pubkey().to_bytes(),
                    key.sign_message(&manifest).as_ref().try_into().unwrap(),
                    &manifest,
                )
            })
            .collect();
        let ix = pairkey_sdk::register(self.payer.pubkey(), controller, reg.clone());
        ixs.push(if cpi {
            pairkey_sdk::through_controller(self.payer.pubkey(), ix)
        } else {
            ix
        });
        self.send(ixs).unwrap();
        reg
    }
    fn sign(&self, reg: &Registration, commit: &Commit, message: &[u8]) -> [u8; 64] {
        let mut random_id = [0; 32];
        OsRng.fill_bytes(&mut random_id);
        let attempt = Attempt {
            authorization: Default::default(),
            commit: commit.clone(),
            random_id,
        };
        let rounds = [
            self.a.begin(reg, &attempt, message, &mut OsRng).unwrap(),
            self.b.begin(reg, &attempt, message, &mut OsRng).unwrap(),
        ];
        let shares = [
            self.a.finish(&attempt, &rounds).unwrap(),
            self.b.finish(&attempt, &rounds).unwrap(),
        ];
        aggregate(reg, &attempt, message, &rounds, &shares).unwrap()
    }
}

#[test]
#[ignore = "requires cargo build-sbf for both programs"]
fn account_and_cpi_requests_native_threshold_transfers_and_response_cache() {
    let mut f = Fixture::new();
    for (id, cpi) in [(1, false), (2, true)] {
        let controller = if cpi {
            example_controller::authority(&example_controller::id(), &f.payer.pubkey()).0
        } else {
            f.payer.pubkey()
        };
        let reg = f.registration(controller, id, cpi);
        let path = AccountPath {
            destination: [8; 32],
            path: vec![0],
        };
        let derived = pairkey_sdk::derived_address(&reg, &path).unwrap();
        f.svm.airdrop(&derived, 1_000_000_000).unwrap();
        let recipient = Pubkey::new_unique();
        let message = Message::new_with_blockhash(
            &[system_instruction::transfer(
                &derived, &recipient, 5_000_000,
            )],
            Some(&derived),
            &f.svm.latest_blockhash(),
        );
        let bytes = message.serialize();
        let commit = Commit::new(&reg, [id; 32], path, &bytes).unwrap();
        let ix = pairkey_sdk::commit(f.payer.pubkey(), controller, &reg, commit.clone());
        f.send(vec![if cpi {
            pairkey_sdk::through_controller(f.payer.pubkey(), ix)
        } else {
            ix
        }])
        .unwrap();
        let ns = pair_registry::namespace_address(&pair_registry::id(), &reg).0;
        let request =
            pair_registry::request_address(&pair_registry::id(), &ns, &commit.request_id).0;
        let ns_record: NamespaceRecord =
            borsh::from_slice(&f.svm.get_account(&ns).unwrap().data).unwrap();
        let req_record: RequestRecord =
            borsh::from_slice(&f.svm.get_account(&request).unwrap().data).unwrap();
        assert_eq!(ns_record.controller, controller.to_bytes());
        assert_eq!(req_record.commit, commit);
        let sig = f.sign(&reg, &commit, &bytes);
        assert!(pairkey_sdk::verify_signature(&reg, &commit, &bytes, &sig));
        let another = f.sign(&reg, &commit, &bytes);
        assert_ne!(sig, another);
        f.send(pairkey_sdk::respond(
            f.payer.pubkey(),
            &reg,
            &commit,
            bytes.clone(),
            sig,
        ))
        .unwrap();
        let response = pair_registry::response_address(&pair_registry::id(), &request).0;
        let record: ResponseRecord =
            borsh::from_slice(&f.svm.get_account(&response).unwrap().data).unwrap();
        assert_eq!(record.signature, sig);
        let tx = Transaction {
            signatures: vec![Signature::from(sig)],
            message,
        };
        f.svm.send_transaction(tx).unwrap();
        assert_eq!(f.svm.get_balance(&recipient), Some(5_000_000));
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        assert!(commit.authorize(&reg, &changed).is_err());
        let mut forged = sig;
        forged[0] ^= 1;
        assert!(f
            .send(pairkey_sdk::respond(
                f.payer.pubkey(),
                &reg,
                &commit,
                bytes,
                forged
            ))
            .is_err());
    }
}

#[test]
#[ignore = "requires cargo build-sbf for both programs"]
fn false_account_or_program_authority_cannot_create_request() {
    let mut f = Fixture::new();
    let controller = example_controller::authority(&example_controller::id(), &f.payer.pubkey()).0;
    let reg = f.registration(controller, 3, true);
    let commit = Commit::new(
        &reg,
        [8; 32],
        AccountPath {
            destination: [8; 32],
            path: vec![0],
        },
        b"approve",
    )
    .unwrap();
    let mut ix = pairkey_sdk::commit(f.payer.pubkey(), controller, &reg, commit.clone());
    ix.accounts[1].is_signer = false;
    assert!(f.send(vec![ix]).is_err());
    let ix = pairkey_sdk::commit(f.payer.pubkey(), f.payer.pubkey(), &reg, commit.clone());
    assert!(f.send(vec![ix]).is_err());
    let mut ix = pairkey_sdk::through_controller(
        f.payer.pubkey(),
        pairkey_sdk::commit(f.payer.pubkey(), controller, &reg, commit),
    );
    ix.accounts[1].pubkey = Pubkey::new_unique();
    assert!(f.send(vec![ix]).is_err());
}

#[test]
#[ignore = "requires cargo build-sbf for both programs"]
fn native_public_checks_reject_identity_torsion_noncanonical_and_wrong_interpolation() {
    let mut f = Fixture::new();
    let controller = f.payer.pubkey();
    let ns = Namespace {
        version: 1,
        scheme: Scheme::FrostEd25519,
        network: [1; 32],
        registry: pair_registry::id().to_bytes(),
        derivation_authority: controller.to_bytes(),
        namespace_id: [99; 32],
        enclave_set: [5; 32],
    };
    let valid = register(
        ns.clone(),
        &f.a.proof(&ns, &mut OsRng).unwrap(),
        &f.b.proof(&ns, &mut OsRng).unwrap(),
    )
    .unwrap();
    let identity = {
        let mut b = [0; 32];
        b[0] = 1;
        b
    };
    let negative_zero = {
        let mut b = identity;
        b[31] = 128;
        b
    };
    for bytes in [identity, negative_zero, [0; 32], [255; 32]] {
        let mut reg = valid.clone();
        reg.public_shares[1] = bytes;
        let message = pair_registry::registration_message(&reg, &controller);
        let mut ixs: Vec<_> = f
            .identities
            .iter()
            .map(|k| {
                pairkey_sdk::ed25519_instruction(
                    k.pubkey().to_bytes(),
                    k.sign_message(&message).as_ref().try_into().unwrap(),
                    &message,
                )
            })
            .collect();
        ixs.push(pairkey_sdk::register(controller, controller, reg));
        assert!(f.send(ixs).is_err());
    }
    let mut degenerate = valid.clone();
    degenerate.public_shares[1] = degenerate.public_shares[0];
    degenerate.public_key = degenerate.public_shares[0];
    let message = pair_registry::registration_message(&degenerate, &controller);
    let mut ixs: Vec<_> = f
        .identities
        .iter()
        .map(|k| {
            pairkey_sdk::ed25519_instruction(
                k.pubkey().to_bytes(),
                k.sign_message(&message).as_ref().try_into().unwrap(),
                &message,
            )
        })
        .collect();
    ixs.push(pairkey_sdk::register(controller, controller, degenerate));
    assert!(f.send(ixs).is_err());
    let mut reg = valid;
    reg.public_key = reg.public_shares[0];
    let message = pair_registry::registration_message(&reg, &controller);
    let mut ixs: Vec<_> = f
        .identities
        .iter()
        .map(|k| {
            pairkey_sdk::ed25519_instruction(
                k.pubkey().to_bytes(),
                k.sign_message(&message).as_ref().try_into().unwrap(),
                &message,
            )
        })
        .collect();
    ixs.push(pairkey_sdk::register(controller, controller, reg));
    assert!(f.send(ixs).is_err());
}

#[test]
#[ignore = "requires SBF programs"]
fn controller_and_cpi_can_grant_revoke_and_version_sessions_but_cannot_reuse_ids_or_budget_promises(
) {
    use pair_registry::{PolicyRecord, SessionRecord};
    use pairkey_types::policy::*;
    let mut f = Fixture::new();
    for (id, cpi) in [(71, false), (72, true)] {
        let controller = if cpi {
            example_controller::authority(&example_controller::id(), &f.payer.pubkey()).0
        } else {
            f.payer.pubkey()
        };
        let reg = f.registration(controller, id, cpi);
        let payer = f.payer.pubkey();
        let wrap = |ix| {
            if cpi {
                pairkey_sdk::through_controller(payer, ix)
            } else {
                ix
            }
        };
        let policy = Policy {
            version: 1,
            allow_session: true,
            require_commit: false,
            require_session: true,
            access: None,
            simulation: None,
        };
        f.send(vec![wrap(pairkey_sdk::set_policy(
            f.payer.pubkey(),
            controller,
            &reg,
            policy.clone(),
        ))])
        .unwrap();
        let ns = pair_registry::namespace_address(&pair_registry::id(), &reg).0;
        let policy_address = pair_registry::policy_address(&pair_registry::id(), &ns).0;
        let record: PolicyRecord =
            borsh::from_slice(&f.svm.get_account(&policy_address).unwrap().data).unwrap();
        assert_eq!(record.policy, policy);
        let now = f
            .svm
            .get_sysvar::<solana_sdk::clock::Clock>()
            .unix_timestamp;
        let grant = SessionGrant {
            session_id: [id; 32],
            policy_version: 1,
            account: AccountPath {
                destination: solana_destination(reg.namespace.network),
                path: vec![0],
            },
            credential: Credential::Service {
                public_key: f.identities[0].pubkey().to_bytes(),
            },
            not_before: now,
            expires_at: now + 60,
            recipient: Pubkey::new_unique().to_bytes(),
            max_lamports_per_operation: 100,
            cumulative_budget: None,
        };
        let grant_ix = wrap(pairkey_sdk::grant_session(
            f.payer.pubkey(),
            controller,
            &reg,
            grant.clone(),
        ));
        f.send(vec![grant_ix.clone()]).unwrap();
        assert!(f.send(vec![grant_ix]).is_err());
        let session_address =
            pair_registry::session_address(&pair_registry::id(), &ns, &grant.session_id).0;
        let record: SessionRecord =
            borsh::from_slice(&f.svm.get_account(&session_address).unwrap().data).unwrap();
        assert_eq!(record.grant, grant);
        assert!(!record.revoked);
        f.send(vec![wrap(pairkey_sdk::revoke_session(
            controller,
            &reg,
            grant.session_id,
        ))])
        .unwrap();
        let record: SessionRecord =
            borsh::from_slice(&f.svm.get_account(&session_address).unwrap().data).unwrap();
        assert!(record.revoked);
        let mut budget = grant.clone();
        budget.session_id = [id + 2; 32];
        budget.cumulative_budget = Some(100);
        assert!(f
            .send(vec![wrap(pairkey_sdk::grant_session(
                f.payer.pubkey(),
                controller,
                &reg,
                budget
            ))])
            .is_err());
        let mut changed = policy.clone();
        changed.version = 2;
        changed.access = Some(Credential::Service {
            public_key: f.identities[1].pubkey().to_bytes(),
        });
        f.send(vec![wrap(pairkey_sdk::set_policy(
            f.payer.pubkey(),
            controller,
            &reg,
            changed,
        ))])
        .unwrap();
        assert!(f
            .send(vec![wrap(pairkey_sdk::set_policy(
                f.payer.pubkey(),
                controller,
                &reg,
                policy
            ))])
            .is_err());
    }
}

#[test]
#[ignore = "requires SBF programs"]
fn simulation_requires_real_enrolled_identity_proof_exact_state_and_no_preparatory_instructions() {
    use pairkey_types::policy::*;
    let mut f = Fixture::new();
    let controller = f.payer.pubkey();
    let reg = f.registration(controller, 81, false);
    let policy = Policy {
        version: 1,
        allow_session: false,
        require_commit: true,
        require_session: false,
        access: None,
        simulation: Some(SimulationConfig {
            program: example_policy::id().to_bytes(),
            code_hash: pairkey_core::code_hash(
                &f.svm.get_account(&example_policy::id()).unwrap().data,
            ),
            max_lamports: 100,
        }),
    };
    f.send(vec![pairkey_sdk::set_policy(
        controller,
        controller,
        &reg,
        policy.clone(),
    )])
    .unwrap();
    let ns = pair_registry::namespace_address(&pair_registry::id(), &reg).0;
    let set = pair_registry::set_address(&pair_registry::id(), &reg.namespace.enclave_set).0;
    let policy_address = pair_registry::policy_address(&pair_registry::id(), &ns).0;
    let input = SimulationInput {
        commit_digest: [9; 32],
        policy_digest: policy.digest(),
        authorization_digest: [10; 32],
        state_digest: simulation_state(
            &f.svm.get_account(&set).unwrap().data,
            &f.svm.get_account(&ns).unwrap().data,
            &f.svm.get_account(&policy_address).unwrap().data,
        ),
        recipient: Pubkey::new_unique().to_bytes(),
        lamports: 50,
    };
    let challenge = simulation_message(&input);
    let signature = f.identities[0]
        .sign_message(&challenge)
        .as_ref()
        .try_into()
        .unwrap();
    let mut tx = pairkey_sdk::simulation_transaction(
        example_policy::id(),
        controller,
        &reg,
        f.identities[0].pubkey().to_bytes(),
        signature,
        input.clone(),
    );
    tx.try_sign(&[&f.payer], f.svm.latest_blockhash()).unwrap();
    assert!(f.svm.simulate_transaction(tx.clone()).is_ok());
    let unknown = Keypair::new();
    let mut forged = pairkey_sdk::simulation_transaction(
        example_policy::id(),
        controller,
        &reg,
        unknown.pubkey().to_bytes(),
        unknown
            .sign_message(&challenge)
            .as_ref()
            .try_into()
            .unwrap(),
        input.clone(),
    );
    forged
        .try_sign(&[&f.payer], f.svm.latest_blockhash())
        .unwrap();
    assert!(f.svm.simulate_transaction(forged).is_err());
    let mut bad_state = input.clone();
    bad_state.state_digest[0] ^= 1;
    let sig = f.identities[0]
        .sign_message(&simulation_message(&bad_state))
        .as_ref()
        .try_into()
        .unwrap();
    let mut changed = pairkey_sdk::simulation_transaction(
        example_policy::id(),
        controller,
        &reg,
        f.identities[0].pubkey().to_bytes(),
        sig,
        bad_state,
    );
    changed
        .try_sign(&[&f.payer], f.svm.latest_blockhash())
        .unwrap();
    assert!(f.svm.simulate_transaction(changed).is_err());
    let mut injected = tx.clone();
    injected
        .message
        .instructions
        .insert(0, injected.message.instructions[0].clone());
    injected
        .try_sign(&[&f.payer], f.svm.latest_blockhash())
        .unwrap();
    assert!(f.svm.simulate_transaction(injected).is_err());
    let mut invalid = tx;
    invalid.message.instructions[0].data[16] ^= 1;
    invalid
        .try_sign(&[&f.payer], f.svm.latest_blockhash())
        .unwrap();
    assert!(f.svm.simulate_transaction(invalid).is_err());
    // Exercise maximum permitted access-credential strings and both identities
    // under the ordinary two-instruction simulation budget, with headroom.
    let mut large = policy.clone();
    large.version = 2;
    let passkey = p256::ecdsa::SigningKey::from_slice(&[70; 32]).unwrap();
    large.access = Some(Credential::Passkey {
        public_key: passkey
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        rp_id: "a".repeat(128),
        origin: format!("https://{}", "a".repeat(248)),
    });
    f.send(vec![pairkey_sdk::set_policy(
        controller,
        controller,
        &reg,
        large.clone(),
    )])
    .unwrap();
    let mut large_input = input;
    large_input.policy_digest = large.digest();
    large_input.state_digest = simulation_state(
        &f.svm.get_account(&set).unwrap().data,
        &f.svm.get_account(&ns).unwrap().data,
        &f.svm.get_account(&policy_address).unwrap().data,
    );
    for identity in &f.identities {
        let challenge = simulation_message(&large_input);
        let mut tx = pairkey_sdk::simulation_transaction(
            example_policy::id(),
            controller,
            &reg,
            identity.pubkey().to_bytes(),
            identity
                .sign_message(&challenge)
                .as_ref()
                .try_into()
                .unwrap(),
            large_input.clone(),
        );
        tx.try_sign(&[&f.payer], f.svm.latest_blockhash()).unwrap();
        let result = f.svm.simulate_transaction(tx).unwrap();
        assert!(
            result.meta.compute_units_consumed < 100_000,
            "simulation needs headroom: {}",
            result.meta.compute_units_consumed
        );
    }
}

#[test]
#[ignore = "requires SBF programs"]
fn account_and_cpi_evm_grants_preserve_scope_and_revocation() {
    use pair_registry::{EvmSessionRecord, PolicyRecord};
    use pairkey_types::policy::*;
    let mut f = Fixture::new();
    for (id, cpi) in [(71, false), (72, true)] {
        let controller = if cpi {
            example_controller::authority(&example_controller::id(), &f.payer.pubkey()).0
        } else {
            f.payer.pubkey()
        };
        let reg = f.registration(controller, id, cpi);
        let payer = f.payer.pubkey();
        let wrap = |ix| {
            if cpi {
                pairkey_sdk::through_controller(payer, ix)
            } else {
                ix
            }
        };
        let policy = Policy {
            version: 1,
            allow_session: true,
            require_commit: false,
            require_session: true,
            access: None,
            simulation: None,
        };
        f.send(vec![wrap(pairkey_sdk::set_policy(
            f.payer.pubkey(),
            controller,
            &reg,
            policy.clone(),
        ))])
        .unwrap();
        let ns = pair_registry::namespace_address(&pair_registry::id(), &reg).0;
        let policy_address = pair_registry::policy_address(&pair_registry::id(), &ns).0;
        let record: PolicyRecord =
            borsh::from_slice(&f.svm.get_account(&policy_address).unwrap().data).unwrap();
        assert_eq!(record.policy, policy);
        let now = f
            .svm
            .get_sysvar::<solana_sdk::clock::Clock>()
            .unix_timestamp;
        let grant = EvmSessionGrant {
            session_id: [id; 32],
            policy_version: 1,
            account: AccountPath {
                destination: evm_destination(31337),
                path: vec![0],
            },
            credential: Credential::Service {
                public_key: f.identities[0].pubkey().to_bytes(),
            },
            not_before: now,
            expires_at: now + 60,
            key_digest: [21; 32],
            chain_id: 31337,
            recipient: [42; 20],
            max_value_wei: 100,
            max_gas_price_wei: 10,
            max_fee_wei: 210000,
            cumulative_budget: None,
        };
        let grant_ix = wrap(pairkey_sdk::grant_evm_session(
            f.payer.pubkey(),
            controller,
            &reg,
            grant.clone(),
        ));
        f.send(vec![grant_ix.clone()]).unwrap();
        assert!(f.send(vec![grant_ix]).is_err());
        let session_address =
            pair_registry::evm_session_address(&pair_registry::id(), &ns, &grant.session_id).0;
        let record: EvmSessionRecord =
            borsh::from_slice(&f.svm.get_account(&session_address).unwrap().data).unwrap();
        assert_eq!(record.grant, grant);
        assert!(!record.revoked);
        f.send(vec![wrap(pairkey_sdk::revoke_evm_session(
            controller,
            &reg,
            grant.session_id,
        ))])
        .unwrap();
        let record: EvmSessionRecord =
            borsh::from_slice(&f.svm.get_account(&session_address).unwrap().data).unwrap();
        assert!(record.revoked);
        let mut budget = grant.clone();
        budget.session_id = [id + 2; 32];
        budget.cumulative_budget = Some(100);
        assert!(f
            .send(vec![wrap(pairkey_sdk::grant_evm_session(
                f.payer.pubkey(),
                controller,
                &reg,
                budget
            ))])
            .is_err());
        let mut changed = policy.clone();
        changed.version = 2;
        changed.access = Some(Credential::Service {
            public_key: f.identities[1].pubkey().to_bytes(),
        });
        f.send(vec![wrap(pairkey_sdk::set_policy(
            f.payer.pubkey(),
            controller,
            &reg,
            changed,
        ))])
        .unwrap();
        assert!(f
            .send(vec![wrap(pairkey_sdk::set_policy(
                f.payer.pubkey(),
                controller,
                &reg,
                policy
            ))])
            .is_err());
    }
}
