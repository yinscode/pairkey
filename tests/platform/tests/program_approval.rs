use borsh::BorshDeserialize;
use example_controller::approval::AppPolicy;
use litesvm::LiteSVM;
use pairkey_types::{
    approval::{Identity, Request, Rules},
    program_approval::{AccountState, Input, Mode, Output, Source},
    AccountPath, Commit, Namespace, Registration, Role, Scheme,
};
use rand_core::OsRng;
use solana_sdk::{
    clock::Clock,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
struct Fixture {
    svm: LiteSVM,
    owner: Keypair,
    identities: [Keypair; 2],
    reg: Registration,
    policy: Pubkey,
    set: Pubkey,
}
impl Fixture {
    fn new(require_commit: bool) -> Self {
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
        let mut clock = svm.get_sysvar::<Clock>();
        clock.unix_timestamp = 1000;
        svm.set_sysvar(&clock);
        let owner = Keypair::new();
        svm.airdrop(&owner.pubkey(), 20_000_000_000).unwrap();
        let identities = [Keypair::new(), Keypair::new()];
        let ns = Namespace {
            version: 1,
            scheme: Scheme::FrostEd25519,
            network: [1; 32],
            registry: pair_registry::id().to_bytes(),
            derivation_authority: example_controller::authority(
                &example_controller::id(),
                &owner.pubkey(),
            )
            .0
            .to_bytes(),
            namespace_id: [4; 32],
            enclave_set: [5; 32],
        };
        let a = pairkey_frost::Signer::new(pairkey_frost::Root::new([11; 32]), Role::A);
        let b = pairkey_frost::Signer::new(pairkey_frost::Root::new([22; 32]), Role::B);
        let reg = pairkey_frost::register(
            ns.clone(),
            &a.proof(&ns, &mut OsRng).unwrap(),
            &b.proof(&ns, &mut OsRng).unwrap(),
        )
        .unwrap();
        let policy = example_controller::approval::policy_address(
            &example_controller::id(),
            &owner.pubkey(),
        )
        .0;
        let set = pair_registry::set_address(&pair_registry::id(), &[5; 32]).0;
        let mut f = Self {
            svm,
            owner,
            identities,
            reg,
            policy,
            set,
        };
        f.send(vec![pairkey_sdk::create_set(
            f.owner.pubkey(),
            [5; 32],
            f.identities.each_ref().map(|k| k.pubkey().to_bytes()),
            true,
        )])
        .unwrap();
        f.send(vec![pairkey_sdk::program_approval::example_policy(
            example_controller::id(),
            AppPolicy {
                owner: f.owner.pubkey().to_bytes(),
                enclave_set: [5; 32],
                revision: 1,
                enabled: true,
                destination: [8; 32],
                path_prefix: vec![1],
                max_payload_bytes: 512,
                require_commit,
                remaining_approvals: 2,
            },
        )])
        .unwrap();
        assert!(f
            .svm
            .get_account(&pair_registry::namespace_address(&pair_registry::id(), &f.reg).0)
            .is_none());
        f
    }
    fn send(&mut self, instructions: Vec<Instruction>) -> Result<(), String> {
        self.svm.expire_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &instructions,
            Some(&self.owner.pubkey()),
            &[&self.owner],
            self.svm.latest_blockhash(),
        );
        assert!(
            bincode::serialized_size(&tx).unwrap() <= 1232,
            "must fit an actual Solana transaction: {}",
            bincode::serialized_size(&tx).unwrap()
        );
        self.svm
            .send_transaction(tx)
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }
    fn request(&self, mode: Mode, id: u8, message: &[u8]) -> Request {
        let program = self.svm.get_account(&example_controller::id()).unwrap();
        let identity = Identity::Program(Box::new(Source {
            program: example_controller::id().to_bytes(),
            authority: self.reg.namespace.derivation_authority,
            seeds: vec![
                example_controller::AUTHORITY_SEED.to_vec(),
                self.owner.pubkey().to_bytes().to_vec(),
            ],
            code_hash: if mode == Mode::Offchain {
                pairkey_core::code_hash(&program.data)
            } else {
                [0; 32]
            },
            accounts: vec![self.policy.to_bytes()],
            mode,
        }));
        Request {
            version: 1,
            identity,
            commit: Commit::new(
                &self.reg,
                [id; 32],
                AccountPath {
                    destination: [8; 32],
                    path: vec![1, 2],
                },
                message,
            )
            .unwrap(),
            policy_revision: 0,
            policy_digest: Rules::default().digest(),
            issued_at: 990,
            expires_at: 1100,
        }
    }
    fn state(&self) -> Vec<AccountState> {
        [self.set, self.policy]
            .map(|address| {
                let a = self.svm.get_account(&address).unwrap();
                AccountState {
                    address: address.to_bytes(),
                    owner: a.owner.to_bytes(),
                    lamports: a.lamports,
                    executable: a.executable,
                    data: a.data,
                }
            })
            .to_vec()
    }
    fn input(&self, request: &Request, message: Vec<u8>) -> Input {
        Input {
            version: 1,
            namespace_digest: self.reg.namespace.digest(),
            request_digest: request.digest(),
            authority: self.reg.namespace.derivation_authority,
            caller: self.owner.pubkey().to_bytes(),
            account: request.commit.account.clone(),
            request_id: request.commit.request_id,
            payload: message,
            expires_at: request.expires_at,
            state_digest: pairkey_types::program_approval::state_digest(&self.state()),
        }
    }
    fn tx(&self, input: &Input, signer: &Keypair) -> Transaction {
        let signature = signer
            .sign_message(&input.attestation_message())
            .as_ref()
            .try_into()
            .unwrap();
        let mut tx = pairkey_sdk::program_approval::simulation_transaction(
            example_controller::id(),
            self.owner.pubkey(),
            self.set,
            &[self.policy.to_bytes()],
            signer.pubkey().to_bytes(),
            signature,
            input,
        )
        .unwrap();
        tx.sign(&[&self.owner], self.svm.latest_blockhash());
        tx
    }
    fn current(&self) -> AppPolicy {
        AppPolicy::try_from_slice(&self.svm.get_account(&self.policy).unwrap().data).unwrap()
    }
    fn commit(&self, request: Request, message: Vec<u8>) -> Instruction {
        pairkey_sdk::program_approval::example_commit(
            self.owner.pubkey(),
            self.reg.namespace.clone(),
            request,
            message,
        )
        .unwrap()
    }
}
#[test]
#[ignore = "requires SBF programs"]
fn program_simulation_authenticates_context_and_cannot_consume_state() {
    let f = Fixture::new(false);
    let request = f.request(Mode::Offchain, 7, b"hello");
    let input = f.input(&request, b"hello".to_vec());
    let before = f.svm.get_account(&f.policy).unwrap();
    let balance = f.svm.get_account(&f.owner.pubkey()).unwrap().lamports;
    for signer in &f.identities {
        let result = f.svm.simulate_transaction(f.tx(&input, signer)).unwrap();
        let output = Output::try_from_slice(&result.meta.return_data.data).unwrap();
        assert!(output.allowed);
        assert_eq!(output.input_digest, input.digest());
        assert!(result.meta.compute_units_consumed < 100_000);
    }
    assert_eq!(f.svm.get_account(&f.policy).unwrap().data, before.data);
    assert_eq!(
        f.svm.get_account(&f.owner.pubkey()).unwrap().lamports,
        balance
    );
    assert!(f
        .svm
        .simulate_transaction(f.tx(&input, &Keypair::new()))
        .is_err());
    let mut forged = input.clone();
    forged.caller = Keypair::new().pubkey().to_bytes();
    let result = f
        .svm
        .simulate_transaction(f.tx(&forged, &f.identities[0]))
        .unwrap();
    assert!(
        !Output::try_from_slice(&result.meta.return_data.data)
            .unwrap()
            .allowed
    );
    let mut forged = input.clone();
    forged.state_digest[0] ^= 1;
    assert!(f
        .svm
        .simulate_transaction(f.tx(&forged, &f.identities[0]))
        .is_err());
    let mut forged = input.clone();
    forged.expires_at = 999;
    assert!(f
        .svm
        .simulate_transaction(f.tx(&forged, &f.identities[0]))
        .is_err());
    let mut forged = input;
    forged.account.destination = [9; 32];
    let result = f
        .svm
        .simulate_transaction(f.tx(&forged, &f.identities[0]))
        .unwrap();
    assert!(
        !Output::try_from_slice(&result.meta.return_data.data)
            .unwrap()
            .allowed
    );
}
#[test]
#[ignore = "requires SBF programs"]
fn commit_consumes_budget_atomically_without_registration_and_duplicate_rolls_back() {
    let mut f = Fixture::new(true);
    let offchain = f.request(Mode::Offchain, 7, b"hello");
    let result = f
        .svm
        .simulate_transaction(f.tx(&f.input(&offchain, b"hello".to_vec()), &f.identities[0]))
        .unwrap();
    assert!(
        !Output::try_from_slice(&result.meta.return_data.data)
            .unwrap()
            .allowed
    );
    let request = f.request(Mode::Onchain, 7, b"hello");
    let ix = f.commit(request.clone(), b"hello".to_vec());
    f.send(vec![ix.clone()]).unwrap();
    assert_eq!(f.current().remaining_approvals, 1);
    let address = pair_registry::program_approval::approval_address(
        &pair_registry::id(),
        &f.reg.namespace.digest(),
        &[7; 32],
    )
    .0;
    let record = pair_registry::program_approval::ProgramApprovalRecord::try_from_slice(
        &f.svm.get_account(&address).unwrap().data,
    )
    .unwrap();
    assert_eq!(record.request_digest, request.digest());
    assert_eq!(record.expires_at, 1100);
    assert!(f.send(vec![ix]).is_err());
    assert_eq!(f.current().remaining_approvals, 1);
    let wrong = f.request(Mode::Onchain, 8, b"different");
    assert!(f.send(vec![f.commit(wrong, b"hello".to_vec())]).is_err());
    assert_eq!(f.current().remaining_approvals, 1);
    let next = f.request(Mode::Onchain, 8, b"hello");
    f.send(vec![f.commit(next, b"hello".to_vec())]).unwrap();
    assert_eq!(f.current().remaining_approvals, 0);
    let exhausted = f.request(Mode::Onchain, 9, b"hello");
    assert!(f
        .send(vec![f.commit(exhausted, b"hello".to_vec())])
        .is_err());
    assert!(f
        .svm
        .get_account(&pair_registry::namespace_address(&pair_registry::id(), &f.reg).0)
        .is_none());
}
#[test]
#[ignore = "requires SBF programs"]
fn program_policy_changes_invalidate_old_state_and_require_owner_next_revision() {
    let mut f = Fixture::new(false);
    let r = f.request(Mode::Offchain, 7, b"hello");
    let old = f.input(&r, b"hello".to_vec());
    let mut update = f.current();
    update.enabled = false;
    assert!(f
        .send(vec![pairkey_sdk::program_approval::example_policy(
            example_controller::id(),
            update.clone()
        )])
        .is_err());
    update.revision += 1;
    f.send(vec![pairkey_sdk::program_approval::example_policy(
        example_controller::id(),
        update,
    )])
    .unwrap();
    assert!(f
        .svm
        .simulate_transaction(f.tx(&old, &f.identities[0]))
        .is_err());
    let fresh = f.input(&r, b"hello".to_vec());
    let result = f
        .svm
        .simulate_transaction(f.tx(&fresh, &f.identities[0]))
        .unwrap();
    assert!(
        !Output::try_from_slice(&result.meta.return_data.data)
            .unwrap()
            .allowed
    );
    let mut wrong = f.current();
    wrong.owner = Keypair::new().pubkey().to_bytes();
    wrong.revision += 1;
    let mut ix = pairkey_sdk::program_approval::example_policy(example_controller::id(), wrong);
    ix.accounts[0].pubkey = f.owner.pubkey();
    ix.accounts[1].pubkey = f.policy;
    assert!(f.send(vec![ix]).is_err());
}

#[test]
#[ignore = "requires SBF programs"]
fn program_authority_and_standard_rules_cannot_be_forged_by_a_wallet() {
    use pairkey_types::approval::{PolicyProof, PolicyUpdate};
    let mut f = Fixture::new(false);
    let request = f.request(Mode::Onchain, 7, b"hello");
    let call = pairkey_types::program_approval::CommitCall {
        namespace: f.reg.namespace.clone(),
        request: request.clone(),
        payload: b"hello".to_vec(),
    };
    let ix = pairkey_sdk::program_approval::commit_instruction(
        f.owner.pubkey(),
        f.owner.pubkey(),
        call.approval(),
    );
    assert!(f.send(vec![ix]).is_err());
    let update = PolicyUpdate {
        namespace: f.reg.namespace.clone(),
        identity: request.identity.clone(),
        rules: Rules {
            revision: 1,
            disabled: true,
            ..Rules::default()
        },
        issued_at: 990,
        expires_at: 1100,
    };
    let mut direct =
        pairkey_sdk::approval::set_rules(f.owner.pubkey(), update.clone(), PolicyProof::ProgramCpi);
    direct.accounts[1].pubkey = f.owner.pubkey();
    assert!(f.send(vec![direct]).is_err());
    let Identity::Program(source) = &request.identity else {
        unreachable!()
    };
    let mut forged = source.clone();
    forged.program = Keypair::new().pubkey().to_bytes();
    assert!(pair_registry::program_approval::validate_source(&forged).is_err());
    let ix = pairkey_sdk::through_controller(
        f.owner.pubkey(),
        pairkey_sdk::approval::set_rules(f.owner.pubkey(), update.clone(), PolicyProof::ProgramCpi),
    );
    f.send(vec![ix.clone()]).unwrap();
    assert!(f.send(vec![ix]).is_err());
    let address =
        pair_registry::approval::rules_address(&pair_registry::id(), &f.reg.namespace.digest()).0;
    let record = pair_registry::approval::RulesRecord::try_from_slice(
        &f.svm.get_account(&address).unwrap().data,
    )
    .unwrap();
    assert_eq!(record.rules, update.rules);
    // A separately created, attacker-controlled enclave set cannot authenticate this app's input.
    f.send(vec![pairkey_sdk::create_set(
        f.owner.pubkey(),
        [99; 32],
        [
            f.owner.pubkey().to_bytes(),
            Keypair::new().pubkey().to_bytes(),
        ],
        true,
    )])
    .unwrap();
    let set = pair_registry::set_address(&pair_registry::id(), &[99; 32]).0;
    let mut input = f.input(&request, b"hello".to_vec());
    let mut states = f.state();
    let a = f.svm.get_account(&set).unwrap();
    states[0] = AccountState {
        address: set.to_bytes(),
        owner: a.owner.to_bytes(),
        lamports: a.lamports,
        executable: a.executable,
        data: a.data,
    };
    input.state_digest = pairkey_types::program_approval::state_digest(&states);
    let signature = f
        .owner
        .sign_message(&input.attestation_message())
        .as_ref()
        .try_into()
        .unwrap();
    let mut tx = pairkey_sdk::program_approval::simulation_transaction(
        example_controller::id(),
        f.owner.pubkey(),
        set,
        &[f.policy.to_bytes()],
        f.owner.pubkey().to_bytes(),
        signature,
        &input,
    )
    .unwrap();
    tx.sign(&[&f.owner], f.svm.latest_blockhash());
    assert!(f.svm.simulate_transaction(tx).is_err());
}
