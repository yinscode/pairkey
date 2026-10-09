use super::*;
use pairkey_sdk::hosted::offchain::management::*;
use pairkey_types::program_approval::Mode;
use sha2::{Digest, Sha256};
use solana_sdk::{account::Account, clock::Clock, transaction::Transaction};

struct Programs {
    svm: litesvm::LiteSVM,
    owner: Keypair,
}
impl Programs {
    fn new(f: &Fixture) -> Self {
        let mut svm = litesvm::LiteSVM::new();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy");
        svm.add_program_from_file(pair_registry::id(), root.join("pair_registry.so"))
            .unwrap();
        svm.add_program_from_file(example_controller::id(), root.join("example_controller.so"))
            .unwrap();
        let mut clock = svm.get_sysvar::<Clock>();
        clock.unix_timestamp = crate::chain::now().unwrap();
        svm.set_sysvar(&clock);
        let owner = Keypair::new();
        svm.airdrop(&owner.pubkey(), 10_000_000_000).unwrap();
        let set = pair_registry::set_address(&pair_registry::id(), &f.app.journal.read().set_id).0;
        let value = f.accounts.lock().unwrap()[&set.to_string()].clone();
        svm.set_account(
            set,
            Account {
                lamports: 10_000_000,
                data: STANDARD.decode(value["data"][0].as_str().unwrap()).unwrap(),
                owner: pair_registry::id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        Self { svm, owner }
    }
    fn owner_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.owner.to_bytes()[..32].try_into().unwrap())
    }
    fn send(&mut self, list: &Instructions) {
        let mut clock = self.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = crate::chain::now().unwrap();
        self.svm.set_sysvar(&clock);
        let mut instructions = vec![
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ];
        instructions.extend(list.instructions.iter().map(|i| i.instruction().unwrap()));
        let tx = Transaction::new_signed_with_payer(
            &instructions,
            Some(&self.owner.pubkey()),
            &[&self.owner],
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).unwrap();
    }
    fn publish(&self, f: &Fixture, address: Pubkey) {
        let a = self.svm.get_account(&address).unwrap();
        f.accounts.lock().unwrap().insert(address.to_string(),json!({"owner":a.owner.to_string(),"data":[STANDARD.encode(a.data),"base64"],"lamports":a.lamports,"executable":a.executable}));
    }
}
#[tokio::test]
#[ignore = "requires SBF programs built by scripts/build-programs.sh"]
async fn hosted_wallet_policy_helpers_execute_real_gateway_updates() {
    let f = Fixture::new().await;
    let mut p = Programs::new(&f);
    let owner = p.owner_key();
    let ns = f.metadata(&owner).await;
    let read: RulesResponse = f
        .client
        .post(
            "/policies",
            &RulesRequest {
                registration: ns.proposal.registration.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(read.rules, Rules::default());
    let q = PolicyRequest {
        registration: ns.proposal.registration.clone(),
        identity: ns.identity.clone(),
        rules: Rules {
            revision: 1,
            path_prefixes: Some(vec![vec![0]]),
            ..Rules::default()
        },
    };
    let update: PolicyPrepared = f.client.post("/policies/prepare", &q).await.unwrap();
    update.verify(&q, crate::chain::now().unwrap()).unwrap();
    let authorize = PolicyInstructionsRequest {
        payer: p.owner.pubkey().to_string(),
        update: update.update,
        authentication: PolicyAuthentication::Wallet,
    };
    let instructions: Instructions = f
        .client
        .post("/policies/instructions", &authorize)
        .await
        .unwrap();
    p.send(&instructions);
    p.publish(&f, read.policy_address.parse().unwrap());
    assert!(
        f.client
            .post::<Value>("/policies/instructions", &authorize)
            .await
            .is_err(),
        "stale revision must be rejected"
    );
    let (prepared, key) = f.prepared(&ns, Chain::Solana).await;
    assert_eq!(prepared.request.policy_revision, 1);
    let id: Value = f
        .client
        .post("/jobs", &signed(&prepared, &owner))
        .await
        .unwrap();
    let result = f.wait(id["job_id"].as_str().unwrap()).await;
    wire::verify_result(
        &prepared.signing_request,
        &prepared.request,
        &key,
        &result,
        f.app.identities,
    )
    .unwrap();
    let mut changed = q.clone();
    changed.rules.revision = 2;
    changed.rules.disabled = true;
    let update: PolicyPrepared = f.client.post("/policies/prepare", &changed).await.unwrap();
    let authorize = PolicyInstructionsRequest {
        payer: p.owner.pubkey().to_string(),
        update: update.update,
        authentication: PolicyAuthentication::Wallet,
    };
    let instructions: Instructions = f
        .client
        .post("/policies/instructions", &authorize)
        .await
        .unwrap();
    p.send(&instructions);
    p.publish(&f, read.policy_address.parse().unwrap());
    let mut next = prepared.signing_request.clone();
    next.request_id = fresh();
    assert!(f
        .client
        .post::<Value>(
            "/approvals",
            &wire::PrepareRequest {
                signing_request: next,
                identity: ns.identity
            }
        )
        .await
        .is_err());
    assert!(
        p.svm
            .get_account(&ns.namespace_address.parse().unwrap())
            .is_none(),
        "no registration account required"
    );
    f.close().await;
}
#[tokio::test]
#[ignore = "requires SBF programs built by scripts/build-programs.sh"]
async fn hosted_program_helpers_execute_policy_and_commit_before_signing() {
    let f = Fixture::new().await;
    let mut p = Programs::new(&f);
    let owner = p.owner_key();
    let q = ExampleSourceRequest {
        program: example_controller::id().to_string(),
        owner: p.owner.pubkey().to_string(),
        mode: Mode::Onchain,
    };
    let source: ExampleSourceResponse = f.client.post("/programs/example", &q).await.unwrap();
    assert_eq!(
        source.identity.authority(),
        example_controller::authority(&example_controller::id(), &p.owner.pubkey())
            .0
            .to_bytes()
    );
    let nsq = wire::NamespaceRequest {
        identity: source.identity.clone(),
        namespace_id: [0; 32],
    };
    let ns: wire::NamespaceResponse = f.client.post("/namespaces", &nsq).await.unwrap();
    wire::verify_namespace(
        &nsq,
        &ns,
        GENESIS.parse::<Pubkey>().unwrap().to_bytes(),
        pair_registry::id(),
        f.app.journal.read().set_id,
        f.app.identities,
    )
    .unwrap();
    let policy = ExamplePolicyRequest {
        program: q.program,
        owner: q.owner,
        revision: 1,
        enabled: true,
        chain: Chain::Solana,
        path_prefix: vec![0],
        max_payload_bytes: 1232,
        require_commit: true,
        remaining_approvals: 2,
    };
    let instructions: Instructions = f
        .client
        .post("/programs/example/policy", &policy)
        .await
        .unwrap();
    p.send(&instructions);
    p.publish(&f, source.policy_address.parse().unwrap());
    assert!(f
        .client
        .post::<Value>("/programs/example/policy", &policy)
        .await
        .is_err());
    let (prepared, key) = f.prepared(&ns, Chain::Solana).await;
    let submission = prepared.clone().submission(Proof::Program {
        caller: owner.verifying_key().to_bytes(),
        signature: owner.sign(&prepared.signing_message).to_bytes().to_vec(),
    });
    assert!(
        f.client.post::<Value>("/jobs", &submission).await.is_err(),
        "committed approval must exist before signing"
    );
    let instructions: Instructions = f
        .client
        .post(
            "/programs/example/commit",
            &ExampleCommitRequest {
                owner: p.owner.pubkey().to_string(),
                prepared: prepared.clone(),
            },
        )
        .await
        .unwrap();
    p.send(&instructions);
    let address = pair_registry::program_approval::approval_address(
        &pair_registry::id(),
        &ns.proposal.registration.namespace.digest(),
        &prepared.signing_request.request_id,
    )
    .0;
    p.publish(&f, address);
    let id: Value = f.client.post("/jobs", &submission).await.unwrap();
    let result = f.wait(id["job_id"].as_str().unwrap()).await;
    wire::verify_result(
        &prepared.signing_request,
        &prepared.request,
        &key,
        &result,
        f.app.identities,
    )
    .unwrap();
    let policy: example_controller::approval::AppPolicy = borsh::from_slice(
        &p.svm
            .get_account(&source.policy_address.parse().unwrap())
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(
        policy.remaining_approvals, 1,
        "signing must not consume the committed budget a second time"
    );
    f.close().await;
}

fn assertion(
    key: &p256::ecdsa::SigningKey,
    challenge: [u8; 32],
) -> pairkey_types::approval::Assertion {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut auth = Sha256::digest(b"pairkey.example").to_vec();
    auth.push(5);
    auth.extend([0; 4]);
    let client=serde_json::to_vec(&json!({"type":"webauthn.get","challenge":URL_SAFE_NO_PAD.encode(challenge),"origin":"https://pairkey.example"})).unwrap();
    let mut message = auth.clone();
    message.extend(Sha256::digest(&client));
    let sig: p256::ecdsa::Signature = key.sign(&message);
    pairkey_types::approval::Assertion {
        authenticator_data: auth,
        client_data_json: client,
        signature_der: sig.to_der().as_bytes().to_vec(),
    }
}

#[tokio::test]
#[ignore = "requires SBF programs built by scripts/build-programs.sh"]
async fn hosted_program_simulation_uses_deployed_code_and_never_consumes_a_counter() {
    let f = Fixture::new().await;
    let mut p = Programs::new(&f);
    let owner = p.owner_key();
    p.publish(&f, example_controller::id());
    let q = ExampleSourceRequest {
        program: example_controller::id().to_string(),
        owner: p.owner.pubkey().to_string(),
        mode: Mode::Offchain,
    };
    let source: ExampleSourceResponse = f.client.post("/programs/example", &q).await.unwrap();
    let Identity::Program(ref src) = source.identity else {
        panic!("program source")
    };
    assert_eq!(
        src.code_hash,
        pairkey_core::code_hash(&p.svm.get_account(&example_controller::id()).unwrap().data)
    );
    let nsq = wire::NamespaceRequest {
        identity: source.identity.clone(),
        namespace_id: [0; 32],
    };
    let ns: wire::NamespaceResponse = f.client.post("/namespaces", &nsq).await.unwrap();
    let policy = ExamplePolicyRequest {
        program: q.program,
        owner: q.owner,
        revision: 1,
        enabled: true,
        chain: Chain::Solana,
        path_prefix: vec![0],
        max_payload_bytes: 1232,
        require_commit: false,
        remaining_approvals: 2,
    };
    let instructions: Instructions = f
        .client
        .post("/programs/example/policy", &policy)
        .await
        .unwrap();
    p.send(&instructions);
    for key in f.app.identities {
        p.svm
            .airdrop(&Pubkey::new_from_array(key), 1_000_000_000)
            .unwrap();
    }
    *f.rpc_state.vm.lock().unwrap() = Some(p.svm);
    let current: Option<ExamplePolicyState> = f
        .client
        .post(
            "/programs/example/policy/read",
            &ExamplePolicyReadRequest {
                program: example_controller::id().to_string(),
                owner: p.owner.pubkey().to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(current.unwrap().revision, 1);
    let (prepared, key) = f.prepared(&ns, Chain::Solana).await;
    let submission = prepared.clone().submission(Proof::Program {
        caller: owner.verifying_key().to_bytes(),
        signature: owner.sign(&prepared.signing_message).to_bytes().to_vec(),
    });
    let job: Value = f.client.post("/jobs", &submission).await.unwrap();
    let result = f.wait(job["job_id"].as_str().unwrap()).await;
    wire::verify_result(
        &prepared.signing_request,
        &prepared.request,
        &key,
        &result,
        f.app.identities,
    )
    .unwrap();
    {
        let lock = f.rpc_state.vm.lock().unwrap();
        let vm = lock.as_ref().unwrap();
        let policy: example_controller::approval::AppPolicy = borsh::from_slice(
            &vm.get_account(&source.policy_address.parse().unwrap())
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(policy.remaining_approvals, 2);
        let request = pair_registry::program_approval::approval_address(
            &pair_registry::id(),
            &ns.proposal.registration.namespace.digest(),
            &prepared.signing_request.request_id,
        )
        .0;
        assert!(
            vm.get_account(&request).is_none(),
            "read-only evaluation must not create an approval account"
        );
    }
    f.close().await;
}
#[tokio::test]
#[ignore = "requires SBF programs built by scripts/build-programs.sh"]
async fn hosted_passkey_updates_policy_natively_and_signs_with_a_bound_ephemeral_key() {
    let f = Fixture::new().await;
    let mut p = Programs::new(&f);
    let passkey = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let identity = Identity::Passkey {
        public_key: passkey
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        rp_id: "pairkey.example".into(),
        origin: "https://pairkey.example".into(),
    };
    let nsq = wire::NamespaceRequest {
        identity: identity.clone(),
        namespace_id: [0; 32],
    };
    let ns: wire::NamespaceResponse = f.client.post("/namespaces", &nsq).await.unwrap();
    wire::verify_namespace(
        &nsq,
        &ns,
        GENESIS.parse::<Pubkey>().unwrap().to_bytes(),
        pair_registry::id(),
        f.app.journal.read().set_id,
        f.app.identities,
    )
    .unwrap();
    let q = PolicyRequest {
        registration: ns.proposal.registration.clone(),
        identity: identity.clone(),
        rules: Rules {
            revision: 1,
            ..Rules::default()
        },
    };
    let update: PolicyPrepared = f.client.post("/policies/prepare", &q).await.unwrap();
    update.verify(&q, crate::chain::now().unwrap()).unwrap();
    let auth = PolicyAuthentication::Passkey(assertion(&passkey, update.challenge));
    let instructions: Instructions = f
        .client
        .post(
            "/policies/instructions",
            &PolicyInstructionsRequest {
                payer: p.owner.pubkey().to_string(),
                update: update.update,
                authentication: auth,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        instructions.instructions[0].program_id,
        pair_registry::approval::P256_PROGRAM.to_string()
    );
    p.send(&instructions);
    p.publish(
        &f,
        pair_registry::approval::rules_address(
            &pair_registry::id(),
            &ns.proposal.registration.namespace.digest(),
        )
        .0,
    );
    let (prepared, key) = f.prepared(&ns, Chain::Solana).await;
    let ephemeral = SigningKey::from_bytes(&fresh());
    let binding = pairkey_types::approval::Binding {
        namespace_digest: ns.proposal.registration.namespace.digest(),
        identity_digest: identity.digest(),
        public_key: ephemeral.verifying_key().to_bytes(),
        issued_at: prepared.request.issued_at,
        expires_at: prepared.request.expires_at,
    };
    let proof = Proof::Passkey {
        assertion: assertion(&passkey, binding.challenge()),
        signature: ephemeral
            .sign(&prepared.signing_message)
            .to_bytes()
            .to_vec(),
        binding,
    };
    let submission = prepared.clone().submission(proof);
    let mut wrong = submission.clone();
    if let Proof::Passkey { binding, .. } = &mut wrong.approval.proof {
        binding.public_key = fresh();
    }
    assert!(
        f.client.post::<Value>("/jobs", &wrong).await.is_err(),
        "a valid passkey assertion cannot bind a different ephemeral key"
    );
    let job: Value = f.client.post("/jobs", &submission).await.unwrap();
    let result = f.wait(job["job_id"].as_str().unwrap()).await;
    wire::verify_result(
        &prepared.signing_request,
        &prepared.request,
        &key,
        &result,
        f.app.identities,
    )
    .unwrap();
    let journal = std::fs::read_to_string(f.dir.join("hosted.json")).unwrap();
    assert!(
        !journal.contains("authenticator_data")
            && !journal.contains("signature_der")
            && !journal.contains("client_data_json")
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires SBF programs built by scripts/build-programs.sh"]
async fn hosted_oidc_policy_fetches_https_keys_and_executes_dual_attested_update() {
    let issuer = super::oidc::Issuer::start().await;
    let f = Fixture::with_oidc(
        vec![issuer.config.clone()],
        Some(super::oidc::Issuer::root()),
    )
    .await;
    let mut p = Programs::new(&f);
    let ns = issuer.namespace(&f).await;
    let q = PolicyRequest {
        registration: ns.proposal.registration.clone(),
        identity: ns.identity.clone(),
        rules: Rules {
            revision: 1,
            path_prefixes: Some(vec![vec![0]]),
            ..Rules::default()
        },
    };
    let prepared: PolicyPrepared = f.client.post("/policies/prepare", &q).await.unwrap();
    prepared.verify(&q, crate::chain::now().unwrap()).unwrap();
    let ephemeral = SigningKey::from_bytes(&fresh());
    let binding = super::oidc::binding(
        &ns,
        &ephemeral,
        prepared.update.issued_at,
        prepared.update.expires_at,
    );
    let token = issuer.token(&binding);
    let approval = PolicyInstructionsRequest {
        payer: p.owner.pubkey().to_string(),
        authentication: PolicyAuthentication::Oidc {
            binding,
            id_token: token.clone(),
            signature: ephemeral
                .sign(&prepared.signing_message)
                .to_bytes()
                .to_vec(),
        },
        update: prepared.update,
    };
    let mut wrong = approval.clone();
    wrong.update.rules.disabled = true;
    assert!(f
        .client
        .post::<Value>("/policies/instructions", &wrong)
        .await
        .is_err());
    let instructions: Instructions = f
        .client
        .post("/policies/instructions", &approval)
        .await
        .unwrap();
    assert!(!serde_json::to_string(&instructions)
        .unwrap()
        .contains(&token));
    p.send(&instructions);
    let address = pair_registry::approval::rules_address(
        &pair_registry::id(),
        &ns.proposal.registration.namespace.digest(),
    )
    .0;
    p.publish(&f, address);
    let read: RulesResponse = f
        .client
        .post(
            "/policies",
            &RulesRequest {
                registration: ns.proposal.registration.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(read.rules, q.rules);
    assert!(
        f.client
            .post::<Value>("/policies/instructions", &approval)
            .await
            .is_err(),
        "stale revision accepted"
    );
    let (prepared, key) = f.prepared(&ns, Chain::Solana).await;
    let binding = super::oidc::binding(
        &ns,
        &ephemeral,
        prepared.request.issued_at,
        prepared.request.expires_at,
    );
    let proof = Proof::Oidc {
        id_token: issuer.token(&binding),
        binding,
        signature: ephemeral
            .sign(&prepared.signing_message)
            .to_bytes()
            .to_vec(),
    };
    let job: Value = f
        .client
        .post("/jobs", &prepared.clone().submission(proof))
        .await
        .unwrap();
    let result = f.wait(job["job_id"].as_str().unwrap()).await;
    wire::verify_result(
        &prepared.signing_request,
        &prepared.request,
        &key,
        &result,
        f.app.identities,
    )
    .unwrap();
    assert_eq!(issuer.requests.load(std::sync::atomic::Ordering::SeqCst), 2);
    f.close().await;
}
