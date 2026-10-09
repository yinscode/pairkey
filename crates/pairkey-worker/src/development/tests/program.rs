//! Worker integration against an RPC adapter backed by actual SBF execution.
use super::*;
use borsh::BorshDeserialize;
use litesvm::LiteSVM;
use pairkey_types::program_approval::{Mode, Source};
use solana_sdk::{
    account::Account,
    clock::Clock,
    signature::{Keypair, Signer as SolanaSigner},
    transaction::Transaction,
};
pub(super) struct ProgramRpc {
    svm: LiteSVM,
    tamper_output: bool,
}
impl ProgramRpc {
    pub fn rpc(&mut self, state: &RpcState, q: &Value) -> Value {
        let o = state.observation.lock().unwrap();
        let account = |key: &str| -> Value {
            self.svm
                .get_account(&key.parse().unwrap())
                .map(|a| {
                    json!({"owner":a.owner.to_string(),"lamports":a.lamports,
                "executable":a.executable,"data":[STANDARD.encode(a.data),"base64"]})
                })
                .unwrap_or(Value::Null)
        };
        match q["method"].as_str().unwrap() {
            "getMultipleAccounts" => {
                json!({"context":{"slot":o.slot},"value":q["params"][0].as_array().unwrap().iter().map(|key|account(key.as_str().unwrap())).collect::<Vec<_>>()})
            }
            "getAccountInfo" => {
                json!({"context":{"slot":o.slot},"value":account(q["params"][0].as_str().unwrap())})
            }
            "getBlockTime" => json!(o.block_time),
            "getLatestBlockhash" => {
                json!({"context":{"slot":o.slot},"value":{"blockhash":self.svm.latest_blockhash().to_string()}})
            }
            "simulateTransaction" => {
                assert_eq!(q["params"][1]["sigVerify"], true);
                assert_eq!(q["params"][1]["replaceRecentBlockhash"], false);
                let bytes = STANDARD.decode(q["params"][0].as_str().unwrap()).unwrap();
                let tx: Transaction = bincode::deserialize(&bytes).unwrap();
                match self.svm.simulate_transaction(tx) {
                    Ok(out) => {
                        let mut data = out.meta.return_data.data;
                        if self.tamper_output {
                            data[0] ^= 1;
                        }
                        json!({"context":{"slot":o.slot},"value":{"err":null,"returnData":{"programId":out.meta.return_data.program_id.to_string(),"data":[STANDARD.encode(data),"base64"]}}})
                    }
                    Err(e) => json!({"context":{"slot":o.slot},"value":{"err":format!("{e:?}")}}),
                }
            }
            method => panic!("unexpected SBF RPC {method}"),
        }
    }
}
struct ProgramFixture {
    f: Fixture,
    q: Submission,
    owner: Keypair,
    policy: Pubkey,
}
impl ProgramFixture {
    async fn new(mode: Mode) -> Self {
        let owner = Keypair::from_bytes(
            &ed25519_dalek::SigningKey::from_bytes(&[42; 32]).to_keypair_bytes(),
        )
        .unwrap();
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
        let policy = example_controller::approval::policy_address(
            &example_controller::id(),
            &owner.pubkey(),
        )
        .0;
        let program_account = svm.get_account(&example_controller::id()).unwrap();
        assert!(pairkey_core::immutable_loader(program_account.owner));
        let source = Source {
            program: example_controller::id().to_bytes(),
            authority: example_controller::authority(&example_controller::id(), &owner.pubkey())
                .0
                .to_bytes(),
            seeds: vec![
                example_controller::AUTHORITY_SEED.to_vec(),
                owner.pubkey().to_bytes().to_vec(),
            ],
            code_hash: if mode == Mode::Offchain {
                pairkey_core::code_hash(&program_account.data)
            } else {
                [0; 32]
            },
            accounts: vec![policy.to_bytes()],
            mode,
        };
        let identity = Identity::Program(Box::new(source));
        let f = Fixture::new_source(false, Some(identity.clone())).await;
        let mut clock = svm.get_sysvar::<Clock>();
        clock.unix_timestamp = now();
        clock.slot = 100;
        svm.set_sysvar(&clock);
        svm.airdrop(&owner.pubkey(), 20_000_000_000).unwrap();
        svm.airdrop(
            &Pubkey::new_from_array(f.worker.channel.identity()),
            1_000_000_000,
        )
        .unwrap();
        let set = f.rpc.observation.lock().unwrap().set.clone();
        svm.set_account(
            set.address,
            Account {
                lamports: 10_000_000,
                data: set.data.clone(),
                owner: set.owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        let ix = pairkey_sdk::program_approval::example_policy(
            example_controller::id(),
            example_controller::approval::AppPolicy {
                owner: owner.pubkey().to_bytes(),
                enclave_set: [5; 32],
                revision: 1,
                enabled: true,
                destination: [8; 32],
                path_prefix: vec![1],
                max_payload_bytes: 512,
                require_commit: mode == Mode::Onchain,
                remaining_approvals: 2,
            },
        );
        svm.send_transaction(Transaction::new_signed_with_payer(
            &[ix],
            Some(&owner.pubkey()),
            &[&owner],
            svm.latest_blockhash(),
        ))
        .unwrap();
        let request = Request {
            version: 1,
            identity,
            commit: f.begin.attempt.commit.clone(),
            policy_revision: 0,
            policy_digest: Rules::default().digest(),
            issued_at: now(),
            expires_at: now() + 120,
        };
        let proof = Proof::Program {
            caller: owner.pubkey().to_bytes(),
            signature: owner
                .sign_message(&request.signing_message())
                .as_ref()
                .to_vec(),
        };
        let q = Submission {
            registration: f.begin.registration.clone(),
            payload: f.begin.message.clone(),
            approval: Approval { request, proof },
        };
        f.rpc.program.lock().unwrap().replace(ProgramRpc {
            svm,
            tamper_output: false,
        });
        Self {
            f,
            q,
            owner,
            policy,
        }
    }
    async fn approve(&mut self) {
        self.f.begin.attempt.authorization =
            offchain::approve(State(self.f.worker.clone()), Json(self.q.clone()))
                .await
                .unwrap()
                .0;
    }
    fn commit(&self) {
        let ix = pairkey_sdk::program_approval::example_commit(
            self.owner.pubkey(),
            self.q.registration.namespace.clone(),
            self.q.approval.request.clone(),
            self.q.payload.clone(),
        )
        .unwrap();
        let mut guard = self.f.rpc.program.lock().unwrap();
        let p = guard.as_mut().unwrap();
        p.svm
            .send_transaction(Transaction::new_signed_with_payer(
                &[ix],
                Some(&self.owner.pubkey()),
                &[&self.owner],
                p.svm.latest_blockhash(),
            ))
            .unwrap();
    }
    fn deny(&self) {
        let mut guard = self.f.rpc.program.lock().unwrap();
        let p = guard.as_mut().unwrap();
        let mut policy = example_controller::approval::AppPolicy::try_from_slice(
            &p.svm.get_account(&self.policy).unwrap().data,
        )
        .unwrap();
        policy.enabled = false;
        policy.revision += 1;
        let ix = pairkey_sdk::program_approval::example_policy(example_controller::id(), policy);
        p.svm.expire_blockhash();
        p.svm
            .send_transaction(Transaction::new_signed_with_payer(
                &[ix],
                Some(&self.owner.pubkey()),
                &[&self.owner],
                p.svm.latest_blockhash(),
            ))
            .unwrap();
        let mut o = self.f.rpc.observation.lock().unwrap();
        o.slot += 1;
        o.block_time = now();
        let mut clock = p.svm.get_sysvar::<Clock>();
        clock.slot = o.slot;
        clock.unix_timestamp = o.block_time;
        p.svm.set_sysvar(&clock);
    }
    async fn sign(&self) -> ResultResponse {
        let rounds = self.f.rounds().await;
        let shares = self.f.shares(&rounds).await;
        let output = result(
            State(self.f.worker.clone()),
            Json(ResultRequest {
                finish: rounds,
                shares,
            }),
        )
        .await
        .unwrap()
        .0;
        pairkey_sdk::service::verify_receipt(
            &self.q.registration,
            &self.f.begin.attempt,
            &self.q.payload,
            &output,
            self.f.worker.channel.identity(),
            Role::A,
            true,
        )
        .unwrap();
        output
    }
}
#[tokio::test]
#[ignore = "requires SBF programs"]
async fn worker_authenticates_program_caller_and_signs_only_after_real_simulation() {
    let mut p = ProgramFixture::new(Mode::Offchain).await;
    let mut bad = p.q.clone();
    if let Proof::Program { signature, .. } = &mut bad.approval.proof {
        signature[0] ^= 1;
    }
    assert!(offchain::approve(State(p.f.worker.clone()), Json(bad))
        .await
        .is_err());
    p.approve().await;
    p.sign().await;
    let guard = p.f.rpc.program.lock().unwrap();
    let policy = example_controller::approval::AppPolicy::try_from_slice(
        &guard
            .as_ref()
            .unwrap()
            .svm
            .get_account(&p.policy)
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(policy.remaining_approvals, 2);
}
#[tokio::test]
#[ignore = "requires SBF programs"]
async fn worker_requires_committed_program_record_and_does_not_consume_budget_again() {
    let mut p = ProgramFixture::new(Mode::Onchain).await;
    assert!(
        offchain::approve(State(p.f.worker.clone()), Json(p.q.clone()))
            .await
            .is_err()
    );
    p.commit();
    p.approve().await;
    p.sign().await;
    let guard = p.f.rpc.program.lock().unwrap();
    let policy = example_controller::approval::AppPolicy::try_from_slice(
        &guard
            .as_ref()
            .unwrap()
            .svm
            .get_account(&p.policy)
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(policy.remaining_approvals, 1);
}
#[tokio::test]
#[ignore = "requires SBF programs"]
async fn worker_rejects_tampered_program_result_and_denial_fences_prepared_release() {
    let mut p = ProgramFixture::new(Mode::Offchain).await;
    p.f.rpc
        .program
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .tamper_output = true;
    assert!(
        offchain::approve(State(p.f.worker.clone()), Json(p.q.clone()))
            .await
            .is_err()
    );
    p.f.rpc
        .program
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .tamper_output = false;
    p.approve().await;
    let view = p.f.worker.observe(&p.f.begin).await.unwrap();
    p.deny();
    assert!(p.f.worker.observe(&p.f.begin).await.is_err());
    assert!(p.f.worker.release_guard(&p.f.begin, &view).is_err());
}
