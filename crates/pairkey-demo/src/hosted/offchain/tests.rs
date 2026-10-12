//! Real HTTP coordinator and two independent development workers. Only Solana
//! account reads are supplied by a deterministic RPC fixture; no approval tx exists.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::Signer as _;
use pairkey_types::approval::{Approval as PrivateApproval, Proof};
mod management;
mod oidc;

struct Fixture {
    app: Arc<App>,
    client: pairkey_sdk::hosted::Client,
    accounts: Arc<Mutex<BTreeMap<String, Value>>>,
    rpc_state: Arc<TestRpc>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    dir: PathBuf,
    endpoint: String,
}
struct TestRpc {
    accounts: Arc<Mutex<BTreeMap<String, Value>>>,
    vm: Mutex<Option<litesvm::LiteSVM>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
async fn test_rpc(State(state): State<Arc<TestRpc>>, Json(q): Json<Value>) -> Json<Value> {
    let slot = crate::chain::now().unwrap() as u64;
    if let Some(vm) = state.vm.lock().unwrap().as_mut() {
        let mut clock = vm.get_sysvar::<solana_sdk::clock::Clock>();
        clock.unix_timestamp = slot as i64;
        clock.slot = slot;
        vm.set_sysvar(&clock);
        let account = |key: &Value| {
            vm.get_account(&key.as_str().unwrap().parse().unwrap()).map(|a|json!({"owner":a.owner.to_string(),"data":[STANDARD.encode(a.data),"base64"],"lamports":a.lamports,"executable":a.executable})).unwrap_or(Value::Null)
        };
        let result = match q["method"].as_str().unwrap() {
            "getGenesisHash" => json!(GENESIS),
            "getBlockTime" => json!(slot),
            "getAccountInfo" => json!({"context":{"slot":slot},"value":account(&q["params"][0])}),
            "getMultipleAccounts" => {
                json!({"context":{"slot":slot},"value":q["params"][0].as_array().unwrap().iter().map(account).collect::<Vec<_>>()})
            }
            "getLatestBlockhash" => {
                json!({"context":{"slot":slot},"value":{"blockhash":vm.latest_blockhash().to_string()}})
            }
            "simulateTransaction" => {
                assert_eq!(q["params"][1]["sigVerify"], true);
                assert_eq!(q["params"][1]["replaceRecentBlockhash"], false);
                let tx: solana_sdk::transaction::Transaction = bincode::deserialize(
                    &STANDARD.decode(q["params"][0].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                match vm.simulate_transaction(tx) {
                    Ok(out) => {
                        json!({"context":{"slot":slot},"value":{"err":null,"returnData":{"programId":out.meta.return_data.program_id.to_string(),"data":[STANDARD.encode(out.meta.return_data.data),"base64"]}}})
                    }
                    Err(e) => json!({"context":{"slot":slot},"value":{"err":format!("{e:?}")}}),
                }
            }
            method => panic!("RPC evaluation must not broadcast: {method}"),
        };
        return Json(json!({"jsonrpc":"2.0","id":q["id"],"result":result}));
    }
    let accounts = &state.accounts;
    let result = match q["method"].as_str().unwrap() {
        "getGenesisHash" => json!(GENESIS),
        "getBlockTime" => json!(crate::chain::now().unwrap()),
        "getAccountInfo" => {
            json!({"context":{"slot":slot},"value":accounts.lock().unwrap().get(q["params"][0].as_str().unwrap()).cloned().unwrap_or(Value::Null)})
        }
        "getMultipleAccounts" => {
            let map = accounts.lock().unwrap();
            let values: Vec<Value> = q["params"][0]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| map.get(a.as_str().unwrap()).cloned().unwrap_or(Value::Null))
                .collect();
            json!({"context":{"slot":slot},"value":values})
        }
        method => panic!("signing must not broadcast a transaction: {method}"),
    };
    Json(json!({"jsonrpc":"2.0","id":q["id"],"result":result}))
}
fn account(data: &impl borsh::BorshSerialize) -> Value {
    json!({"owner":pair_registry::id().to_string(),"data":[STANDARD.encode(borsh::to_vec(data).unwrap()),"base64"],"lamports":1000000,"executable":false})
}
async fn ready(url: &str, path: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if reqwest::get(format!("{url}{path}")).await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server did not start"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
impl Fixture {
    async fn new() -> Self {
        Self::with_oidc(vec![], None).await
    }
    async fn with_oidc(
        issuers: Vec<pairkey_sdk::approval::IssuerConfig>,
        test_root: Option<Vec<u8>>,
    ) -> Self {
        let dir = std::env::temp_dir().join(format!("pairkey-hosted-v2-{}", hex(&fresh())));
        std::fs::create_dir(&dir).unwrap();
        let journal = Journal::open(&dir.join("state.json"), "isolated test".into()).unwrap();
        let set_id = journal.read().set_id;
        let payer = Keypair::new();
        let keys = [
            SigningKey::from_bytes(&fresh()),
            SigningKey::from_bytes(&fresh()),
        ];
        let identities = keys.each_ref().map(|k| k.verifying_key().to_bytes());
        let accounts = Arc::new(Mutex::new(BTreeMap::from([(
            pair_registry::set_address(&pair_registry::id(), &set_id)
                .0
                .to_string(),
            account(&pair_registry::EnclaveSet {
                version: 1,
                set_id,
                governor: payer.pubkey().to_bytes(),
                identities,
                retired: false,
                development: true,
            }),
        )])));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc = format!("http://{}", listener.local_addr().unwrap());
        let rpc_state = Arc::new(TestRpc {
            accounts: accounts.clone(),
            vm: Mutex::new(None),
        });
        let server = Router::new()
            .route("/", post(test_rpc))
            .with_state(rpc_state.clone());
        let mut tasks = vec![tokio::spawn(async move {
            axum::serve(listener, server).await.unwrap();
        })];
        let mut workers = [String::new(), String::new()];
        for i in 0..2 {
            workers[i] = format!("http://127.0.0.1:{}", port().unwrap());
            let root_file = dir.join(format!("root-{i}"));
            let identity_file = dir.join(format!("identity-{i}"));
            private(&root_file, &fresh()).unwrap();
            private(&identity_file, &keys[i].to_bytes()).unwrap();
            let config_file = dir.join(format!("worker-{i}.json"));
            let config = json!({"role":if i==0 {Role::A}else{Role::B},"bind":workers[i].trim_start_matches("http://"),"root_file":root_file,"identity_file":identity_file,"peer_identity":identities[1-i],"rpc_url":rpc,"provider_domain":format!("test-{i}"),"network":GENESIS.parse::<Pubkey>().unwrap().to_bytes(),"set_id":set_id,"set_governor":payer.pubkey().to_bytes(),"dkls_binary":PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/silence-dkls23/release/dkls-spike")});
            let mut config = config;
            config["oidc_issuers"] = serde_json::to_value(&issuers).unwrap();
            private(&config_file, &serde_json::to_vec(&config).unwrap()).unwrap();
            let test_root = test_root.clone();
            tasks.push(tokio::spawn(async move {
                if let Some(root) = test_root {
                    pairkey_worker::development::run_with_test_oidc_root(
                        config_file.to_str().unwrap(),
                        &root,
                    )
                    .await
                    .unwrap();
                } else {
                    pairkey_worker::development::run(config_file.to_str().unwrap())
                        .await
                        .unwrap();
                }
            }));
            ready(&workers[i], "/health").await;
        }
        let coordinator = format!("127.0.0.1:{}", port().unwrap());
        let config = pairkey_coordinator::Config {
            bind: coordinator.clone(),
            workers: workers.clone(),
            identities,
            jobs_file: Some(dir.join("jobs.json").to_str().unwrap().into()),
        };
        tasks.push(tokio::spawn(async move {
            pairkey_coordinator::run(config).await.unwrap();
        }));
        ready(&format!("http://{coordinator}"), "/health").await;
        let app = Arc::new(App {
            oidc_issuers: issuers,
            root: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()
                .unwrap(),
            dir: dir.clone(),
            journal,
            hosted: Mutex::new(Store::open(&dir.join("hosted.json"), [9; 32]).unwrap()),
            payer,
            delegate: SigningKey::from_bytes(&fresh()),
            identities,
            controller: example_controller::id(),
            sol: Rpc::new(rpc.clone()).unwrap(),
            solana_rpc_url: rpc.clone(),
            evm: Rpc::new(rpc).unwrap(),
            sdk: pairkey_sdk::service::Client::new(format!("http://{coordinator}")).unwrap(),
            workers,
            stage: Mutex::new(json!({"ready":true})),
            gate: Arc::new(tokio::sync::Mutex::new(())),
            processes: Mutex::new(Processes(vec![])),
            coordinator,
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = crate::api::router(app.clone(), base.clone());
        tasks.push(tokio::spawn(async move {
            axum::serve(listener, server).await.unwrap();
        }));
        Self {
            app,
            client: pairkey_sdk::hosted::Client::new(format!("{base}/api/v2")).unwrap(),
            accounts,
            rpc_state,
            tasks,
            dir,
            endpoint: format!("{base}/api/v2"),
        }
    }
    async fn metadata(&self, owner: &SigningKey) -> wire::NamespaceResponse {
        let q = wire::NamespaceRequest {
            identity: Identity::Account {
                public_key: owner.verifying_key().to_bytes(),
            },
            namespace_id: [0; 32],
        };
        let response: wire::NamespaceResponse = self.client.post("/namespaces", &q).await.unwrap();
        wire::verify_namespace(
            &q,
            &response,
            GENESIS.parse::<Pubkey>().unwrap().to_bytes(),
            pair_registry::id(),
            self.app.journal.read().set_id,
            self.app.identities,
        )
        .unwrap();
        response
    }
    async fn prepared(
        &self,
        ns: &wire::NamespaceResponse,
        chain: Chain,
    ) -> (wire::Prepared, KeyResponse) {
        let key_request = KeyRequest {
            registration: ns.proposal.registration.clone(),
            chain,
            path: vec![0],
        };
        let key: KeyResponse = self.client.post("/keys", &key_request).await.unwrap();
        let q = wire::PrepareRequest {
            signing_request: SigningRequest {
                key: key_request,
                request_id: fresh(),
                message: "Hosted request without a registration transaction".into(),
                transaction: None,
            },
            identity: ns.identity.clone(),
        };
        let prepared: wire::Prepared = self.client.post("/approvals", &q).await.unwrap();
        prepared
            .verify(&q, &key, self.app.identities, crate::chain::now().unwrap())
            .unwrap();
        (prepared, key)
    }
    async fn wait(&self, id: &str) -> Value {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        loop {
            let status: Value = self.client.get(&format!("/jobs/{id}")).await.unwrap();
            if status["status"] == "complete" {
                return status["result"].clone();
            }
            assert_ne!(status["status"], "failed", "{status}");
            assert!(tokio::time::Instant::now() < deadline, "job timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn close(mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        let dir = self.dir.clone();
        drop(self);
        // Worker shutdown sends a kill to native DKLS children; a child may
        // still be exiting and creating its final journal file here.
        for attempt in 0..20 {
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty && attempt < 19 => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(e) => panic!("failed to remove test directory {}: {e}", dir.display()),
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires Node 22+ and the native DKLS sidecar"]
async fn hosted_browser_sdk_runs_all_five_signing_flows_and_recovery() {
    use std::io::Write;
    let f = Fixture::new().await;
    let input = serde_json::to_vec(&json!({"endpoint":f.endpoint,"seed":fresh(),"chains":["solana","evm","zcash","near","bitcoin"]})).unwrap();
    let output = tokio::task::spawn_blocking(move || {
        let mut child = std::process::Command::new("node")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../website/tests/hosted-v2-live.mjs"),
            )
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&input).unwrap();
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "browser SDK integration failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        f.accounts.lock().unwrap().len(),
        1,
        "browser must not broadcast a registration or approval transaction"
    );
    assert_eq!(f.app.hosted.lock().unwrap().snapshot.offchain_jobs.len(), 5);
    f.close().await;
}
fn signed(prepared: &wire::Prepared, owner: &SigningKey) -> wire::SubmitRequest {
    prepared.clone().submission(Proof::Account {
        signature: owner.sign(&prepared.signing_message).to_bytes().to_vec(),
    })
}
#[tokio::test]
async fn hosted_account_signs_without_registration_and_recovers_exact_requests() {
    let f = Fixture::new().await;
    let owner = SigningKey::from_bytes(&fresh());
    let ns = f.metadata(&owner).await;
    assert!(!f
        .accounts
        .lock()
        .unwrap()
        .contains_key(&ns.namespace_address));
    let config: Value = f.client.get("/config").await.unwrap();
    assert_eq!(config["registration_required"], false);
    assert_eq!(
        config["program_policy_scopes"],
        json!(["namespace", "shared"])
    );
    assert_eq!(config["transaction_signing"]["solana"]["sign"], true);
    assert_eq!(config["transaction_signing"]["bitcoin"]["sign"], false);
    for chain in [Chain::Solana, Chain::Near, Chain::Zcash, Chain::Bitcoin] {
        let (prepared, key) = f.prepared(&ns, chain).await;
        let mut wrong = signed(&prepared, &SigningKey::from_bytes(&fresh()));
        assert!(f.client.post::<Value>("/jobs", &wrong).await.is_err());
        assert!(f
            .app
            .hosted
            .lock()
            .unwrap()
            .snapshot
            .offchain_jobs
            .values()
            .all(|j| !matches!(j.state, JobState::Working)));
        wrong = signed(&prepared, &owner);
        wrong.signing_request.message.push('!');
        assert!(f.client.post::<Value>("/jobs", &wrong).await.is_err());
        let submitted = signed(&prepared, &owner);
        let first: Value = f.client.post("/jobs", &submitted).await.unwrap();
        let id = first["job_id"].as_str().unwrap();
        let retried: Value = f.client.post("/jobs", &submitted).await.unwrap();
        assert_eq!(first, retried);
        let value = f.wait(id).await;
        wire::verify_result(
            &prepared.signing_request,
            &prepared.request,
            &key,
            &value,
            f.app.identities,
        )
        .unwrap();
        let mut changed = prepared.request.clone();
        changed.expires_at -= 1;
        assert!(wire::verify_result(
            &prepared.signing_request,
            &changed,
            &key,
            &value,
            f.app.identities
        )
        .is_err());
        // Lose only the hosted delivery status. Recovery obtains the coordinator's
        // persisted result without a new proof, nonce, or signing request.
        {
            let mut store = f.app.hosted.lock().unwrap();
            store.snapshot.offchain_jobs.get_mut(id).unwrap().state =
                JobState::Uncertain("lost delivery".into());
            store.save().unwrap();
        }
        let recovered: Value = f
            .client
            .post(&format!("/jobs/{id}/recover"), &json!({}))
            .await
            .unwrap();
        assert_eq!(recovered["result"], value);
        let mut changed = submitted.clone();
        changed.approval.request.expires_at -= 1;
        changed.approval.proof = Proof::Account {
            signature: owner
                .sign(&changed.approval.request.signing_message())
                .to_bytes()
                .to_vec(),
        };
        assert!(f.client.post::<Value>("/jobs", &changed).await.is_err());
        let journal = std::fs::read_to_string(f.dir.join("hosted.json")).unwrap();
        assert!(!journal.contains(&serde_json::to_string(&submitted.approval.proof).unwrap()));
    }
    assert_eq!(
        f.accounts.lock().unwrap().len(),
        1,
        "no chain accounts were created"
    );
    f.close().await;
}

#[tokio::test]
async fn hosted_account_signs_typed_solana_evm_and_near_transactions() {
    use pairkey_signing::transaction::{NearAction, NearPublicKey, NearTransaction};
    use solana_sdk::{hash::Hash, message::Message, system_instruction};

    let f = Fixture::new().await;
    let owner = SigningKey::from_bytes(&fresh());
    let ns = f.metadata(&owner).await;
    for chain in [Chain::Solana, Chain::Evm, Chain::Near] {
        let key_request = KeyRequest {
            registration: ns.proposal.registration.clone(),
            chain,
            path: vec![0],
        };
        let key: KeyResponse = f.client.post("/keys", &key_request).await.unwrap();
        let transaction = match chain {
            Chain::Solana => {
                let signer = Pubkey::new_from_array(key.public_key.clone().try_into().unwrap());
                let message = Message::new_with_blockhash(
                    &[system_instruction::transfer(
                        &signer,
                        &Pubkey::new_unique(),
                        1,
                    )],
                    Some(&signer),
                    &Hash::new_unique(),
                );
                TransactionRequest::Solana {
                    message: bincode::serialize(&solana_sdk::message::VersionedMessage::Legacy(
                        message,
                    ))
                    .unwrap(),
                }
            }
            Chain::Near => TransactionRequest::Near {
                transaction: borsh::to_vec(&NearTransaction {
                    signer_id: "alice.near".into(),
                    public_key: NearPublicKey::Ed25519(key.public_key.clone().try_into().unwrap()),
                    nonce: 1,
                    receiver_id: "bob.near".into(),
                    block_hash: [8; 32],
                    actions: vec![NearAction::Transfer { deposit: 1 }],
                })
                .unwrap(),
            },
            Chain::Evm => TransactionRequest::EvmLegacy {
                transfer: pairkey_signing::evm::Transfer {
                    chain_id: 84532,
                    nonce: 1,
                    gas_price: 2,
                    gas_limit: 21_000,
                    to: [3; 20],
                    value: 4,
                },
            },
            _ => unreachable!(),
        };
        let request = wire::PrepareRequest {
            signing_request: SigningRequest {
                key: key_request,
                request_id: fresh(),
                message: String::new(),
                transaction: Some(transaction.clone()),
            },
            identity: ns.identity.clone(),
        };
        let prepared: wire::Prepared = f.client.post("/approvals", &request).await.unwrap();
        prepared
            .verify(
                &request,
                &key,
                f.app.identities,
                crate::chain::now().unwrap(),
            )
            .unwrap();
        let submission = signed(&prepared, &owner);
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
        assert_eq!(
            result["transaction"],
            serde_json::to_value(transaction).unwrap()
        );
        if chain == Chain::Solana || chain == Chain::Near {
            assert!(result["signing_payload_hex"]
                .as_str()
                .unwrap()
                .starts_with("0x"));
        }
        if chain == Chain::Evm || chain == Chain::Near {
            assert!(result["signed_transaction_hex"]
                .as_str()
                .unwrap()
                .starts_with("0x"));
        }
    }
    f.close().await;
}
#[tokio::test]
async fn hosted_current_rules_override_prepared_approvals_and_cannot_be_treated_as_absent() {
    let f = Fixture::new().await;
    let owner = SigningKey::from_bytes(&fresh());
    let ns = f.metadata(&owner).await;
    let (prepared, _) = f.prepared(&ns, Chain::Solana).await;
    let address = pair_registry::approval::rules_address(
        &pair_registry::id(),
        &ns.proposal.registration.namespace.digest(),
    )
    .0
    .to_string();
    f.accounts.lock().unwrap().insert(
        address.clone(),
        account(&pair_registry::approval::RulesRecord {
            namespace_digest: ns.proposal.registration.namespace.digest(),
            rules: Rules {
                revision: 1,
                disabled: true,
                ..Rules::default()
            },
        }),
    );
    assert!(f
        .client
        .post::<Value>("/jobs", &signed(&prepared, &owner))
        .await
        .is_err());
    let q = wire::PrepareRequest {
        signing_request: prepared.signing_request.clone(),
        identity: ns.identity.clone(),
    };
    assert!(f.client.post::<Value>("/approvals", &q).await.is_err());
    f.accounts.lock().unwrap().get_mut(&address).unwrap()["owner"] =
        json!(solana_sdk::system_program::id().to_string());
    assert!(f.client.post::<Value>("/approvals", &q).await.is_err());
    assert!(f
        .app
        .hosted
        .lock()
        .unwrap()
        .snapshot
        .offchain_jobs
        .is_empty());
    f.close().await;
}
#[tokio::test]
async fn policy_change_after_submission_is_rejected_before_signing() {
    let f = Fixture::new().await;
    let owner = SigningKey::from_bytes(&fresh());
    let ns = f.metadata(&owner).await;
    let (prepared, _) = f.prepared(&ns, Chain::Solana).await;
    let submission = signed(&prepared, &owner);
    let registration = &prepared.signing_request.key.registration;
    let authorization = f
        .app
        .sdk
        .approve_offchain(&pairkey_types::approval::Submission {
            registration: registration.clone(),
            payload: prepared.payload.clone(),
            approval: submission.approval,
        })
        .await
        .unwrap();
    f.accounts.lock().unwrap().insert(
        pair_registry::approval::rules_address(
            &pair_registry::id(),
            &registration.namespace.digest(),
        )
        .0
        .to_string(),
        account(&pair_registry::approval::RulesRecord {
            namespace_digest: registration.namespace.digest(),
            rules: Rules {
                revision: 1,
                disabled: true,
                ..Rules::default()
            },
        }),
    );
    let id = f
        .app
        .sdk
        .submit_authorized(
            registration,
            &prepared.request.commit,
            &prepared.payload,
            &authorization,
        )
        .await
        .unwrap();
    let status = f.app.sdk.wait(&id).await.unwrap();
    assert_eq!(status["status"], "failed");
    assert_eq!(status["code"], "admission_failed");
    assert_eq!(status["may_have_signed"], false);
    assert_eq!(f.app.sdk.recover_job(&id).await.unwrap(), status);
    f.close().await;
}
#[tokio::test]
#[ignore = "requires the native DKLS sidecar built by scripts/ci.sh"]
async fn hosted_evm_offchain_approval_runs_real_dkls_signing() {
    async fn donor_status(workers: &[String; 2]) -> [pairkey_signing::wire::DStatus; 2] {
        let client = reqwest::Client::new();
        let mut states = Vec::new();
        for worker in workers {
            states.push(
                client
                    .post(format!("{worker}/multi/d/status"))
                    .json(&())
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap(),
            );
        }
        states.try_into().unwrap()
    }
    let f = Fixture::new().await;
    let owner = SigningKey::from_bytes(&fresh());
    let ns = f.metadata(&owner).await;
    let (prepared, key) = f.prepared(&ns, Chain::Evm).await;
    let submitted = signed(&prepared, &owner);
    let job: Value = f.client.post("/jobs", &submitted).await.unwrap();
    let value = f.wait(job["job_id"].as_str().unwrap()).await;
    wire::verify_result(
        &prepared.signing_request,
        &prepared.request,
        &key,
        &value,
        f.app.identities,
    )
    .unwrap();
    let before = donor_status(&f.app.workers).await;
    assert_eq!(before[0], before[1]);
    assert!(before[0].generation.is_some());
    assert_eq!(before[0].uses, 1);
    let (second_prepared, second_key) = f.prepared(&ns, Chain::Evm).await;
    let second_job: Value = f
        .client
        .post("/jobs", &signed(&second_prepared, &owner))
        .await
        .unwrap();
    let second_value = f.wait(second_job["job_id"].as_str().unwrap()).await;
    wire::verify_result(
        &second_prepared.signing_request,
        &second_prepared.request,
        &second_key,
        &second_value,
        f.app.identities,
    )
    .unwrap();
    let after = donor_status(&f.app.workers).await;
    assert_eq!(after[0], after[1]);
    assert_eq!(after[0].generation, before[0].generation);
    assert_eq!(after[0].uses, 2);
    assert_eq!(f.accounts.lock().unwrap().len(), 1);
    f.close().await;
}

#[test]
fn hosted_restart_preserves_public_jobs_and_marks_inflight_uncertain() {
    let transcript: Value = serde_json::from_str(include_str!(
        "../../../../../sdk/tests/fixtures/hosted-devnet.json"
    ))
    .unwrap();
    let signing_request: SigningRequest =
        serde_json::from_value(transcript[0]["request"].clone()).unwrap();
    let key: KeyResponse = serde_json::from_value(transcript[0]["key"].clone()).unwrap();
    let (commit, _, _) = prepared(&signing_request, &key).unwrap();
    let approval = PrivateApproval {
        request: Request {
            version: 1,
            identity: Identity::Account {
                public_key: signing_request
                    .key
                    .registration
                    .namespace
                    .derivation_authority,
            },
            commit,
            policy_revision: 0,
            policy_digest: Rules::default().digest(),
            issued_at: 10,
            expires_at: 100,
        },
        proof: Proof::Account {
            signature: vec![0; 64],
        },
    };
    let authorization = Authorization::offchain(&approval);
    let id = pairkey_sdk::approval::job_id(&authorization).unwrap();
    let path = std::env::temp_dir().join(format!("pairkey-hosted-v2-restart-{}", hex(&fresh())));
    {
        let mut store = Store::open(&path, [8; 32]).unwrap();
        store.snapshot.offchain_jobs.insert(
            id.clone(),
            SavedJob {
                signing_request,
                authorization,
                state: JobState::Working,
            },
        );
        store.save().unwrap();
    }
    {
        let store = Store::open(&path, [8; 32]).unwrap();
        assert_eq!(
            store.snapshot.offchain_jobs[&id].public()["code"],
            "uncertain"
        );
        assert_eq!(
            store.snapshot.offchain_jobs[&id]
                .authorization
                .offchain_request(),
            Some(&approval.request)
        );
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(format!("{}.lock", path.display())).unwrap();
}

/// Manual browser QA uses only generated test workers and an in-memory chain.
/// It never loads .local/testnet-demo or sends a transaction to a public network.
#[tokio::test]
#[ignore = "manual browser preview; set PAIRKEY_BROWSER_STOP to a new stop-file path"]
async fn hosted_manual_browser_preview() {
    let stop =
        PathBuf::from(std::env::var("PAIRKEY_BROWSER_STOP").expect("explicit stop path required"));
    assert!(!stop.exists(), "use a new stop-file path");
    let f = Fixture::new().await;
    let mut vm = litesvm::LiteSVM::new();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy");
    vm.add_program_from_file(pair_registry::id(), root.join("pair_registry.so"))
        .unwrap();
    vm.add_program_from_file(example_controller::id(), root.join("example_controller.so"))
        .unwrap();
    let set_id = f.app.journal.read().set_id;
    let set = pair_registry::set_address(&pair_registry::id(), &set_id).0;
    let record = f.accounts.lock().unwrap()[&set.to_string()].clone();
    vm.set_account(
        set,
        solana_sdk::account::Account {
            lamports: 10_000_000,
            data: STANDARD
                .decode(record["data"][0].as_str().unwrap())
                .unwrap(),
            owner: pair_registry::id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    // Public, test-only wallet seed. No real network assets or operator material.
    let owner =
        Pubkey::new_from_array(SigningKey::from_bytes(&[61; 32]).verifying_key().to_bytes());
    let policy = example_controller::approval::AppPolicy {
        owner: owner.to_bytes(),
        enclave_set: set_id,
        revision: 1,
        enabled: true,
        destination: Chain::Solana.account(vec![0]).unwrap().destination,
        path_prefix: vec![0],
        max_payload_bytes: 1232,
        require_commit: false,
        remaining_approvals: 2,
    };
    vm.set_account(
        example_controller::approval::policy_address(&example_controller::id(), &owner).0,
        solana_sdk::account::Account {
            lamports: 10_000_000,
            data: borsh::to_vec(&policy).unwrap(),
            owner: example_controller::id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    for identity in f.app.identities {
        vm.airdrop(&Pubkey::new_from_array(identity), 1_000_000_000)
            .unwrap();
    }
    *f.rpc_state.vm.lock().unwrap() = Some(vm);
    for asset in [
        "examples/hosted-client-v2.zip",
        "examples/hosted-controller.zip",
        "examples/verify_hosted.rs",
    ] {
        let response = reqwest::get(format!(
            "{}/{asset}",
            f.endpoint.trim_end_matches("/api/v2")
        ))
        .await
        .unwrap();
        assert!(
            response.status().is_success(),
            "download unavailable: {asset}"
        );
    }
    println!(
        "PAIRKEY_BROWSER_PREVIEW={}/demo",
        f.endpoint.trim_end_matches("/api/v2")
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3600);
    while !stop.exists() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(stop.exists(), "browser preview timed out");
    let completed = f
        .app
        .hosted
        .lock()
        .unwrap()
        .snapshot
        .offchain_jobs
        .values()
        .filter(|j| matches!(j.state, JobState::Complete(_)))
        .count();
    assert!(
        completed >= 2,
        "exercise account and program signing before stopping"
    );
    println!("Browser preview completed {completed} real signing jobs on the in-memory chain.");
    f.close().await;
}
