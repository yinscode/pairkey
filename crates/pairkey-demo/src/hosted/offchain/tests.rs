//! Real HTTP coordinator and two independent development workers. Only Solana
//! account reads are supplied by a deterministic RPC fixture; no approval tx exists.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::Signer as _;
use pairkey_types::approval::{Approval as PrivateApproval, Proof};

struct Fixture {
    app: Arc<App>,
    client: pairkey_sdk::hosted::Client,
    accounts: Arc<Mutex<BTreeMap<String, Value>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    dir: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
async fn test_rpc(
    State(accounts): State<Arc<Mutex<BTreeMap<String, Value>>>>,
    Json(q): Json<Value>,
) -> Json<Value> {
    let slot = crate::chain::now().unwrap() as u64;
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
        let server = Router::new()
            .route("/", post(test_rpc))
            .with_state(accounts.clone());
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
            private(&config_file, &serde_json::to_vec(&config).unwrap()).unwrap();
            tasks.push(tokio::spawn(async move {
                pairkey_worker::development::run(config_file.to_str().unwrap())
                    .await
                    .unwrap();
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
            root: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
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
            tasks,
            dir,
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
        std::fs::remove_dir_all(dir).unwrap();
    }
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
#[ignore = "requires the native DKLS sidecar built by scripts/ci.sh"]
async fn hosted_evm_offchain_approval_runs_real_dkls_signing() {
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
