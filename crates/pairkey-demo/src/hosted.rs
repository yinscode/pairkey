//! Public hosted onboarding. All approvals are signed by the caller on Solana.
//! No route can spend the demo payer's funds or select an internal worker endpoint.
use super::*;
use axum::{
    extract::{Path as UrlPath, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use pairkey_core::local_store::LocalStore;
use pairkey_sdk::hosted::*;
use pairkey_types::{Attempt, Commit, Namespace, Registration, Role, Scheme};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Instant};

const MAX_KEYS: usize = 1024;
const MAX_JOBS: usize = 1024;
#[derive(Clone, Default, Serialize, Deserialize)]
struct Snapshot {
    context: [u8; 32],
    keys: BTreeMap<String, KeyResponse>,
    jobs: BTreeMap<String, Value>,
}
pub struct Store {
    disk: LocalStore,
    snapshot: Snapshot,
    poisoned: bool,
    window: Instant,
    calls: usize,
}
impl Store {
    pub fn open(path: &Path, context: [u8; 32]) -> Result<Self> {
        let disk = LocalStore::open(path, 32 * 1024 * 1024)?;
        let mut snapshot = match disk.read()? {
            Some(b) => serde_json::from_slice::<Snapshot>(&b)?,
            None => Snapshot {
                context,
                ..Default::default()
            },
        };
        ensure!(
            snapshot.context == context,
            "hosted store identity mismatch"
        );
        ensure!(
            snapshot.keys.len() <= MAX_KEYS && snapshot.jobs.len() <= MAX_JOBS,
            "hosted store capacity"
        );
        for job in snapshot.jobs.values_mut() {
            if job["status"] == "working" {
                *job = json!({"status":"failed","code":"interrupted","may_have_signed":true,"error":"Service restarted. Reconcile this request; it will not be signed again automatically."});
            }
        }
        let mut s = Self {
            disk,
            snapshot,
            poisoned: false,
            window: Instant::now(),
            calls: 0,
        };
        s.save()?;
        Ok(s)
    }
    fn save(&mut self) -> Result<()> {
        ensure!(!self.poisoned, "hosted store unavailable");
        let result = self.disk.write(&serde_json::to_vec(&self.snapshot)?);
        if result.is_err() {
            self.poisoned = true;
        }
        result.map_err(Into::into)
    }
    pub fn admit(&mut self) -> bool {
        if self.poisoned {
            return false;
        }
        if self.window.elapsed() > Duration::from_secs(60) {
            self.window = Instant::now();
            self.calls = 0;
        }
        self.calls += 1;
        self.calls <= 120
    }
}
type ApiResult<T> = std::result::Result<Json<T>, (StatusCode, Json<Value>)>;
fn fail(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":e.to_string()})),
    )
}
fn busy() -> (StatusCode, Json<Value>) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"error":"Signers busy; retry the same request after a few seconds."})),
    )
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/config", get(config))
        .route("/api/v1/verify", post(crate::api::verify_message))
        .route("/api/v1/namespaces", post(namespace))
        .route("/api/v1/keys", post(key))
        .route("/api/v1/approvals", post(approval))
        .route("/api/v1/jobs", post(submit))
        .route("/api/v1/jobs/:id", get(job))
        .route("/api/v1/rpc", post(rpc))
}
async fn config(State(app): State<Arc<App>>) -> Json<Value> {
    Json(
        json!({"version":1,"network":"solana-devnet","genesis_hash":GENESIS,
        "registry":pair_registry::id().to_string(),"enclave_set":app.journal.read().set_id,
        "signer_identities":app.identities,"hardware_backed":false,
        "chains":["solana","evm","zcash","near","bitcoin"],"evm_chain_id":CHAIN,
        "bitcoin_network":"testnet","authorization":"per_message_commit",
        "ready":app.stage.lock().unwrap()["ready"],"limits":{"message_bytes":256,"keys_per_namespace":16,"retained_jobs":MAX_JOBS}}),
    )
}
fn context(app: &App, reg: &Registration) -> Result<()> {
    reg.validate()?;
    let n = &reg.namespace;
    ensure!(
        n.network == GENESIS.parse::<Pubkey>()?.to_bytes()
            && n.registry == pair_registry::id().to_bytes()
            && n.enclave_set == app.journal.read().set_id,
        "registration is not for this hosted deployment"
    );
    Ok(())
}
async fn registered(app: &App, reg: &Registration) -> Result<Pubkey> {
    context(app, reg)?;
    let address = pair_registry::namespace_address(&pair_registry::id(), reg).0;
    let record = app
        .account::<pair_registry::NamespaceRecord>(address)
        .await?
        .context("namespace must be registered and finalized on Solana first")?;
    ensure!(
        record.registration == *reg
            && !record.frozen
            && record.controller == reg.namespace.derivation_authority,
        "namespace does not match its active authority"
    );
    Ok(address)
}
async fn namespace(
    State(app): State<Arc<App>>,
    Json(q): Json<NamespaceRequest>,
) -> ApiResult<NamespaceResponse> {
    let lease = app.gate.clone().try_lock_owned().map_err(|_| busy())?;
    // The owner survives a disconnected HTTP client.
    tokio::spawn(async move {
        let _lease = lease;
        let authority: Pubkey = q.authority.parse()?;
        let payer: Pubkey = q.payer.parse()?;
        ensure!(payer.is_on_curve(), "payer must be a wallet account");
        let ns = Namespace {
            version: 1,
            scheme: Scheme::FrostEd25519,
            network: GENESIS.parse::<Pubkey>()?.to_bytes(),
            registry: pair_registry::id().to_bytes(),
            derivation_authority: authority.to_bytes(),
            namespace_id: q.namespace_id,
            enclave_set: app.journal.read().set_id,
        };
        let proposal = app
            .sdk
            .namespace(ns, authority.to_bytes(), app.identities)
            .await?;
        let message = pair_registry::registration_message(&proposal.registration, &authority);
        let mut instructions = vec![];
        for (i, identity) in app.identities.iter().enumerate() {
            instructions.push(
                pairkey_sdk::ed25519_instruction(
                    *identity,
                    proposal.identity_signatures[i].as_slice().try_into()?,
                    &message,
                )
                .into(),
            );
        }
        instructions
            .push(pairkey_sdk::register(payer, authority, proposal.registration.clone()).into());
        Ok::<_, anyhow::Error>(NamespaceResponse {
            namespace_address: pair_registry::namespace_address(
                &pair_registry::id(),
                &proposal.registration,
            )
            .0
            .to_string(),
            proposal,
            instructions,
        })
    })
    .await
    .map_err(fail)?
    .map(Json)
    .map_err(fail)
}
fn key_id(q: &KeyRequest) -> String {
    hex(&pairkey_types::digest(
        b"pairkey/hosted-key/v1",
        &(q.registration.digest(), q.chain, q.path.clone()),
    ))
}
fn namespace_prefix(reg: &Registration) -> String {
    hex(&reg.digest())
}
fn cache_id(q: &KeyRequest) -> String {
    format!("{}:{}", namespace_prefix(&q.registration), key_id(q))
}
async fn enrolled(app: &App, q: &KeyRequest) -> Result<KeyResponse> {
    registered(app, &q.registration).await?;
    let account = q.chain.account(q.path.clone())?;
    let id = cache_id(q);
    {
        let store = app.hosted.lock().unwrap();
        ensure!(!store.poisoned, "hosted store unavailable");
        if let Some(key) = store.snapshot.keys.get(&id) {
            return Ok(key.clone());
        }
        ensure!(
            store.snapshot.keys.len() < MAX_KEYS,
            "hosted key capacity reached"
        );
        ensure!(
            store
                .snapshot
                .keys
                .keys()
                .filter(|k| k.starts_with(&namespace_prefix(&q.registration)))
                .count()
                < 16,
            "namespace key limit reached"
        );
    }
    let multi = if let Some(suite) = q.chain.suite() {
        Some(
            app.sdk
                .signing_key(
                    &pairkey_sdk::multi::KeyRequest {
                        registration: q.registration.clone(),
                        account: account.clone(),
                        suite,
                    },
                    app.identities,
                )
                .await?,
        )
    } else {
        None
    };
    let public_key = match &multi {
        Some(m) => m.key.public_key.clone(),
        None => pairkey_sdk::derive_public(&q.registration, &account)?.to_vec(),
    };
    let address = match q.chain {
        Chain::Evm => Some(format!(
            "0x{}",
            hex(&pairkey_signing::evm::address(&public_key)?)
        )),
        Chain::Solana => {
            Some(Pubkey::new_from_array(public_key.as_slice().try_into()?).to_string())
        }
        Chain::Near => Some(format!(
            "ed25519:{}",
            Pubkey::new_from_array(public_key.as_slice().try_into()?)
        )),
        _ => None,
    };
    let key = KeyResponse {
        account,
        public_key_hex: format!("0x{}", hex(&public_key)),
        public_key,
        address,
        multi,
    };
    let mut store = app.hosted.lock().unwrap();
    store.snapshot.keys.insert(id, key.clone());
    store.save()?;
    Ok(key)
}
async fn key(State(app): State<Arc<App>>, Json(q): Json<KeyRequest>) -> ApiResult<KeyResponse> {
    let lease = app.gate.clone().try_lock_owned().map_err(|_| busy())?;
    tokio::spawn(async move {
        let _lease = lease;
        enrolled(&app, &q).await
    })
    .await
    .map_err(fail)?
    .map(Json)
    .map_err(fail)
}
fn prepared(
    q: &SigningRequest,
    key: &KeyResponse,
) -> Result<(Commit, Vec<u8>, Option<pairkey_signing::Intent>)> {
    ensure!(
        !q.message.trim().is_empty() && q.message.len() <= 256,
        "message must contain 1–256 UTF-8 bytes"
    );
    ensure!(
        key.account == q.key.chain.account(q.key.path.clone())?,
        "key path mismatch"
    );
    let intent = key.multi.as_ref().map(|k| pairkey_signing::Intent {
        version: 1,
        key: k.key.clone(),
        payload: match q.key.chain {
            Chain::Evm => {
                pairkey_signing::Payload::EvmMessage(pairkey_signing::evm_message::Message {
                    chain_id: CHAIN,
                    message: q.message.as_bytes().to_vec(),
                })
            }
            Chain::Bitcoin => {
                pairkey_signing::Payload::BitcoinMessage(pairkey_signing::bitcoin::Message {
                    network: pairkey_signing::bitcoin::Network::Testnet,
                    message: q.message.as_bytes().to_vec(),
                })
            }
            _ => pairkey_signing::Payload::RedPallas {
                message: q.message.as_bytes().to_vec(),
            },
        },
    });
    let bytes = match &intent {
        Some(i) => {
            i.validate(&q.key.registration)?;
            i.bytes()?
        }
        None => q.message.as_bytes().to_vec(),
    };
    let commit = Commit::new(
        &q.key.registration,
        q.request_id,
        key.account.clone(),
        &bytes,
    )?;
    Ok((commit, bytes, intent))
}
fn cached(app: &App, q: &KeyRequest) -> Result<KeyResponse> {
    app.hosted
        .lock()
        .unwrap()
        .snapshot
        .keys
        .get(&cache_id(q))
        .cloned()
        .context("enroll the key using /keys first")
}
async fn approval(
    State(app): State<Arc<App>>,
    Json(q): Json<PrepareRequest>,
) -> ApiResult<Approval> {
    async {
        registered(&app, &q.key.registration).await?;
        let key = cached(&app, &q.key)?;
        let signing_request = SigningRequest {
            key: q.key,
            request_id: q.request_id,
            message: q.message,
        };
        let (commit, _, _) = prepared(&signing_request, &key)?;
        let controller = Pubkey::new_from_array(
            signing_request
                .key
                .registration
                .namespace
                .derivation_authority,
        );
        let ix = pairkey_sdk::commit(
            q.payer.parse()?,
            controller,
            &signing_request.key.registration,
            commit.clone(),
        );
        Ok::<_, anyhow::Error>(Approval {
            commit,
            instructions: vec![ix.into()],
            signing_request,
        })
    }
    .await
    .map(Json)
    .map_err(fail)
}
fn job_id(commit: &Commit) -> String {
    Pubkey::new_from_array(commit.digest()).to_string()
}
async fn submit(State(app): State<Arc<App>>, Json(q): Json<SigningRequest>) -> ApiResult<Value> {
    let key = cached(&app, &q.key).map_err(fail)?;
    let (commit, bytes, intent) = prepared(&q, &key).map_err(fail)?;
    let id = job_id(&commit);
    if app.hosted.lock().unwrap().snapshot.jobs.contains_key(&id) {
        return Ok(Json(json!({"job_id":id})));
    }
    let lease = app.gate.clone().try_lock_owned().map_err(|_| busy())?;
    // Reject unapproved requests before they can touch signing nonces or job capacity.
    let ns = registered(&app, &q.key.registration).await.map_err(fail)?;
    let req = app
        .account::<pair_registry::RequestRecord>(
            pair_registry::request_address(&pair_registry::id(), &ns, &commit.request_id).0,
        )
        .await
        .map_err(fail)?
        .ok_or_else(|| fail("approval must be finalized on Solana before signing"))?;
    if req.namespace_address != ns.to_bytes()
        || req.commit != commit
        || req.derived_key
            != pairkey_sdk::derive_public(&q.key.registration, &commit.account).map_err(fail)?
    {
        return Err(fail(
            "on-chain approval does not match this exact message, key and path",
        ));
    }
    {
        let mut store = app.hosted.lock().unwrap();
        if store.snapshot.jobs.len() >= MAX_JOBS {
            return Err(busy());
        }
        store
            .snapshot
            .jobs
            .insert(id.clone(), json!({"status":"working"}));
        store.save().map_err(fail)?;
    }
    let saved_id = id.clone();
    tokio::spawn(async move {
        let _lease = lease;
        let result = sign(&app, &q, &key, commit, bytes, intent).await;
        let value = match result {
            Ok(value) => json!({"status":"complete","result":value}),
            Err(e) => json!({"status":"failed","may_have_signed":true,"error":e.to_string()}),
        };
        let mut store = app.hosted.lock().unwrap();
        store.snapshot.jobs.insert(saved_id, value);
        if store.save().is_err() {
            app.stage("Hosted journal failed; operator reconciliation required");
        }
    });
    Ok(Json(json!({"job_id":id})))
}
async fn sign(
    app: &App,
    q: &SigningRequest,
    key: &KeyResponse,
    commit: Commit,
    bytes: Vec<u8>,
    intent: Option<pairkey_signing::Intent>,
) -> Result<Value> {
    let ns = pair_registry::namespace_address(&pair_registry::id(), &q.key.registration).0;
    let policy = app
        .account::<pair_registry::PolicyRecord>(
            pair_registry::policy_address(&pair_registry::id(), &ns).0,
        )
        .await?;
    let authorization = pairkey_types::policy::Authorization {
        policy_version: policy.map(|p| p.policy.version).unwrap_or(0),
        ..Default::default()
    };
    let (signature, receipts, attempt) = if let Some(intent) = intent {
        let request = pairkey_sdk::multi::SignRequest {
            protocol: pairkey_sdk::multi::PROTOCOL_VERSION,
            registration: q.key.registration.clone(),
            attempt: Attempt {
                commit,
                random_id: fresh(),
                authorization,
            },
            intent,
            certificate: key
                .multi
                .as_ref()
                .context("key certificate")?
                .certificate
                .clone(),
        };
        app.sdk.submit_intent(&request).await?;
        let result = app
            .sdk
            .wait_intent(&request, app.identities, Duration::from_secs(180))
            .await?;
        (
            result.signature,
            serde_json::to_value(result.receipts)?,
            Value::Null,
        )
    } else {
        let id = app
            .sdk
            .submit_authorized(&q.key.registration, &commit, &bytes, &authorization)
            .await?;
        let deadline = Instant::now() + Duration::from_secs(180);
        let result = loop {
            match serde_json::from_value::<pairkey_coordinator::Job>(app.sdk.poll(&id).await?)? {
                pairkey_coordinator::Job::Complete { result } => break result,
                pairkey_coordinator::Job::Failed { error } => {
                    anyhow::bail!("signing failed: {error}")
                }
                _ => {}
            }
            ensure!(
                Instant::now() < deadline,
                "signing timed out; reconcile this job"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        ensure!(
            result.attempt.commit == commit && result.attempt.authorization == authorization,
            "result approval mismatch"
        );
        for (i, role) in [Role::A, Role::B].into_iter().enumerate() {
            pairkey_sdk::service::verify_receipt(
                &q.key.registration,
                &result.attempt,
                &bytes,
                &result.receipts[i],
                app.identities[i],
                role,
                true,
            )?;
        }
        ensure!(
            result.receipts[0].receipt.signature == result.signature
                && result.receipts[1].receipt.signature == result.signature,
            "result signature mismatch"
        );
        (
            result.signature,
            serde_json::to_value(result.receipts)?,
            serde_json::to_value(result.attempt)?,
        )
    };
    Ok(
        json!({"chain":q.key.chain,"public_key_hex":key.public_key_hex,"signature_hex":format!("0x{}",hex(&signature)),"signed_message":q.message,"receipts":receipts,"attempt":attempt,"signature_verified":true,"hardware_backed":false}),
    )
}
async fn job(State(app): State<Arc<App>>, UrlPath(id): UrlPath<String>) -> ApiResult<Value> {
    app.hosted
        .lock()
        .unwrap()
        .snapshot
        .jobs
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"unknown hosted job"})),
            )
        })
}
/// A small public-devnet RPC facade for wallets. No secret URL is returned.
async fn rpc(State(app): State<Arc<App>>, Json(q): Json<Value>) -> ApiResult<Value> {
    let result = async {
        let method = q["method"].as_str().context("RPC method")?;
        let p = &q["params"];
        match method {
            "getLatestBlockhash" | "getBlockHeight"
                if p.as_array().is_some_and(|a| a.len() <= 1) =>
            {
                app.sol
                    .call(method, json!([{"commitment":"finalized"}]))
                    .await
            }
            "getSignatureStatuses"
                if p[0].as_array().is_some_and(|a| {
                    a.len() <= 4
                        && a.iter().all(|s| {
                            s.as_str().is_some_and(|s| {
                                s.parse::<solana_sdk::signature::Signature>().is_ok()
                            })
                        })
                }) =>
            {
                app.sol
                    .call(method, json!([p[0],{"searchTransactionHistory":true}]))
                    .await
            }
            "getAccountInfo" | "getBalance"
                if p[0].as_str().is_some_and(|s| s.parse::<Pubkey>().is_ok()) =>
            {
                app.sol
                    .call(
                        method,
                        json!([p[0],{"encoding":"base64","commitment":"finalized"}]),
                    )
                    .await
            }
            "sendTransaction" => {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(p[0].as_str().context("base64 transaction")?)?;
                ensure!(bytes.len() <= 1232, "transaction too large");
                let tx: solana_sdk::transaction::Transaction = bincode::deserialize(&bytes)?;
                use solana_sdk::sanitize::Sanitize;
                tx.sanitize()?;
                ensure!(!tx.signatures.is_empty(), "signed transaction required");
                tx.verify()?;
                ensure!(
                    tx.message.account_keys.first() != Some(&app.payer.pubkey()),
                    "demo payer is not available through hosted onboarding"
                );
                Ok(json!(app.sol.send_bytes(&bytes).await?.to_string()))
            }
            _ => anyhow::bail!("RPC method or parameters not supported"),
        }
    }
    .await;
    Ok(Json(match result {
        Ok(result) => json!({"jsonrpc":"2.0","id":q["id"],"result":result}),
        Err(e) => {
            json!({"jsonrpc":"2.0","id":q["id"],"error":{"code":-32000,"message":e.to_string()}})
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_jobs_fail_closed_and_completed_jobs_survive_restart() {
        let path = std::env::temp_dir().join(format!("pairkey-hosted-{}.json", hex(&fresh())));
        {
            let mut s = Store::open(&path, [7; 32]).unwrap();
            s.snapshot
                .jobs
                .insert("a".into(), json!({"status":"working"}));
            s.snapshot.jobs.insert(
                "b".into(),
                json!({"status":"complete","result":{"signature_hex":"test"}}),
            );
            s.save().unwrap();
        }
        {
            let s = Store::open(&path, [7; 32]).unwrap();
            assert_eq!(s.snapshot.jobs["a"]["may_have_signed"], true);
            assert_eq!(s.snapshot.jobs["a"]["status"], "failed");
            assert_eq!(s.snapshot.jobs["b"]["result"]["signature_hex"], "test");
        }
        assert!(Store::open(&path, [8; 32]).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(format!("{}.lock", path.display())).unwrap();
    }
    #[test]
    fn message_and_path_changes_produce_distinct_approval_ids() {
        let c = Commit {
            registration_digest: [1; 32],
            request_id: [2; 32],
            account: pairkey_types::AccountPath {
                destination: [3; 32],
                path: vec![0],
            },
            message_hash: [4; 32],
            message_len: 5,
        };
        let mut changed = c.clone();
        changed.message_hash[0] ^= 1;
        assert_ne!(job_id(&c), job_id(&changed));
        changed = c.clone();
        changed.account.path = vec![1];
        assert_ne!(job_id(&c), job_id(&changed));
        changed = c.clone();
        changed.registration_digest[0] ^= 1;
        assert_ne!(job_id(&c), job_id(&changed));
    }
    #[test]
    fn destination_and_path_are_isolated() {
        assert_ne!(
            Chain::Solana.account(vec![0]).unwrap(),
            Chain::Near.account(vec![0]).unwrap()
        );
        assert_ne!(
            Chain::Evm.account(vec![0]).unwrap(),
            Chain::Bitcoin.account(vec![0]).unwrap()
        );
        assert!(Chain::Solana.account(vec![0; 1000]).is_err());
    }
}
