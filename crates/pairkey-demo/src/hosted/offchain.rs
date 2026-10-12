//! Hosted v2 never persists JWTs, passkey assertions or caller signatures.
//! A saved public job can only be recovered, never assigned fresh randomness.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use pairkey_sdk::hosted::offchain as wire;
use pairkey_types::{
    approval::{Identity, Request, Rules},
    policy::Authorization,
};
mod management;
#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SavedJob {
    signing_request: SigningRequest,
    authorization: Authorization,
    state: JobState,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum JobState {
    Working,
    Rejected(String),
    Uncertain(String),
    Complete(Value),
}
#[derive(Debug)]
struct AdmissionRejected(String);
impl std::fmt::Display for AdmissionRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for AdmissionRejected {}
impl SavedJob {
    pub(super) fn validate(&self, id: &str) -> Result<()> {
        ensure!(
            pairkey_sdk::approval::job_id(&self.authorization)? == id,
            "hosted job identity mismatch"
        );
        let r = self
            .authorization
            .offchain_request()
            .context("off-chain request missing")?;
        ensure!(
            r.commit.registration_digest == self.signing_request.key.registration.digest()
                && r.commit.request_id == self.signing_request.request_id
                && r.commit.account
                    == self
                        .signing_request
                        .key
                        .chain
                        .account(self.signing_request.key.path.clone())?
                && r.identity.authority()
                    == self
                        .signing_request
                        .key
                        .registration
                        .namespace
                        .derivation_authority,
            "hosted job request mismatch"
        );
        Ok(())
    }
    pub(super) fn interrupt(&mut self) {
        if matches!(self.state, JobState::Working) {
            self.state = JobState::Uncertain(
                "Service restarted. Recover this job without signing again.".into(),
            );
        }
    }
    fn public(&self) -> Value {
        match &self.state {
            JobState::Working => json!({"status":"working"}),
            JobState::Rejected(error) => {
                json!({"status":"failed","code":"admission_failed","may_have_signed":false,"error":error})
            }
            JobState::Uncertain(error) => {
                json!({"status":"failed","code":"uncertain","may_have_signed":true,"error":error})
            }
            JobState::Complete(result) => json!({"status":"complete","result":result}),
        }
    }
}
pub(super) fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v2/config", get(config))
        .route("/api/v2/namespaces", post(namespace))
        .route("/api/v2/keys", post(key))
        .route("/api/v2/approvals", post(prepare))
        .route("/api/v2/jobs", post(submit))
        .route("/api/v2/jobs/:id", get(job))
        .route("/api/v2/jobs/:id/recover", post(recover))
        .route("/api/v2/rpc", post(super::rpc))
        .route("/api/v2/verify", post(crate::api::verify_message))
        .merge(management::router())
}
async fn config(State(app): State<Arc<App>>) -> Json<Value> {
    let Json(mut value) = super::config(State(app.clone())).await;
    value["version"] = json!(2);
    value["authorization"] = json!("exact_request");
    value["registration_required"] = json!(false);
    value["sessions"] = json!(false);
    value["program_approval"] = json!(["offchain", "onchain"]);
    value["program_policy_scopes"] = json!(["namespace", "shared"]);
    value["transaction_signing"] = json!({
        "solana": {"sign": true, "send": "client_rpc"},
        "evm": {"sign": true, "send": "client_rpc", "formats": ["legacy_native_transfer"]},
        "near": {"sign": true, "send": "client_rpc"},
        "bitcoin": {"sign": false, "reason": "PSBT and BIP-341 input context adapter required"},
        "zcash": {"sign": false, "reason": "ZIP transaction digest and shielded authorization adapter required"}
    });
    value["example_program"] = json!(example_controller::id().to_string());
    let mut identity_sources = vec!["account", "program", "passkey"];
    if !app.oidc_issuers.is_empty() {
        identity_sources.push("oidc");
    }
    value["identity_sources"] = json!(identity_sources);
    // Configured does not mean the provider has completed a live integration test.
    value["oidc_issuers"] = json!(app
        .oidc_issuers
        .iter()
        .map(|c| json!({"issuer":c.issuer,"audience":c.audience}))
        .collect::<Vec<_>>());
    Json(value)
}
fn identity(identity: &Identity) -> Result<()> {
    identity.validate()?;
    match identity {
        Identity::Account { public_key } => {
            ensure!(
                Pubkey::new_from_array(*public_key).is_on_curve(),
                "account source must be a wallet key"
            );
        }
        Identity::Program(source) => {
            pair_registry::program_approval::validate_source(source)?;
        }
        _ => (),
    }
    Ok(())
}
async fn namespace(
    State(app): State<Arc<App>>,
    Json(q): Json<wire::NamespaceRequest>,
) -> ApiResult<wire::NamespaceResponse> {
    identity(&q.identity).map_err(fail)?;
    let lease = app.gate.clone().try_lock_owned().map_err(|_| busy())?;
    tokio::spawn(async move {
        let _lease = lease;
        let ns = Namespace {
            version: 1,
            scheme: Scheme::FrostEd25519,
            network: GENESIS.parse::<Pubkey>()?.to_bytes(),
            registry: pair_registry::id().to_bytes(),
            derivation_authority: q.identity.authority(),
            namespace_id: q.namespace_id,
            enclave_set: app.journal.read().set_id,
        };
        let proposal = app
            .sdk
            .namespace(ns, q.identity.authority(), app.identities)
            .await?;
        available(&app, &proposal.registration).await?;
        Ok::<_, anyhow::Error>(wire::NamespaceResponse {
            namespace_address: pair_registry::namespace_address(
                &pair_registry::id(),
                &proposal.registration,
            )
            .0
            .to_string(),
            proposal,
            identity: q.identity,
        })
    })
    .await
    .map_err(fail)?
    .map(Json)
    .map_err(fail)
}
/// Preserve existing controller/freeze restrictions. Absence is allowed; RPC failure isn't.
async fn available(app: &App, reg: &Registration) -> Result<()> {
    context(app, reg)?;
    let address = pair_registry::namespace_address(&pair_registry::id(), reg).0;
    if let Some(record) = app
        .account::<pair_registry::NamespaceRecord>(address)
        .await?
    {
        ensure!(
            record.registration == *reg
                && !record.frozen
                && record.controller == reg.namespace.derivation_authority,
            "namespace is frozen or controlled by another authority"
        );
    }
    Ok(())
}
async fn key(State(app): State<Arc<App>>, Json(q): Json<KeyRequest>) -> ApiResult<KeyResponse> {
    let lease = app.gate.clone().try_lock_owned().map_err(|_| busy())?;
    tokio::spawn(async move {
        let _lease = lease;
        available(&app, &q.registration).await?;
        enrolled_metadata(&app, &q).await
    })
    .await
    .map_err(fail)?
    .map(Json)
    .map_err(fail)
}
async fn rules(app: &App, reg: &Registration) -> Result<Rules> {
    let record = app
        .account::<pair_registry::approval::RulesRecord>(
            pair_registry::approval::rules_address(&pair_registry::id(), &reg.namespace.digest()).0,
        )
        .await?;
    if let Some(record) = record {
        ensure!(
            record.namespace_digest == reg.namespace.digest() && record.rules.revision > 0,
            "rules account context mismatch"
        );
        record.rules.validate()?;
        Ok(record.rules)
    } else {
        Ok(Rules::default())
    }
}
/// Read the namespace and rules at one finalized Solana context slot.
async fn preparation_rules(app: &App, reg: &Registration) -> Result<Rules> {
    context(app, reg)?;
    let namespace = pair_registry::namespace_address(&pair_registry::id(), reg).0;
    let rules_address =
        pair_registry::approval::rules_address(&pair_registry::id(), &reg.namespace.digest()).0;
    let response = app
        .sol
        .call(
            "getMultipleAccounts",
            json!([[namespace.to_string(), rules_address.to_string()],
            {"encoding":"base64","commitment":"finalized"}]),
        )
        .await?;
    ensure!(
        response["context"]["slot"].as_u64().is_some(),
        "missing preparation slot"
    );
    let accounts = response["value"]
        .as_array()
        .context("missing preparation accounts")?;
    ensure!(accounts.len() == 2, "preparation account count");
    let decode = |index: usize| -> Result<Option<Vec<u8>>> {
        let account = &accounts[index];
        if account.is_null() {
            return Ok(None);
        }
        ensure!(
            account["owner"] == pair_registry::id().to_string(),
            "unexpected account owner"
        );
        ensure!(account["data"][1] == "base64", "invalid account encoding");
        Ok(Some(STANDARD.decode(
            account["data"][0].as_str().context("account bytes")?,
        )?))
    };
    if let Some(bytes) = decode(0)? {
        let record: pair_registry::NamespaceRecord = borsh::from_slice(&bytes)?;
        ensure!(
            record.registration == *reg
                && !record.frozen
                && record.controller == reg.namespace.derivation_authority,
            "namespace is frozen or controlled by another authority"
        );
    }
    if let Some(bytes) = decode(1)? {
        let record: pair_registry::approval::RulesRecord = borsh::from_slice(&bytes)?;
        ensure!(
            record.namespace_digest == reg.namespace.digest() && record.rules.revision > 0,
            "rules account context mismatch"
        );
        record.rules.validate()?;
        Ok(record.rules)
    } else {
        Ok(Rules::default())
    }
}
async fn prepare(
    State(app): State<Arc<App>>,
    Json(q): Json<wire::PrepareRequest>,
) -> ApiResult<wire::Prepared> {
    async {
        identity(&q.identity).context("approval identity")?;
        let rules = preparation_rules(&app, &q.signing_request.key.registration)
            .await
            .context("approval namespace and rules")?;
        let key = cached(&app, &q.signing_request.key).context("approval cached key")?;
        let (commit, payload, _) =
            prepared(&q.signing_request, &key).context("approval payload")?;
        let now = crate::chain::now()?;
        let request = Request {
            version: 1,
            identity: q.identity,
            commit,
            policy_revision: rules.revision,
            policy_digest: rules.digest(),
            issued_at: now,
            expires_at: now + pairkey_types::approval::MAX_APPROVAL_LIFETIME,
        };
        request
            .validate(&q.signing_request.key.registration, &payload, &rules, now)
            .context("approval request validation")?;
        Ok::<_, anyhow::Error>(wire::Prepared {
            signing_request: q.signing_request,
            signing_message: request.signing_message(),
            request,
            rules,
            payload,
        })
    }
    .await
    .map(Json)
    .map_err(fail)
}
async fn submit(
    State(app): State<Arc<App>>,
    Json(q): Json<wire::SubmitRequest>,
) -> ApiResult<Value> {
    let key = cached(&app, &q.signing_request.key).map_err(fail)?;
    let (commit, payload, intent) = prepared(&q.signing_request, &key).map_err(fail)?;
    if q.approval.request.commit != commit {
        return Err(fail("approval does not match message, chain and key"));
    }
    let expected = Authorization::offchain(&q.approval);
    let id = pairkey_sdk::approval::job_id(&expected).map_err(fail)?;
    // Exact retries recover the original job, including after approval expiry.
    if existing(&app, &id, &q.signing_request, &expected).map_err(fail)? {
        return Ok(Json(json!({"job_id":id})));
    }
    let lease = app.gate.clone().try_lock_owned().map_err(|_| busy())?;
    // Both workers independently read rules and verify private authentication before
    // any hosted capacity is reserved. Raw proofs never enter the journal.
    let authorization = app
        .sdk
        .approve_offchain(&pairkey_types::approval::Submission {
            registration: q.signing_request.key.registration.clone(),
            payload: payload.clone(),
            approval: q.approval,
        })
        .await
        .map_err(fail)?;
    let saved = SavedJob {
        signing_request: q.signing_request,
        authorization,
        state: JobState::Working,
    };
    {
        let mut store = app.hosted.lock().unwrap();
        ensure_capacity(&store).map_err(fail)?;
        store
            .snapshot
            .offchain_jobs
            .insert(id.clone(), saved.clone());
        store.save().map_err(fail)?;
    }
    let saved_id = id.clone();
    tokio::spawn(async move {
        let _lease = lease;
        let result = run(&app, &saved_id, &saved, &key, commit, payload, intent).await;
        finish(&app, &saved_id, result);
    });
    Ok(Json(json!({"job_id":id})))
}
fn ensure_capacity(store: &Store) -> Result<()> {
    ensure!(
        !store.poisoned
            && store.snapshot.jobs.len() + store.snapshot.offchain_jobs.len() < MAX_JOBS,
        "hosted job capacity reached"
    );
    Ok(())
}
fn existing(app: &App, id: &str, q: &SigningRequest, auth: &Authorization) -> Result<bool> {
    let store = app.hosted.lock().unwrap();
    ensure!(!store.poisoned, "hosted store unavailable");
    if let Some(saved) = store.snapshot.offchain_jobs.get(id) {
        ensure!(
            saved.authorization.offchain_request() == auth.offchain_request()
                && serde_json::to_value(&saved.signing_request)? == serde_json::to_value(q)?,
            "job request changed"
        );
        return Ok(true);
    }
    ensure!(
        !store.snapshot.offchain_jobs.values().any(|saved| saved
            .signing_request
            .key
            .registration
            .namespace
            .digest()
            == q.key.registration.namespace.digest()
            && saved.signing_request.request_id == q.request_id),
        "request ID already used; recover its existing job"
    );
    ensure_capacity(&store)?;
    Ok(false)
}
async fn run(
    app: &App,
    id: &str,
    saved: &SavedJob,
    key: &KeyResponse,
    commit: Commit,
    payload: Vec<u8>,
    intent: Option<pairkey_signing::Intent>,
) -> Result<Value> {
    let q = &saved.signing_request;
    let returned = if let Some(intent) = intent {
        app.sdk
            .submit_intent(&pairkey_sdk::multi::SignRequest {
                protocol: pairkey_sdk::multi::PROTOCOL_VERSION,
                registration: q.key.registration.clone(),
                attempt: Attempt {
                    commit,
                    random_id: fresh(),
                    authorization: saved.authorization.clone(),
                },
                intent,
                certificate: key
                    .multi
                    .as_ref()
                    .context("key certificate missing")?
                    .certificate
                    .clone(),
            })
            .await?
    } else if let Some(transaction) = q.transaction.as_ref().and_then(TransactionRequest::ed25519) {
        app.sdk
            .submit_transaction_authorized(
                &q.key.registration,
                &commit,
                &transaction,
                &saved.authorization,
            )
            .await?
    } else {
        app.sdk
            .submit_authorized(&q.key.registration, &commit, &payload, &saved.authorization)
            .await?
    };
    ensure!(returned == id, "coordinator job identity changed");
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let status = app.sdk.wait(id).await?;
        if status["status"] == "complete" {
            return result(saved, key, status["result"].clone(), app.identities);
        }
        if status["status"] == "failed" {
            if status["may_have_signed"] == false && status["code"] == "admission_failed" {
                return Err(AdmissionRejected(
                    status["error"]
                        .as_str()
                        .unwrap_or("signing admission failed")
                        .to_owned(),
                )
                .into());
            }
            anyhow::bail!(
                "coordinator could not complete this job; recover the same request: {status}"
            );
        }
        ensure!(Instant::now() < deadline, "timed out; recover the same job");
    }
}
fn result(
    saved: &SavedJob,
    key: &KeyResponse,
    value: Value,
    identities: [[u8; 32]; 2],
) -> Result<Value> {
    let q = &saved.signing_request;
    let request = saved
        .authorization
        .offchain_request()
        .context("approval missing")?;
    let (signature, receipts, attempt) = if key.multi.is_some() {
        let result: pairkey_sdk::multi::Signed = serde_json::from_value(value)?;
        (
            result.signature,
            serde_json::to_value(result.receipts)?,
            Value::Null,
        )
    } else {
        let result: pairkey_coordinator::SignedResult = serde_json::from_value(value)?;
        (
            result.signature,
            serde_json::to_value(result.receipts)?,
            serde_json::to_value(result.attempt)?,
        )
    };
    let mut value = json!({"chain":q.key.chain,"public_key_hex":key.public_key_hex,"signature_hex":format!("0x{}",hex(&signature)),"receipts":receipts,"attempt":attempt,"signature_verified":true,"hardware_backed":false});
    if let Some(transaction) = &q.transaction {
        value["transaction"] = serde_json::to_value(transaction)?;
        value["signed_message"] = Value::Null;
        if let TransactionRequest::EvmLegacy { transfer } = transaction {
            value["signed_transaction_hex"] = json!(format!(
                "0x{}",
                hex(&transfer.signed_bytes(&key.public_key, &signature)?)
            ));
        } else if let Some(adapter) = transaction.ed25519() {
            value["signing_payload_hex"] = json!(format!(
                "0x{}",
                hex(&adapter.signing_bytes(&key.public_key)?)
            ));
            if matches!(
                adapter,
                pairkey_signing::transaction::Transaction::Near { .. }
            ) {
                value["signed_transaction_hex"] = json!(format!(
                    "0x{}",
                    hex(&adapter.signed_bytes(&key.public_key, &signature)?)
                ));
            }
        }
    } else {
        value["signed_message"] = json!(q.message);
        value["transaction"] = Value::Null;
    }
    wire::verify_result(q, request, key, &value, identities)?;
    Ok(value)
}
fn finish(app: &App, id: &str, result: Result<Value>) {
    let mut store = app.hosted.lock().unwrap();
    if let Some(saved) = store.snapshot.offchain_jobs.get_mut(id) {
        // Never downgrade a terminal result if a concurrent recovery finishes later.
        if !matches!(saved.state, JobState::Complete(_) | JobState::Rejected(_)) {
            saved.state = match result {
                Ok(value) => JobState::Complete(value),
                Err(error) => match error.downcast_ref::<AdmissionRejected>() {
                    Some(rejected) => JobState::Rejected(rejected.0.clone()),
                    None => JobState::Uncertain(error.to_string()),
                },
            };
        }
    }
    if store.save().is_err() {
        app.stage("Hosted journal failed; operator reconciliation required");
    }
}
fn saved(app: &App, id: &str) -> Result<SavedJob> {
    let store = app.hosted.lock().unwrap();
    ensure!(!store.poisoned, "hosted store unavailable");
    store
        .snapshot
        .offchain_jobs
        .get(id)
        .cloned()
        .context("unknown hosted job")
}
async fn job(State(app): State<Arc<App>>, UrlPath(id): UrlPath<String>) -> ApiResult<Value> {
    saved(&app, &id).map(|s| Json(s.public())).map_err(fail)
}
async fn recover(State(app): State<Arc<App>>, UrlPath(id): UrlPath<String>) -> ApiResult<Value> {
    let saved = saved(&app, &id).map_err(fail)?;
    if !matches!(saved.state, JobState::Uncertain(_)) {
        return Ok(Json(saved.public()));
    }
    let key = cached(&app, &saved.signing_request.key).map_err(fail)?;
    // This endpoint cannot authenticate, derive keys, submit a job, or sign.
    let status = app.sdk.recover_job(&id).await.map_err(fail)?;
    if status["status"] == "complete" {
        let value = result(&saved, &key, status["result"].clone(), app.identities).map_err(fail)?;
        finish(&app, &id, Ok(value));
    } else if status["status"] == "failed"
        && status["code"] == "admission_failed"
        && status["may_have_signed"] == false
    {
        finish(
            &app,
            &id,
            Err(AdmissionRejected(
                status["error"]
                    .as_str()
                    .unwrap_or("signing admission failed")
                    .to_owned(),
            )
            .into()),
        );
    }
    job(State(app), UrlPath(id)).await
}
