//! Hosted v2 never persists JWTs, passkey assertions or caller signatures.
//! A saved public job can only be recovered, never assigned fresh randomness.
use super::*;
use pairkey_sdk::hosted::offchain as wire;
use pairkey_types::{
    approval::{Identity, Request, Rules},
    policy::Authorization,
};
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
    Uncertain(String),
    Complete(Value),
}
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
}
async fn config(State(app): State<Arc<App>>) -> Json<Value> {
    let Json(mut value) = super::config(State(app)).await;
    value["version"] = json!(2);
    value["authorization"] = json!("exact_request");
    value["registration_required"] = json!(false);
    value["sessions"] = json!(false);
    value["program_approval"] = json!(["offchain", "onchain"]);
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
async fn prepare(
    State(app): State<Arc<App>>,
    Json(q): Json<wire::PrepareRequest>,
) -> ApiResult<wire::Prepared> {
    async {
        identity(&q.identity)?;
        available(&app, &q.signing_request.key.registration).await?;
        let key = cached(&app, &q.signing_request.key)?;
        let (commit, payload, _) = prepared(&q.signing_request, &key)?;
        let rules = rules(&app, &q.signing_request.key.registration).await?;
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
        request.validate(&q.signing_request.key.registration, &payload, &rules, now)?;
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
    } else {
        app.sdk
            .submit_authorized(&q.key.registration, &commit, &payload, &saved.authorization)
            .await?
    };
    ensure!(returned == id, "coordinator job identity changed");
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let status = app.sdk.poll(id).await?;
        if status["status"] == "complete" {
            return result(saved, key, status["result"].clone(), app.identities);
        }
        ensure!(
            status["status"] != "failed",
            "coordinator could not complete this job; recover the same request"
        );
        ensure!(Instant::now() < deadline, "timed out; recover the same job");
        tokio::time::sleep(Duration::from_secs(1)).await;
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
    let value = json!({"chain":q.key.chain,"public_key_hex":key.public_key_hex,"signature_hex":format!("0x{}",hex(&signature)),"signed_message":q.message,"receipts":receipts,"attempt":attempt,"signature_verified":true,"hardware_backed":false});
    wire::verify_result(q, request, key, &value, identities)?;
    Ok(value)
}
fn finish(app: &App, id: &str, result: Result<Value>) {
    let mut store = app.hosted.lock().unwrap();
    if let Some(saved) = store.snapshot.offchain_jobs.get_mut(id) {
        // Never downgrade a complete result if a concurrent recovery finishes later.
        if !matches!(saved.state, JobState::Complete(_)) {
            saved.state = match result {
                Ok(value) => JobState::Complete(value),
                Err(error) => JobState::Uncertain(error.to_string()),
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
    }
    job(State(app), UrlPath(id)).await
}
