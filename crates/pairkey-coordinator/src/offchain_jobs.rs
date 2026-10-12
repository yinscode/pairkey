//! One durable coordinator attempt per owner-approved request, across all suites.
//! Recovery reads public worker receipts; it never calls a signing endpoint.
use super::*;
use pairkey_core::{approval_store::Status as WorkerStatus, local_store::LocalStore};
use pairkey_signing::wire as mw;
use tokio::sync::watch;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Input {
    Ed {
        request: Box<SignRequest>,
        attempt: Box<Attempt>,
    },
    Multi(Box<mw::SignRequest>),
}
impl Input {
    pub fn ed(request: SignRequest) -> Self {
        let attempt = Attempt {
            authorization: request.authorization.clone(),
            commit: request.commit.clone(),
            random_id: pairkey_signing::dkls::fresh(),
        };
        Self::Ed {
            request: Box::new(request),
            attempt: Box::new(attempt),
        }
    }
    fn check(&self) -> ApprovalCheck {
        match self {
            Self::Ed { request, attempt } => ApprovalCheck {
                registration: request.registration.clone(),
                attempt: (**attempt).clone(),
                payload: request
                    .transaction
                    .as_ref()
                    .map(|t| t.bytes().expect("validated transaction"))
                    .unwrap_or_else(|| request.message.clone()),
            },
            Self::Multi(q) => ApprovalCheck {
                registration: q.registration.clone(),
                attempt: q.attempt.clone(),
                payload: q.intent.bytes().expect("validated intent"),
            },
        }
    }
    fn validate(&self) -> anyhow::Result<String> {
        match self {
            Self::Ed { request, attempt } => {
                validate_signing_request(request)?;
                ensure!(
                    attempt.commit == request.commit
                        && attempt.authorization == request.authorization,
                    "attempt mismatch"
                );
            }
            Self::Multi(q) => q.validate()?,
        }
        let q = self.check();
        let a = &q.attempt.authorization;
        let r = a
            .offchain_request()
            .context("off-chain approval required")?;
        r.identity.validate()?;
        ensure!(
            a.session_id.is_none()
                && a.session_proof.is_none()
                && a.policy_version == r.policy_revision
                && r.commit == q.attempt.commit
                && r.identity.authority() == q.registration.namespace.derivation_authority
                && r.version == pairkey_types::approval::APPROVAL_VERSION
                && r.commit.request_id != [0; 32],
            "off-chain request binding"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= 64 * 1024,
            "off-chain job input bound"
        );
        pairkey_sdk::approval::job_id(a)
    }
    fn lookup(&self) -> ApprovalLookup {
        let q = self.check();
        ApprovalLookup {
            namespace_digest: q.registration.namespace.digest(),
            request_id: q.attempt.commit.request_id,
            approval_digest: q.attempt.authorization.offchain_request().unwrap().digest(),
        }
    }
    fn same_request(&self, other: &Self) -> bool {
        let a = self.lookup();
        let b = other.lookup();
        a.namespace_digest == b.namespace_digest && a.request_id == b.request_id
    }
    fn verify(&self, result: &Output, identities: [[u8; 32]; 2]) -> anyhow::Result<()> {
        match (self, result) {
            (Self::Ed { request, attempt }, Output::Ed(r)) => {
                ensure!(r.attempt == **attempt, "recovered attempt mismatch");
                for (i, receipt) in r.receipts.iter().enumerate() {
                    let approved = request
                        .transaction
                        .as_ref()
                        .map(|t| t.bytes())
                        .transpose()?
                        .unwrap_or_else(|| request.message.clone());
                    pairkey_sdk::service::verify_receipt_payload(
                        &request.registration,
                        attempt,
                        pairkey_sdk::service::ReceiptPayloads {
                            approved: &approved,
                            signed: &request.message,
                        },
                        receipt,
                        identities[i],
                        if i == 0 { Role::A } else { Role::B },
                        true,
                    )?;
                    ensure!(
                        receipt.receipt.signature == r.signature
                            && receipt.receipt.peer_boot == r.receipts[1 - i].receipt.boot_id,
                        "recovered receipt disagreement"
                    );
                }
            }
            (Self::Multi(q), Output::Multi(r)) => {
                // Recovery of our persisted attempt is stricter than the public SDK's
                // semantic retry check: a different attempt must never replace this one.
                ensure!(
                    r.receipts.iter().all(|r| r.request.attempt == q.attempt),
                    "recovered attempt mismatch"
                );
                pairkey_sdk::multi::verify_result(q, r, identities)?;
            }
            _ => anyhow::bail!("recovered result suite mismatch"),
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Output {
    Ed(Box<SignedResult>),
    Multi(Box<mw::Signed>),
}
impl Output {
    fn public(&self) -> Value {
        match self {
            Self::Ed(result) => json!({"status":"complete", "result":result}),
            Self::Multi(result) => json!({"status":"complete", "result":result}),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum StateKind {
    Working,
    Rejected(String),
    Uncertain(String),
    Complete(Output),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    input: Input,
    state: StateKind,
}
impl Record {
    fn public(&self) -> Value {
        match &self.state {
            StateKind::Working => json!({"status":"working"}),
            StateKind::Rejected(error) => json!({"status":"failed", "code":"admission_failed",
                "error":error, "may_have_signed":false}),
            StateKind::Uncertain(error) => {
                json!({"status":"failed", "code":"uncertain", "error":error,
                "may_have_signed":true})
            }
            StateKind::Complete(r) => r.public(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u16,
    context: [u8; 32],
    records: BTreeMap<String, Record>,
}
pub(super) struct Store {
    disk: LocalStore,
    snapshot: Snapshot,
    poisoned: bool,
}
impl Store {
    pub fn open(path: &str, context: [u8; 32]) -> anyhow::Result<Self> {
        let disk = LocalStore::open(path, 64 * 1024 * 1024)?;
        let snapshot = match disk.read()? {
            Some(bytes) => serde_json::from_slice::<Snapshot>(&bytes)?,
            None => Snapshot {
                version: 1,
                context,
                records: BTreeMap::new(),
            },
        };
        ensure!(
            snapshot.version == 1 && snapshot.context == context && snapshot.records.len() <= 4096,
            "off-chain job store context/version/capacity"
        );
        let mut s = Self {
            disk,
            snapshot,
            poisoned: false,
        };
        let mut claims = std::collections::BTreeSet::new();
        for (id, record) in &mut s.snapshot.records {
            ensure!(*id == record.input.validate()?, "off-chain job ID mismatch");
            let q = record.input.lookup();
            ensure!(
                claims.insert((q.namespace_digest, q.request_id)),
                "duplicate persisted request claim"
            );
            if matches!(record.state, StateKind::Working) {
                record.state = StateKind::Uncertain(
                    "Coordinator restarted; recover this job without starting a new attempt".into(),
                );
            }
        }
        s.save()?;
        Ok(s)
    }
    fn ready(&self) -> anyhow::Result<()> {
        ensure!(
            !self.poisoned,
            "off-chain job store unavailable; reconcile before restarting"
        );
        Ok(())
    }
    fn save(&mut self) -> anyhow::Result<()> {
        self.ready()?;
        let result = serde_json::to_vec(&self.snapshot)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| self.disk.write(&bytes).map_err(anyhow::Error::from));
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn record(&self, id: &str) -> anyhow::Result<Option<Record>> {
        self.ready()?;
        Ok(self.snapshot.records.get(id).cloned())
    }
    pub fn get(&self, id: &str) -> anyhow::Result<Option<Value>> {
        Ok(self.record(id)?.map(|r| r.public()))
    }
    fn existing(&self, input: &Input) -> anyhow::Result<bool> {
        self.ready()?;
        let id = input.validate()?;
        if let Some(old) = self.snapshot.records.get(&id) {
            // The approved request commits all bytes, chain/path/key and policy.
            // Only private-proof commitment and protocol randomness may differ on retry.
            ensure!(
                old.input.same_request(input)
                    && std::mem::discriminant(&old.input) == std::mem::discriminant(input),
                "request collision"
            );
            return Ok(true);
        }
        ensure!(
            !self
                .snapshot
                .records
                .values()
                .any(|r| r.input.same_request(input)),
            "request ID already belongs to another approval; recover the original job"
        );
        Ok(false)
    }
    /// Persist pending admission before workers can allocate signing nonces.
    fn reserve(&mut self, input: Input) -> anyhow::Result<bool> {
        if self.existing(&input)? {
            return Ok(false);
        }
        ensure!(
            self.snapshot.records.len() < 4096,
            "off-chain job capacity reached"
        );
        let id = input.validate()?;
        self.snapshot.records.insert(
            id,
            Record {
                input,
                state: StateKind::Working,
            },
        );
        self.save()?;
        Ok(true)
    }
    fn uncertain(&mut self, id: &str, error: String) -> anyhow::Result<()> {
        self.ready()?;
        let record = self
            .snapshot
            .records
            .get_mut(id)
            .context("unknown off-chain job")?;
        if matches!(record.state, StateKind::Working) {
            record.state = StateKind::Uncertain(error);
            self.save()?;
        }
        Ok(())
    }
    fn reject(&mut self, id: &str, error: String) -> anyhow::Result<()> {
        self.ready()?;
        let record = self
            .snapshot
            .records
            .get_mut(id)
            .context("unknown off-chain job")?;
        if matches!(record.state, StateKind::Working) {
            record.state = StateKind::Rejected(error);
            self.save()?;
        }
        Ok(())
    }
    fn complete(
        &mut self,
        id: &str,
        result: Output,
        identities: [[u8; 32]; 2],
    ) -> anyhow::Result<()> {
        self.ready()?;
        let record = self
            .snapshot
            .records
            .get_mut(id)
            .context("unknown off-chain job")?;
        record.input.verify(&result, identities)?;
        if let StateKind::Complete(existing) = &record.state {
            // Elapsed delivery time need not match a worker-only reconstruction.
            record.input.verify(existing, identities)?;
            return Ok(());
        }
        record.state = StateKind::Complete(result);
        self.save()
    }
}
fn error(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": e.to_string()})),
    )
}
pub(super) async fn enqueue(s: S, input: Input) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let id = input.validate().map_err(error)?;
    if s.offchain_jobs
        .lock()
        .unwrap()
        .existing(&input)
        .map_err(error)?
    {
        return Ok(Json(json!({"job_id":id})));
    }
    let permit = s
        .capacity
        .clone()
        .try_acquire_owned()
        .map_err(|_| error("job capacity reached"))?;
    if !s
        .offchain_jobs
        .lock()
        .unwrap()
        .reserve(input.clone())
        .map_err(error)?
    {
        return Ok(Json(json!({"job_id":id})));
    }
    let (tx, mut cancel) = watch::channel(false);
    s.cancels.lock().unwrap().insert(id.clone(), tx);
    let job_id = id.clone();
    tokio::spawn(async move {
        // Serialize only multi-suite protocols; cleanup stays under the same lock.
        let guard = if matches!(input, Input::Multi(_)) {
            Some(s.multi.lock().await)
        } else {
            None
        };
        let work = async {
            match input {
                Input::Ed { request, attempt } => s
                    .relay
                    .sign_attempt(*request, *attempt)
                    .await
                    .map(|r| Output::Ed(Box::new(r))),
                Input::Multi(q) => {
                    s.relay.multi_clear_ephemeral_checked().await?;
                    s.relay
                        .multi_sign(*q)
                        .await
                        .map(|r| Output::Multi(Box::new(r)))
                }
            }
        };
        use futures_util::FutureExt;
        let outcome = if *cancel.borrow() {
            Err(anyhow::anyhow!("delivery cancelled"))
        } else {
            tokio::select! {
                biased;
                _ = cancel.changed() => Err(anyhow::anyhow!("delivery cancelled; recover the same job")),
                out = tokio::time::timeout(Duration::from_secs(150), std::panic::AssertUnwindSafe(work).catch_unwind()) => {
                    match out {
                        Ok(Ok(r)) => r,
                        Ok(Err(_)) => Err(anyhow::anyhow!("signing task panicked")),
                        Err(_) => Err(anyhow::anyhow!("signing timed out; recover the same job")),
                    }
                }
            }
        };
        if guard.is_some() {
            if outcome.is_ok() {
                if s.relay.multi_clear_ephemeral_checked().await.is_err() {
                    s.relay.multi_reset().await;
                }
            } else {
                s.relay.multi_reset().await;
            }
        }
        let mut store = s.offchain_jobs.lock().unwrap();
        let saved = match outcome {
            Ok(r) => store.complete(&job_id, r, s.relay.config.identities),
            Err(e) => match e.downcast_ref::<PreSignFailure>() {
                Some(rejected) => store.reject(&job_id, rejected.0.clone()),
                None => store.uncertain(&job_id, e.to_string()),
            },
        };
        if let Err(e) = saved {
            eprintln!("off-chain job persistence failed: {e}");
        }
        s.cancels.lock().unwrap().remove(&job_id);
        drop(guard);
        drop(permit);
    });
    Ok(Json(json!({"job_id":id})))
}
pub(super) async fn recover(
    State(s): State<S>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let record = s
        .offchain_jobs
        .lock()
        .unwrap()
        .record(&id)
        .map_err(error)?
        .ok_or_else(|| error("unknown off-chain job"))?;
    if matches!(
        record.state,
        StateKind::Working | StateKind::Complete(_) | StateKind::Rejected(_)
    ) {
        return Ok(Json(record.public()));
    }
    let _permit = s
        .capacity
        .clone()
        .try_acquire_owned()
        .map_err(|_| error("recovery capacity reached"))?;
    let lookup = record.input.lookup();
    let (a, b) = tokio::join!(
        s.relay
            .post::<_, Option<WorkerStatus>>(0, "/approve/result", &lookup),
        s.relay
            .post::<_, Option<WorkerStatus>>(1, "/approve/result", &lookup)
    );
    let bytes = [a.map_err(error)?, b.map_err(error)?].map(|r| match r {
        Some(WorkerStatus::Complete(bytes)) => Some(bytes),
        _ => None,
    });
    let [Some(a), Some(b)] = bytes else {
        return Ok(Json(record.public()));
    };
    let result = match &record.input {
        Input::Ed { attempt, .. } => {
            let receipts: [ResultResponse; 2] = [
                serde_json::from_slice(&a).map_err(error)?,
                serde_json::from_slice(&b).map_err(error)?,
            ];
            Output::Ed(Box::new(SignedResult {
                attempt: (**attempt).clone(),
                signature: receipts[0].receipt.signature.clone(),
                receipts,
                elapsed_ms: 0,
            }))
        }
        Input::Multi(_) => {
            let receipts: [mw::Receipt; 2] = [
                serde_json::from_slice(&a).map_err(error)?,
                serde_json::from_slice(&b).map_err(error)?,
            ];
            Output::Multi(Box::new(mw::Signed {
                signature: receipts[0].signature.clone(),
                receipts,
            }))
        }
    };
    let mut store = s.offchain_jobs.lock().unwrap();
    store
        .complete(&id, result, s.relay.config.identities)
        .map_err(error)?;
    Ok(Json(store.get(&id).map_err(error)?.unwrap()))
}
pub(super) fn cancel(s: &S, id: &str) -> anyhow::Result<Option<Value>> {
    let store = s.offchain_jobs.lock().unwrap();
    let Some(record) = store.record(id)? else {
        return Ok(None);
    };
    let working = matches!(record.state, StateKind::Working);
    if working {
        if let Some(tx) = s.cancels.lock().unwrap().get(id) {
            let _ = tx.send(true);
        }
    }
    Ok(Some(json!({"job_id":id, "cancellation_requested":working})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairkey_types::{
        approval::{Approval, Identity, Proof, Request, Rules},
        policy::{AccessProof, Authorization},
        AccountPath, Namespace, Scheme,
    };
    fn path() -> String {
        std::env::temp_dir()
            .join(format!(
                "pairkey-offchain-jobs-{}",
                Pubkey::new_from_array(pairkey_signing::dkls::fresh())
            ))
            .to_string_lossy()
            .into()
    }
    fn fixture() -> (Input, Output, [[u8; 32]; 2]) {
        let owner = ed25519_dalek::SigningKey::from_bytes(&[45; 32])
            .verifying_key()
            .to_bytes();
        let ns = Namespace {
            version: 1,
            scheme: Scheme::FrostEd25519,
            network: [1; 32],
            registry: [2; 32],
            derivation_authority: owner,
            namespace_id: [3; 32],
            enclave_set: [4; 32],
        };
        let signers = [
            pairkey_frost::Signer::new(pairkey_frost::Root::new([11; 32]), Role::A),
            pairkey_frost::Signer::new(pairkey_frost::Root::new([22; 32]), Role::B),
        ];
        let reg = pairkey_frost::register(
            ns.clone(),
            &signers[0].proof(&ns, &mut OsRng).unwrap(),
            &signers[1].proof(&ns, &mut OsRng).unwrap(),
        )
        .unwrap();
        let message = b"recover this exact signed message".to_vec();
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
        let approval = Approval {
            request: Request {
                version: 1,
                identity: Identity::Account { public_key: owner },
                commit: commit.clone(),
                policy_revision: 0,
                policy_digest: Rules::default().digest(),
                issued_at: 1000,
                expires_at: 1100,
            },
            proof: Proof::Account { signature: vec![] },
        };
        // Coordinator fixtures exercise receipt verification, not owner authentication.
        // Worker authentication has separate real-signature tests.
        let input = Input::ed(SignRequest {
            authorization: Authorization::offchain(&approval),
            registration: reg.clone(),
            commit,
            transaction: None,
            message: message.clone(),
        });
        let attempt = input.check().attempt;
        let rounds = std::array::from_fn(|i| {
            signers[i]
                .begin(&reg, &attempt, &message, &mut OsRng)
                .unwrap()
        });
        let shares = std::array::from_fn(|i| signers[i].finish(&attempt, &rounds).unwrap());
        let signature = pairkey_frost::aggregate(&reg, &attempt, &message, &rounds, &shares)
            .unwrap()
            .to_vec();
        let seeds = [[31; 32], [32; 32]];
        let identities = seeds.map(|s| {
            ed25519_dalek::SigningKey::from_bytes(&s)
                .verifying_key()
                .to_bytes()
        });
        let channels = [
            pairkey_channel::Channel::development(Role::A, seeds[0], identities[1]),
            pairkey_channel::Channel::development(Role::B, seeds[1], identities[0]),
        ];
        let receipts = std::array::from_fn(|i| {
            let receipt = Receipt {
                version: 1,
                development: true,
                role: if i == 0 { Role::A } else { Role::B },
                boot_id: channels[i].boot_id(),
                peer_boot: channels[1 - i].boot_id(),
                attempt_digest: attempt.digest(),
                public_key: derive_public(&reg, &attempt.commit.account).unwrap(),
                message_hash: attempt.commit.message_hash,
                signature: signature.clone(),
                finalized_slot: 100,
                provider_domain: format!("test-{i}"),
            };
            ResultResponse {
                attestation: channels[i].attest(channels[1 - i].boot_id()),
                identity_signature: channels[i].sign_public(&receipt_message(&receipt)),
                receipt,
            }
        });
        let output = Output::Ed(Box::new(SignedResult {
            attempt,
            signature,
            receipts,
            elapsed_ms: 1,
        }));
        input.verify(&output, identities).unwrap();
        (input, output, identities)
    }
    fn multi_fixture() -> (Input, Output, [[u8; 32]; 2]) {
        use ed25519_dalek::Signer;
        use pairkey_signing::{redpallas as red, Intent, Payload};
        let (ed, _, identities) = fixture();
        let base = ed.check();
        let reg = base.registration;
        let path = base.attempt.commit.account.clone();
        let public = red::Public {
            proofs: [
                red::proof(&[11; 32], &reg, &path, Role::A).unwrap(),
                red::proof(&[22; 32], &reg, &path, Role::B).unwrap(),
            ],
        };
        let message = b"recovered RedPallas message".to_vec();
        let intent = Intent {
            version: 1,
            key: public.key(&reg, &path).unwrap(),
            payload: Payload::RedPallas {
                message: message.clone(),
            },
        };
        let commit = Commit::new(&reg, [8; 32], path.clone(), &intent.bytes().unwrap()).unwrap();
        let mut attempt = base.attempt;
        attempt.commit = commit.clone();
        let Some(AccessProof::Offchain { request, .. }) = &mut attempt.authorization.access_proof
        else {
            unreachable!()
        };
        request.commit = commit;
        let q = mw::SignRequest {
            protocol: mw::PROTOCOL_VERSION,
            registration: reg.clone(),
            attempt,
            intent,
            certificate: mw::Certificate::RedPallas(public.clone()),
        };
        let (a, ap) =
            red::Pending::begin(&[11; 32], &reg, &path, &public, Role::A, &message).unwrap();
        let (b, bp) =
            red::Pending::begin(&[22; 32], &reg, &path, &public, Role::B, &message).unwrap();
        let rounds = [a, b];
        let shares = [ap.finish(&rounds).unwrap(), bp.finish(&rounds).unwrap()];
        let signature = red::aggregate(&reg, &path, &public, &message, &rounds, &shares).unwrap();
        let receipts = std::array::from_fn(|i| {
            let mut r = mw::Receipt {
                version: mw::PROTOCOL_VERSION,
                development: true,
                hardware_backed: false,
                request: q.clone(),
                signature: signature.clone(),
                role: if i == 0 { Role::A } else { Role::B },
                boot: [i as u8 + 1; 32],
                peer_boot: [2 - i as u8; 32],
                finalized_slot: 100,
                identity_signature: vec![],
            };
            r.identity_signature = ed25519_dalek::SigningKey::from_bytes(&[31 + i as u8; 32])
                .sign(&r.message())
                .to_bytes()
                .to_vec();
            r
        });
        let input = Input::Multi(Box::new(q));
        let output = Output::Multi(Box::new(mw::Signed {
            signature,
            receipts,
        }));
        input.verify(&output, identities).unwrap();
        (input, output, identities)
    }
    #[tokio::test]
    async fn multisuite_recovery_and_sdk_retries_bind_the_same_approval_and_receipt_pair() {
        use ed25519_dalek::Signer;
        let (input, output, identities) = multi_fixture();
        let Input::Multi(q) = &input else {
            unreachable!()
        };
        let Output::Multi(result) = &output else {
            unreachable!()
        };
        let mut retry = q.clone();
        retry.attempt.random_id[0] ^= 1;
        let Some(AccessProof::Offchain { proof_digest, .. }) =
            &mut retry.attempt.authorization.access_proof
        else {
            unreachable!()
        };
        proof_digest[0] ^= 1;
        assert_eq!(
            pairkey_sdk::multi::intent_job_id(q).unwrap(),
            pairkey_sdk::multi::intent_job_id(&retry).unwrap()
        );
        pairkey_sdk::multi::verify_result(&retry, result, identities).unwrap();
        assert!(pairkey_sdk::multi::fresh_attempt(q, [99; 32]).is_err());
        let mut spliced = result.clone();
        spliced.receipts[1].request.attempt.random_id[0] ^= 1;
        spliced.receipts[1].identity_signature = ed25519_dalek::SigningKey::from_bytes(&[32; 32])
            .sign(&spliced.receipts[1].message())
            .to_bytes()
            .to_vec();
        assert!(pairkey_sdk::multi::verify_result(q, &spliced, identities).is_err());
        let Some(AccessProof::Offchain { request: r, .. }) =
            &mut retry.attempt.authorization.access_proof
        else {
            unreachable!()
        };
        r.expires_at += 1;
        assert!(pairkey_sdk::multi::verify_result(&retry, result, identities).is_err());
        let statuses = result
            .receipts
            .each_ref()
            .map(|r| WorkerStatus::Complete(serde_json::to_vec(r).unwrap()));
        let (a, ta) = worker(Some(statuses[0].clone())).await;
        let (b, tb) = worker(Some(statuses[1].clone())).await;
        let p = path();
        let mut store = Store::open(&p, [1; 32]).unwrap();
        let id = input.validate().unwrap();
        store.reserve(input).unwrap();
        drop(store);
        let s = service([a, b], identities, Store::open(&p, [1; 32]).unwrap());
        let recovered = recover(State(s), Path(id)).await.unwrap().0;
        assert_eq!(recovered["status"], "complete");
        assert_eq!(recovered["result"]["signature"], json!(result.signature));
        ta.abort();
        tb.abort();
    }
    #[test]
    fn restart_preserves_claim_and_recovers_only_matching_verified_receipts() {
        let (input, output, identities) = fixture();
        let path = path();
        let id = input.validate().unwrap();
        let mut store = Store::open(&path, [1; 32]).unwrap();
        assert!(store.reserve(input.clone()).unwrap());
        assert!(!store.reserve(input.clone()).unwrap());
        assert!(Store::open(&path, [1; 32]).is_err()); // one writer
        drop(store);
        assert!(Store::open(&path, [2; 32]).is_err()); // context pinned
        let mut store = Store::open(&path, [1; 32]).unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap()["code"], "uncertain");
        assert!(!store.reserve(input.clone()).unwrap());
        let Output::Ed(mut bad) = output.clone() else {
            unreachable!()
        };
        bad.receipts[1].identity_signature[0] ^= 1;
        assert!(store.complete(&id, Output::Ed(bad), identities).is_err());
        let Output::Ed(mut bad) = output.clone() else {
            unreachable!()
        };
        bad.attempt.random_id[0] ^= 1;
        assert!(store.complete(&id, Output::Ed(bad), identities).is_err());
        let Output::Ed(mut bad) = output.clone() else {
            unreachable!()
        };
        bad.receipts[1].receipt.peer_boot[0] ^= 1;
        assert!(store.complete(&id, Output::Ed(bad), identities).is_err());
        store.complete(&id, output.clone(), identities).unwrap(); // even after request expiry
        drop(store);
        let store = Store::open(&path, [1; 32]).unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap()["status"], "complete");
        assert!(store.existing(&input).unwrap());
    }
    #[test]
    fn pre_signing_rejection_is_terminal_and_restart_safe() {
        let (input, _, _) = fixture();
        let path = path();
        let id = input.validate().unwrap();
        let mut store = Store::open(&path, [1; 32]).unwrap();
        store.reserve(input.clone()).unwrap();
        store.reject(&id, "policy changed".into()).unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap()["may_have_signed"], false);
        drop(store);
        let mut reopened = Store::open(&path, [1; 32]).unwrap();
        assert_eq!(
            reopened.get(&id).unwrap().unwrap()["code"],
            "admission_failed"
        );
        assert!(!reopened.reserve(input).unwrap());
    }
    #[test]
    fn retries_cannot_replace_request_but_may_renew_private_evidence() {
        let (input, _, _) = fixture();
        let mut store = Store::open(&path(), [1; 32]).unwrap();
        store.reserve(input.clone()).unwrap();
        let Input::Ed {
            mut request,
            mut attempt,
        } = input.clone()
        else {
            unreachable!()
        };
        attempt.random_id[0] ^= 1;
        let Some(AccessProof::Offchain { proof_digest, .. }) =
            &mut attempt.authorization.access_proof
        else {
            unreachable!()
        };
        proof_digest[0] ^= 1;
        request.authorization = attempt.authorization.clone();
        let retry = Input::Ed {
            request: request.clone(),
            attempt: attempt.clone(),
        };
        assert_eq!(input.validate().unwrap(), retry.validate().unwrap());
        assert!(!store.reserve(retry).unwrap());
        let Some(AccessProof::Offchain { request: r, .. }) =
            &mut attempt.authorization.access_proof
        else {
            unreachable!()
        };
        r.policy_revision += 1;
        attempt.authorization.policy_version += 1;
        request.authorization = attempt.authorization.clone();
        assert!(store.reserve(Input::Ed { request, attempt }).is_err());
    }
    #[test]
    fn concurrent_retries_reserve_once_and_disk_failure_poison_is_sticky() {
        let (input, _, _) = fixture();
        let p = path();
        let store = Arc::new(Mutex::new(Store::open(&p, [1; 32]).unwrap()));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let s = store.clone();
                let i = input.clone();
                std::thread::spawn(move || s.lock().unwrap().reserve(i).unwrap())
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
        // Use a separate store for fault injection; production state is never reset.
        let p = path();
        let mut broken = Store::open(&p, [1; 32]).unwrap();
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        assert!(broken.reserve(input.clone()).is_err());
        assert!(broken.existing(&input).is_err());
        assert!(broken.get(&input.validate().unwrap()).is_err());
    }
    async fn worker(response: Option<WorkerStatus>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().route(
            "/approve/result",
            post(move || {
                let r = response.clone();
                async move { Json(r) }
            }),
        );
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, task)
    }
    fn service(workers: [String; 2], identities: [[u8; 32]; 2], store: Store) -> S {
        Arc::new(Service {
            offchain_jobs: Mutex::new(store),
            intent_jobs: Mutex::new(jobs::Store::open(&path(), [0; 32]).unwrap()),
            cancels: Default::default(),
            multi: Default::default(),
            relay: Relay::new(Config {
                jobs_file: None,
                bind: "127.0.0.1:0".into(),
                workers,
                identities,
            })
            .unwrap(),
            jobs: Default::default(),
            capacity: Arc::new(tokio::sync::Semaphore::new(64)),
            subscriptions: Arc::new(tokio::sync::Semaphore::new(64)),
        })
    }
    #[tokio::test]
    async fn recovery_reads_both_workers_without_any_signing_route_and_requires_both_results() {
        let (input, output, identities) = fixture();
        let Output::Ed(output) = output else {
            unreachable!()
        };
        let statuses = output
            .receipts
            .each_ref()
            .map(|r| WorkerStatus::Complete(serde_json::to_vec(r).unwrap()));
        let (a, ta) = worker(Some(statuses[0].clone())).await;
        let (b, tb) = worker(Some(statuses[1].clone())).await;
        let path = path();
        let mut store = Store::open(&path, [1; 32]).unwrap();
        store.reserve(input.clone()).unwrap();
        drop(store);
        let s = service(
            [a.clone(), b],
            identities,
            Store::open(&path, [1; 32]).unwrap(),
        );
        let id = input.validate().unwrap();
        let result = recover(State(s.clone()), Path(id.clone())).await.unwrap().0;
        assert_eq!(result["status"], "complete");
        assert_eq!(result["result"]["signature"], json!(output.signature));
        drop(s);
        // An incomplete worker pair cannot turn uncertainty into completion.
        let (missing, tm) = worker(Some(WorkerStatus::Uncertain)).await;
        let mut store = Store::open(&super::tests::path(), [1; 32]).unwrap();
        store.reserve(input).unwrap();
        store.uncertain(&id, "interrupted".into()).unwrap();
        let s = service([a, missing], identities, store);
        assert_eq!(
            recover(State(s), Path(id)).await.unwrap().0["code"],
            "uncertain"
        );
        ta.abort();
        tb.abort();
        tm.abort();
    }
}
