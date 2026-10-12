//! Restart-safe multi-suite delivery. Solana records remain the only authorization source.
use super::*;
use pairkey_core::local_store::LocalStore;
use pairkey_sdk::multi::{intent_job_id, IntentJob};
use pairkey_signing::wire as mw;
use tokio::sync::watch;
const RETENTION: u64 = 86400;
const MAX_JOBS: usize = 256;
fn clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
#[derive(Debug)]
pub(super) struct RetryAfter(pub u64);
impl std::fmt::Display for RetryAfter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "worker rate limited; retry after {} seconds", self.0)
    }
}
impl std::error::Error for RetryAfter {}
fn failed(code: &str, error: &str, may_have_signed: bool) -> IntentJob {
    IntentJob::Failed {
        code: code.into(),
        error: error.into(),
        may_have_signed,
        retry_after_secs: None,
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    created: u64,
    job: IntentJob,
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
    pub(super) fn open(path: &str, context: [u8; 32]) -> anyhow::Result<Self> {
        let disk = LocalStore::open(path, 32 * 1024 * 1024)?;
        let snapshot = match disk.read()? {
            None => Snapshot {
                version: 1,
                context,
                records: BTreeMap::new(),
            },
            Some(bytes) => serde_json::from_slice::<Snapshot>(&bytes)?,
        };
        ensure!(
            snapshot.version == 1 && snapshot.context == context,
            "job store version/configuration mismatch"
        );
        ensure!(snapshot.records.len() <= MAX_JOBS, "job store capacity");
        let mut s = Self {
            disk,
            snapshot,
            poisoned: false,
        };
        for (id, record) in &mut s.snapshot.records {
            id.parse::<Pubkey>()?;
            if !record.job.terminal() {
                record.job = failed(
                    "interrupted",
                    "coordinator restarted; reconcile destination before a fresh attempt",
                    true,
                );
            }
        }
        s.save()?;
        Ok(s)
    }
    fn save(&mut self) -> anyhow::Result<()> {
        ensure!(
            !self.poisoned,
            "job store unavailable; restart and reconcile"
        );
        let result = self.disk.write(&serde_json::to_vec(&self.snapshot)?);
        if result.is_err() {
            self.poisoned = true;
        }
        Ok(result?)
    }
    pub(super) fn get(&self, id: &str) -> anyhow::Result<Option<IntentJob>> {
        ensure!(
            !self.poisoned,
            "job store unavailable; restart and reconcile"
        );
        Ok(self.snapshot.records.get(id).map(|r| r.job.clone()))
    }
    fn insert(&mut self, id: String) -> anyhow::Result<()> {
        ensure!(!self.snapshot.records.contains_key(&id), "duplicate job");
        self.snapshot
            .records
            .retain(|_, r| !r.job.terminal() || clock().saturating_sub(r.created) < RETENTION);
        ensure!(
            self.snapshot.records.len() < MAX_JOBS,
            "job result capacity reached"
        );
        self.snapshot.records.insert(
            id,
            Record {
                created: clock(),
                job: IntentJob::Queued,
            },
        );
        self.save()
    }
    fn update(&mut self, id: &str, job: IntentJob) -> anyhow::Result<()> {
        let r = self.snapshot.records.get_mut(id).context("unknown job")?;
        ensure!(!r.job.terminal(), "job already terminal");
        r.job = job;
        self.save()
    }
}
pub(super) type Cancels = Mutex<BTreeMap<String, watch::Sender<bool>>>;
fn error(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": e.to_string()})),
    )
}
pub(super) async fn enqueue(
    s: S,
    q: mw::SignRequest,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if q.attempt.authorization.offchain_request().is_some() {
        return super::offchain_jobs::enqueue(s, super::offchain_jobs::Input::Multi(Box::new(q)))
            .await;
    }
    let id = intent_job_id(&q).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":e.to_string()})),
        )
    })?;
    let mut store = s.intent_jobs.lock().unwrap();
    if store.get(&id).map_err(error)?.is_some() {
        return Ok(Json(json!({"job_id":id})));
    }
    let permit = s.capacity.clone().try_acquire_owned().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"job capacity reached"})),
        )
    })?;
    store.insert(id.clone()).map_err(error)?;
    let (tx, mut cancel) = watch::channel(false);
    s.cancels.lock().unwrap().insert(id.clone(), tx);
    drop(store);
    let job_id = id.clone();
    tokio::spawn(async move {
        // Serialize all multi-suite work, including cleanup, so old work cannot reset a new job.
        let guard = tokio::select! {
            g = s.multi.lock() => Some(g),
            _ = cancel.changed() => None,
        };
        let started = if guard.is_some() && !*cancel.borrow() {
            s.intent_jobs
                .lock()
                .unwrap()
                .update(&job_id, IntentJob::Working)
        } else {
            Ok(())
        };
        let job = if guard.is_none() || *cancel.borrow() {
            failed("cancelled", "cancelled before starting", false)
        } else if let Err(e) = started {
            failed("storage_failed", &e.to_string(), false)
        } else {
            let work = async {
                s.relay.multi_clear_ephemeral_checked().await?;
                s.relay.multi_sign(q).await
            };
            use futures_util::FutureExt;
            let result = tokio::select! {
                biased;
                _ = cancel.changed() => failed("cancelled", "delivery cancelled; signing may already have occurred", true),
                out = tokio::time::timeout(Duration::from_secs(150), std::panic::AssertUnwindSafe(work).catch_unwind()) => match out {
                    Ok(Ok(Ok(result))) => IntentJob::Complete { result: Box::new(result) },
                    Ok(Ok(Err(e))) => {
                        if let Some(delay) = e.downcast_ref::<RetryAfter>() {
                            IntentJob::Failed { code:"rate_limited".into(),error:e.to_string(),may_have_signed:true,retry_after_secs:Some(delay.0) }
                        } else { failed("signing_failed", &e.to_string(), true) }
                    },
                    Ok(Err(_)) => failed("internal_failure", "signing task panicked", true),
                    Err(_) => failed("timeout", "signing deadline exceeded", true),
                }
            };
            // Keep an idle donor only after a completed signing operation.
            let cleanup = if matches!(&result, IntentJob::Complete { .. }) {
                s.relay.multi_clear_ephemeral_checked().await
            } else {
                s.relay.multi_reset_checked().await
            };
            if let Err(e) = cleanup {
                s.relay.multi_reset().await;
                eprintln!("multi-suite cleanup incomplete: {e}");
            }
            result
        };
        if let Err(e) = s.intent_jobs.lock().unwrap().update(&job_id, job) {
            eprintln!("job persistence failed: {e}");
        }
        s.cancels.lock().unwrap().remove(&job_id);
        drop(guard);
        drop(permit);
    });
    Ok(Json(json!({"job_id":id})))
}
pub(super) async fn cancel(
    State(s): State<S>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Some(value) = super::offchain_jobs::cancel(&s, &id).map_err(error)? {
        return Ok(Json(value));
    }
    let job = s
        .intent_jobs
        .lock()
        .unwrap()
        .get(&id)
        .map_err(error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error":"unknown job"}))))?;
    if !job.terminal() {
        if let Some(tx) = s.cancels.lock().unwrap().get(&id) {
            let _ = tx.send(true);
        }
    }
    Ok(Json(
        json!({"job_id":id,"cancellation_requested":!job.terminal()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Submission {
    pub signing: mw::SignRequest,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn location() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "pairkey-jobs-{}",
            Pubkey::new_from_array(pairkey_signing::dkls::fresh())
        ))
    }
    #[test]
    fn restart_interrupts_active_work_preserves_terminal_and_rejects_corrupt_or_changed_config() {
        let path = location();
        let name = path.to_str().unwrap();
        let queued = Pubkey::new_from_array(pairkey_signing::dkls::fresh()).to_string();
        let working = Pubkey::new_from_array(pairkey_signing::dkls::fresh()).to_string();
        let terminal = Pubkey::new_from_array(pairkey_signing::dkls::fresh()).to_string();
        {
            let mut s = Store::open(name, [1; 32]).unwrap();
            assert!(
                Store::open(name, [1; 32]).is_err(),
                "second process/store owner"
            );
            for id in [&queued, &working, &terminal] {
                s.insert(id.clone()).unwrap();
            }
            s.update(&working, IntentJob::Working).unwrap();
            s.update(&terminal, failed("cancelled", "before start", false))
                .unwrap();
            assert!(s.insert(queued.clone()).is_err());
        }
        {
            let s = Store::open(name, [1; 32]).unwrap();
            for id in [&queued, &working] {
                assert!(
                    matches!(s.get(id).unwrap(), Some(IntentJob::Failed { code, may_have_signed:true,.. }) if code == "interrupted")
                );
            }
            assert!(
                matches!(s.get(&terminal).unwrap(), Some(IntentJob::Failed { code, may_have_signed:false,.. }) if code == "cancelled")
            );
        }
        assert!(Store::open(name, [2; 32]).is_err());
        std::fs::write(&path, b"{").unwrap();
        assert!(Store::open(name, [1; 32]).is_err());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{name}.lock"));
    }
    #[test]
    fn failed_persistence_poisoning_and_retention_never_evict_live_work() {
        let path = location();
        let mut s = Store::open(path.to_str().unwrap(), [0; 32]).unwrap();
        for _ in 0..MAX_JOBS {
            s.snapshot.records.insert(
                Pubkey::new_from_array(pairkey_signing::dkls::fresh()).to_string(),
                Record {
                    created: 0,
                    job: IntentJob::Working,
                },
            );
        }
        assert!(s
            .insert(Pubkey::new_from_array(pairkey_signing::dkls::fresh()).to_string())
            .is_err());
        let id = s.snapshot.records.keys().next().unwrap().clone();
        s.snapshot.records.get_mut(&id).unwrap().job = failed("cancelled", "done", false);
        s.insert(Pubkey::new_from_array(pairkey_signing::dkls::fresh()).to_string())
            .unwrap();
        assert!(!s.snapshot.records.contains_key(&id));
        // A directory at the staging path forces a write failure without elevated privileges.
        let next = format!("{}.next", path.display());
        std::fs::create_dir(&next).unwrap();
        let id = s.snapshot.records.keys().next().unwrap().clone();
        assert!(s.update(&id, failed("test", "test", true)).is_err());
        assert!(s.get(&id).is_err());
        std::fs::remove_dir(next).unwrap();
        drop(s);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }
}
