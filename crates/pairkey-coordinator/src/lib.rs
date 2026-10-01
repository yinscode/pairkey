//! Untrusted routing, bounded jobs, public results. No provisioning files or keys.
mod jobs;
mod multi;
use anyhow::{ensure, Context};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Json, Router,
};
use pairkey_channel::{verify_attestation, Attestation, Envelope};
use pairkey_sdk::service::{RegistrationProposal, RegistrationRequest};
use pairkey_types::{derive_public, Attempt, Commit, Registration, Role};
use pairkey_worker::wire::*;
use rand_core::{OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use solana_sdk::pubkey::Pubkey;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub jobs_file: Option<String>,
    pub bind: String,
    pub workers: [String; 2],
    pub identities: [[u8; 32]; 2],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    #[serde(default)]
    pub authorization: pairkey_types::policy::Authorization,
    pub registration: Registration,
    pub commit: Commit,
    pub message: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedResult {
    pub attempt: Attempt,
    pub signature: Vec<u8>,
    pub receipts: [ResultResponse; 2],
    pub elapsed_ms: u64,
}
#[derive(Clone)]
pub struct Relay {
    client: reqwest::Client,
    config: Config,
}
impl Relay {
    pub async fn registration(
        &self,
        request: RegistrationRequest,
    ) -> anyhow::Result<RegistrationProposal> {
        ensure!(
            request.namespace.derivation_authority == request.controller,
            "controller mismatch"
        );
        let (a, b) = tokio::join!(
            self.post::<_, pairkey_frost::Possession>(0, "/proof", &request.namespace),
            self.post::<_, pairkey_frost::Possession>(1, "/proof", &request.namespace)
        );
        let proofs = [a?, b?];
        let registration = pairkey_frost::register(request.namespace, &proofs[0], &proofs[1])?;
        let ack = Ack {
            registration: registration.clone(),
            proofs,
            controller: request.controller,
        };
        let (a, b) = tokio::join!(
            self.post::<_, Vec<u8>>(0, "/ack", &ack),
            self.post::<_, Vec<u8>>(1, "/ack", &ack)
        );
        Ok(RegistrationProposal {
            registration,
            identity_signatures: [a?, b?],
        })
    }
    pub fn new(config: Config) -> anyhow::Result<Self> {
        ensure!(
            cfg!(debug_assertions),
            "development relay cannot run as a production release"
        );
        ensure!(
            config.workers[0] != config.workers[1] && config.identities[0] != config.identities[1],
            "two different enrolled endpoints and identities required"
        );
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(6))
                .build()?,
            config,
        })
    }
    pub async fn post<I: Serialize + ?Sized, O: DeserializeOwned>(
        &self,
        index: usize,
        path: &str,
        input: &I,
    ) -> anyhow::Result<O> {
        let response = self
            .client
            .post(format!("{}{}", self.config.workers[index], path))
            .json(input)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let status = response.status();
        let bytes = pairkey_sdk::http::bounded_body(
            response,
            if path.starts_with("/multi/") {
                12 * 1024 * 1024
            } else {
                pairkey_sdk::http::MAX_SERVICE_RESPONSE
            },
        )
        .await?;
        if status == StatusCode::TOO_MANY_REQUESTS {
            let error: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            if error["code"] == "backend_rate_limited" {
                return Err(jobs::RetryAfter(
                    error["retry_after_secs"]
                        .as_u64()
                        .unwrap_or(61)
                        .clamp(1, 300),
                )
                .into());
            }
        }
        ensure!(
            status.is_success(),
            "worker {} rejected {path}: {}",
            index + 1,
            String::from_utf8_lossy(&bytes)
        );
        Ok(serde_json::from_slice(&bytes)?)
    }
    pub async fn health(&self, index: usize) -> anyhow::Result<Health> {
        let response = self
            .client
            .get(format!("{}/health", self.config.workers[index]))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        pairkey_sdk::http::bounded_json(response, pairkey_sdk::http::MAX_SERVICE_RESPONSE).await
    }
    pub async fn peers(&self) -> anyhow::Result<[Attestation; 2]> {
        let (a, b) = tokio::join!(self.health(0), self.health(1));
        let a = a?;
        let b = b?;
        ensure!(
            a.role == Role::A
                && b.role == Role::B
                && a.identity == self.config.identities[0]
                && b.identity == self.config.identities[1]
                && !a.incident
                && !b.incident,
            "worker enrollment or incident mismatch"
        );
        let challenges = [
            Challenge {
                challenge: b.boot_id,
            },
            Challenge {
                challenge: a.boot_id,
            },
        ];
        let (ac, bc) = tokio::join!(
            self.post::<_, Attestation>(0, "/attest", &challenges[0]),
            self.post::<_, Attestation>(1, "/attest", &challenges[1])
        );
        let ac = ac?;
        let bc = bc?;
        verify_attestation(&ac, self.config.identities[0], Role::A, b.boot_id, true)?;
        verify_attestation(&bc, self.config.identities[1], Role::B, a.boot_id, true)?;
        ensure!(
            ac.evidence.boot_id == a.boot_id && bc.evidence.boot_id == b.boot_id,
            "worker restarted during handshake"
        );
        Ok([ac, bc])
    }
    pub async fn sign(&self, request: SignRequest) -> anyhow::Result<SignedResult> {
        request
            .commit
            .authorize(&request.registration, &request.message)?;
        let started = Instant::now();
        let peers = self.peers().await?;
        let mut random_id = [0; 32];
        OsRng.fill_bytes(&mut random_id);
        let attempt = Attempt {
            authorization: request.authorization,
            commit: request.commit,
            random_id,
        };
        let begins = [
            Begin {
                registration: request.registration.clone(),
                attempt: attempt.clone(),
                message: request.message.clone(),
                peer: peers[1].clone(),
            },
            Begin {
                registration: request.registration.clone(),
                attempt: attempt.clone(),
                message: request.message.clone(),
                peer: peers[0].clone(),
            },
        ];
        let work = async {
            let (a, b) = tokio::join!(
                self.post::<_, Envelope>(0, "/begin", &begins[0]),
                self.post::<_, Envelope>(1, "/begin", &begins[1])
            );
            let rounds = [a?, b?];
            let finishes = [
                Finish {
                    begin: begins[0].clone(),
                    rounds: rounds.clone(),
                },
                Finish {
                    begin: begins[1].clone(),
                    rounds,
                },
            ];
            let (a, b) = tokio::join!(
                self.post::<_, Envelope>(0, "/finish", &finishes[0]),
                self.post::<_, Envelope>(1, "/finish", &finishes[1])
            );
            let shares = [a?, b?];
            let results = [
                ResultRequest {
                    finish: finishes[0].clone(),
                    shares: shares.clone(),
                },
                ResultRequest {
                    finish: finishes[1].clone(),
                    shares,
                },
            ];
            let (a, b) = tokio::join!(
                self.post::<_, ResultResponse>(0, "/result", &results[0]),
                self.post::<_, ResultResponse>(1, "/result", &results[1])
            );
            let receipts = [a?, b?];
            let expected = derive_public(&request.registration, &attempt.commit.account)?;
            for i in 0..2 {
                let r = &receipts[i].receipt;
                pairkey_sdk::service::verify_receipt(
                    &request.registration,
                    &attempt,
                    &request.message,
                    &receipts[i],
                    self.config.identities[i],
                    if i == 0 { Role::A } else { Role::B },
                    true,
                )?;
                ensure!(
                    r.version == 1
                        && r.development
                        && r.role.index() == i
                        && r.boot_id == peers[i].evidence.boot_id
                        && r.peer_boot == peers[1 - i].evidence.boot_id
                        && r.attempt_digest == attempt.digest()
                        && r.public_key == expected
                        && r.message_hash == attempt.commit.message_hash,
                    "receipt context mismatch"
                );
                let public = ed25519_dalek::VerifyingKey::from_bytes(&self.config.identities[i])?;
                public.verify_strict(
                    &receipt_message(r),
                    &ed25519_dalek::Signature::from_slice(&receipts[i].identity_signature)?,
                )?;
                let signature: [u8; 64] = r
                    .signature
                    .as_slice()
                    .try_into()
                    .context("signature length")?;
                ensure!(
                    pairkey_sdk::verify_signature(
                        &request.registration,
                        &attempt.commit,
                        &request.message,
                        &signature
                    ),
                    "signature does not verify"
                );
            }
            ensure!(
                receipts[0].receipt.signature == receipts[1].receipt.signature,
                "workers produced different results"
            );
            Ok::<_, anyhow::Error>(SignedResult {
                attempt: attempt.clone(),
                signature: receipts[0].receipt.signature.clone(),
                receipts,
                elapsed_ms: started.elapsed().as_millis() as u64,
            })
        }
        .await;
        if work.is_err() {
            let _ = tokio::join!(
                self.client
                    .post(format!("{}/abort", self.config.workers[0]))
                    .json(&attempt)
                    .send(),
                self.client
                    .post(format!("{}/abort", self.config.workers[1]))
                    .json(&attempt)
                    .send()
            );
        }
        work
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Job {
    Queued,
    Working,
    Complete { result: Box<SignedResult> },
    Failed { error: String },
}
struct Entry {
    job: Job,
    created: Instant,
}
struct Service {
    intent_jobs: Mutex<jobs::Store>,
    cancels: jobs::Cancels,
    multi: Arc<tokio::sync::Mutex<()>>,
    relay: Relay,
    jobs: Mutex<BTreeMap<String, Entry>>,
    capacity: Arc<tokio::sync::Semaphore>,
    subscriptions: Arc<tokio::sync::Semaphore>,
}
type S = Arc<Service>;
async fn propose(
    State(s): State<S>,
    Json(request): Json<RegistrationRequest>,
) -> Result<Json<RegistrationProposal>, (StatusCode, Json<Value>)> {
    let _permit = s.capacity.clone().try_acquire_owned().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"job capacity reached"})),
        )
    })?;
    s.relay.registration(request).await.map(Json).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":e.to_string()})),
        )
    })
}
async fn enqueue(
    State(s): State<S>,
    Json(value): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if value.get("signing").is_some() {
        let q: jobs::Submission = serde_json::from_value(value).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":e.to_string()})),
            )
        })?;
        return jobs::enqueue(s, q.signing).await;
    }
    let request: SignRequest = serde_json::from_value(value).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":e.to_string()})),
        )
    })?;
    request
        .commit
        .authorize(&request.registration, &request.message)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":e.to_string()})),
            )
        })?;
    let permit = s.capacity.clone().try_acquire_owned().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"job capacity reached"})),
        )
    })?;
    let mut random = [0; 32];
    OsRng.fill_bytes(&mut random);
    let id = Pubkey::new_from_array(random).to_string();
    {
        let mut jobs = s.jobs.lock().unwrap();
        jobs.retain(|_, v| v.created.elapsed().as_secs() < 300);
        if jobs.len() >= 512 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error":"result cache full"})),
            ));
        }
        jobs.insert(
            id.clone(),
            Entry {
                job: Job::Queued,
                created: Instant::now(),
            },
        );
    }
    let job_id = id.clone();
    tokio::spawn(async move {
        s.jobs.lock().unwrap().get_mut(&job_id).unwrap().job = Job::Working;
        let job = match s.relay.sign(request).await {
            Ok(result) => Job::Complete {
                result: Box::new(result),
            },
            Err(e) => Job::Failed {
                error: e.to_string(),
            },
        };
        s.jobs.lock().unwrap().get_mut(&job_id).unwrap().job = job;
        drop(permit);
    });
    Ok(Json(json!({"job_id":id})))
}
async fn poll(State(s): State<S>, Path(id): Path<String>) -> Result<Json<Value>, StatusCode> {
    if let Some(job) = s
        .intent_jobs
        .lock()
        .unwrap()
        .get(&id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Ok(Json(serde_json::to_value(job).unwrap()));
    }
    s.jobs
        .lock()
        .unwrap()
        .get(&id)
        .map(|e| Json(serde_json::to_value(&e.job).unwrap()))
        .ok_or(StatusCode::NOT_FOUND)
}
async fn events(
    State(s): State<S>,
    Path(id): Path<String>,
) -> Result<
    Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>>,
    StatusCode,
> {
    if !s.jobs.lock().unwrap().contains_key(&id)
        && s.intent_jobs
            .lock()
            .unwrap()
            .get(&id)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .is_none()
    {
        return Err(StatusCode::NOT_FOUND);
    }
    let permit = s
        .subscriptions
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let stream = futures_util::stream::unfold(
        (s, id, false, permit),
        |(s, id, done, permit)| async move {
            if done {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            let job = match poll(State(s.clone()), Path(id.clone())).await {
                Ok(Json(job)) => job,
                Err(_) => {
                    json!({"status":"failed","code":"unavailable","error":"job expired or store unavailable","may_have_signed":true})
                }
            };
            let done = matches!(job["status"].as_str(), Some("complete" | "failed"));
            Some((
                Ok(Event::default().json_data(job).expect("job serialization")),
                (s, id, done, permit),
            ))
        },
    );
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
pub async fn run(config: Config) -> anyhow::Result<()> {
    let bind: std::net::SocketAddr = config.bind.parse()?;
    ensure!(
        bind.ip().is_loopback(),
        "local coordinator must bind loopback"
    );
    let context = pairkey_types::digest(
        b"pairkey/job-store/v2",
        &(config.workers.clone(), config.identities),
    );
    let intent_jobs = jobs::Store::open(
        config
            .jobs_file
            .as_deref()
            .context("jobs_file must be configured")?,
        context,
    )?;
    let service = Arc::new(Service {
        intent_jobs: Mutex::new(intent_jobs),
        cancels: Default::default(),
        multi: Default::default(),
        relay: Relay::new(config)?,
        jobs: Mutex::new(BTreeMap::new()),
        capacity: Arc::new(tokio::sync::Semaphore::new(64)),
        subscriptions: Arc::new(tokio::sync::Semaphore::new(64)),
    });
    let app = Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"development":true,"ready":true})) }),
        )
        .route("/multi/keys", post(multi::key))
        .route("/multi/sign", post(multi::sign))
        .route("/registrations", post(propose))
        .route("/jobs", post(enqueue))
        .route("/jobs/:id", get(poll))
        .route("/jobs/:id/events", get(events))
        .route("/jobs/:id/cancel", post(jobs::cancel))
        .layer(DefaultBodyLimit::max(16_384))
        .with_state(service);
    println!(
        "{}",
        json!({"event":"local_coordinator_ready", "bind":bind.to_string()})
    );
    axum::serve(tokio::net::TcpListener::bind(bind).await?, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn live_subscription_limit_is_released_when_client_body_is_dropped() {
        let relay = Relay::new(Config {
            jobs_file: None,
            bind: "127.0.0.1:0".into(),
            workers: ["http://127.0.0.1:1".into(), "http://127.0.0.1:2".into()],
            identities: [[1; 32], [2; 32]],
        })
        .unwrap();
        let path = std::env::temp_dir().join(format!(
            "pairkey-subscriptions-{}",
            Pubkey::new_from_array(pairkey_signing::dkls::fresh())
        ));
        let s = Arc::new(Service {
            intent_jobs: Mutex::new(jobs::Store::open(path.to_str().unwrap(), [0; 32]).unwrap()),
            cancels: Default::default(),
            multi: Default::default(),
            relay,
            jobs: Mutex::new(BTreeMap::from([(
                "job".into(),
                Entry {
                    job: Job::Working,
                    created: Instant::now(),
                },
            )])),
            capacity: Arc::new(tokio::sync::Semaphore::new(64)),
            subscriptions: Arc::new(tokio::sync::Semaphore::new(64)),
        });
        let mut bodies = Vec::new();
        for _ in 0..64 {
            bodies.push(
                events(State(s.clone()), Path("job".into()))
                    .await
                    .expect("subscription refused before limit"),
            );
        }
        assert_eq!(
            events(State(s.clone()), Path("job".into())).await.err(),
            Some(StatusCode::TOO_MANY_REQUESTS)
        );
        bodies.pop();
        assert!(events(State(s), Path("job".into())).await.is_ok());
    }
}
