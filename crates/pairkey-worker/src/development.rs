//! Local-host adapter: this does not implement Phala or Oyster attestation/KMS.
use crate::wire::*;
use anyhow::{ensure, Context};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use pairkey_channel::{Channel, Envelope};
use pairkey_core::{
    authorize, prepare, ControlFence, Freshness, Observation, ObservedAccount,
    SimulationObservation, Trust,
};
use pairkey_frost::{
    aggregate, register, Possession, Root, RoundOne, RoundTwo, Signer, SigningAttempt,
};
use pairkey_sdk::rpc::Rpc;
use pairkey_types::{derive_public, Attempt, Namespace, Role};
use rand_core::OsRng;
use serde::Deserialize;
use serde_json::{json, Value};
use solana_sdk::pubkey::Pubkey;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

mod multi;
#[cfg(test)]
mod tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub dkls_binary: Option<String>,
    pub role: Role,
    pub bind: String,
    pub root_file: String,
    pub identity_file: String,
    pub peer_identity: [u8; 32],
    pub rpc_url: String,
    pub provider_domain: String,
    pub network: [u8; 32],
    pub set_id: [u8; 32],
    pub set_governor: [u8; 32],
}
const ATTEMPT_TTL: Duration = Duration::from_secs(15);
struct AttemptLease {
    cancelled: AtomicBool,
    // Held until BOTH metadata and any in-flight nonce owner have been dropped.
    _permit: tokio::sync::OwnedSemaphorePermit,
}
struct Pending {
    signing: Option<SigningAttempt>,
    lease: Arc<AttemptLease>,
    peer_boot: [u8; 32],
    created: Instant,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.lease.cancelled.store(true, Ordering::SeqCst);
    }
}
struct InFlight {
    worker: W,
    id: [u8; 32],
    signing: Option<SigningAttempt>,
    lease: Arc<AttemptLease>,
    peer_boot: [u8; 32],
    deadline: Instant,
}
impl InFlight {
    fn sign(&mut self, rounds: &[RoundOne; 2]) -> anyhow::Result<RoundTwo> {
        ensure!(
            !self.lease.cancelled.load(Ordering::SeqCst) && Instant::now() < self.deadline,
            "cancelled or expired attempt"
        );
        Ok(self
            .signing
            .take()
            .context("consumed attempt")?
            .finish(rounds)?)
    }
}
impl Drop for InFlight {
    fn drop(&mut self) {
        let mut pending = self.worker.pending.lock().unwrap();
        // An expired/aborted identifier may already name a new generation.
        if pending
            .get(&self.id)
            .is_some_and(|p| Arc::ptr_eq(&p.lease, &self.lease))
        {
            pending.remove(&self.id);
        }
        // The owned SigningAttempt clears its nonce and key on every exit.
    }
}
#[derive(Default)]
struct ReleaseState {
    highest_slot: u64,
    controls: ControlFence,
    incident: bool,
    incident_store: Option<pairkey_core::local_store::LocalStore>,
    policies: BTreeMap<Pubkey, (u64, u64)>,
}
impl ReleaseState {
    fn load(path: &str) -> anyhow::Result<Self> {
        let store = pairkey_core::local_store::LocalStore::open(path, 1024)?;
        let incident = match store.read()? {
            None => {
                store.write(b"ready-v1\n")?;
                false
            }
            Some(bytes) => bytes != b"ready-v1\n",
        };
        Ok(Self {
            incident,
            incident_store: Some(store),
            ..Default::default()
        })
    }
    fn record_incident(&mut self) -> anyhow::Result<()> {
        self.incident = true;
        if let Some(store) = &self.incident_store {
            store.write(b"incident-v1\n")?;
        }
        Ok(())
    }
    fn protocol_error(&mut self, error: &pairkey_frost::Error) -> anyhow::Result<()> {
        // An attempt/transcript mismatch is stale routing, not proof of cheating.
        if matches!(error, pairkey_frost::Error::Frost(_)) {
            self.record_incident()?;
        }
        Ok(())
    }
}
struct AuthorizedView {
    observation: Observation,
    minimum_slot: u64,
}
struct Worker {
    multi: multi::Multi,
    signer: Signer,
    channel: Channel,
    rpc: Rpc,
    trust: Trust,
    pending: Mutex<BTreeMap<[u8; 32], Pending>>,
    // One lock orders known control/policy/incident updates with local issuance.
    // It is held through signing/sealing, never across an await or network I/O.
    release: Mutex<ReleaseState>,
    freshness: Freshness,
    started: Instant,
    capacity: Arc<tokio::sync::Semaphore>,
    nonce_capacity: Arc<tokio::sync::Semaphore>,
}
type W = Arc<Worker>;
type Failure = (StatusCode, Json<Value>);
fn failure(error: impl std::fmt::Display) -> Failure {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":error.to_string()})),
    )
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64
}
fn secret_file(path: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.len() == 32,
        "development secret must be a private 32-byte regular file"
    );
    let bytes = Zeroizing::new(std::fs::read(path)?);
    Ok(Zeroizing::new(
        bytes
            .as_slice()
            .try_into()
            .context("invalid secret length")?,
    ))
}
impl Worker {
    fn active(&self) -> anyhow::Result<()> {
        ensure!(
            !self.release.lock().unwrap().incident,
            "authenticated protocol incident; worker refuses signing until operator investigation"
        );
        Ok(())
    }
    fn prune(&self) {
        let _release = self.release.lock().unwrap();
        let mut map = self.pending.lock().unwrap();
        map.retain(|_, p| p.created.elapsed() < ATTEMPT_TTL);
        self.multi.prune();
    }
    fn claim(self: &Arc<Self>, id: [u8; 32]) -> anyhow::Result<InFlight> {
        let mut pending = self.pending.lock().unwrap();
        let p = pending.get_mut(&id).context("unknown or expired attempt")?;
        Ok(InFlight {
            worker: Arc::clone(self),
            id,
            signing: Some(p.signing.take().context("attempt already in flight")?),
            lease: Arc::clone(&p.lease),
            peer_boot: p.peer_boot,
            deadline: p.created + ATTEMPT_TTL,
        })
    }
    fn observe_inactive(&self, slot: u64) -> anyhow::Result<()> {
        let mut release = self.release.lock().unwrap();
        release.controls.observe_inactive(slot)?;
        release.highest_slot = release.highest_slot.max(slot);
        Ok(())
    }
    fn release_guard(
        &self,
        begin: &Begin,
        view: &AuthorizedView,
    ) -> anyhow::Result<MutexGuard<'_, ReleaseState>> {
        let release = self.release.lock().unwrap();
        ensure!(!release.incident, "authenticated protocol incident");
        // Revalidate time/session expiry after waiting for the issuance lock.
        self.freshness.check(
            view.observation.slot,
            view.observation.block_time,
            self.started.elapsed().as_millis() as u64,
            self.trust.max_observation_age_secs as u64 * 1000,
        )?;
        let reg = authorize(
            &self.trust,
            &view.observation,
            &begin.attempt,
            &begin.message,
            now(),
            view.minimum_slot,
        )?;
        ensure!(reg == begin.registration, "registration changed");
        release.controls.check_active(view.observation.slot)?;
        ensure!(
            release
                .policies
                .get(&view.observation.namespace.address)
                .map(|p| p.0)
                == Some(begin.attempt.authorization.policy_version),
            "policy changed before issuance"
        );
        Ok(release)
    }
    async fn observe(&self, begin: &Begin) -> anyhow::Result<AuthorizedView> {
        self.active()?;
        // Capture the lower bound once; concurrent newer reads cannot invalidate this read.
        let minimum_slot = {
            let release = self.release.lock().unwrap();
            release.highest_slot.max(release.controls.minimum_slot())
        };
        let program = pair_registry::id();
        let namespace = pair_registry::namespace_address(&program, &begin.registration).0;
        let request =
            pair_registry::request_address(&program, &namespace, &begin.attempt.commit.request_id)
                .0;
        let policy_address = pair_registry::policy_address(&program, &namespace).0;
        let session_address = begin.attempt.authorization.session_id.map(|id| {
            pairkey_core::session_address_for_message(&program, &namespace, &id, &begin.message)
        });
        let rules_address = pair_registry::approval::rules_address(
            &program,
            &begin.registration.namespace.digest(),
        )
        .0;
        let mut addresses = vec![
            self.trust.enclave_set,
            namespace,
            request,
            policy_address,
            rules_address,
        ];
        if let Some(session) = session_address {
            addresses.push(session);
        }
        let response = self.rpc.call("getMultipleAccounts", json!([addresses.iter().map(ToString::to_string).collect::<Vec<_>>(), {"encoding":"base64", "commitment":"finalized", "minContextSlot": minimum_slot}])).await?;
        let slot = response["context"]["slot"]
            .as_u64()
            .context("invalid slot")?;
        let observed_at = now();
        let accounts = response["value"]
            .as_array()
            .context("invalid account response")?;
        ensure!(accounts.len() == addresses.len(), "missing accounts");
        let decode = |index: usize| -> anyhow::Result<ObservedAccount> {
            let value = &accounts[index];
            let owner: Pubkey = value["owner"].as_str().context("account owner")?.parse()?;
            ensure!(value["data"][1] == "base64", "invalid account encoding");
            let data = STANDARD.decode(value["data"][0].as_str().context("account bytes")?)?;
            Ok(ObservedAccount {
                address: addresses[index],
                owner,
                data,
            })
        };
        let block_time = self
            .rpc
            .call("getBlockTime", json!([slot]))
            .await?
            .as_i64()
            .context("missing finalized block time")?;
        let mut observation = Observation {
            rules: if accounts[4].is_null() {
                None
            } else {
                Some(decode(4)?)
            },
            policy: if accounts[3].is_null() {
                None
            } else {
                Some(decode(3)?)
            },
            session: if session_address.is_some() {
                Some(decode(5)?)
            } else {
                None
            },
            simulation: None,
            network: self.trust.network,
            finalized: true,
            slot,
            block_time,
            observed_at,
            provider_domain: self.trust.provider_domain.clone(),
            set: decode(0)?,
            namespace: decode(1)?,
            request: if accounts[2].is_null() {
                ObservedAccount {
                    address: request,
                    owner: program,
                    data: Vec::new(),
                }
            } else {
                decode(2)?
            },
        };
        // Authenticate the entire authorization before contacting the simulator.
        let preparation = prepare(
            &self.trust,
            &observation,
            &begin.attempt,
            &begin.message,
            now(),
            minimum_slot,
        );
        if let Err(error) = preparation {
            if matches!(error, pairkey_core::Error::Inactive) {
                self.observe_inactive(slot)?;
            }
            return Err(error.into());
        }
        {
            let mut release = self.release.lock().unwrap();
            let policies = &mut release.policies;
            let version = begin.attempt.authorization.policy_version;
            if let Some((old_version, old_slot)) = policies.get(&namespace) {
                ensure!(
                    version >= *old_version && (version == *old_version || slot >= *old_slot),
                    "stale policy observation"
                );
            } else {
                ensure!(policies.len() < 1024, "policy fence capacity reached");
            }
            let highest = policies
                .get(&namespace)
                .map(|(_, old_slot)| (*old_slot).max(slot))
                .unwrap_or(slot);
            policies.insert(namespace, (version, highest));
        }
        if let Some(input) =
            pairkey_core::simulation_input(&observation, &begin.attempt, &begin.message)?
        {
            let record: pair_registry::PolicyRecord =
                borsh::from_slice(&observation.policy.as_ref().context("policy")?.data)?;
            let config = record.policy.simulation.context("simulation config")?;
            let program_key = Pubkey::new_from_array(config.program);
            let executable = self.rpc.executable(program_key, slot).await?;
            ensure!(
                executable.hash()? == config.code_hash,
                "unapproved simulation program"
            );
            let challenge = pairkey_types::policy::simulation_message(&input);
            let signature = self
                .channel
                .sign_public(&challenge)
                .try_into()
                .map_err(|_| anyhow::anyhow!("identity signature"))?;
            let mut tx = pairkey_sdk::simulation_transaction(
                program_key,
                Pubkey::new_from_array(self.channel.identity()),
                &begin.registration,
                self.channel.identity(),
                signature,
                input,
            );
            let blockhash = self
                .rpc
                .call(
                    "getLatestBlockhash",
                    json!([{"commitment":"finalized","minContextSlot":slot}]),
                )
                .await?;
            tx.message.recent_blockhash = blockhash["value"]["blockhash"]
                .as_str()
                .context("simulation blockhash")?
                .parse()?;
            tx.signatures[0] = solana_sdk::signature::Signature::from(
                <[u8; 64]>::try_from(self.channel.sign_public(&tx.message.serialize()).as_slice())
                    .map_err(|_| anyhow::anyhow!("transaction signature"))?,
            );
            let simulated = self.rpc.call("simulateTransaction",json!([STANDARD.encode(bincode::serialize(&tx)?),{"encoding":"base64","commitment":"finalized","minContextSlot":slot,"replaceRecentBlockhash":false,"sigVerify":true}])).await?;
            ensure!(
                simulated["value"].get("err") == Some(&Value::Null),
                "simulation refused: {}",
                simulated["value"]["err"]
            );
            let returned = &simulated["value"]["returnData"];
            ensure!(
                returned["programId"].as_str() == Some(&program_key.to_string())
                    && returned["data"][1] == "base64",
                "simulation return program mismatch"
            );
            let bytes =
                STANDARD.decode(returned["data"][0].as_str().context("simulation output")?)?;
            observation.simulation = Some(SimulationObservation {
                slot: simulated["context"]["slot"]
                    .as_u64()
                    .context("simulation slot")?,
                program: executable,
                output: borsh::from_slice(&bytes)?,
            });
        }
        self.freshness.check(
            slot,
            block_time,
            self.started.elapsed().as_millis() as u64,
            self.trust.max_observation_age_secs as u64 * 1000,
        )?;
        let decision = authorize(
            &self.trust,
            &observation,
            &begin.attempt,
            &begin.message,
            now(),
            minimum_slot,
        );
        let reg=match decision {
            Ok(reg)=>reg,
            Err(pairkey_core::Error::Inactive)=> {
                self.observe_inactive(slot)?;
                return Err(pairkey_core::Error::Inactive.into());
            }
            Err(e)=>return Err(e).with_context(||format!("finalized view rejected: slot={slot}, required={minimum_slot}, block_time={block_time}, now={}",now())),
        };
        ensure!(
            reg == begin.registration,
            "delivered registration differs from chain"
        );
        let mut release = self.release.lock().unwrap();
        release.highest_slot = release.highest_slot.max(slot);
        // Also fences older reads which began before another request saw the freeze.
        release.controls.check_active(slot)?;
        {
            let (version, _) = release.policies.get(&namespace).context("policy fence")?;
            ensure!(
                *version == begin.attempt.authorization.policy_version,
                "policy changed during authorization"
            );
        }
        Ok(AuthorizedView {
            observation,
            minimum_slot,
        })
    }
    fn decode_rounds(&self, request: &Finish) -> anyhow::Result<[RoundOne; 2]> {
        let b = &request.begin;
        let id = b.attempt.digest();
        ensure!(
            request.rounds[0].sender == Role::A && request.rounds[1].sender == Role::B,
            "incorrect role order"
        );
        Ok([
            self.channel.open(&b.peer, id, 1, &request.rounds[0])?,
            self.channel.open(&b.peer, id, 1, &request.rounds[1])?,
        ])
    }
}
async fn health(State(w): State<W>) -> Json<Health> {
    Json(Health {
        role: w.channel.attest([0; 32]).evidence.role,
        identity: w.channel.identity(),
        boot_id: w.channel.boot_id(),
        development: true,
        incident: w.release.lock().unwrap().incident,
    })
}
async fn attest(
    State(w): State<W>,
    Json(q): Json<Challenge>,
) -> Json<pairkey_channel::Attestation> {
    Json(w.channel.attest(q.challenge))
}
async fn proof(State(w): State<W>, Json(ns): Json<Namespace>) -> Result<Json<Possession>, Failure> {
    w.active().map_err(failure)?;
    if ns.network != w.trust.network
        || ns.registry != w.trust.registry.to_bytes()
        || pair_registry::set_address(&w.trust.registry, &ns.enclave_set).0 != w.trust.enclave_set
    {
        return Err(failure("wrong namespace trust domain"));
    }
    w.signer.proof(&ns, &mut OsRng).map(Json).map_err(failure)
}
async fn ack(State(w): State<W>, Json(q): Json<Ack>) -> Result<Json<Vec<u8>>, Failure> {
    w.active().map_err(failure)?;
    let reg =
        register(q.registration.namespace.clone(), &q.proofs[0], &q.proofs[1]).map_err(failure)?;
    if reg != q.registration
        || reg.namespace.derivation_authority != q.controller
        || reg.namespace.network != w.trust.network
        || reg.namespace.registry != w.trust.registry.to_bytes()
        || pair_registry::set_address(&w.trust.registry, &reg.namespace.enclave_set).0
            != w.trust.enclave_set
    {
        return Err(failure("registration metadata mismatch"));
    }
    let own = w
        .signer
        .proof(&reg.namespace, &mut OsRng)
        .map_err(failure)?;
    if own.public_share != reg.public_shares[own.role.index()] {
        return Err(failure("own share mismatch"));
    }
    Ok(Json(w.channel.sign_public(
        &pair_registry::registration_message(&reg, &Pubkey::new_from_array(q.controller)),
    )))
}
async fn begin(State(w): State<W>, Json(q): Json<Begin>) -> Result<Json<Envelope>, Failure> {
    if q.attempt.authorization.session_id.is_some()
        && q.message.starts_with(pairkey_signing::INTENT_PREFIX)
    {
        return Err(failure(
            "multi-suite sessions require the matching signing endpoint",
        ));
    }
    w.prune();
    w.channel.authenticate_peer(&q.peer).map_err(failure)?;
    let view = w.observe(&q).await.map_err(failure)?;
    let _release = w.release_guard(&q, &view).map_err(failure)?;
    let mut pending = w.pending.lock().unwrap();
    let id = q.attempt.digest();
    if pending.contains_key(&id) {
        return Err(failure("attempt already pending"));
    }
    let permit = w
        .nonce_capacity
        .clone()
        .try_acquire_owned()
        .map_err(failure)?;
    let (round, signing) = w
        .signer
        .begin_owned(&q.registration, &q.attempt, &q.message, &mut OsRng)
        .map_err(failure)?;
    let envelope = w.channel.seal(&q.peer, id, 1, &round).map_err(failure)?;
    pending.insert(
        id,
        Pending {
            signing: Some(signing),
            lease: Arc::new(AttemptLease {
                cancelled: AtomicBool::new(false),
                _permit: permit,
            }),
            peer_boot: q.peer.evidence.boot_id,
            created: Instant::now(),
        },
    );
    Ok(Json(envelope))
}
async fn finish(State(w): State<W>, Json(q): Json<Finish>) -> Result<Json<Envelope>, Failure> {
    w.prune();
    let mut in_flight = w.claim(q.begin.attempt.digest()).map_err(failure)?;
    let deadline = in_flight.deadline;
    let work = async {
        ensure!(
            in_flight.peer_boot == q.begin.peer.evidence.boot_id,
            "peer restarted during attempt"
        );
        w.channel.authenticate_peer(&q.begin.peer)?;
        let view = w.observe(&q.begin).await?;
        let rounds = w.decode_rounds(&q)?;
        let mut release = w.release_guard(&q.begin, &view)?;
        let share = match in_flight.sign(&rounds) {
            Ok(share) => share,
            Err(e) => {
                if let Some(protocol) = e.downcast_ref::<pairkey_frost::Error>() {
                    release.protocol_error(protocol)?;
                }
                return Err(e);
            }
        };
        Ok::<_, anyhow::Error>(w.channel.seal(
            &q.begin.peer,
            q.begin.attempt.digest(),
            2,
            &share,
        )?)
    };
    let work = tokio::time::timeout_at(deadline.into(), work)
        .await
        .map_err(failure)?;
    work.map(Json).map_err(failure)
}
async fn result(
    State(w): State<W>,
    Json(q): Json<ResultRequest>,
) -> Result<Json<ResultResponse>, Failure> {
    let begin = &q.finish.begin;
    let id = begin.attempt.digest();
    w.channel.authenticate_peer(&begin.peer).map_err(failure)?;
    let view = w.observe(begin).await.map_err(failure)?;
    let rounds = w.decode_rounds(&q.finish).map_err(failure)?;
    if q.shares[0].sender != Role::A || q.shares[1].sender != Role::B {
        return Err(failure("incorrect role order"));
    }
    let shares: [RoundTwo; 2] = [
        w.channel
            .open(&begin.peer, id, 2, &q.shares[0])
            .map_err(failure)?,
        w.channel
            .open(&begin.peer, id, 2, &q.shares[1])
            .map_err(failure)?,
    ];
    let mut release = w.release_guard(begin, &view).map_err(failure)?;
    let signature = match aggregate(
        &begin.registration,
        &begin.attempt,
        &begin.message,
        &rounds,
        &shares,
    ) {
        Ok(signature) => signature,
        Err(e) => {
            release.protocol_error(&e).map_err(failure)?;
            return Err(failure(e));
        }
    };
    let receipt = Receipt {
        version: 1,
        development: true,
        role: w.channel.attest([0; 32]).evidence.role,
        boot_id: w.channel.boot_id(),
        peer_boot: begin.peer.evidence.boot_id,
        attempt_digest: id,
        public_key: derive_public(&begin.registration, &begin.attempt.commit.account)
            .map_err(failure)?,
        message_hash: begin.attempt.commit.message_hash,
        signature: signature.to_vec(),
        finalized_slot: view.observation.slot,
        provider_domain: w.trust.provider_domain.clone(),
    };
    let identity_signature = w.channel.sign_public(&receipt_message(&receipt));
    Ok(Json(ResultResponse {
        attestation: w.channel.attest(begin.peer.evidence.boot_id),
        receipt,
        identity_signature,
    }))
}
async fn abort(State(w): State<W>, Json(at): Json<Attempt>) -> StatusCode {
    let _release = w.release.lock().unwrap();
    w.pending.lock().unwrap().remove(&at.digest());
    StatusCode::NO_CONTENT
}
async fn limit(
    State(w): State<W>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(_permit) = w.capacity.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"worker request capacity reached"})),
        )
            .into_response();
    };
    next.run(request).await
}
pub async fn run(path: &str) -> anyhow::Result<()> {
    let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    let bind: std::net::SocketAddr = config.bind.parse()?;
    ensure!(
        bind.ip().is_loopback(),
        "development worker must bind loopback"
    );
    let root = secret_file(&config.root_file)?;
    let identity = secret_file(&config.identity_file)?;
    let channel = Channel::development(config.role, *identity, config.peer_identity);
    let rpc = Rpc::new(config.rpc_url)?;
    let genesis: Pubkey = rpc
        .call("getGenesisHash", json!([]))
        .await?
        .as_str()
        .context("genesis hash")?
        .parse()?;
    ensure!(
        genesis.to_bytes() == config.network,
        "wrong authorization network"
    );
    let mut identities = [[0; 32]; 2];
    identities[config.role.index()] = channel.identity();
    identities[config.role.peer().index()] = config.peer_identity;
    let trust = Trust {
        registry: pair_registry::id(),
        network: config.network,
        enclave_set: pair_registry::set_address(&pair_registry::id(), &config.set_id).0,
        identity_keys: identities,
        set_governor: config.set_governor,
        provider_domain: config.provider_domain,
        allow_development: true,
        max_observation_age_secs: 3,
        max_chain_lag_secs: 30,
    };
    let root_path = std::fs::canonicalize(&config.root_file)?;
    let release = ReleaseState::load(&format!("{}.incident", root_path.display()))?;
    let worker = Arc::new(Worker {
        multi: multi::Multi::new(*root, config.root_file.clone(), config.dkls_binary),
        signer: Signer::new(Root::new(*root), config.role),
        channel,
        rpc,
        trust,
        pending: Mutex::new(BTreeMap::new()),
        release: Mutex::new(release),
        freshness: Freshness::default(),
        started: Instant::now(),
        capacity: Arc::new(tokio::sync::Semaphore::new(16)),
        nonce_capacity: Arc::new(tokio::sync::Semaphore::new(64)),
    });
    let multi_router = Router::new()
        .route("/multi/info", post(multi::info))
        .route("/multi/d/open", post(multi::open))
        .route("/multi/d/enroll", post(multi::enroll))
        .route("/multi/d/start", post(multi::start))
        .route("/multi/d/exchange", post(multi::exchange))
        .route("/multi/reset", post(multi::reset))
        .route("/multi/r/begin", post(multi::rbegin))
        .route("/multi/r/finish", post(multi::rfinish))
        .route("/multi/r/result", post(multi::rresult))
        .layer(DefaultBodyLimit::max(12 * 1024 * 1024));
    let router = Router::new()
        .route("/health", get(health))
        .route("/attest", post(attest))
        .route("/proof", post(proof))
        .route("/ack", post(ack))
        .route("/begin", post(begin))
        .route("/finish", post(finish))
        .route("/result", post(result))
        .route("/abort", post(abort))
        .layer(DefaultBodyLimit::max(16_384))
        .merge(multi_router)
        .layer(axum::middleware::from_fn_with_state(worker.clone(), limit))
        .with_state(worker.clone());
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            worker.prune();
            worker.multi.expire().await;
        }
    });
    println!(
        "{}",
        json!({"event":"development_worker_ready", "role":config.role, "bind":bind.to_string(), "hardware_backed":false})
    );
    axum::serve(tokio::net::TcpListener::bind(bind).await?, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
