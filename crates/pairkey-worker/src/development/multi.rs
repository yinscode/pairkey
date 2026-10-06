//! Local multi-suite bridge. Native D workers own their roots and donor lifecycle.
//! Every outgoing signing frame is checked against current Solana authority.
use super::*;
use pairkey_signing::{self as signing, dkls, redpallas, wire as mw, Payload, Suite};
use std::process::Stdio;
#[derive(Debug)]
struct BackendRateLimit;
impl std::fmt::Display for BackendRateLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native peer transport rate limited")
    }
}
impl std::error::Error for BackendRateLimit {}

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::mpsc,
};

pub(super) struct Multi {
    root: Zeroizing<[u8; 32]>,
    root_path: String,
    binary: Option<String>,
    d: tokio::sync::Mutex<Option<DChild>>,
    red: Mutex<BTreeMap<[u8; 32], RedAttempt>>,
}
struct RedAttempt {
    pending: Option<redpallas::Pending>,
    created: Instant,
    peer_boot: [u8; 32],
    lease: Arc<AttemptLease>,
}
impl Drop for RedAttempt {
    fn drop(&mut self) {
        self.lease.cancelled.store(true, Ordering::SeqCst);
    }
}
struct RedFlight {
    worker: W,
    id: [u8; 32],
    pending: Option<redpallas::Pending>,
    peer_boot: [u8; 32],
    deadline: Instant,
    lease: Arc<AttemptLease>,
}
impl Drop for RedFlight {
    fn drop(&mut self) {
        let mut map = self.worker.multi.red.lock().unwrap();
        if map
            .get(&self.id)
            .is_some_and(|p| Arc::ptr_eq(&p.lease, &self.lease))
        {
            map.remove(&self.id);
        }
    }
}
struct DChild {
    child: Child,
    input: ChildStdin,
    events: mpsc::Receiver<dkls::Frame>,
    reader: tokio::task::JoinHandle<()>,
    boot: dkls::pool::Boot,
    peer: mw::Info,
    enrolled: bool,
    active: Option<([u8; 32], Option<mw::Authorized>, Instant)>,
}
impl Drop for DChild {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        self.reader.abort();
    }
}
impl Multi {
    pub(super) fn prune(&self) {
        self.red
            .lock()
            .unwrap()
            .retain(|_, p| p.created.elapsed() < ATTEMPT_TTL);
    }
    pub(super) async fn expire(&self) {
        let mut state = self.d.lock().await;
        if state
            .as_ref()
            .and_then(|d| d.active.as_ref())
            .is_some_and(|(_, _, t)| t.elapsed() >= Duration::from_secs(35))
        {
            *state = None;
        }
    }
    pub(super) fn new(root: [u8; 32], root_path: String, binary: Option<String>) -> Self {
        Self {
            root: Zeroizing::new(root),
            root_path,
            binary,
            d: Default::default(),
            red: Default::default(),
        }
    }
}
fn role(w: &Worker) -> Role {
    w.channel.attest([0; 32]).evidence.role
}
fn namespace(w: &Worker, reg: &pairkey_types::Registration) -> anyhow::Result<()> {
    reg.validate()?;
    ensure!(
        reg.namespace.network == w.trust.network
            && reg.namespace.registry == w.trust.registry.to_bytes()
            && pair_registry::set_address(&w.trust.registry, &reg.namespace.enclave_set).0
                == w.trust.enclave_set,
        "namespace trust mismatch"
    );
    let own = w.signer.proof(&reg.namespace, &mut OsRng)?;
    ensure!(
        own.public_share == reg.public_shares[role(w).index()],
        "namespace root mismatch"
    );
    Ok(())
}
fn begin(a: &mw::Authorized) -> anyhow::Result<Begin> {
    a.request.validate()?;
    Ok(Begin {
        registration: a.request.registration.clone(),
        attempt: a.request.attempt.clone(),
        message: a.request.intent.bytes()?,
        peer: a.peer.clone(),
    })
}
async fn view(w: &Worker, a: &mw::Authorized) -> anyhow::Result<(Begin, AuthorizedView)> {
    let b = begin(a)?;
    w.channel.authenticate_peer(&b.peer)?;
    let v = w.observe(&b).await?;
    Ok((b, v))
}
fn receipt(
    w: &Worker,
    a: &mw::Authorized,
    signature: Vec<u8>,
    slot: u64,
) -> anyhow::Result<mw::Receipt> {
    a.request.intent.verify(&signature)?;
    let mut r = mw::Receipt {
        version: mw::PROTOCOL_VERSION,
        development: true,
        hardware_backed: false,
        request: a.request.clone(),
        signature,
        role: role(w),
        boot: w.channel.boot_id(),
        peer_boot: a.peer.evidence.boot_id,
        finalized_slot: slot,
        identity_signature: vec![],
    };
    r.identity_signature = w.channel.sign_public(&r.message());
    Ok(r)
}
pub(super) async fn info(
    State(w): State<W>,
    Json(q): Json<mw::KeyRequest>,
) -> Result<Json<mw::Info>, Failure> {
    let work = || -> anyhow::Result<_> {
        w.active()?;
        namespace(&w, &q.registration)?;
        q.account.validate()?;
        let root = dkls::Root::load(std::path::Path::new(&w.multi.root_path))?;
        let mut i = mw::Info {
            protocol: mw::PROTOCOL_VERSION,
            request: q.clone(),
            role: role(&w),
            boot: w.channel.boot_id(),
            dkls_identity: root
                .identity(role(&w).index() as u8)
                .verifying_key()
                .to_bytes(),
            redpallas: if q.suite == Suite::FrostRedPallas {
                Some(redpallas::proof(
                    &w.multi.root,
                    &q.registration,
                    &q.account,
                    role(&w),
                )?)
            } else {
                None
            },
            signature: vec![],
        };
        i.signature = w.channel.sign_public(&i.message());
        Ok(i)
    };
    work().map(Json).map_err(failure)
}
pub(super) async fn open(
    State(w): State<W>,
    Json(q): Json<mw::Open>,
) -> Result<Json<dkls::pool::Boot>, Failure> {
    async {
        w.active()?;
        namespace(&w, &q.peer.request.registration)?;
        ensure!(q.peer.role == role(&w).peer(), "peer role");
        q.peer.verify(w.trust.identity_keys[q.peer.role.index()])?;
        let mut state = w.multi.d.lock().await;
        if let Some(d) = state.as_ref() {
            ensure!(
                d.peer.dkls_identity == q.peer.dkls_identity && d.peer.boot == q.peer.boot,
                "backend peer restarted; reset both backends"
            );
            return Ok(d.boot.clone());
        }
        let binary = w
            .multi
            .binary
            .as_ref()
            .context("DKLS binary not configured")?;
        let mut child = Command::new(binary)
            .args([
                "d-worker",
                &role(&w).index().to_string(),
                &w.multi.root_path,
                &signing::hex(&q.peer.dkls_identity),
                "100",
                "600",
            ])
            .env_remove("PAIRKEY_RESEARCH_BAD_MIGRATION_PPRF")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().context("stdin")?;
        let mut out = BufReader::new(child.stdout.take().context("stdout")?);
        let (tx, mut events) = mpsc::channel(16);
        let reader = tokio::spawn(async move {
            loop {
                let mut line = Vec::new();
                let result = (&mut out)
                    .take(dkls::MAX_FRAME as u64 + 1)
                    .read_until(b'\n', &mut line)
                    .await;
                if !matches!(result,Ok(n) if n>0) || line.len() > dkls::MAX_FRAME {
                    break;
                }
                match serde_json::from_slice(&line) {
                    Ok(frame) => {
                        if tx.send(frame).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(dkls::Frame::Closed).await;
        });
        let frame = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await?
            .context("backend startup closed")?;
        let dkls::Frame::PoolHello(boot) = frame else {
            anyhow::bail!("backend startup")
        };
        boot.validate()?;
        let root = dkls::Root::load(std::path::Path::new(&w.multi.root_path))?;
        ensure!(
            boot.identity
                == root
                    .identity(role(&w).index() as u8)
                    .verifying_key()
                    .to_bytes()
                && boot.role as usize == role(&w).index(),
            "backend identity"
        );
        *state = Some(DChild {
            child,
            input,
            events,
            reader,
            boot: boot.clone(),
            peer: q.peer,
            enrolled: false,
            active: None,
        });
        Ok(boot)
    }
    .await
    .map(Json)
    .map_err(failure)
}
async fn send(d: &mut DChild, f: &dkls::Frame) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec(f)?;
    ensure!(bytes.len() <= dkls::MAX_FRAME, "frame bound");
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(2), d.input.write_all(&bytes)).await??;
    Ok(())
}
pub(super) async fn enroll(
    State(w): State<W>,
    Json(boots): Json<[dkls::pool::Boot; 2]>,
) -> Result<StatusCode, Failure> {
    async {
        let mut state = w.multi.d.lock().await;
        let d = state.as_mut().context("backend absent")?;
        for b in &boots {
            b.validate()?;
        }
        ensure!(
            boots[role(&w).index()].message() == d.boot.message()
                && boots[role(&w).peer().index()].identity == d.peer.dkls_identity,
            "backend enrollment"
        );
        if !d.enrolled {
            send(
                d,
                &dkls::Frame::DCommand(Box::new(dkls::d::Command::Enroll(boots))),
            )
            .await?;
            d.enrolled = true;
        }
        Ok::<_, anyhow::Error>(StatusCode::NO_CONTENT)
    }
    .await
    .map_err(failure)
}
pub(super) async fn start(
    State(w): State<W>,
    Json(q): Json<mw::DStart>,
) -> Result<StatusCode, Failure> {
    async {
        w.active()?;
        let auth = match &q.operation {
            mw::DOperation::Sign { authorized, .. } => {
                ensure!(
                    q.id == authorized.request.attempt.digest(),
                    "operation context"
                );
                Some((**authorized).clone())
            }
            _ => None,
        };
        let checked = if let Some(a) = &auth {
            Some(view(&w, a).await?)
        } else {
            None
        };
        let mut state = w.multi.d.lock().await;
        let d = state.as_mut().context("backend absent")?;
        ensure!(
            d.enrolled && d.active.is_none(),
            "backend busy or unenrolled"
        );
        let mut identities = [[0; 32]; 2];
        identities[role(&w).index()] = d.boot.identity;
        identities[role(&w).peer().index()] = d.peer.dkls_identity;
        let command = match q.operation {
            mw::DOperation::Register(r) => {
                namespace(&w, &r.registration)?;
                r.account.validate()?;
                ensure!(r.suite == Suite::Dkls23Secp256k1, "suite");
                dkls::d::Command::Register {
                    wallet: signing::wallet(&r.registration, &r.account, identities),
                    attempt: q.id,
                    fault: None,
                }
            }
            mw::DOperation::Prepare => dkls::d::Command::Prepare {
                attempt: q.id,
                fault: None,
            },
            mw::DOperation::Sign {
                authorized,
                generation,
            } => {
                ensure!(
                    authorized.peer.evidence.boot_id == d.peer.boot,
                    "backend peer boot mismatch"
                );
                let r = &authorized.request;
                let mw::Certificate::Dkls(c) = &r.certificate else {
                    anyhow::bail!("certificate suite")
                };
                ensure!(
                    c.record.wallet
                        == signing::wallet(&r.registration, &r.intent.key.account, identities),
                    "DKLS identity/domain mismatch"
                );
                let prehash = match &r.intent.payload {
                    Payload::EvmTransfer(tx) => tx.prehash()?,
                    Payload::EvmMessage(message) => message.prehash()?,
                    _ => anyhow::bail!("ECDSA payload"),
                };
                dkls::d::Command::Sign(dkls::d::Request {
                    wallet: c.record.wallet.clone(),
                    record: c.record.digest(),
                    generation,
                    path: "m".into(),
                    prehash,
                    attempt: q.id,
                    fault: None,
                })
            }
        };
        if let Some((b, v)) = &checked {
            drop(w.release_guard(b, v)?);
        }
        d.active = Some((q.id, auth, Instant::now()));
        if let Err(e) = send(d, &dkls::Frame::DCommand(Box::new(command))).await {
            *state = None;
            return Err(e);
        }
        Ok::<_, anyhow::Error>(StatusCode::NO_CONTENT)
    }
    .await
    .map_err(failure)
}
pub(super) async fn exchange(
    State(w): State<W>,
    Json(q): Json<mw::Exchange>,
) -> Result<Json<mw::DOutput>, Failure> {
    let work = async {
        w.active()?;
        ensure!(q.frames.len() <= 4, "frame batch bound");
        let mut state = w.multi.d.lock().await;
        let d = state.as_mut().context("backend absent")?;
        let (id, auth, created) = d.active.as_ref().context("no active operation")?;
        ensure!(
            *id == q.id && created.elapsed() < Duration::from_secs(35),
            "expired or wrong operation"
        );
        let auth = auth.clone();
        // Incoming transport may only carry protocol data, never a worker command.
        for f in &q.frames {
            ensure!(
                matches!(f, dkls::Frame::Setup(_) | dkls::Frame::Relay(_)),
                "forbidden backend frame"
            );
            send(d, f).await?;
        }
        let mut frames = vec![];
        let mut result = None;
        let mut terminal = false;
        // One frame keeps response size bounded even for native DKG messages.
        if let Ok(frame) = d.events.try_recv() {
            match frame {
                dkls::Frame::DReply(dkls::d::Reply::Signed {
                    signature,
                    public_key,
                    recovery_id,
                    ..
                }) => {
                    let a = auth
                        .as_ref()
                        .context("unsigned operation produced signature")?;
                    ensure!(
                        public_key == a.request.intent.key.public_key,
                        "signed wrong key"
                    );
                    let mut sig = signature;
                    sig.push(recovery_id);
                    let (b, v) = view(&w, a).await?;
                    let _release = w.release_guard(&b, &v)?;
                    result = Some(receipt(&w, a, sig, v.observation.slot)?);
                    terminal = true;
                }
                dkls::Frame::Failure(f) => {
                    if f.detail == "D peer transport rate limited" {
                        return Err(BackendRateLimit.into());
                    }
                    if matches!(
                        f.action,
                        dkls::lifecycle::Action::QuarantinePeer
                            | dkls::lifecycle::Action::FreezeConfiguration
                    ) {
                        w.release.lock().unwrap().record_incident()?;
                    }
                    anyhow::bail!("backend failed: {f:?}")
                }
                dkls::Frame::Closed => anyhow::bail!("backend closed"),
                other => {
                    if let Some(a) = &auth {
                        let (b, v) = view(&w, a).await?;
                        let _release = w.release_guard(&b, &v)?;
                        frames.push(other);
                    } else {
                        terminal = matches!(other, dkls::Frame::DReply(_));
                        frames.push(other);
                    }
                }
            }
        }
        if terminal {
            d.active = None;
        }
        Ok::<_, anyhow::Error>(mw::DOutput {
            frames,
            receipt: result,
        })
    }
    .await;
    if work.is_err() {
        *w.multi.d.lock().await = None;
    }
    work.map(Json).map_err(|e| {
        if e.is::<BackendRateLimit>() { (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error":e.to_string(),"code":"backend_rate_limited","retry_after_secs":61}))) } else { failure(e) }
    })
}
pub(super) async fn reset(State(w): State<W>) -> StatusCode {
    *w.multi.d.lock().await = None;
    let _release = w.release.lock().unwrap();
    w.multi.red.lock().unwrap().clear();
    StatusCode::NO_CONTENT
}

pub(super) async fn rbegin(
    State(w): State<W>,
    Json(q): Json<mw::RBegin>,
) -> Result<Json<Envelope>, Failure> {
    async {
        let a = &q.authorized;
        let (b, v) = view(&w, a).await?;
        let _release = w.release_guard(&b, &v)?;
        let mw::Certificate::RedPallas(public) = &a.request.certificate else {
            anyhow::bail!("RedPallas certificate")
        };
        let Payload::RedPallas { message } = &a.request.intent.payload else {
            anyhow::bail!("RedPallas payload")
        };
        let id = b.attempt.digest();
        let mut pending = w.multi.red.lock().unwrap();
        pending.retain(|_, p| p.created.elapsed() < ATTEMPT_TTL);
        ensure!(
            pending.len() < 64 && !pending.contains_key(&id),
            "RedPallas capacity or duplicate attempt"
        );
        let permit = w.nonce_capacity.clone().try_acquire_owned()?;
        let (round, owned) = redpallas::Pending::begin(
            &w.multi.root,
            &b.registration,
            &a.request.intent.key.account,
            public,
            role(&w),
            message,
        )?;
        let envelope = w.channel.seal(&b.peer, id, 11, &round)?;
        pending.insert(
            id,
            RedAttempt {
                pending: Some(owned),
                created: Instant::now(),
                peer_boot: b.peer.evidence.boot_id,
                lease: Arc::new(AttemptLease {
                    cancelled: AtomicBool::new(false),
                    _permit: permit,
                }),
            },
        );
        Ok::<_, anyhow::Error>(envelope)
    }
    .await
    .map(Json)
    .map_err(failure)
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct RedFinish {
    pub authorized: mw::Authorized,
    pub rounds: [Envelope; 2],
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct RedResult {
    pub finish: RedFinish,
    pub shares: [Envelope; 2],
}
fn rounds(w: &Worker, q: &RedFinish) -> anyhow::Result<[Vec<u8>; 2]> {
    let b = begin(&q.authorized)?;
    ensure!(
        q.rounds[0].sender == Role::A && q.rounds[1].sender == Role::B,
        "round role order"
    );
    Ok([
        w.channel
            .open(&b.peer, b.attempt.digest(), 11, &q.rounds[0])?,
        w.channel
            .open(&b.peer, b.attempt.digest(), 11, &q.rounds[1])?,
    ])
}
pub(super) async fn rfinish(
    State(w): State<W>,
    Json(q): Json<RedFinish>,
) -> Result<Json<Envelope>, Failure> {
    async {
        let id = q.authorized.request.attempt.digest();
        // Leave a lease in the map while the nonce is owned by this future.
        // This rejects duplicate begins and lets reset/expiry cancel in-flight work.
        let mut owned = {
            let mut map = w.multi.red.lock().unwrap();
            let p = map.get_mut(&id).context("nonce absent or consumed")?;
            RedFlight {
                worker: Arc::clone(&w),
                id,
                pending: Some(p.pending.take().context("nonce already in flight")?),
                peer_boot: p.peer_boot,
                deadline: p.created + ATTEMPT_TTL,
                lease: Arc::clone(&p.lease),
            }
        };
        let deadline = owned.deadline;
        tokio::time::timeout_at(deadline.into(), async {
            let (b, v) = view(&w, &q.authorized).await?;
            let rounds = rounds(&w, &q)?;
            ensure!(
                owned.peer_boot == b.peer.evidence.boot_id && Instant::now() < deadline,
                "expired or restarted attempt"
            );
            let _release = w.release_guard(&b, &v)?;
            ensure!(
                !owned.lease.cancelled.load(Ordering::SeqCst),
                "cancelled RedPallas attempt"
            );
            let share = owned
                .pending
                .take()
                .context("consumed nonce")?
                .finish(&rounds)?;
            let transcript = pairkey_types::digest(b"pairkey/redpallas/rounds/v1", &(id, &rounds));
            Ok::<_, anyhow::Error>(w.channel.seal(&b.peer, id, 12, &(transcript, share))?)
        })
        .await?
    }
    .await
    .map(Json)
    .map_err(failure)
}
pub(super) async fn rresult(
    State(w): State<W>,
    Json(q): Json<RedResult>,
) -> Result<Json<mw::Receipt>, Failure> {
    async {
        let a = &q.finish.authorized;
        let (b, v) = view(&w, a).await?;
        let rounds = rounds(&w, &q.finish)?;
        ensure!(
            q.shares[0].sender == Role::A && q.shares[1].sender == Role::B,
            "share roles"
        );
        let mut shares = [vec![], vec![]];
        let id = b.attempt.digest();
        let transcript = pairkey_types::digest(b"pairkey/redpallas/rounds/v1", &(id, &rounds));
        for (i, e) in q.shares.iter().enumerate() {
            let (t, s): ([u8; 32], Vec<u8>) = w.channel.open(&b.peer, id, 12, e)?;
            ensure!(t == transcript, "stale RedPallas transcript");
            shares[i] = s;
        }
        let mw::Certificate::RedPallas(public) = &a.request.certificate else {
            anyhow::bail!("certificate")
        };
        let Payload::RedPallas { message } = &a.request.intent.payload else {
            anyhow::bail!("payload")
        };
        let mut release = w.release_guard(&b, &v)?;
        let sig = match redpallas::aggregate(
            &b.registration,
            &a.request.intent.key.account,
            public,
            message,
            &rounds,
            &shares,
        ) {
            Ok(s) => s,
            Err(e) => {
                release.record_incident()?;
                return Err(e);
            }
        };
        receipt(&w, a, sig, v.observation.slot)
    }
    .await
    .map(Json)
    .map_err(failure)
}
