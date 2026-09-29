//! Research lifecycle authority. Trusted filesystem; no hostile-host guarantees.
use crate::{check_incident, digest, incident, reserve, Manifest};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sl_dkls23::{keygen::KeygenError, sign::SignError};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    Admission,
    DirectSetup,
    Migration,
    Signing,
    Transport,
    Control,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
    Burn,
    QuarantinePeer,
    FreezeConfiguration,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailureKind {
    ProtocolViolation,
    PeerAbort,
    Transport,
    Context,
    Cancelled,
    Timeout,
    Local,
    Quarantined,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Failure {
    pub phase: Phase,
    pub kind: FailureKind,
    pub peer: Option<[u8; 32]>,
    pub action: Action,
    pub detail: String,
    pub incident_persisted: bool,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}/{:?}: {}", self.phase, self.kind, self.detail)
    }
}
impl std::error::Error for Failure {}
impl Failure {
    pub fn burn(phase: Phase, kind: FailureKind, detail: impl Into<String>) -> Self {
        Self {
            phase,
            kind,
            peer: None,
            action: Action::Burn,
            detail: detail.into(),
            incident_persisted: false,
        }
    }
    pub fn violation(phase: Phase, peer: [u8; 32], detail: impl Into<String>) -> Self {
        Self {
            phase,
            kind: FailureKind::ProtocolViolation,
            peer: Some(peer),
            action: Action::QuarantinePeer,
            detail: detail.into(),
            incident_persisted: false,
        }
    }
    pub fn native_sign(error: &SignError, peer: [u8; 32]) -> Self {
        use SignError::*;
        match error {
            AbortProtocol(_) => {
                Self::burn(Phase::Signing, FailureKind::PeerAbort, error.to_string())
            }
            MissingMessage | SendMessage => {
                Self::burn(Phase::Signing, FailureKind::Transport, error.to_string())
            }
            // Session/config disagreements do not establish cheating.
            InvalidFinalSessionID => {
                Self::burn(Phase::Signing, FailureKind::Context, error.to_string())
            }
            InvalidMessage | InvalidCommitment | InvalidDigest | AbortProtocolAndBanParty(_) => {
                Self::violation(Phase::Signing, peer, error.to_string())
            }
            // Aggregate/local errors cannot safely identify the offending party.
            FailedCheck(_) | K256Error | InvalidPreSign => Self {
                action: Action::FreezeConfiguration,
                ..Self::burn(Phase::Signing, FailureKind::Local, error.to_string())
            },
        }
    }
    pub fn native_migration(error: &KeygenError, peer: [u8; 32]) -> Self {
        use KeygenError::*;
        match error {
            AbortProtocol(_) => {
                Self::burn(Phase::Migration, FailureKind::PeerAbort, error.to_string())
            }
            MissingMessage | SendMessage => {
                Self::burn(Phase::Migration, FailureKind::Transport, error.to_string())
            }
            InvalidKeyRefresh | InvalidQuorumChange | PublicKeyMismatch | BigSMismatch
            | NotUniqueXiValues | FailedFelmanVerify => Self {
                action: Action::FreezeConfiguration,
                ..Self::burn(Phase::Migration, FailureKind::Local, error.to_string())
            },
            // Pinned native Round handlers only process authenticated/decrypted
            // peer payloads. Invalid envelope signatures are ignored, not returned
            // as these variants. Two parties fixes the sole peer attribution.
            InvalidMessage
            | InvalidCommitmentHash
            | InvalidDLogProof
            | InvalidPolynomialPoint
            | BigFVecMismatch
            | PPRFError(_) => Self::violation(Phase::Migration, peer, error.to_string()),
        }
    }
}

/// Same ordered stable peer identities and approved protocol configuration across
/// wallets/paths/boots. A production authority must approve configuration changes.
pub fn scope(manifest: &Manifest) -> [u8; 32] {
    digest(
        b"pairkey/dkls-research/incident-scope/v1",
        &(
            manifest.identities,
            manifest.version,
            crate::REVISION,
            "sl-oblivious/1.0.0-beta",
            2u8,
            2u8,
        ),
    )
}
pub fn scope_dir(controls: &Path, manifest: &Manifest) -> PathBuf {
    let name = scope(manifest)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    controls.join("scopes").join(name)
}
#[derive(Clone)]
pub struct ReleaseGate(Arc<GateAuthority>);
struct GateAuthority {
    state: Mutex<GateState>,
    changed: tokio::sync::watch::Sender<bool>,
}
struct GateState {
    stopped: bool,
    dir: PathBuf,
    role: u8,
}
impl ReleaseGate {
    pub fn new(dir: PathBuf, role: u8) -> Self {
        type Registry = Mutex<BTreeMap<(PathBuf, u8), Weak<GateAuthority>>>;
        static REGISTRY: OnceLock<Registry> = OnceLock::new();
        let mut registry = REGISTRY
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .expect("gate registry poisoned");
        registry.retain(|_, gate| gate.strong_count() > 0);
        let key = (dir.clone(), role);
        if let Some(gate) = registry.get(&key).and_then(Weak::upgrade) {
            return Self(gate);
        }
        let (changed, _) = tokio::sync::watch::channel(false);
        let gate = Arc::new(GateAuthority {
            state: Mutex::new(GateState {
                stopped: false,
                dir,
                role,
            }),
            changed,
        });
        registry.insert(key, Arc::downgrade(&gate));
        Self(gate)
    }
    /// The cutoff is ownership handoff to the transport queue under this lock.
    /// Queued material is conservatively counted as already released.
    pub fn release<T>(&self, send: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release gate poisoned"))?;
        if check_incident(&state.dir, state.role).is_err() {
            state.stopped = true;
            self.0.changed.send_replace(true);
        }
        ensure!(
            !state.stopped,
            "durable research quarantine; release fenced"
        );
        send()
    }
    pub fn publish(&self, context: [u8; 32]) -> Result<()> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release gate poisoned"))?;
        state.stopped = true; // Remains stopped even if durable publication fails.
        self.0.changed.send_replace(true);
        incident(&state.dir, state.role, context)
    }
    pub async fn cancelled(&self) {
        let mut receiver = self.0.changed.subscribe();
        let _ = receiver.wait_for(|stopped| *stopped).await;
    }
    pub fn apply(&self, mut failure: Failure, context: [u8; 32]) -> Failure {
        if failure.action != Action::Burn {
            match self.publish(context) {
                Ok(()) => failure.incident_persisted = true,
                Err(e) => failure
                    .detail
                    .push_str(&format!("; incident persistence failed: {e:#}")),
            }
        }
        failure
    }
}

/// Structured terminal collection never treats a broken pipe as the originator's
/// terminal diagnostic. Collect until both stdout streams end or bounded grace.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Terminals {
    pub failures: Vec<(usize, Failure)>,
    pub closed: [bool; 2],
    pub pipes: Vec<String>,
    pub drain_timed_out: bool,
}
impl Terminals {
    pub fn failure(&mut self, role: usize, failure: Failure) {
        self.failures.push((role, failure));
    }
    pub fn closed(&mut self, role: usize) {
        self.closed[role] = true;
    }
    pub fn pipe(&mut self, role: usize, error: &std::io::Error) {
        self.pipes.push(format!("worker {role} pipe: {error}"));
    }
    pub fn failed(&self) -> bool {
        !self.failures.is_empty() || !self.pipes.is_empty()
    }
    pub fn diagnostic(&self) -> String {
        let mut details = self
            .failures
            .iter()
            .map(|(role, f)| {
                format!(
                    "worker {role}: {f}; action={:?}; persisted={}",
                    f.action, f.incident_persisted
                )
            })
            .collect::<Vec<_>>();
        details.extend(self.pipes.clone());
        if self.drain_timed_out {
            details.push("terminal drain timeout; missing diagnostics/persistence unknown".into());
        }
        if details.is_empty() {
            details.push("worker exited without terminal diagnostic".into());
        }
        details.join("; ")
    }
}

impl std::fmt::Display for Terminals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.diagnostic())
    }
}
impl std::error::Error for Terminals {}

/// Specification test scaffold only: carries no OT material and is not a pool.
/// Private, non-Clone ownership plus durable retirement; context mismatches burn.
pub struct ReservedEntry {
    entry: [u8; 32],
    preprocessing: [u8; 32],
    consumption: [u8; 32],
}
impl ReservedEntry {
    pub fn reserve(
        dir: &Path,
        role: u8,
        entry: [u8; 32],
        preprocessing: [u8; 32],
        consumption: [u8; 32],
    ) -> Result<Self> {
        reserve(
            dir,
            role,
            entry,
            digest(b"pool-spec-reservation/v1", &(preprocessing, consumption)),
        )?;
        Ok(Self {
            entry,
            preprocessing,
            consumption,
        })
    }
    pub fn consume(
        self,
        entry: [u8; 32],
        preprocessing: [u8; 32],
        consumption: [u8; 32],
    ) -> Result<()> {
        ensure!(
            self.entry == entry
                && self.preprocessing == preprocessing
                && self.consumption == consumption,
            "pool specification binding mismatch"
        );
        Ok(())
    }
}
