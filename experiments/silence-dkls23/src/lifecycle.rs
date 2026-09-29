//! Research lifecycle authority. Trusted filesystem; no hostile-host guarantees.
use crate::{authority::AuthorityLock, check_incident, digest, incident_locked, reserve, Manifest};
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
    #[serde(default)]
    pub incident_attempted: bool,
    #[serde(default)]
    pub abort_send_failed: bool,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}/{:?}: {}", self.phase, self.kind, self.detail)
    }
}
impl std::error::Error for Failure {}
impl Failure {
    /// Registration validation can identify either endorser. A violation signed
    /// by this worker's own identity is local compromise/failure, not peer blame.
    pub fn registration_perspective(mut self, own: [u8; 32]) -> Self {
        if self.phase == Phase::Admission && self.peer == Some(own) {
            self.peer = None;
            self.action = Action::FreezeConfiguration;
        }
        self
    }
    pub fn burn(phase: Phase, kind: FailureKind, detail: impl Into<String>) -> Self {
        Self {
            phase,
            kind,
            peer: None,
            action: Action::Burn,
            detail: detail.into(),
            incident_persisted: false,
            incident_attempted: false,
            abort_send_failed: false,
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
            incident_attempted: false,
            abort_send_failed: false,
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
    pair_scope(manifest.identities, manifest.version)
}
pub fn pair_scope(identities: [[u8; 32]; 2], version: u16) -> [u8; 32] {
    digest(
        b"pairkey/dkls-research/incident-scope/v1",
        &(
            identities,
            version,
            crate::REVISION,
            "sl-oblivious/1.0.0-beta",
            2u8,
            2u8,
        ),
    )
}
pub fn scope_dir(controls: &Path, manifest: &Manifest) -> PathBuf {
    pair_scope_dir(controls, manifest.identities, manifest.version)
}
pub fn pair_scope_dir(controls: &Path, identities: [[u8; 32]; 2], version: u16) -> PathBuf {
    let name = pair_scope(identities, version)
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
        ensure!(!state.stopped, "research quarantine; release fenced");
        let lock = AuthorityLock::acquire(&state.dir);
        // Any marker for this pairing stops both signer roles, including replicas
        // which did not originate the incident. Hold the OS lock through handoff.
        let checked = lock.and_then(|lock| {
            check_incident(&state.dir, 0)?;
            check_incident(&state.dir, 1)?;
            Ok(lock)
        });
        let _lock = checked.map_err(|error| {
            state.stopped = true;
            self.0.changed.send_replace(true);
            error.context("research authority failure; release fenced")
        })?;
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
        let _lock = AuthorityLock::acquire(&state.dir)?;
        incident_locked(&state.dir, state.role, context, |_| Ok(()))
    }
    pub async fn cancelled(&self) {
        let mut receiver = self.0.changed.subscribe();
        let mut poll = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = receiver.wait_for(|stopped| *stopped) => return,
                _ = poll.tick() => if self.release(|| Ok(())).is_err() { return; },
            }
        }
    }
    pub fn apply(&self, failure: Failure, context: [u8; 32]) -> Failure {
        self.apply_using(failure, context, |dir, role, context| {
            incident_locked(dir, role, context, |_| Ok(()))
        })
    }
    fn apply_using(
        &self,
        mut failure: Failure,
        context: [u8; 32],
        publish: impl FnOnce(&Path, u8, [u8; 32]) -> Result<()>,
    ) -> Failure {
        if failure.action != Action::Burn && !failure.incident_attempted {
            failure.incident_attempted = true;
            failure.incident_persisted = false;
            let result = (|| {
                let mut state = self
                    .0
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("release gate poisoned"))?;
                state.stopped = true;
                self.0.changed.send_replace(true);
                let _lock = AuthorityLock::acquire(&state.dir)?;
                publish(&state.dir, state.role, context)
            })();
            match result {
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

#[cfg(test)]
mod publication_tests {
    use super::*;
    use crate::{fresh, incident_locked, IncidentStep};
    #[test]
    fn a_failure_is_published_once_and_retains_unconfirmed_status() {
        let dir = std::env::temp_dir().join(format!("dkls-apply-{:?}", fresh()));
        let gate = ReleaseGate::new(dir.clone(), 0);
        let failure = Failure::violation(Phase::Migration, [8; 32], "PPRF error");
        let failure = gate.apply_using(failure, [3; 32], |dir, role, context| {
            incident_locked(dir, role, context, |step| {
                if step == IncidentStep::Created {
                    anyhow::bail!("injected write failure after creation");
                }
                Ok(())
            })
        });
        assert!(failure.incident_attempted);
        assert!(!failure.incident_persisted);
        assert!(std::fs::read(dir.join("0.quarantined")).unwrap().is_empty());
        let failure = gate.apply_using(failure, [3; 32], |_, _, _| {
            panic!("same failure published twice")
        });
        assert!(!failure.incident_persisted);
        assert!(gate.release(|| Ok(())).is_err());
        assert!(ReleaseGate::new(dir.clone(), 0).release(|| Ok(())).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn successful_publication_is_also_applied_only_once() {
        let dir = std::env::temp_dir().join(format!("dkls-apply-{:?}", fresh()));
        let gate = ReleaseGate::new(dir.clone(), 0);
        let failure = gate.apply(
            Failure::violation(Phase::Signing, [8; 32], "proof failure"),
            [3; 32],
        );
        assert!(failure.incident_attempted && failure.incident_persisted);
        let failure = gate.apply_using(failure, [3; 32], |_, _, _| {
            panic!("already confirmed failure republished")
        });
        assert!(failure.incident_persisted);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
