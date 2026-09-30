//! Test-binary-only barriers and independent transport-queue observations.
use pairkey_dkls23_research::{digest, Frame};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub struct Probe {
    pub dir: PathBuf,
    pub role: u8,
    pub stage: String,
    pub bypass: bool,
    pub r4: [u8; 32],
    armed: AtomicBool,
}
impl Probe {
    pub fn from_env(role: u8) -> Option<Self> {
        let dir = PathBuf::from(std::env::var_os("PAIRKEY_NATIVE_RACE_DIR")?);
        Some(Self {
            dir,
            role,
            stage: std::env::var("PAIRKEY_NATIVE_RACE_STAGE").unwrap(),
            bypass: std::env::var("PAIRKEY_NATIVE_RACE_BYPASS").unwrap() == "1",
            r4: [0; 32],
            armed: AtomicBool::new(false),
        })
    }
    pub fn setup(&self, label: &str) {
        if (self.stage == "setup" && matches!(label, "base-ot-1" | "pool-base-ot-1"))
            || (self.stage == "consume" && label == "pool-reservation")
            || (self.stage == "setup" && label == "d-sign-generation")
        {
            self.armed.store(true, Ordering::SeqCst);
        }
    }
    pub fn pause(&self, frame: &Frame) -> bool {
        if std::env::var("PAIRKEY_PROBE_ROLE")
            .ok()
            .is_some_and(|r| r != self.role.to_string())
        {
            return false;
        }
        let selected = match frame {
            Frame::Setup(_) => {
                matches!(self.stage.as_str(), "setup" | "consume")
                    && self.armed.swap(false, Ordering::SeqCst)
            }
            Frame::WalletEndorsement(_) => self.stage == "endorsement",
            Frame::WalletRegistered(_) => self.stage == "commit",
            Frame::Relay(b) => {
                (self.stage == "r4" && b.get(..32) == Some(self.r4.as_slice()))
                    || (self.stage == "first-native" && !self.armed.swap(true, Ordering::SeqCst))
            }
            Frame::Result(_) => self.stage == "result",
            Frame::DReply(pairkey_dkls23_research::d::Reply::Signed { .. }) => {
                self.stage == "result"
            }
            _ => false,
        };
        if !selected {
            return false;
        }
        fs::write(
            self.dir.join(format!("{}.target", self.role)),
            fingerprint(frame),
        )
        .unwrap();
        fs::write(self.dir.join(format!("{}.reached", self.role)), []).unwrap();
        self.wait_resume();
        true
    }
    fn wait_resume(&self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !self.dir.join("resume").exists() {
            assert!(Instant::now() < deadline, "native process barrier timeout");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    pub fn point(&self, stage: &str) -> anyhow::Result<()> {
        if self.stage != stage {
            return Ok(());
        }
        if std::env::var("PAIRKEY_PROBE_ROLE")
            .ok()
            .is_some_and(|r| r != self.role.to_string())
        {
            return Ok(());
        }
        fs::write(self.dir.join(format!("{}.reached", self.role)), []).unwrap();
        self.wait_resume();
        if self.dir.join("cancel").exists() {
            return Err(pairkey_dkls23_research::lifecycle::Failure::burn(
                pairkey_dkls23_research::lifecycle::Phase::Control,
                pairkey_dkls23_research::lifecycle::FailureKind::Cancelled,
                "test-only ownership cancellation",
            )
            .into());
        }
        Ok(())
    }
}
fn fingerprint(frame: &Frame) -> Vec<u8> {
    digest(b"test-only/native-frame/v1", frame).to_vec()
}
/// Runs in stdio's consumer, independently of gate/send return values. Both
/// actors are paused before their target, so a target observed after cutoff
/// cannot be a previously queued target. Persist hashes/counts, never payloads.
pub fn observe(frame: &Frame) {
    let Some(dir) = std::env::var_os("PAIRKEY_NATIVE_RACE_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let role = std::env::var("PAIRKEY_NATIVE_RACE_ROLE").unwrap();
    if std::env::var_os("PAIRKEY_TRACE_ALL").is_some()
        && matches!(
            frame,
            Frame::Relay(_)
                | Frame::Setup(_)
                | Frame::Result(_)
                | Frame::WalletEndorsement(_)
                | Frame::WalletRegistered(_)
                | Frame::DReply(pairkey_dkls23_research::d::Reply::Signed { .. })
        )
    {
        use std::io::Write;
        let kind = match frame {
            Frame::Relay(_) => "native",
            Frame::Setup(_) => "setup",
            Frame::Result(_) | Frame::DReply(pairkey_dkls23_research::d::Reply::Signed { .. }) => {
                "result"
            }
            Frame::WalletEndorsement(_) => "endorsement",
            _ => "commit",
        };
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(format!("{role}.handoffs")))
            .unwrap();
        writeln!(log,"{}",serde_json::json!({"kind":kind,"late":dir.join("published").exists(),"fingerprint":fingerprint(frame)})).unwrap();
    }
    if fs::read(dir.join(format!("{role}.target"))).ok() == Some(fingerprint(frame)) {
        fs::write(
            dir.join(format!("{role}.queued")),
            if dir.join("published").exists() {
                b"late".as_slice()
            } else {
                b"ordinary".as_slice()
            },
        )
        .unwrap();
    }
}

/// Limit competing heavy fixtures, not signers/attempts within a fixture. Each
/// native process otherwise creates its own worker/Rayon pools and can exhaust
/// CPU while unrelated test runtimes/builds compete with bounded deadlines.
pub async fn native_fixture_slot() -> tokio::sync::OwnedSemaphorePermit {
    static SLOT: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1)))
        .clone()
        .acquire_owned()
        .await
        .unwrap()
}
