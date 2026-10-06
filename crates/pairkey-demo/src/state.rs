use anyhow::{ensure, Context, Result};
use pairkey_core::local_store::LocalStore;
use pairkey_sdk::multi;
use pairkey_types::{policy::EvmSessionGrant, Registration};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

pub const GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
pub const CHAIN: u64 = 84_532;
pub const MAX_VALUE: u64 = 10_000_000_000_000; // 0.00001 test ETH per grant
pub const MAX_FEE: u64 = 100_000_000_000_000;
pub const TOTAL_BUDGET: u64 = 10_000_000_000_000_000;
pub fn fresh() -> [u8; 32] {
    use rand_core::RngCore;
    let mut v = [0; 32];
    rand_core::OsRng.fill_bytes(&mut v);
    v
}
pub fn hex(v: &[u8]) -> String {
    pairkey_signing::hex(v)
}
pub fn quantity(v: &Value) -> Result<u64> {
    let s = v.as_str().context("RPC quantity")?;
    Ok(u64::from_str_radix(
        s.strip_prefix("0x").context("hex quantity")?,
        16,
    )?)
}
pub fn amount(s: &str) -> Result<u64> {
    ensure!(
        !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()),
        "amount must be an integer wei string"
    );
    Ok(s.parse()?)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    SignMessage {
        id: String,
        authority: crate::messages::Authority,
        chain: crate::messages::Chain,
        message: String,
    },
    Grant {
        id: String,
        max_value_wei: String,
        recipient: usize,
        duration_seconds: u64,
    },
    Transfer {
        id: String,
        value_wei: String,
        recipient: usize,
    },
    Revoke {
        id: String,
    },
    Retry {
        id: String,
        original_id: String,
    },
}
impl Command {
    pub fn id(&self) -> &str {
        match self {
            Self::SignMessage { id, .. }
            | Self::Grant { id, .. }
            | Self::Transfer { id, .. }
            | Self::Revoke { id }
            | Self::Retry { id, .. } => id,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.id().len() == 32 && self.id().bytes().all(|b| b.is_ascii_hexdigit()),
            "id must be 32 hex characters"
        );
        match self {
            Self::SignMessage { message, .. } => {
                ensure!(
                    !message.trim().is_empty() && message.len() <= 256,
                    "message must contain 1–256 UTF-8 bytes"
                );
            }
            Self::Grant {
                max_value_wei,
                recipient,
                duration_seconds,
                ..
            } => {
                let n = amount(max_value_wei)?;
                ensure!(
                    n > 0
                        && n <= MAX_VALUE
                        && *recipient < 2
                        && (60..=600).contains(duration_seconds),
                    "grant exceeds demo bounds"
                );
            }
            Self::Transfer {
                value_wei,
                recipient,
                ..
            } => {
                let n = amount(value_wei)?;
                ensure!(
                    n > 0 && n <= MAX_VALUE * 2 && *recipient < 2,
                    "request exceeds demo bounds"
                );
            }
            Self::Retry { id, original_id } => {
                ensure!(
                    id != original_id
                        && original_id.len() == 32
                        && original_id.bytes().all(|b| b.is_ascii_hexdigit()),
                    "invalid original operation ID"
                );
            }
            _ => {}
        };
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Operation {
    #[serde(default)]
    pub ed_request: Option<Value>,
    pub command: Command,
    pub status: String,
    pub events: Vec<String>,
    pub result: Value,
    pub uncertain: bool,
    pub solana_tx: Option<String>,
    pub signing_request: Option<multi::SignRequest>,
    pub raw_transaction: Option<String>,
    pub transaction_hash: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub message_namespaces: Vec<crate::messages::MessageNamespace>,
    pub version: u8,
    #[serde(default)]
    pub service_ports: Option<[u16; 3]>,
    pub setup_pending: Option<String>,
    pub binding: String,
    pub set_id: [u8; 32],
    pub namespace_id: [u8; 32],
    pub recipients: [[u8; 20]; 2],
    pub registration: Option<Registration>,
    pub key: Option<multi::KeyResponse>,
    pub session: Option<EvmSessionGrant>,
    pub revoked: bool,
    pub reserved_budget: u64,
    pub operations: Vec<Operation>,
}
pub struct Journal {
    failed: AtomicBool,
    store: LocalStore,
    pub data: Mutex<Snapshot>,
}
impl Journal {
    pub fn open(path: &Path, binding: String) -> Result<Self> {
        let store = LocalStore::open(path, 8 * 1024 * 1024)?;
        let mut data: Snapshot = match store.read()? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Snapshot {
                message_namespaces: vec![],
                version: 1,
                service_ports: None,
                setup_pending: None,
                binding: binding.clone(),
                set_id: fresh(),
                namespace_id: fresh(),
                recipients: [fresh()[..20].try_into()?, fresh()[..20].try_into()?],
                registration: None,
                key: None,
                session: None,
                revoked: false,
                reserved_budget: 0,
                operations: vec![],
            },
        };
        ensure!(
            data.version == 1 && data.binding == binding,
            "demo state configuration mismatch"
        );
        for op in &mut data.operations {
            if op.status == "working" {
                op.status = "interrupted".into();
                op.uncertain = true;
                op.events.push(
                    "Process interrupted. Operator reconciliation required before new mutations."
                        .into(),
                );
            }
        }
        store.write(&serde_json::to_vec(&data)?)?;
        Ok(Self {
            failed: AtomicBool::new(false),
            store,
            data: Mutex::new(data),
        })
    }
    pub fn read(&self) -> Snapshot {
        self.data.lock().unwrap().clone()
    }
    pub fn update<T>(&self, f: impl FnOnce(&mut Snapshot) -> Result<T>) -> Result<T> {
        ensure!(
            !self.failed.load(Ordering::SeqCst),
            "journal failed; restart and reconcile before continuing"
        );
        let mut guard = self.data.lock().unwrap();
        let mut next = guard.clone();
        let value = f(&mut next)?;
        if let Err(e) = self.store.write(&serde_json::to_vec(&next)?) {
            self.failed.store(true, Ordering::SeqCst);
            for op in &mut guard.operations {
                if op.status == "working" {
                    op.uncertain = true;
                }
            }
            return Err(e.into());
        }
        *guard = next;
        Ok(value)
    }
    pub fn op(&self, id: &str, f: impl FnOnce(&mut Operation)) -> Result<()> {
        self.update(|s| {
            f(s.operations
                .iter_mut()
                .find(|o| o.command.id() == id)
                .context("operation missing")?);
            Ok(())
        })
    }
    pub fn event(&self, id: &str, event: &str) -> Result<()> {
        self.op(id, |o| o.events.push(event.into()))
    }
}
pub fn public_operation(op: &Operation) -> Value {
    let action = match op.command {
        Command::SignMessage { .. } => "sign_message",
        Command::Grant { .. } => "grant",
        Command::Transfer { .. } => "transfer",
        Command::Revoke { .. } => "revoke",
        Command::Retry { .. } => "retry",
    };
    json!({"id":op.command.id(),"action":action,"signing_started":op.signing_request.is_some() || op.result["signing_started"] == true,"status":op.status,"events":op.events,"result":op.result,"needs_reconciliation":op.uncertain,"solana_tx":op.solana_tx,"transaction_hash":op.transaction_hash})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (std::path::PathBuf, Journal) {
        let path = std::env::temp_dir().join(format!("pairkey-demo-{}", hex(&fresh())));
        std::fs::create_dir(&path).unwrap();
        let journal =
            Journal::open(&path.join("state.json"), "network-and-key-binding".into()).unwrap();
        (path, journal)
    }
    fn operation() -> Operation {
        Operation {
            ed_request: None,
            command: Command::Revoke {
                id: "12".repeat(16),
            },
            status: "working".into(),
            events: vec![],
            result: Value::Null,
            uncertain: false,
            solana_tx: Some("saved-before-send".into()),
            signing_request: None,
            raw_transaction: None,
            transaction_hash: None,
        }
    }
    #[test]
    fn restart_preserves_identity_and_blocks_unfinished_work() {
        let (path, j) = fixture();
        let ids = (j.read().set_id, j.read().namespace_id);
        j.update(|s| {
            s.operations.push(operation());
            s.service_ports = Some([4181, 4182, 4183]);
            s.reserved_budget = 123;
            Ok(())
        })
        .unwrap();
        drop(j);
        assert!(Journal::open(&path.join("state.json"), "another-network".into()).is_err());
        let j = Journal::open(&path.join("state.json"), "network-and-key-binding".into()).unwrap();
        let s = j.read();
        assert_eq!(ids, (s.set_id, s.namespace_id));
        assert_eq!(s.reserved_budget, 123);
        assert_eq!(s.service_ports, Some([4181, 4182, 4183]));
        assert_eq!(s.operations[0].status, "interrupted");
        assert!(s.operations[0].uncertain);
        assert_eq!(
            s.operations[0].solana_tx.as_deref(),
            Some("saved-before-send")
        );
        drop(j);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn failed_write_poisoned_until_restart_and_no_partial_update() {
        let (path, j) = fixture();
        std::fs::create_dir(path.join("state.json.next")).unwrap();
        assert!(j
            .update(|s| {
                s.reserved_budget = 123;
                Ok(())
            })
            .is_err());
        std::fs::remove_dir(path.join("state.json.next")).unwrap();
        assert_eq!(j.read().reserved_budget, 0);
        assert!(j.update(|_| Ok(())).is_err());
        drop(j);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn rejects_floats_overflow_and_arbitrary_request_parameters() {
        for s in ["1.0", "1e3", "-1", "18446744073709551616", ""] {
            assert!(amount(s).is_err());
        }
        let id = "ab".repeat(16);
        let invalid =
            json!({"action":"transfer","id":id,"value_wei":"1","recipient":0,"chain_id":1});
        assert!(serde_json::from_value::<Command>(invalid).is_err());
        assert!(Command::Grant {
            id: id.clone(),
            max_value_wei: (MAX_VALUE + 1).to_string(),
            recipient: 0,
            duration_seconds: 60
        }
        .validate()
        .is_err());
        assert!(Command::Transfer {
            id,
            value_wei: "1".into(),
            recipient: 2
        }
        .validate()
        .is_err());
    }
    #[test]
    fn journal_has_exclusive_process_lock() {
        let (path, j) = fixture();
        assert!(Journal::open(&path.join("state.json"), "network-and-key-binding".into()).is_err());
        drop(j);
        std::fs::remove_dir_all(path).unwrap();
    }
}
