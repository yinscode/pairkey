//! Durable, single-host request claims and policy fences. Call only after independent
//! authentication. A claim is persisted before generating or exposing signing rounds.
//! This does not provide replication, filesystem rollback protection, or a trusted clock.
use crate::local_store::LocalStore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io, path::Path};

const MAX_REQUESTS: usize = 4096;
const MAX_POLICIES: usize = 4096;
const MAX_RESULT: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub namespace_digest: [u8; 32],
    pub request_id: [u8; 32],
    pub approval_digest: [u8; 32],
    pub attempt_digest: [u8; 32],
    pub expires_at: i64,
}
impl Claim {
    fn key(&self) -> String {
        request_key(self.namespace_digest, self.request_id)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Started,
    Uncertain,
    Complete(Vec<u8>),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    claim: Claim,
    status: Status,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFence {
    revision: u64,
    digest: [u8; 32],
    slot: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u16,
    context: [u8; 32],
    clock_floor: i64,
    minimum_slot: u64,
    records: BTreeMap<String, Record>,
    policies: BTreeMap<String, PolicyFence>,
}
pub struct ApprovalStore {
    disk: LocalStore,
    snapshot: Snapshot,
    poisoned: bool,
}
impl ApprovalStore {
    pub fn open(path: impl AsRef<Path>, context: [u8; 32]) -> io::Result<Self> {
        let disk = LocalStore::open(path, 64 * 1024 * 1024)?;
        let snapshot = match disk.read()? {
            None => Snapshot {
                version: 1,
                context,
                clock_floor: 0,
                minimum_slot: 0,
                records: BTreeMap::new(),
                policies: BTreeMap::new(),
            },
            Some(bytes) => serde_json::from_slice::<Snapshot>(&bytes).map_err(io::Error::other)?,
        };
        if snapshot.version != 1
            || snapshot.context != context
            || snapshot.clock_floor < 0
            || snapshot.records.len() > MAX_REQUESTS
            || snapshot.policies.len() > MAX_POLICIES
        {
            return Err(invalid());
        }
        let mut store = Self {
            disk,
            snapshot,
            poisoned: false,
        };
        for (id, record) in &mut store.snapshot.records {
            if *id != record.claim.key()
                || record.claim.request_id == [0; 32]
                || record.claim.expires_at < 0
                || matches!(&record.status,Status::Complete(result) if result.is_empty() || result.len()>MAX_RESULT)
            {
                return Err(invalid());
            }
            if record.status == Status::Started {
                record.status = Status::Uncertain;
            }
        }
        for id in store.snapshot.policies.keys() {
            if URL_SAFE_NO_PAD.decode(id).map_err(io::Error::other)?.len() != 32 {
                return Err(invalid());
            }
        }
        store.save()?;
        Ok(store)
    }
    fn ready(&self) -> io::Result<()> {
        if self.poisoned {
            Err(io::Error::other(
                "approval store unavailable; reconcile before restarting",
            ))
        } else {
            Ok(())
        }
    }
    fn clock(&self, now: i64) -> io::Result<()> {
        self.ready()?;
        if now < self.snapshot.clock_floor {
            Err(io::Error::other(
                "clock moved behind durable approval fence",
            ))
        } else {
            Ok(())
        }
    }
    fn save(&mut self) -> io::Result<()> {
        self.ready()?;
        let result = serde_json::to_vec(&self.snapshot)
            .map_err(io::Error::other)
            .and_then(|bytes| self.disk.write(&bytes));
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// True means this invocation alone may start the attempt. False means an
    /// identical claim already exists and must never generate another nonce.
    pub fn reserve(&mut self, claim: Claim, now: i64) -> io::Result<bool> {
        self.clock(now)?;
        if claim.request_id == [0; 32] || claim.expires_at <= now {
            return Err(invalid());
        }
        let id = claim.key();
        if let Some(old) = self.snapshot.records.get(&id) {
            if old.claim != claim {
                return Err(io::Error::other(
                    "request ID already claimed with different approval or attempt",
                ));
            }
            return Ok(false);
        }
        if self.snapshot.records.len() >= MAX_REQUESTS {
            return Err(io::Error::other("approval store capacity reached"));
        }
        self.snapshot.records.insert(
            id,
            Record {
                claim,
                status: Status::Started,
            },
        );
        self.snapshot.clock_floor = now;
        self.save()?;
        Ok(true)
    }
    pub fn check_started(&self, claim: &Claim, now: i64) -> io::Result<()> {
        self.clock(now)?;
        if claim.expires_at <= now {
            return Err(invalid());
        }
        match self.snapshot.records.get(&claim.key()) {
            Some(r) if &r.claim == claim && r.status == Status::Started => Ok(()),
            _ => Err(io::Error::other(
                "attempt is not active in durable approval store",
            )),
        }
    }
    /// Store only public signature/result data, never an ID token or authentication proof.
    pub fn complete(&mut self, claim: &Claim, result: Vec<u8>, now: i64) -> io::Result<()> {
        self.clock(now)?;
        if result.is_empty() || result.len() > MAX_RESULT {
            return Err(invalid());
        }
        let old = self
            .snapshot
            .records
            .get(&claim.key())
            .ok_or_else(invalid)?;
        if &old.claim != claim {
            return Err(invalid());
        }
        if let Status::Complete(existing) = &old.status {
            return if existing == &result {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        self.check_started(claim, now)?;
        self.snapshot.records.get_mut(&claim.key()).unwrap().status = Status::Complete(result);
        self.snapshot.clock_floor = now;
        self.save()
    }
    pub fn uncertain(&mut self, claim: &Claim, now: i64) -> io::Result<()> {
        self.clock(now)?;
        let old = self
            .snapshot
            .records
            .get_mut(&claim.key())
            .ok_or_else(invalid)?;
        if &old.claim != claim {
            return Err(invalid());
        }
        if old.status == Status::Started {
            old.status = Status::Uncertain;
            self.snapshot.clock_floor = now;
            self.save()?;
        }
        Ok(())
    }
    /// Completed results remain recoverable after expiry without new signing.
    pub fn lookup(
        &self,
        namespace: [u8; 32],
        request_id: [u8; 32],
        approval: [u8; 32],
    ) -> io::Result<Option<Status>> {
        self.ready()?;
        match self
            .snapshot
            .records
            .get(&request_key(namespace, request_id))
        {
            Some(r) if r.claim.approval_digest == approval => Ok(Some(r.status.clone())),
            Some(_) => Err(io::Error::other(
                "request ID belongs to a different approval",
            )),
            None => Ok(None),
        }
    }
    pub fn minimum_slot(&self) -> io::Result<u64> {
        self.ready()?;
        Ok(self.snapshot.minimum_slot)
    }
    pub fn knows_policy(&self, namespace: [u8; 32]) -> io::Result<bool> {
        self.ready()?;
        Ok(self
            .snapshot
            .policies
            .contains_key(&URL_SAFE_NO_PAD.encode(namespace)))
    }
    /// Caller has already validated the finalized record's ownership and namespace.
    pub fn observe_policy(
        &mut self,
        namespace: [u8; 32],
        revision: u64,
        digest: [u8; 32],
        slot: u64,
        now: i64,
    ) -> io::Result<()> {
        self.clock(now)?;
        if slot < self.snapshot.minimum_slot {
            return Err(invalid());
        }
        let key = URL_SAFE_NO_PAD.encode(namespace);
        if let Some(old) = self.snapshot.policies.get(&key) {
            if revision < old.revision
                || slot < old.slot
                || (revision == old.revision && digest != old.digest)
            {
                return Err(io::Error::other("stale or conflicting policy observation"));
            }
        } else if self.snapshot.policies.len() >= MAX_POLICIES {
            return Err(io::Error::other("policy fence capacity reached"));
        }
        self.snapshot.policies.insert(
            key,
            PolicyFence {
                revision,
                digest,
                slot,
            },
        );
        self.snapshot.minimum_slot = slot;
        self.snapshot.clock_floor = now;
        self.save()
    }
    pub fn check_policy(
        &self,
        namespace: [u8; 32],
        revision: u64,
        digest: [u8; 32],
        slot: u64,
    ) -> io::Result<()> {
        self.ready()?;
        match self
            .snapshot
            .policies
            .get(&URL_SAFE_NO_PAD.encode(namespace))
        {
            Some(p)
                if p.revision == revision
                    && p.digest == digest
                    && slot >= p.slot
                    && slot >= self.snapshot.minimum_slot =>
            {
                Ok(())
            }
            _ => Err(io::Error::other("policy changed before signature release")),
        }
    }
    pub fn observe_inactive(&mut self, slot: u64, now: i64) -> io::Result<()> {
        self.clock(now)?;
        self.snapshot.minimum_slot = self
            .snapshot
            .minimum_slot
            .max(slot.checked_add(1).ok_or_else(invalid)?);
        self.snapshot.clock_floor = now;
        self.save()
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid approval store state or transition",
    )
}
fn request_key(namespace: [u8; 32], request_id: [u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(pairkey_types::digest(
        b"pairkey/request-claim/v1",
        &(namespace, request_id),
    ))
}

#[cfg(test)]
mod tests;
