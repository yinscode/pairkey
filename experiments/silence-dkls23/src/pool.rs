//! Spike C: canonical public contexts and linear, RAM-only preprocessing ownership.
//! Not a production authority or proof of the custom cryptographic composition.
use crate::{fresh, lifecycle::ReleaseGate, point, reserve, Manifest, Request, Root, REVISION};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use k256::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sl_dkls23::keygen::Keyshare;
use sl_oblivious::soft_spoken::{ReceiverOTSeed, SenderOTSeed};
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

pub type Hash = [u8; 32];
/// Canonical versioned, length-prefixed encoding. All integers are big endian.
struct Encoding(Zeroizing<Vec<u8>>);
impl Encoding {
    fn new(domain: &str) -> Self {
        let mut e = Self(Zeroizing::new(Vec::new()));
        e.0.extend(1u16.to_be_bytes());
        e.bytes(domain.as_bytes());
        e
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend((b.len() as u64).to_be_bytes());
        self.0.extend(b);
    }
    fn fixed(&mut self, b: &[u8]) {
        self.0.extend(b);
    }
    fn hash(self) -> Hash {
        Sha256::digest(self.0.as_slice()).into()
    }
}
pub fn hash(domain: &str, fields: &[&[u8]]) -> Hash {
    let mut e = Encoding::new(domain);
    for f in fields {
        e.bytes(f);
    }
    e.hash()
}
/// Commits to local research sources, enabled fault mode and locked realization.
/// The trusted test driver approves this config; this is not enrollment governance.
pub fn configuration() -> Hash {
    hash("pairkey/pool/config/v1", &[
        REVISION.as_bytes(), b"secp256k1/n=2/t=2/ids=0,1/xi=1,2/ranks=0",
        b"sl-oblivious=1.0.0-beta/sl-mpc-mate=1.0.0-beta/recipe=1",
        &[u8::from(cfg!(feature="research-faults")),u8::from(cfg!(target_endian="little"))],
        include_bytes!("../Cargo.toml"),
        b"KAPPA=256/LAMBDA_C=256/LAMBDA_S=128/S=128/L_BATCH=2/RHO=1/OT_WIDTH=3/K=4/Q=16/L=512/L_PRIME=640/M=4/trees=64",
        include_bytes!("../Cargo.lock"),include_bytes!("../patch-source.py"),
        include_bytes!("../patches/research-keyshare.rs"),include_bytes!("pool.rs"),
        include_bytes!("pool_worker.rs"),include_bytes!("wire.rs"),include_bytes!("lib.rs"),
        include_bytes!("lifecycle.rs"),
    ])
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupInput {
    pub version: u16,
    pub recipe: u16,
    pub peers: [Hash; 2],
    pub boots: [Hash; 2],
    pub configuration: Hash,
    pub entry: Hash,
}
impl SetupInput {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.recipe == 1 && self.configuration == configuration(),
            "unapproved pool configuration"
        );
        ensure!(
            self.peers[0] != self.peers[1]
                && self.boots[0] != self.boots[1]
                && self.entry != [0; 32],
            "invalid pool identity/entry"
        );
        for p in self.peers {
            VerifyingKey::from_bytes(&p)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Hash {
        let mut e = Encoding::new("pairkey/pool/input/v1");
        e.fixed(&self.version.to_be_bytes());
        e.fixed(&self.recipe.to_be_bytes());
        for p in self.peers {
            e.fixed(&p);
        }
        for b in self.boots {
            e.fixed(&b);
        }
        e.fixed(&self.configuration);
        e.fixed(&self.entry);
        e.hash()
    }
    pub fn sid(&self, label: &str, sender: u8, receiver: u8) -> Hash {
        hash(label, &[&self.digest(), &[sender], &[receiver]])
    }
    /// Base OT is receiver-initiated; its canonical role order is receiver/sender.
    pub fn base_ot_sid(&self, receiver: u8, sender: u8) -> Hash {
        self.sid("pairkey/pool/base-ot/v1", receiver, sender)
    }
    /// PPRF is sender-initiated; its canonical role order is sender/receiver.
    pub fn pprf_sid(&self, sender: u8, receiver: u8) -> Hash {
        self.sid("pairkey/pool/pprf/v1", sender, receiver)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Boot {
    pub role: u8,
    pub identity: Hash,
    pub generation: Hash,
    pub ephemeral: Hash,
    pub signature: Vec<u8>,
}
impl Boot {
    pub fn message(&self) -> Hash {
        hash(
            "pairkey/pool/boot/v1",
            &[
                &[self.role],
                &self.identity,
                &self.generation,
                &self.ephemeral,
            ],
        )
    }
    pub fn new(root: &Root, role: u8, ephemeral: Hash) -> Self {
        let mut b = Self {
            role,
            identity: root.identity(role).verifying_key().to_bytes(),
            generation: fresh(),
            ephemeral,
            signature: vec![],
        };
        b.signature = root.identity(role).sign(&b.message()).to_bytes().to_vec();
        b
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.role < 2, "invalid pool boot role");
        VerifyingKey::from_bytes(&self.identity)?
            .verify_strict(&self.message(), &Signature::from_slice(&self.signature)?)?;
        Ok(())
    }
}
/// Wallet pin encoding independent of serde/JSON representation.
pub fn manifest_digest(m: &Manifest) -> Hash {
    let mut e = Encoding::new("pairkey/pool/manifest/v1");
    e.fixed(&m.version.to_be_bytes());
    e.fixed(&m.key_id);
    for p in m.identities {
        e.fixed(&p);
    }
    for p in &m.additive_public {
        e.bytes(p);
    }
    e.bytes(&m.public_key);
    e.fixed(&m.chain_code);
    e.hash()
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Consumption {
    pub version: u16,
    pub input: Hash,
    pub completed: Hash,
    pub entry: Hash,
    pub wallet: Hash,
    pub scheme: String,
    pub path: String,
    pub prehash: Hash,
    pub receipt: Hash,
    pub policy_version: u64,
    pub attempt: Hash,
}
impl Consumption {
    pub fn new(
        input: &SetupInput,
        completed: Hash,
        r: &Request,
        receipt: Hash,
        policy_version: u64,
    ) -> Self {
        Self {
            version: 1,
            input: input.digest(),
            completed,
            entry: input.entry,
            wallet: manifest_digest(&r.manifest),
            scheme: "secp256k1/bip32-public".into(),
            path: r.path.clone(),
            prehash: r.prehash,
            receipt,
            policy_version,
            attempt: r.attempt,
        }
    }
    pub fn validate_request(&self, r: &Request) -> Result<()> {
        ensure!(
            self.version == 1
                && self.scheme == "secp256k1/bip32-public"
                && self.wallet == manifest_digest(&r.manifest)
                && self.entry == r.entry
                && self.path == r.path
                && self.prehash == r.prehash
                && self.attempt == r.attempt
                && self.receipt != [0; 32]
                && self.policy_version > 0,
            "pool consumption/request mismatch"
        );
        Ok(())
    }
    pub fn digest(&self) -> Hash {
        let mut e = Encoding::new("pairkey/pool/consumption/v1");
        e.fixed(&self.version.to_be_bytes());
        for f in [&self.input, &self.completed, &self.entry, &self.wallet] {
            e.fixed(f);
        }
        e.bytes(self.scheme.as_bytes());
        e.bytes(self.path.as_bytes());
        e.fixed(&self.prehash);
        e.fixed(&self.receipt);
        e.fixed(&self.policy_version.to_be_bytes());
        e.fixed(&self.attempt);
        e.hash()
    }
    /// Native dsg.rs folds this package SID into its final SID, then derives
    /// directional MtA SIDs from that final SID and sender/receiver party IDs.
    pub fn package_sid(&self) -> Hash {
        hash(
            "pairkey/pool/package/v1",
            &[&self.completed, &self.digest()],
        )
    }
}
/// Exact validated bodies, indexed by stage and role. Secret reveals are cleared.
/// Stage order: commitment, reveal, receiver msg1, sender msg2+PPRF.
pub struct Transcript {
    input: Hash,
    records: BTreeMap<(u8, u8), Zeroizing<Vec<u8>>>,
}
impl Transcript {
    pub fn new(input: Hash) -> Self {
        Self {
            input,
            records: BTreeMap::new(),
        }
    }
    pub fn record(&mut self, stage: u8, sender: u8, body: &[u8]) -> Result<()> {
        ensure!(
            stage < 4 && sender < 2 && !self.records.contains_key(&(stage, sender)),
            "duplicate/invalid setup record"
        );
        ensure!(body.len() <= crate::MAX_FRAME, "oversized setup record");
        self.records
            .insert((stage, sender), Zeroizing::new(body.to_vec()));
        Ok(())
    }
    pub fn completed(&self) -> Result<Hash> {
        ensure!(self.records.len() == 8, "incomplete setup transcript");
        let mut e = Encoding::new("pairkey/pool/completed/v1");
        e.fixed(&self.input);
        for (&(stage, sender), body) in &self.records {
            e.fixed(&1u16.to_be_bytes());
            e.fixed(&self.input);
            e.fixed(&[stage, sender, 1 - sender, stage]);
            e.bytes(body);
        }
        Ok(e.hash())
    }
}
#[derive(Serialize, Deserialize)]
pub enum Command {
    Ping(Hash),
    Enroll([Boot; 2]),
    Describe(Hash),
    Setup {
        input: SetupInput,
        fault: Option<String>,
    },
    Sign {
        request: Box<Request>,
        consumption: Consumption,
    },
    Incident(Hash),
    Stop,
}
#[derive(Serialize, Deserialize)]
pub struct Status {
    pub operation: String,
    pub entry: Hash,
    pub input: Hash,
    pub completed: Hash,
    pub available: usize,
    pub elapsed_ms: f64,
    pub compute_ms: f64,
}

struct Clearing<T: bytemuck::AnyBitPattern + bytemuck::NoUninit>(T);
impl<T: bytemuck::AnyBitPattern + bytemuck::NoUninit> Drop for Clearing<T> {
    fn drop(&mut self) {
        bytemuck::bytes_of_mut(&mut self.0).zeroize();
    }
}
/// No Clone, serialization, reusable references, or public seed fields.
pub struct Material {
    sender: Clearing<SenderOTSeed>,
    receiver: Clearing<ReceiverOTSeed>,
    zero: Zeroizing<Hash>,
}
impl Material {
    pub fn new(sender: SenderOTSeed, receiver: ReceiverOTSeed, zero: Hash) -> Self {
        Self {
            sender: Clearing(sender),
            receiver: Clearing(receiver),
            zero: Zeroizing::new(zero),
        }
    }
}
/// Linear seed owner: cloning is intentionally unavailable.
/// ```compile_fail
/// fn duplicate(e: pairkey_dkls23_research::pool::AvailableEntry) { let _ = e.clone(); }
/// ```
pub struct AvailableEntry {
    input: SetupInput,
    completed: Hash,
    material: Material,
    expires: Instant,
}
/// A reserved entry cannot build two packages.
/// ```compile_fail
/// use pairkey_dkls23_research::{pool::ReservedEntry, Request, Root};
/// fn reuse(e: ReservedEntry,r:&Request,root:&Root) {
///     let _=e.into_package(r,root,0);
///     let _=e.into_package(r,root,0);
/// }
/// ```
pub struct ReservedEntry {
    entry: AvailableEntry,
    consumption: Consumption,
    gate: ReleaseGate,
    role: u8,
}
impl AvailableEntry {
    /// Caller must have authenticated the peer's equal completed-digest ACK.
    /// This constructor checks local metadata; it does not prove peer agreement.
    pub fn agreed(
        input: SetupInput,
        completed: Hash,
        material: Material,
        ttl: Duration,
    ) -> Result<Self> {
        input.validate()?;
        ensure!(
            completed != [0; 32] && !ttl.is_zero(),
            "invalid completed setup/TTL"
        );
        Ok(Self {
            input,
            completed,
            material,
            expires: Instant::now() + ttl,
        })
    }
}
impl ReservedEntry {
    /// Consumes ownership even on mismatch, expiration, incident or constructor failure.
    pub fn into_package(self, r: &Request, root: &Root, role: u8) -> Result<Keyshare> {
        self.gate.release(|| {
            ensure!(
                self.role == role && Instant::now() < self.entry.expires,
                "reserved entry role/expiry mismatch"
            );
            self.consumption.validate_request(r)?;
            let a = root.derive(role, r.manifest.key_id)?;
            let s = Zeroizing::new(if role == 0 {
                *a * Scalar::from(2u64).invert().unwrap()
            } else {
                -*a
            });
            Keyshare::pairkey_research_two_party(
                role,
                *s,
                r.manifest.stored_public()?,
                point(&r.manifest.public_key)?,
                r.manifest.key_id,
                r.manifest.chain_code,
                self.consumption.package_sid(),
                &self.entry.material.zero,
                &self.entry.material.sender.0,
                &self.entry.material.receiver.0,
                &self.consumption.digest(),
            )
            .context("pooled constructor refused")
        })
    }
}
/// Bounded pool, serialized ownership transitions; no synchronous refill on miss.
pub struct RamPool {
    entries: Mutex<VecDeque<AvailableEntry>>,
    seen: Mutex<std::collections::BTreeSet<Hash>>,
    gate: ReleaseGate,
    ledger: PathBuf,
    role: u8,
    peers: [Hash; 2],
    boots: [Hash; 2],
    capacity: usize,
}
impl RamPool {
    pub fn new(
        gate: ReleaseGate,
        ledger: PathBuf,
        role: u8,
        peers: [Hash; 2],
        boots: [Hash; 2],
        capacity: usize,
    ) -> Result<Self> {
        ensure!(
            role < 2 && (1..=16).contains(&capacity),
            "invalid pool capacity/role"
        );
        Ok(Self {
            entries: Mutex::new(VecDeque::new()),
            seen: Mutex::new(std::collections::BTreeSet::new()),
            gate,
            ledger,
            role,
            peers,
            boots,
            capacity,
        })
    }
    pub fn insert(&self, entry: AvailableEntry) -> Result<()> {
        self.gate.release(|| {
            ensure!(
                self.seen.lock().unwrap().len() < 1024,
                "pool generation entry budget exhausted"
            );
            ensure!(
                self.seen.lock().unwrap().insert(entry.input.entry),
                "pool entry already admitted"
            );
            ensure!(
                entry.input.peers == self.peers && entry.input.boots == self.boots,
                "pool enrollment/generation mismatch"
            );
            let mut entries = self.entries.lock().unwrap();
            entries.retain(|e| Instant::now() < e.expires);
            ensure!(
                entries.len() < self.capacity
                    && !entries.iter().any(|e| e.input.entry == entry.input.entry),
                "pool full/duplicate entry"
            );
            entries.push_back(entry);
            Ok(())
        })
    }
    pub fn reserve(&self, c: &Consumption) -> Result<ReservedEntry> {
        self.gate.release(|| {
            let mut entries = self.entries.lock().unwrap();
            entries.retain(|e| Instant::now() < e.expires);
            let index = entries
                .iter()
                .position(|e| e.input.entry == c.entry)
                .context("pool empty or entry unavailable")?;
            let entry = entries.remove(index).unwrap(); // removed before ANY fallible validation
                                                        // A malformed reservation still irreversibly retires the selected entry.
            reserve(&self.ledger, self.role, c.entry, c.digest())?;
            ensure!(
                c.input == entry.input.digest() && c.completed == entry.completed,
                "pool provenance mismatch"
            );
            Ok(ReservedEntry {
                entry,
                consumption: c.clone(),
                gate: self.gate.clone(),
                role: self.role,
            })
        })
    }
    pub fn available(&self) -> usize {
        if self.gate.release(|| Ok(())).is_err() {
            self.invalidate();
            return 0;
        }
        let mut e = self.entries.lock().unwrap();
        e.retain(|e| Instant::now() < e.expires);
        e.len()
    }
    pub fn invalidate(&self) {
        self.entries.lock().unwrap().clear();
    }
}

#[cfg(test)]
#[path = "pool_tests.rs"]
mod tests;
