//! Public-only, immutable transitions. Unfinished pre-reveal openings stay in
//! RAM; a restart retires that wallet slot rather than persisting the salt.
use super::*;
use crate::authority::AuthorityLock;
use anyhow::Context;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteStep {
    BeforeCreate,
    Created,
    Partial,
    Written,
    BeforeFileSync,
    FileSynced,
    BeforeDirectorySync,
    DirectorySynced,
}
#[derive(Clone)]
pub struct Journal {
    pub dir: PathBuf,
    pub role: u8,
}
fn hex(value: &Hash) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
impl Journal {
    pub fn new(base: &Path, wallet: &Wallet, role: u8) -> Result<Self> {
        wallet.validate()?;
        ensure!(role < 2, "invalid journal role");
        Ok(Self {
            dir: base.join(hex(&wallet.digest())),
            role,
        })
    }
    pub fn path(&self, stage: &str) -> PathBuf {
        self.dir.join(format!("{}-{stage}.json", self.role))
    }
    pub fn read<T: DeserializeOwned>(&self, stage: &str) -> Result<T> {
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.path(stage))?;
        ensure!(
            f.metadata()?.is_file() && f.metadata()?.len() < 32768,
            "invalid D journal file"
        );
        let mut b = vec![];
        f.read_to_end(&mut b)?;
        Ok(serde_json::from_slice(&b)?)
    }
    pub fn exists(&self, stage: &str) -> bool {
        self.path(stage).exists()
    }
    pub fn write<T: Serialize>(&self, stage: &str, value: &T) -> Result<()> {
        self.write_checkpoint(stage, value, |_| Ok(()))
    }
    pub(crate) fn write_checkpoint<T: Serialize>(
        &self,
        stage: &str,
        value: &T,
        mut checkpoint: impl FnMut(WriteStep) -> Result<()>,
    ) -> Result<()> {
        let _lock = AuthorityLock::acquire(&self.dir)?;
        let bytes = serde_json::to_vec(value)?;
        ensure!(bytes.len() < 32768, "D journal oversized");
        checkpoint(WriteStep::BeforeCreate)?;
        let path = self.path(stage);
        if path.exists() {
            let mut f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            ensure!(
                f.metadata()?.is_file() && f.metadata()?.len() < 32768,
                "D existing journal invalid"
            );
            let mut old = vec![];
            f.read_to_end(&mut old)?;
            ensure!(old == bytes, "D journal incomplete/conflicting");
            checkpoint(WriteStep::BeforeFileSync)?;
            f.sync_all()?;
            checkpoint(WriteStep::FileSynced)?;
        } else {
            let mut f = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            checkpoint(WriteStep::Created)?;
            let split = bytes.len() / 2;
            f.write_all(&bytes[..split])?;
            checkpoint(WriteStep::Partial)?;
            f.write_all(&bytes[split..])?;
            checkpoint(WriteStep::Written)?;
            checkpoint(WriteStep::BeforeFileSync)?;
            f.sync_all()?;
            checkpoint(WriteStep::FileSynced)?;
        }
        checkpoint(WriteStep::BeforeDirectorySync)?;
        fs::File::open(&self.dir)?.sync_all()?;
        if let Some(parent) = self.dir.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        checkpoint(WriteStep::DirectorySynced)?;
        Ok(())
    }
    pub fn retired(&self) -> bool {
        self.exists("retired")
    }
    pub fn retire(&self) -> Result<()> {
        self.write("retired", &"permanently retired")
    }
    pub fn reserve(&self, wallet: &Wallet, attempt: Hash) -> Result<()> {
        self.reserve_checkpoint(wallet, attempt, |_| Ok(()))
    }
    pub(crate) fn reserve_checkpoint(
        &self,
        wallet: &Wallet,
        attempt: Hash,
        mut checkpoint: impl FnMut(WriteStep) -> Result<()>,
    ) -> Result<()> {
        let _lock = AuthorityLock::acquire(&self.dir)?;
        ensure!(!self.retired(), "D wallet retired");
        checkpoint(WriteStep::BeforeCreate)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.path("reserved"))
            .context("D wallet already reserved")?;
        checkpoint(WriteStep::Created)?;
        let b = serde_json::to_vec(&(wallet, attempt))?;
        let split = b.len() / 2;
        f.write_all(&b[..split])?;
        checkpoint(WriteStep::Partial)?;
        f.write_all(&b[split..])?;
        checkpoint(WriteStep::Written)?;
        checkpoint(WriteStep::BeforeFileSync)?;
        f.sync_all()?;
        checkpoint(WriteStep::FileSynced)?;
        checkpoint(WriteStep::BeforeDirectorySync)?;
        fs::File::open(&self.dir)?.sync_all()?;
        fs::File::open(self.dir.parent().unwrap())?.sync_all()?;
        checkpoint(WriteStep::DirectorySynced)?;
        Ok(())
    }
    pub fn active(&self, root: &Root) -> Result<Certificate> {
        ensure!(!self.retired(), "D wallet retired");
        let c: Certificate = self.read("active")?;
        c.validate()?;
        c.record.local(root, self.role)?;
        self.write("active", &c)?;
        Ok(c)
    }
    pub fn prepare(&self, record: &Record, root: &Root) -> Result<Endorsement> {
        ensure!(!self.retired(), "D wallet retired");
        record.local(root, self.role)?;
        if self.exists("prepared") {
            let (old, e): (Record, Endorsement) = self.read("prepared")?;
            ensure!(old == *record, "D prepared conflict");
            e.validate(record)?;
            self.write("prepared", &(record, &e))?;
            return Ok(e);
        }
        let e = Endorsement::new(record, root, self.role)?;
        self.write("prepared", &(record, &e))?;
        Ok(e)
    }
    pub fn commit(&self, c: &Certificate, root: &Root) -> Result<()> {
        ensure!(!self.retired(), "D wallet retired");
        c.validate()?;
        c.record.local(root, self.role)?;
        let (record, e): (Record, Endorsement) = self.read("prepared")?;
        ensure!(
            record == c.record && e == c.endorsements[self.role as usize],
            "D certificate differs from local prepare"
        );
        self.write("prepared", &(record, e))?;
        self.write("active", c)
    }
}
pub struct Counter {
    dir: PathBuf,
    role: u8,
    last: u64,
}
impl Counter {
    pub fn new(dir: PathBuf, role: u8) -> Self {
        Self { dir, role, last: 0 }
    }
    pub fn check_rate(&self, now: u64, window: u64, limit: usize) -> Result<()> {
        let _lock = AuthorityLock::acquire(&self.dir)?;
        let mut count = 0;
        let prefix = format!("{}-abort-", self.role);
        for p in fs::read_dir(&self.dir)? {
            let p = p?;
            if p.file_name().to_string_lossy().starts_with(&prefix) {
                let (time, _): (u64, Hash) = serde_json::from_slice(&fs::read(p.path())?)?;
                ensure!(time <= now, "D clock regressed relative to abort journal");
                if now - time <= window {
                    count += 1;
                }
            }
        }
        ensure!(count < limit, "D peer transport rate limited");
        Ok(())
    }
    pub fn transport(&self, now: u64, context: Hash) -> Result<()> {
        let _lock = AuthorityLock::acquire(&self.dir)?;
        let name = format!("{}-abort-{}", self.role, hex(&crate::fresh()));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.dir.join(name))?;
        f.write_all(&serde_json::to_vec(&(now, context))?)?;
        f.sync_all()?;
        fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
    pub fn issue(&mut self) -> Result<u64> {
        let _lock = AuthorityLock::acquire(&self.dir)?;
        let path = self.dir.join(format!("{}-counter", self.role));
        let previous = if path.exists() {
            let b = fs::read(&path)?;
            ensure!(b.len() == 8, "partial counter");
            u64::from_be_bytes(b.try_into().unwrap())
        } else {
            0
        };
        let prefix = format!("{}-issued-", self.role);
        let mut max = 0;
        for p in fs::read_dir(&self.dir)? {
            let p = p?;
            let name = p.file_name();
            let name = name.to_string_lossy();
            if let Some(n) = name.strip_prefix(&prefix) {
                let n: u64 = n.parse()?;
                let b = fs::read(p.path())?;
                ensure!(b == n.to_be_bytes(), "partial counter issuance");
                max = max.max(n);
            }
        }
        ensure!(
            previous == max && previous >= self.last,
            "D counter regression or interrupted issuance"
        );
        let next = previous.checked_add(1).context("counter exhausted")?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.dir.join(format!("{prefix}{next}")))?;
        f.write_all(&next.to_be_bytes())?;
        f.sync_all()?;
        fs::File::open(&self.dir)?.sync_all()?;
        let temp = self.dir.join(format!("{}-counter.next", self.role));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        f.write_all(&next.to_be_bytes())?;
        f.sync_all()?;
        fs::rename(temp, path)?;
        fs::File::open(&self.dir)?.sync_all()?;
        self.last = next;
        Ok(next)
    }
}
