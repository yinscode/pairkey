//! Public, immutable local wallet registration. Not a proof of the replacement
//! key-generation ceremony or a hostile-host/rollback-resistant registry.
use crate::lifecycle::{Failure, Phase};
use crate::{authority::AuthorityLock, digest, point, pool, Hello, Manifest, Request, Root};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use k256::{
    elliptic_curve::{
        bigint::{U256, U512},
        ff::PrimeField,
        ops::Reduce,
    },
    Scalar,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const NAMESPACE: &str = "pairkey/dkls-research/key-id/v1";
const MAX_RECORD: u64 = 32_768;

/// Fixed supported representation; versions are validated, not caller-selectable
/// algorithms. Namespace labels the existing key-ID KDF without changing keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletRecord {
    pub version: u16,
    pub namespace: String,
    pub manifest: Manifest,
    pub configuration: [u8; 32],
    pub curve: String,
    pub kdf_version: u16,
    pub chain_code_version: u16,
    pub derivation_version: u16,
    pub share_version: u16,
    pub party_ids: [u8; 2],
    pub coordinates: [u16; 2],
    pub ranks: [u8; 2],
    pub threshold: u8,
}
impl WalletRecord {
    pub fn new(manifest: Manifest) -> Result<Self> {
        let record = Self {
            version: 1,
            namespace: NAMESPACE.into(),
            manifest,
            configuration: pool::configuration(),
            curve: "secp256k1".into(),
            kdf_version: 1,
            chain_code_version: 1,
            derivation_version: 1,
            share_version: 1,
            party_ids: [0, 1],
            coordinates: [1, 2],
            ranks: [0, 0],
            threshold: 2,
        };
        record.validate()?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        ensure!(
            self.version == 1
                && self.namespace == NAMESPACE
                && self.configuration == pool::configuration()
                && self.curve == "secp256k1"
                && self.kdf_version == 1
                && self.chain_code_version == 1
                && self.derivation_version == 1
                && self.share_version == 1
                && self.party_ids == [0, 1]
                && self.coordinates == [1, 2]
                && self.ranks == [0, 0]
                && self.threshold == 2,
            "unsupported wallet registration representation/configuration"
        );
        ensure!(
            self.manifest.chain_code
                == digest(
                    b"pairkey/dkls-research/public-chain-code/v1",
                    &(self.manifest.key_id, self.manifest.public_key.clone())
                ),
            "wallet registration chain-code rule mismatch"
        );
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        pool::hash(
            "pairkey/wallet-record/v1",
            &[
                &self.version.to_be_bytes(),
                self.namespace.as_bytes(),
                &pool::manifest_digest(&self.manifest),
                &self.configuration,
                self.curve.as_bytes(),
                &self.kdf_version.to_be_bytes(),
                &self.chain_code_version.to_be_bytes(),
                &self.derivation_version.to_be_bytes(),
                &self.share_version.to_be_bytes(),
                &self.party_ids,
                &self.coordinates[0].to_be_bytes(),
                &self.coordinates[1].to_be_bytes(),
                &self.ranks,
                &[self.threshold],
            ],
        )
    }
    pub fn validate_hellos(&self, hellos: &[Hello; 2]) -> Result<()> {
        self.validate()?;
        for (i, h) in hellos.iter().enumerate() {
            h.validate()?;
            ensure!(
                h.role as usize == i
                    && h.key_id == self.manifest.key_id
                    && h.identity == self.manifest.identities[i]
                    && h.contribution == self.manifest.additive_public[i],
                "registration contribution mismatch"
            );
        }
        Ok(())
    }
}

/// Dedicated endorsement of the complete record, with a fresh Schnorr proof
/// whose challenge binds that record/role. No claim of stronger extraction or
/// independent root generation; no contribution commit-before-reveal phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endorsement {
    pub role: u8,
    pub record: [u8; 32],
    pub commitment: Vec<u8>,
    pub response: [u8; 32],
    pub signature: Vec<u8>,
}
impl Endorsement {
    fn challenge(&self) -> Scalar {
        <Scalar as Reduce<U256>>::reduce_bytes(
            &pool::hash(
                "pairkey/wallet-registration/proof/v1",
                &[&self.record, &[self.role], &self.commitment],
            )
            .into(),
        )
    }
    fn message(&self) -> [u8; 32] {
        pool::hash(
            "pairkey/wallet-registration/endorsement/v1",
            &[&self.record, &[self.role], &self.commitment, &self.response],
        )
    }
    pub fn new(record: &WalletRecord, root: &Root, role: u8) -> Result<Self> {
        record.validate()?;
        let secret = record.manifest.check_local(root, role)?;
        let mut wide = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(wide.as_mut());
        let nonce = Zeroizing::new(<Scalar as Reduce<U512>>::reduce_bytes(
            k256::WideBytes::from_slice(wide.as_ref()),
        ));
        ensure!(*nonce != Scalar::ZERO, "zero registration proof nonce");
        let mut e = Self {
            role,
            record: record.digest(),
            commitment: crate::public(&nonce),
            response: [0; 32],
            signature: vec![],
        };
        e.response = (*nonce + e.challenge() * *secret).to_bytes().into();
        e.signature = root.identity(role).sign(&e.message()).to_bytes().to_vec();
        Ok(e)
    }
    pub fn validate(&self, record: &WalletRecord) -> Result<()> {
        record.validate()?;
        ensure!(
            self.role < 2 && self.record == record.digest(),
            "wallet endorsement context mismatch"
        );
        VerifyingKey::from_bytes(&record.manifest.identities[self.role as usize])?
            .verify_strict(&self.message(), &Signature::from_slice(&self.signature)?)?;
        // Only failures after identity authentication establish this violation.
        // Wrong context or invalid signatures above never accuse a signer.
        let violation = |detail| {
            Failure::violation(
                Phase::Admission,
                record.manifest.identities[self.role as usize],
                detail,
            )
        };
        let z = Option::<Scalar>::from(Scalar::from_repr(self.response.into()))
            .ok_or_else(|| violation("invalid registration proof scalar"))?;
        let commitment = point(&self.commitment)
            .map_err(|_| violation("invalid registration proof commitment"))?;
        if k256::ProjectivePoint::GENERATOR * z
            != commitment
                + point(&record.manifest.additive_public[self.role as usize])? * self.challenge()
        {
            return Err(violation("registration possession proof failed").into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredWallet {
    pub record: WalletRecord,
    pub endorsements: [Endorsement; 2],
}
impl RegisteredWallet {
    pub fn validate(&self) -> Result<()> {
        self.record.validate()?;
        for (i, e) in self.endorsements.iter().enumerate() {
            ensure!(e.role as usize == i, "wallet endorsement order mismatch");
            e.validate(&self.record)?;
        }
        Ok(())
    }
    pub fn validate_request(&self, r: &Request, root: &Root, role: u8) -> Result<()> {
        self.validate()?;
        ensure!(
            r.wallet_record == Some(self.record.digest()) && r.manifest == self.record.manifest,
            "request differs from registered wallet"
        );
        self.record.manifest.check_local(root, role)?;
        Ok(())
    }
}

/// Public prepare journals are immutable before endorsements leave a worker.
/// A partial journal/commit blocks use and is never silently replaced/repaired.
pub struct WalletStore {
    dir: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    record: WalletRecord,
    endorsement: Endorsement,
}
impl WalletStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
    fn name(key: [u8; 32]) -> String {
        key.iter().map(|b| format!("{b:02x}")).collect()
    }
    pub fn record_path(&self, key: [u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.wallet", Self::name(key)))
    }
    fn prepared_path(&self, key: [u8; 32], role: u8) -> PathBuf {
        self.dir
            .join(format!("{}-{role}.prepared", Self::name(key)))
    }
    pub fn endorse(&self, record: &WalletRecord, root: &Root, role: u8) -> Result<Endorsement> {
        record.validate()?;
        record.manifest.check_local(root, role)?;
        let _lock = AuthorityLock::acquire(&self.dir)?;
        let final_path = self.record_path(record.manifest.key_id);
        if final_path.try_exists()? {
            let final_record: RegisteredWallet = read(&final_path)?;
            final_record.validate()?;
            ensure!(
                final_record.record == *record,
                "conflicting wallet registration"
            );
        }
        let path = self.prepared_path(record.manifest.key_id, role);
        if path.try_exists()? {
            let prepared: Prepared = read(&path)?;
            prepared.endorsement.validate(&prepared.record)?;
            ensure!(
                prepared.record == *record && prepared.endorsement.role == role,
                "conflicting wallet registration"
            );
            sync(&path, &self.dir)?;
            return Ok(prepared.endorsement);
        }
        let endorsement = Endorsement::new(record, root, role)?;
        write_new(
            &path,
            &self.dir,
            &Prepared {
                record: record.clone(),
                endorsement: endorsement.clone(),
            },
        )?;
        Ok(endorsement)
    }
    pub fn commit(&self, wallet: &RegisteredWallet, root: &Root, role: u8) -> Result<[u8; 32]> {
        wallet.validate()?;
        wallet.record.manifest.check_local(root, role)?;
        let _lock = AuthorityLock::acquire(&self.dir)?;
        // Each worker requires its own previously published endorsement. The
        // other signer may use a distinct honest store; its signature suffices.
        let own: Prepared = read(&self.prepared_path(wallet.record.manifest.key_id, role))?;
        ensure!(
            own.record == wallet.record && own.endorsement == wallet.endorsements[role as usize],
            "wallet commit differs from prepared endorsement"
        );
        own.endorsement.validate(&own.record)?;
        let path = self.record_path(wallet.record.manifest.key_id);
        if path.try_exists()? {
            let existing: RegisteredWallet = read(&path)?;
            existing.validate()?;
            ensure!(existing == *wallet, "conflicting wallet registration");
            sync(&path, &self.dir)?;
        } else {
            write_new(&path, &self.dir, wallet)?;
        }
        Ok(wallet.record.digest())
    }
    pub fn load(&self, key: [u8; 32]) -> Result<RegisteredWallet> {
        let _lock = AuthorityLock::acquire(&self.dir)?;
        let wallet: RegisteredWallet =
            read(&self.record_path(key)).context("wallet not committed or record invalid")?;
        wallet.validate()?;
        ensure!(
            wallet.record.manifest.key_id == key,
            "wallet record storage identifier mismatch"
        );
        sync(&self.record_path(key), &self.dir)?;
        Ok(wallet)
    }
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = fs::File::open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= MAX_RECORD,
        "invalid wallet record file"
    );
    let mut data = vec![];
    file.take(MAX_RECORD + 1).read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= MAX_RECORD, "oversized wallet record");
    serde_json::from_slice(&data).context("incomplete or invalid wallet record")
}
fn sync(path: &Path, dir: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}
fn write_new<T: Serialize>(path: &Path, dir: &Path, data: &T) -> Result<()> {
    write_checkpoint(path, dir, data, |_| Ok(()))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteStep {
    Created,
    Written,
    FileSynced,
    DirectorySynced,
}
fn write_checkpoint<T: Serialize>(
    path: &Path,
    dir: &Path,
    data: &T,
    mut checkpoint: impl FnMut(WriteStep) -> Result<()>,
) -> Result<()> {
    let bytes = serde_json::to_vec(data)?;
    ensure!(bytes.len() as u64 <= MAX_RECORD, "oversized wallet record");
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    checkpoint(WriteStep::Created)?;
    file.write_all(&bytes)?;
    checkpoint(WriteStep::Written)?;
    file.sync_all()?;
    checkpoint(WriteStep::FileSynced)?;
    fs::File::open(dir)?.sync_all()?;
    checkpoint(WriteStep::DirectorySynced)?;
    Ok(())
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod tests;
