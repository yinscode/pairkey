//! Isolated research harness. No production authorization or TEE claims.
pub mod lifecycle;
use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{Signature as IdentitySignature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use k256::{
    elliptic_curve::{bigint::U512, group::GroupEncoding, ops::Reduce},
    ProjectivePoint, Scalar, WideBytes,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub const REVISION: &str = "af5ada2a2e573c2c8eac5b01f9bbc4bf1c331ac7";
pub const MAX_FRAME: usize = 2 * 1024 * 1024;

pub fn fresh() -> [u8; 32] {
    let mut out = [0; 32];
    OsRng.fill_bytes(&mut out);
    out
}
pub fn digest<T: Serialize>(label: &[u8], value: &T) -> [u8; 32] {
    let bytes = Zeroizing::new(serde_json::to_vec(value).expect("serializable research metadata"));
    Sha256::new()
        .chain_update((label.len() as u32).to_be_bytes())
        .chain_update(label)
        .chain_update((bytes.len() as u64).to_be_bytes())
        .chain_update(bytes.as_slice())
        .finalize()
        .into()
}
pub fn point(bytes: &[u8]) -> Result<ProjectivePoint> {
    ensure!(bytes.len() == 33, "noncanonical point length");
    let p = Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(bytes.into()))
        .context("invalid curve point")?;
    ensure!(
        p != ProjectivePoint::IDENTITY && p.to_bytes().as_slice() == bytes,
        "identity or noncanonical point"
    );
    Ok(p)
}
pub fn public(s: &Scalar) -> Vec<u8> {
    (ProjectivePoint::GENERATOR * s).to_bytes().to_vec()
}

pub struct Root(Zeroizing<[u8; 32]>);
impl Root {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = Zeroizing::new(fs::read(path)?);
        ensure!(bytes.len() == 32, "root file must contain exactly 32 bytes");
        Ok(Self(Zeroizing::new(bytes.as_slice().try_into()?)))
    }
    pub fn derive(&self, role: u8, key_id: [u8; 32]) -> Result<Zeroizing<Scalar>> {
        ensure!(role < 2, "invalid participant mapping");
        let info = digest(b"pairkey/dkls-research/contribution/v1", &(role, key_id));
        let hk = Hkdf::<Sha512>::new(Some(b"pairkey/dkls-research/root/v1"), self.0.as_ref());
        let mut wide = Zeroizing::new([0; 64]);
        hk.expand(&info, wide.as_mut()).expect("fixed HKDF length");
        let s = Zeroizing::new(<Scalar as Reduce<U512>>::reduce_bytes(
            WideBytes::from_slice(wide.as_ref()),
        ));
        ensure!(*s != Scalar::ZERO, "zero contribution");
        Ok(s)
    }
    pub fn identity(&self, role: u8) -> SigningKey {
        let hk = Hkdf::<Sha256>::new(Some(b"pairkey/dkls-research/identity/v1"), self.0.as_ref());
        let mut seed = Zeroizing::new([0; 32]);
        hk.expand(&[role], seed.as_mut())
            .expect("fixed HKDF length");
        SigningKey::from_bytes(&seed)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u16,
    pub key_id: [u8; 32],
    pub identities: [[u8; 32]; 2],
    pub additive_public: [Vec<u8>; 2],
    pub public_key: Vec<u8>,
    pub chain_code: [u8; 32],
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.identities[0] != self.identities[1],
            "invalid manifest"
        );
        for identity in self.identities {
            VerifyingKey::from_bytes(&identity)?;
        }
        let a = point(&self.additive_public[0])?;
        let b = point(&self.additive_public[1])?;
        let q = point(&self.public_key)?;
        ensure!(a + b == q, "aggregate public key mismatch");
        let shares = self.stored_public()?;
        ensure!(
            shares[0] != shares[1],
            "constant polynomial destroys threshold"
        );
        Ok(())
    }
    pub fn stored_public(&self) -> Result<[ProjectivePoint; 2]> {
        Ok([
            point(&self.additive_public[0])? * Scalar::from(2u64).invert().unwrap(),
            -point(&self.additive_public[1])?,
        ])
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/dkls-research/manifest/v1", self)
    }
    pub fn check_local(&self, root: &Root, role: u8) -> Result<Zeroizing<Scalar>> {
        self.validate()?;
        ensure!(role < 2, "invalid role");
        ensure!(
            root.identity(role).verifying_key().to_bytes() == self.identities[role as usize],
            "wrong root identity"
        );
        let a = root.derive(role, self.key_id)?;
        ensure!(
            public(&a) == self.additive_public[role as usize],
            "wrong root/key pin"
        );
        Ok(a)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub role: u8,
    pub key_id: [u8; 32],
    pub identity: [u8; 32],
    pub contribution: Vec<u8>,
    pub proof_commitment: Vec<u8>,
    pub proof_response: Vec<u8>,
    pub boot: [u8; 32],
    pub ephemeral: [u8; 32],
    pub signature: Vec<u8>,
}
impl Hello {
    pub fn message(&self) -> [u8; 32] {
        digest(
            b"pairkey/dkls-research/hello/v1",
            &(
                self.role,
                self.key_id,
                self.identity,
                &self.contribution,
                &self.proof_commitment,
                &self.proof_response,
                self.boot,
                self.ephemeral,
            ),
        )
    }
    pub fn new(root: &Root, role: u8, key_id: [u8; 32], ephemeral: [u8; 32]) -> Result<Self> {
        let s = root.derive(role, key_id)?;
        let nonce = Zeroizing::new(<Scalar as Reduce<U512>>::reduce(U512::from_be_slice(&{
            let mut wide = Zeroizing::new([0; 64]);
            OsRng.fill_bytes(wide.as_mut());
            *wide
        })));
        ensure!(*nonce != Scalar::ZERO, "zero proof nonce");
        let mut hello = Self {
            role,
            key_id,
            identity: root.identity(role).verifying_key().to_bytes(),
            contribution: public(&s),
            proof_commitment: public(&nonce),
            proof_response: vec![],
            boot: fresh(),
            ephemeral,
            signature: vec![],
        };
        let challenge = proof_challenge(&hello);
        hello.proof_response = (*nonce + challenge * *s).to_bytes().to_vec();
        hello.signature = root
            .identity(role)
            .sign(&hello.message())
            .to_bytes()
            .to_vec();
        Ok(hello)
    }
    pub fn validate(&self) -> Result<()> {
        use k256::elliptic_curve::ff::PrimeField;
        ensure!(
            self.role < 2 && self.proof_response.len() == 32,
            "invalid hello"
        );
        VerifyingKey::from_bytes(&self.identity)?.verify_strict(
            &self.message(),
            &IdentitySignature::from_slice(&self.signature)?,
        )?;
        let response: [u8; 32] = self.proof_response.as_slice().try_into()?;
        let z = Option::<Scalar>::from(Scalar::from_repr(response.into()))
            .context("invalid proof scalar")?;
        ensure!(
            ProjectivePoint::GENERATOR * z
                == point(&self.proof_commitment)?
                    + point(&self.contribution)? * proof_challenge(self),
            "possession proof failed"
        );
        Ok(())
    }
}
fn proof_challenge(hello: &Hello) -> Scalar {
    use k256::elliptic_curve::bigint::U256;
    <Scalar as Reduce<U256>>::reduce_bytes(
        &digest(
            b"pairkey/dkls-research/possession/v1",
            &(
                hello.role,
                hello.key_id,
                hello.identity,
                &hello.contribution,
                &hello.proof_commitment,
            ),
        )
        .into(),
    )
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Route {
    Migration,
    Direct,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub route: Route,
    pub manifest: Manifest,
    pub hellos: [Hello; 2],
    pub entry: [u8; 32],
    pub attempt: [u8; 32],
    pub path: String,
    pub prehash: [u8; 32],
    pub fault: Option<String>,
}
impl Request {
    pub fn fault_is(&self, name: &str) -> bool {
        cfg!(feature = "research-faults") && self.fault.as_deref() == Some(name)
    }
    pub fn context(&self) -> [u8; 32] {
        digest(
            b"pairkey/dkls-research/attempt/v1",
            &(
                self.route,
                self.manifest.digest(),
                self.hellos[0].boot,
                self.hellos[1].boot,
                self.entry,
                self.attempt,
                &self.path,
                self.prehash,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        ensure!(
            cfg!(feature = "research-faults") || self.fault.is_none(),
            "fault injection requires research-faults feature"
        );
        ensure!(
            self.path == "m" || self.path == "m/7/3",
            "unsupported research path"
        );
        for (i, hello) in self.hellos.iter().enumerate() {
            hello.validate()?;
            ensure!(
                hello.role as usize == i
                    && hello.key_id == self.manifest.key_id
                    && hello.identity == self.manifest.identities[i]
                    && hello.contribution == self.manifest.additive_public[i],
                "hello/manifest mismatch"
            );
        }
        ensure!(self.hellos[0].boot != self.hellos[1].boot, "boot collision");
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Outcome {
    pub role: u8,
    pub route: Route,
    pub context: [u8; 32],
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub recovery_id: u8,
    pub setup_ms: f64,
    pub signing_ms: f64,
    pub package_bytes: usize,
    pub setup_id: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "body")]
pub enum Frame {
    Hello(Hello),
    Start(Box<Request>),
    Setup(Vec<u8>),
    Relay(Vec<u8>),
    Ready([u8; 32]),
    Result(Outcome),
    Failure(lifecycle::Failure),
    Closed,
}

/// Public experiment ledger: create-new + fsync makes reservations irreversible
/// across these process restarts. This is NOT a hostile-host durable authority.
pub fn reserve(dir: &Path, role: u8, entry: [u8; 32], context: [u8; 32]) -> Result<()> {
    fs::create_dir_all(dir)?;
    let name = entry.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let path = dir.join(format!("{role}-{name}.retired"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .context("entry already reserved or ledger unavailable")?;
    file.write_all(&context)?;
    file.sync_all()?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}
pub fn incident(dir: &Path, role: u8, context: [u8; 32]) -> Result<()> {
    incident_with_checkpoint(dir, role, context, |_| Ok(()))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IncidentStep {
    Created,
    Written,
    BeforeFileSync,
    FileSynced,
    BeforeDirectorySync,
    DirectorySynced,
}
/// A filename always fences admission, but durability needs a complete record
/// and successful file AND parent-directory sync. Never repair partial records
/// implicitly or confirm them just because create_new returns AlreadyExists.
pub(crate) fn incident_with_checkpoint(
    dir: &Path,
    role: u8,
    context: [u8; 32],
    mut checkpoint: impl FnMut(IncidentStep) -> Result<()>,
) -> Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("{role}.quarantined"));
    let file = match OpenOptions::new().create_new(true).write(true).open(&path) {
        Ok(mut file) => {
            checkpoint(IncidentStep::Created)?;
            file.write_all(&context)?;
            checkpoint(IncidentStep::Written)?;
            file
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut file = OpenOptions::new().read(true).open(&path)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() == 32,
                "incomplete or invalid incident marker; durability unconfirmed"
            );
            let mut stored = [0; 32];
            file.read_exact(&mut stored)?;
            // First incident remains authoritative for this scope. Re-sync it;
            // existence alone is not evidence of completed durability.
            file
        }
        Err(e) => return Err(e.into()),
    };
    checkpoint(IncidentStep::BeforeFileSync)?;
    file.sync_all()?;
    checkpoint(IncidentStep::FileSynced)?;
    checkpoint(IncidentStep::BeforeDirectorySync)?;
    fs::File::open(dir)?.sync_all()?;
    checkpoint(IncidentStep::DirectorySynced)?;
    Ok(())
}
pub fn check_incident(dir: &Path, role: u8) -> Result<()> {
    match fs::metadata(dir.join(format!("{role}.quarantined"))) {
        Ok(_) => bail!("research quarantine marker present; signing refused"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod incident_tests {
    use super::*;
    fn directory() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("dkls-incident-{:?}", fresh()));
        fs::create_dir(&dir).unwrap();
        dir
    }
    #[test]
    fn incomplete_existing_markers_never_confirm_persistence() {
        for bytes in [vec![], vec![1; 7], vec![1; 33]] {
            let dir = directory();
            fs::write(dir.join("0.quarantined"), &bytes).unwrap();
            assert!(incident(&dir, 0, [4; 32]).is_err());
            assert!(check_incident(&dir, 0).is_err());
            assert_eq!(fs::read(dir.join("0.quarantined")).unwrap(), bytes);
            fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn failed_publication_at_each_durability_step_is_not_confirmed() {
        use IncidentStep::*;
        for failed in [
            Created,
            Written,
            BeforeFileSync,
            FileSynced,
            BeforeDirectorySync,
            DirectorySynced,
        ] {
            let dir = directory();
            let error = incident_with_checkpoint(&dir, 0, [4; 32], |step| {
                if step == failed {
                    anyhow::bail!("injected {step:?} failure");
                }
                Ok(())
            });
            assert!(error.is_err(), "{failed:?}");
            assert!(check_incident(&dir, 0).is_err());
            let mut retry_steps = Vec::new();
            let retry = incident_with_checkpoint(&dir, 0, [8; 32], |step| {
                retry_steps.push(step);
                Ok(())
            });
            if failed == Created {
                assert!(retry.is_err());
                assert!(retry_steps.is_empty());
                assert!(fs::read(dir.join("0.quarantined")).unwrap().is_empty());
            } else {
                // A different explicit publication can confirm a complete record
                // only by performing the file and directory syncs again.
                retry.unwrap();
                assert_eq!(
                    retry_steps,
                    vec![
                        BeforeFileSync,
                        FileSynced,
                        BeforeDirectorySync,
                        DirectorySynced
                    ]
                );
                assert_eq!(fs::read(dir.join("0.quarantined")).unwrap(), [4; 32]);
            }
            fs::remove_dir_all(dir).unwrap();
        }
    }
}
