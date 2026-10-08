//! Canonical public metadata. This crate contains no signing secrets.
#![allow(unexpected_cfgs)]
use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "solana"))]
use sha2::Sha256;
use sha2::{Digest, Sha512};

pub const VERSION: u16 = 1;
pub const MAX_PATH: usize = 8;
pub const MAX_MESSAGE: usize = 1232;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("noncanonical, identity, or non-prime-order public point")]
    Point,
    #[error("unsupported version, scheme, role, or invalid bounds")]
    Bounds,
    #[error("public metadata mismatch")]
    Metadata,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub enum Scheme {
    FrostEd25519,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub enum Role {
    A,
    B,
}
impl Role {
    pub fn id(self) -> u16 {
        match self {
            Self::A => 1,
            Self::B => 2,
        }
    }
    pub fn peer(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
    pub fn index(self) -> usize {
        self.id() as usize - 1
    }
}

/// Derivation authority is immutable, including after controller rotation.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub version: u16,
    pub scheme: Scheme,
    pub network: [u8; 32],
    pub registry: [u8; 32],
    pub derivation_authority: [u8; 32],
    pub namespace_id: [u8; 32],
    pub enclave_set: [u8; 32],
}
impl Namespace {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/namespace/v1", self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub namespace: Namespace,
    pub public_shares: [[u8; 32]; 2],
    pub public_key: [u8; 32],
}
impl Registration {
    pub fn validate(&self) -> Result<(), Error> {
        self.namespace.validate()?;
        // Equal evaluations give a constant polynomial: either participant
        // would hold the aggregate key, despite an advertised threshold of two.
        if self.public_shares[0] == self.public_shares[1] {
            return Err(Error::Metadata);
        }
        #[cfg(target_os = "solana")]
        return onchain::registration(self);
        #[cfg(not(target_os = "solana"))]
        {
            let a = point(self.public_shares[0])?;
            let b = point(self.public_shares[1])?;
            let p = point(self.public_key)?;
            if a * Scalar::from(2u64) - b != p {
                return Err(Error::Metadata);
            }
            Ok(())
        }
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/registration/v1", self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountPath {
    /// Application-defined destination identity; signatures themselves are raw Ed25519.
    pub destination: [u8; 32],
    pub path: Vec<u32>,
}
impl AccountPath {
    pub fn validate(&self) -> Result<(), Error> {
        if self.path.len() > MAX_PATH {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub registration_digest: [u8; 32],
    pub request_id: [u8; 32],
    pub account: AccountPath,
    pub message_hash: [u8; 32],
    pub message_len: u32,
}
impl Commit {
    pub fn new(
        reg: &Registration,
        request_id: [u8; 32],
        account: AccountPath,
        message: &[u8],
    ) -> Result<Self, Error> {
        reg.validate()?;
        account.validate()?;
        if message.is_empty() || message.len() > MAX_MESSAGE {
            return Err(Error::Bounds);
        }
        Ok(Self {
            registration_digest: reg.digest(),
            request_id,
            account,
            message_hash: message_hash(message),
            message_len: message.len() as u32,
        })
    }
    pub fn authorize(&self, reg: &Registration, message: &[u8]) -> Result<(), Error> {
        reg.validate()?;
        self.account.validate()?;
        if message.is_empty()
            || message.len() > MAX_MESSAGE
            || self.message_len as usize != message.len()
        {
            return Err(Error::Bounds);
        }
        if self.registration_digest != reg.digest() || self.message_hash != message_hash(message) {
            return Err(Error::Metadata);
        }
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/commit/v1", self)
    }
}

/// Fixed participant set is implicit in v1: A=1, B=2, threshold=2.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    #[serde(default)]
    pub authorization: policy::Authorization,
    pub commit: Commit,
    pub random_id: [u8; 32],
}
impl Attempt {
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/attempt/v2", self)
    }
}

pub fn point(bytes: [u8; 32]) -> Result<EdwardsPoint, Error> {
    let p = CompressedEdwardsY(bytes).decompress().ok_or(Error::Point)?;
    if p.compress().to_bytes() != bytes || p.is_identity() || !p.is_torsion_free() {
        return Err(Error::Point);
    }
    Ok(p)
}

// Identical framing on host and SBF. On-chain software SHA-256 exceeded the
// simulation compute budget for large passkey policies; use the native syscall.
fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        solana_sha256_hasher::hashv(parts).to_bytes()
    }
    #[cfg(not(target_os = "solana"))]
    {
        let mut h = Sha256::new();
        for part in parts {
            h.update(part);
        }
        h.finalize().into()
    }
}
pub fn digest<T: BorshSerialize>(label: &[u8], value: &T) -> [u8; 32] {
    let bytes = borsh::to_vec(value).expect("bounded in-memory serialization");
    hash_parts(&[
        &(label.len() as u32).to_le_bytes(),
        label,
        &(bytes.len() as u32).to_le_bytes(),
        &bytes,
    ])
}
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    hash_parts(&[
        b"pairkey/exact-message/v1",
        &(message.len() as u32).to_le_bytes(),
        message,
    ])
}
pub fn tweak(reg: &Registration, path: &AccountPath) -> Result<Scalar, Error> {
    reg.validate()?;
    path.validate()?;
    let mut h = Sha512::new();
    h.update(b"pairkey/public-account-tweak/v1");
    h.update(borsh::to_vec(&(&reg.namespace, reg.public_key, path)).unwrap());
    Ok(Scalar::from_bytes_mod_order_wide(&h.finalize().into()))
}
pub fn derive_public(reg: &Registration, path: &AccountPath) -> Result<[u8; 32], Error> {
    #[cfg(target_os = "solana")]
    return onchain::derive(reg, path);
    #[cfg(not(target_os = "solana"))]
    {
        shift_public(reg, tweak(reg, path)?)
    }
}

#[cfg(not(target_os = "solana"))]
fn shift_public(reg: &Registration, t: Scalar) -> Result<[u8; 32], Error> {
    let delta = t * ED25519_BASEPOINT_POINT;
    // A zero child share would let the other participant compute the full
    // child key by its known interpolation coefficient. Refuse before funding.
    for share in reg.public_shares {
        point((point(share)? + delta).compress().to_bytes())?;
    }
    let bytes = (point(reg.public_key)? + delta).compress().to_bytes();
    point(bytes)?;
    Ok(bytes)
}

/// Native syscall implementation of the same public algebra used by workers/SDK.
#[cfg(target_os = "solana")]
mod onchain {
    use super::*;
    use solana_curve25519::{
        edwards::{
            add_edwards, multiply_edwards, subtract_edwards, validate_edwards, PodEdwardsPoint,
        },
        scalar::PodScalar,
    };
    const IDENTITY: [u8; 32] = {
        let mut b = [0; 32];
        b[0] = 1;
        b
    };
    fn public(bytes: [u8; 32]) -> Result<PodEdwardsPoint, Error> {
        // Canonical field encoding y < 2^255-19, including the sign bit convention.
        let mut y = bytes;
        y[31] &= 0x7f;
        let mut modulus = [0xff; 32];
        modulus[0] = 0xed;
        modulus[31] = 0x7f;
        if y.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less || y == IDENTITY {
            return Err(Error::Point);
        }
        let p = PodEdwardsPoint(bytes);
        if !validate_edwards(&p) {
            return Err(Error::Point);
        }
        // (l-1)*P + P == identity checks prime-order membership using canonical scalar input.
        let minus_one = PodScalar((-Scalar::ONE).to_bytes());
        let lm1 = multiply_edwards(&minus_one, &p).ok_or(Error::Point)?;
        if add_edwards(&lm1, &p).ok_or(Error::Point)?.0 != IDENTITY {
            return Err(Error::Point);
        }
        Ok(p)
    }
    pub fn registration(reg: &Registration) -> Result<(), Error> {
        let a = public(reg.public_shares[0])?;
        let b = public(reg.public_shares[1])?;
        let p = public(reg.public_key)?;
        let twice =
            multiply_edwards(&PodScalar(Scalar::from(2u64).to_bytes()), &a).ok_or(Error::Point)?;
        if subtract_edwards(&twice, &b).ok_or(Error::Point)? != p {
            return Err(Error::Metadata);
        }
        Ok(())
    }
    pub fn derive(reg: &Registration, path: &AccountPath) -> Result<[u8; 32], Error> {
        let t = tweak(reg, path)?;
        let generator = PodEdwardsPoint(ED25519_BASEPOINT_POINT.compress().to_bytes());
        let tg = multiply_edwards(&PodScalar(t.to_bytes()), &generator).ok_or(Error::Point)?;
        for share in reg.public_shares {
            public(
                add_edwards(&PodEdwardsPoint(share), &tg)
                    .ok_or(Error::Point)?
                    .0,
            )?;
        }
        let p = add_edwards(&PodEdwardsPoint(reg.public_key), &tg).ok_or(Error::Point)?;
        public(p.0)?;
        Ok(p.0)
    }
}

pub mod approval;
pub mod policy;
pub mod receipt;

pub mod attestation;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tweaks_cannot_zero_either_share_or_the_group_key() {
        let reg = Registration {
            namespace: Namespace {
                version: VERSION,
                scheme: Scheme::FrostEd25519,
                network: [1; 32],
                registry: [2; 32],
                derivation_authority: [3; 32],
                namespace_id: [4; 32],
                enclave_set: [5; 32],
            },
            public_shares: [
                (Scalar::from(3u64) * ED25519_BASEPOINT_POINT)
                    .compress()
                    .to_bytes(),
                (Scalar::from(7u64) * ED25519_BASEPOINT_POINT)
                    .compress()
                    .to_bytes(),
            ],
            public_key: (-ED25519_BASEPOINT_POINT).compress().to_bytes(),
        };
        reg.validate().unwrap();
        assert!(shift_public(&reg, -Scalar::from(3u64)).is_err());
        assert!(shift_public(&reg, -Scalar::from(7u64)).is_err());
        assert!(shift_public(&reg, Scalar::ONE).is_err());
        assert!(shift_public(&reg, Scalar::from(2u64)).is_ok());
    }
}
