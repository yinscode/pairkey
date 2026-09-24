//! Experimental injected-share integration; not covered by FROST's DKG audit.
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use frost_ed25519 as frost;
use hkdf::Hkdf;
use pairkey_types::{derive_public, point, tweak, Attempt, Namespace, Registration, Role};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Metadata(#[from] pairkey_types::Error),
    #[error("FROST protocol validation failed: {0}")]
    Frost(#[from] frost::Error),
    #[error("invalid possession proof")]
    Proof,
    #[error("unknown, consumed, or mismatched signing attempt")]
    Attempt,
    #[error("worker capacity reached")]
    Capacity,
}

/// No Debug/Serialize/Clone implementation for provisioning material.
pub struct Root(Zeroizing<[u8; 32]>);
impl Root {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

fn share(root: &Root, ns: &Namespace, role: Role) -> Result<Scalar, Error> {
    ns.validate()?;
    let mut info = Vec::from(b"pairkey/frost-ed25519/namespace-share/v1".as_slice());
    info.extend_from_slice(&ns.digest());
    info.extend_from_slice(&role.id().to_le_bytes());
    let hk = Hkdf::<Sha512>::new(Some(b"pairkey/provider-root/v1"), root.0.as_ref());
    let mut wide = Zeroizing::new([0u8; 64]);
    hk.expand(&info, wide.as_mut()).expect("fixed HKDF length");
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    if s == Scalar::ZERO {
        return Err(Error::Proof);
    }
    Ok(s)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Possession {
    pub role: Role,
    pub public_share: [u8; 32],
    pub commitment: [u8; 32],
    pub response: [u8; 32],
}
fn proof_challenge(ns: &Namespace, proof: &Possession) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"pairkey/share-possession/v1");
    h.update(ns.digest());
    h.update(proof.role.id().to_le_bytes());
    h.update(proof.public_share);
    h.update(proof.commitment);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}
pub fn prove<R: RngCore + CryptoRng>(
    root: &Root,
    ns: &Namespace,
    role: Role,
    rng: &mut R,
) -> Result<Possession, Error> {
    let mut s = share(root, ns, role)?;
    let mut wide = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(wide.as_mut());
    let mut r = Scalar::from_bytes_mod_order_wide(&wide);
    if r == Scalar::ZERO {
        s.zeroize();
        return Err(Error::Proof);
    }
    let mut p = Possession {
        role,
        public_share: (s * ED25519_BASEPOINT_POINT).compress().to_bytes(),
        commitment: (r * ED25519_BASEPOINT_POINT).compress().to_bytes(),
        response: [0; 32],
    };
    p.response = (r + proof_challenge(ns, &p) * s).to_bytes();
    s.zeroize();
    r.zeroize();
    Ok(p)
}
pub fn verify_proof(ns: &Namespace, p: &Possession) -> Result<(), Error> {
    ns.validate()?;
    let s = point(p.public_share)?;
    let r = point(p.commitment)?;
    let z = Option::<Scalar>::from(Scalar::from_canonical_bytes(p.response)).ok_or(Error::Proof)?;
    if z * ED25519_BASEPOINT_POINT != r + proof_challenge(ns, p) * s {
        return Err(Error::Proof);
    }
    Ok(())
}
pub fn register(ns: Namespace, a: &Possession, b: &Possession) -> Result<Registration, Error> {
    if a.role != Role::A || b.role != Role::B {
        return Err(Error::Proof);
    }
    verify_proof(&ns, a)?;
    verify_proof(&ns, b)?;
    let p = point(a.public_share)? * Scalar::from(2u64) - point(b.public_share)?;
    let reg = Registration {
        namespace: ns,
        public_shares: [a.public_share, b.public_share],
        public_key: p.compress().to_bytes(),
    };
    reg.validate()?;
    Ok(reg)
}

fn identifier(role: Role) -> frost::Identifier {
    frost::Identifier::try_from(role.id()).unwrap()
}
fn packages(
    root: &Root,
    reg: &Registration,
    path: &pairkey_types::AccountPath,
    role: Role,
) -> Result<(frost::keys::KeyPackage, frost::keys::PublicKeyPackage), Error> {
    reg.validate()?;
    let mut s = share(root, &reg.namespace, role)?;
    if (s * ED25519_BASEPOINT_POINT).compress().to_bytes() != reg.public_shares[role.index()] {
        s.zeroize();
        return Err(pairkey_types::Error::Metadata.into());
    }
    let t = tweak(reg, path)?;
    s += t;
    let mut serialized = Zeroizing::new(s.to_bytes());
    s.zeroize();
    let signing = frost::keys::SigningShare::deserialize(serialized.as_ref())?;
    serialized.zeroize();
    let mut public = BTreeMap::new();
    for side in [Role::A, Role::B] {
        let p = (point(reg.public_shares[side.index()])? + t * ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        point(p)?;
        public.insert(
            identifier(side),
            frost::keys::VerifyingShare::deserialize(&p)?,
        );
    }
    let vk = frost::VerifyingKey::deserialize(&derive_public(reg, path)?)?;
    let own = public[&identifier(role)];
    let key = frost::keys::KeyPackage::new(identifier(role), signing, own, vk, 2);
    Ok((key, frost::keys::PublicKeyPackage::new(public, vk)))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundOne {
    pub role: Role,
    pub attempt_digest: [u8; 32],
    pub commitment: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundTwo {
    pub role: Role,
    pub attempt_digest: [u8; 32],
    pub share: Vec<u8>,
}
struct Pending {
    nonces: frost::round1::SigningNonces,
    commitment: frost::round1::SigningCommitments,
    key: frost::keys::KeyPackage,
    message: Vec<u8>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.nonces.zeroize();
        self.key.zeroize();
    }
}
/// Pending nonces are memory-only and removed *before* any round-two validation.
/// Transport authenticates RoundOne/Two; this pure wrapper has no identity trust.
pub struct Signer {
    root: Root,
    role: Role,
    pending: Mutex<BTreeMap<[u8; 32], Pending>>,
}
impl Signer {
    pub fn new(root: Root, role: Role) -> Self {
        Self {
            root,
            role,
            pending: Mutex::new(BTreeMap::new()),
        }
    }
    pub fn proof<R: RngCore + CryptoRng>(
        &self,
        ns: &Namespace,
        rng: &mut R,
    ) -> Result<Possession, Error> {
        prove(&self.root, ns, self.role, rng)
    }
    pub fn begin<R: RngCore + CryptoRng>(
        &self,
        reg: &Registration,
        attempt: &Attempt,
        message: &[u8],
        rng: &mut R,
    ) -> Result<RoundOne, Error> {
        attempt.commit.authorize(reg, message)?;
        let (key, _) = packages(&self.root, reg, &attempt.commit.account, self.role)?;
        let id = attempt.digest();
        let mut pending = self.pending.lock().expect("nonce mutex");
        if pending.contains_key(&id) {
            return Err(Error::Attempt);
        }
        if pending.len() >= 64 {
            return Err(Error::Capacity);
        }
        let (nonces, commitment) = frost::round1::commit(key.signing_share(), rng);
        let bytes = commitment.serialize()?;
        pending.insert(
            id,
            Pending {
                nonces,
                commitment,
                key,
                message: message.to_vec(),
            },
        );
        Ok(RoundOne {
            role: self.role,
            attempt_digest: id,
            commitment: bytes,
        })
    }
    pub fn abort(&self, attempt: &Attempt) {
        self.pending.lock().unwrap().remove(&attempt.digest());
    }
    pub fn finish(&self, attempt: &Attempt, rounds: &[RoundOne; 2]) -> Result<RoundTwo, Error> {
        let id = attempt.digest();
        let pending = self
            .pending
            .lock()
            .expect("nonce mutex")
            .remove(&id)
            .ok_or(Error::Attempt)?;
        let commitments = round_map(id, rounds)?;
        if commitments[&identifier(self.role)] != pending.commitment {
            return Err(Error::Attempt);
        }
        let package = frost::SigningPackage::new(commitments, &pending.message);
        let share = frost::round2::sign(&package, &pending.nonces, &pending.key)?;
        Ok(RoundTwo {
            role: self.role,
            attempt_digest: id,
            share: share.serialize().to_vec(),
        })
    }
}
fn round_map(
    id: [u8; 32],
    rounds: &[RoundOne; 2],
) -> Result<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>, Error> {
    if rounds[0].role != Role::A
        || rounds[1].role != Role::B
        || rounds.iter().any(|r| r.attempt_digest != id)
    {
        return Err(Error::Attempt);
    }
    let mut map = BTreeMap::new();
    for r in rounds {
        map.insert(
            identifier(r.role),
            frost::round1::SigningCommitments::deserialize(&r.commitment)?,
        );
    }
    Ok(map)
}
pub fn aggregate(
    reg: &Registration,
    attempt: &Attempt,
    message: &[u8],
    rounds: &[RoundOne; 2],
    responses: &[RoundTwo; 2],
) -> Result<[u8; 64], Error> {
    attempt.commit.authorize(reg, message)?;
    let id = attempt.digest();
    if responses[0].role != Role::A
        || responses[1].role != Role::B
        || responses.iter().any(|r| r.attempt_digest != id)
    {
        return Err(Error::Attempt);
    }
    let t = tweak(reg, &attempt.commit.account)?;
    let mut pubshares = BTreeMap::new();
    let mut shares = BTreeMap::new();
    for r in responses {
        let p = (point(reg.public_shares[r.role.index()])? + t * ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        point(p)?;
        pubshares.insert(
            identifier(r.role),
            frost::keys::VerifyingShare::deserialize(&p)?,
        );
        shares.insert(
            identifier(r.role),
            frost::round2::SignatureShare::deserialize(&r.share)?,
        );
    }
    let vk = frost::VerifyingKey::deserialize(&derive_public(reg, &attempt.commit.account)?)?;
    let pubkeys = frost::keys::PublicKeyPackage::new(pubshares, vk);
    let package = frost::SigningPackage::new(round_map(id, rounds)?, message);
    let signature = frost::aggregate(&package, &shares, &pubkeys)?;
    vk.verify(message, &signature)?;
    signature
        .serialize()?
        .try_into()
        .map_err(|_| Error::Attempt)
}
