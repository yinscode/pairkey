//! Independent root-derived RedPallas shares. Custom setup remains experimental.
//! Uses Zcash Foundation's RedPallas FROST suite and Orchard SpendAuth generator.
use anyhow::{ensure, Result};
use frost::Group;
use group::{
    ff::{Field, FromUniformBytes, PrimeField},
    GroupEncoding,
};
use hkdf::Hkdf;
use pairkey_types::{AccountPath, Registration, Role};
use pasta_curves::pallas;
use rand_core::OsRng;
use reddsa::frost::redpallas as frost;
#[cfg(feature = "zcash-pczt")]
use reddsa::frost::redpallas::keys::EvenY;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};
fn generator() -> pallas::Point {
    frost::PallasGroup::generator()
}
fn point(bytes: &[u8]) -> Result<pallas::Point> {
    Ok(frost::PallasGroup::deserialize(&bytes.try_into()?)?)
}
pub fn validate_key(bytes: &[u8]) -> Result<()> {
    point(bytes)?;
    Ok(())
}
/// Canonical Orchard spend-validating key corresponding to this threshold key.
/// Orchard requires even Y; FROST shares must be negated for the same key when
/// the original group point has odd Y.
#[cfg(feature = "zcash-pczt")]
pub fn orchard_ak(public: &[u8]) -> Result<[u8; 32]> {
    let mut bytes: [u8; 32] = public.try_into()?;
    let p = point(&bytes)?;
    if bytes[31] & 0x80 != 0 {
        bytes = (-p).to_bytes();
    }
    ensure!(
        bytes[31] & 0x80 == 0,
        "invalid Orchard spend-validating key"
    );
    Ok(bytes)
}
fn id(role: Role) -> frost::Identifier {
    frost::Identifier::try_from(role.id()).unwrap()
}
fn scalar(
    root: &[u8; 32],
    reg: &Registration,
    path: &AccountPath,
    role: Role,
) -> Result<pallas::Scalar> {
    reg.validate()?;
    path.validate()?;
    let context = pairkey_types::digest(
        b"pairkey/redpallas/contribution/v1",
        &(reg.digest(), path, role),
    );
    let mut wide = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha512>::new(Some(b"pairkey/redpallas/provider-root/v1"), root)
        .expand(&context, wide.as_mut())
        .unwrap();
    let s = pallas::Scalar::from_uniform_bytes(&wide);
    ensure!(s != pallas::Scalar::ZERO, "zero contribution");
    Ok(s)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub role: Role,
    pub point: Vec<u8>,
    pub commitment: Vec<u8>,
    pub response: Vec<u8>,
}
fn challenge(reg: &Registration, path: &AccountPath, p: &Proof) -> pallas::Scalar {
    let mut h = Sha512::new();
    h.update(b"pairkey/redpallas/possession/v1");
    h.update(borsh::to_vec(&(reg.digest(), path, p.role, &p.point, &p.commitment)).unwrap());
    pallas::Scalar::from_uniform_bytes(&h.finalize().into())
}
pub fn proof(root: &[u8; 32], reg: &Registration, path: &AccountPath, role: Role) -> Result<Proof> {
    let mut s = scalar(root, reg, path, role)?;
    let mut r = pallas::Scalar::random(&mut OsRng);
    let mut p = Proof {
        role,
        point: (generator() * s).to_bytes().to_vec(),
        commitment: (generator() * r).to_bytes().to_vec(),
        response: vec![],
    };
    p.response = (r + challenge(reg, path, &p) * s).to_repr().to_vec();
    s = pallas::Scalar::ZERO;
    r = pallas::Scalar::ZERO;
    std::hint::black_box((s, r));
    Ok(p)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Public {
    pub proofs: [Proof; 2],
}
impl Public {
    fn points(&self, reg: &Registration, path: &AccountPath) -> Result<[pallas::Point; 2]> {
        let mut points = [pallas::Point::default(); 2];
        for (i, p) in self.proofs.iter().enumerate() {
            ensure!(p.role.index() == i, "RedPallas role order");
            let s = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(
                p.response.as_slice().try_into()?,
            ))
            .ok_or_else(|| anyhow::anyhow!("noncanonical response"))?;
            points[i] = point(&p.point)?;
            ensure!(
                generator() * s == point(&p.commitment)? + points[i] * challenge(reg, path, p),
                "RedPallas possession proof"
            );
        }
        ensure!(points[0] != points[1], "constant sharing");
        Ok(points)
    }
    pub fn key(&self, reg: &Registration, path: &AccountPath) -> Result<crate::Key> {
        let pts = self.points(reg, path)?;
        let public = (pts[0] * pallas::Scalar::from(2) - pts[1]).to_bytes();
        validate_key(&public)?;
        // Registration identity depends on stable public shares, not fresh proof nonces.
        let registration = pairkey_types::digest(
            b"pairkey/redpallas/registration/v1",
            &(
                reg.digest(),
                path,
                &self.proofs[0].point,
                &self.proofs[1].point,
            ),
        );
        Ok(crate::Key {
            version: 1,
            suite: crate::Suite::FrostRedPallas,
            namespace: reg.digest(),
            account: path.clone(),
            public_key: public.to_vec(),
            registration,
        })
    }
    fn package(
        &self,
        reg: &Registration,
        path: &AccountPath,
    ) -> Result<frost::keys::PublicKeyPackage> {
        let pts = self.points(reg, path)?;
        let shares = [Role::A, Role::B]
            .into_iter()
            .map(|r| {
                Ok((
                    id(r),
                    frost::keys::VerifyingShare::deserialize(&pts[r.index()].to_bytes())?,
                ))
            })
            .collect::<Result<_>>()?;
        Ok(frost::keys::PublicKeyPackage::new(
            shares,
            frost::VerifyingKey::deserialize(&self.key(reg, path)?.public_key)?,
            Some(2),
        ))
    }
}
/// Non-cloneable nonce owner, consumed before producing the round-two share.
pub struct Pending {
    nonces: Zeroizing<frost::round1::SigningNonces>,
    key: Zeroizing<frost::keys::KeyPackage>,
    commitment: Vec<u8>,
    message: Vec<u8>,
    role: Role,
    #[cfg(feature = "zcash-pczt")]
    orchard_alpha: Option<pallas::Scalar>,
}
impl Pending {
    pub fn begin(
        root: &[u8; 32],
        reg: &Registration,
        path: &AccountPath,
        public: &Public,
        role: Role,
        message: &[u8],
    ) -> Result<(Vec<u8>, Self)> {
        Self::begin_inner(root, reg, path, public, role, message, None)
    }
    #[cfg(feature = "zcash-pczt")]
    pub fn begin_orchard(
        root: &[u8; 32],
        reg: &Registration,
        path: &AccountPath,
        public: &Public,
        role: Role,
        sighash: &[u8; 32],
        alpha_bytes: &[u8; 32],
    ) -> Result<(Vec<u8>, Self)> {
        let alpha = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(*alpha_bytes))
            .ok_or_else(|| anyhow::anyhow!("noncanonical Orchard alpha"))?;
        ensure!(alpha != pallas::Scalar::ZERO, "zero Orchard alpha");
        Self::begin_inner(root, reg, path, public, role, sighash, Some(alpha))
    }
    fn begin_inner(
        root: &[u8; 32],
        reg: &Registration,
        path: &AccountPath,
        public: &Public,
        role: Role,
        message: &[u8],
        orchard_alpha: Option<pallas::Scalar>,
    ) -> Result<(Vec<u8>, Self)> {
        #[cfg(not(feature = "zcash-pczt"))]
        let _ = orchard_alpha;
        let points = public.points(reg, path)?;
        let mut secret = scalar(root, reg, path, role)?;
        ensure!(
            generator() * secret == points[role.index()],
            "own RedPallas share mismatch"
        );
        let mut bytes = secret.to_repr();
        let signing = frost::keys::SigningShare::deserialize(&bytes)?;
        bytes.zeroize();
        secret = pallas::Scalar::ZERO;
        std::hint::black_box(secret);
        let key = frost::keys::KeyPackage::new(
            id(role),
            signing,
            frost::keys::VerifyingShare::deserialize(&points[role.index()].to_bytes())?,
            frost::VerifyingKey::deserialize(&public.key(reg, path)?.public_key)?,
            2,
        );
        #[cfg(feature = "zcash-pczt")]
        let key = if orchard_alpha.is_some() {
            key.into_even_y(None)
        } else {
            key
        };
        let key = Zeroizing::new(key);
        let (nonces, commitment) = frost::round1::commit(key.signing_share(), &mut OsRng);
        let commitment = commitment.serialize()?;
        Ok((
            commitment.clone(),
            Self {
                nonces: Zeroizing::new(nonces),
                key,
                commitment,
                message: message.to_vec(),
                role,
                #[cfg(feature = "zcash-pczt")]
                orchard_alpha,
            },
        ))
    }
    pub fn finish(self, rounds: &[Vec<u8>; 2]) -> Result<Vec<u8>> {
        ensure!(
            rounds[self.role.index()] == self.commitment,
            "own commitment substituted"
        );
        let package = signing_package(&self.message, rounds)?;
        #[cfg(feature = "zcash-pczt")]
        if let Some(alpha) = self.orchard_alpha {
            let randomizer = frost::rerandomized::Randomizer::from_scalar(alpha);
            // The PCZT specifies alpha, so it cannot be derived from fresh FROST
            // commitments as the generic API recommends.
            #[allow(deprecated)]
            return Ok(
                frost_rerandomized::sign(&package, &self.nonces, &self.key, randomizer)?
                    .serialize(),
            );
        }
        Ok(frost::round2::sign(&package, &self.nonces, &self.key)?.serialize())
    }
}
fn signing_package(message: &[u8], rounds: &[Vec<u8>; 2]) -> Result<frost::SigningPackage> {
    let commitments = [Role::A, Role::B]
        .into_iter()
        .map(|r| {
            Ok((
                id(r),
                frost::round1::SigningCommitments::deserialize(&rounds[r.index()])?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(frost::SigningPackage::new(commitments, message))
}
pub fn aggregate(
    reg: &Registration,
    path: &AccountPath,
    public: &Public,
    message: &[u8],
    rounds: &[Vec<u8>; 2],
    shares: &[Vec<u8>; 2],
) -> Result<Vec<u8>> {
    let shares = [Role::A, Role::B]
        .into_iter()
        .map(|r| {
            Ok((
                id(r),
                frost::round2::SignatureShare::deserialize(&shares[r.index()])?,
            ))
        })
        .collect::<Result<_>>()?;
    let sig = frost::aggregate(
        &signing_package(message, rounds)?,
        &shares,
        &public.package(reg, path)?,
    )?
    .serialize()?;
    verify(&public.key(reg, path)?.public_key, message, &sig)?;
    Ok(sig)
}
#[cfg(feature = "zcash-pczt")]
pub fn aggregate_orchard(
    reg: &Registration,
    path: &AccountPath,
    public: &Public,
    sighash: &[u8; 32],
    alpha_bytes: &[u8; 32],
    rounds: &[Vec<u8>; 2],
    shares: &[Vec<u8>; 2],
) -> Result<Vec<u8>> {
    let alpha = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(*alpha_bytes))
        .ok_or_else(|| anyhow::anyhow!("noncanonical Orchard alpha"))?;
    ensure!(alpha != pallas::Scalar::ZERO, "zero Orchard alpha");
    let shares = [Role::A, Role::B]
        .into_iter()
        .map(|r| {
            Ok((
                id(r),
                frost::round2::SignatureShare::deserialize(&shares[r.index()])?,
            ))
        })
        .collect::<Result<_>>()?;
    let package = public.package(reg, path)?.into_even_y(None);
    let randomizer = frost::rerandomized::Randomizer::from_scalar(alpha);
    let params =
        frost::rerandomized::RandomizedParams::from_randomizer(package.verifying_key(), randomizer);
    let sig = frost::rerandomized::aggregate(
        &signing_package(sighash, rounds)?,
        &shares,
        &package,
        &params,
    )?
    .serialize()?;
    let randomized_key = params.randomized_verifying_key().serialize()?;
    verify(&randomized_key, sighash, &sig)?;
    // Independently validate the serialized signature with the v6 Orchard library.
    let vk = orchard::primitives::redpallas::VerificationKey::<
        orchard::primitives::redpallas::SpendAuth,
    >::try_from(<[u8; 32]>::try_from(randomized_key.as_slice())?)?;
    vk.verify(
        sighash,
        &orchard::primitives::redpallas::Signature::from(<[u8; 64]>::try_from(sig.as_slice())?),
    )
    .map_err(|e| anyhow::anyhow!("Orchard signature verification: {e:?}"))?;
    Ok(sig)
}
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    frost::VerifyingKey::deserialize(public)?
        .verify(message, &frost::Signature::deserialize(signature)?)?;
    let vk = reddsa::VerificationKey::<reddsa::orchard::SpendAuth>::try_from(
        <[u8; 32]>::try_from(public)?,
    )?;
    vk.verify(
        message,
        &reddsa::Signature::from(<[u8; 64]>::try_from(signature)?),
    )?;
    Ok(())
}

#[cfg(all(test, feature = "zcash-pczt"))]
mod pczt_tests {
    use super::*;
    use pairkey_frost::{register, Root, Signer};
    use pairkey_types::{Namespace, Scheme};

    #[test]
    fn randomized_threshold_signature_verifies_with_orchard_v6() {
        let ns = Namespace {
            version: 1,
            scheme: Scheme::FrostEd25519,
            network: [1; 32],
            registry: [2; 32],
            derivation_authority: [3; 32],
            namespace_id: [4; 32],
            enclave_set: [5; 32],
        };
        let signer_a = Signer::new(Root::new([11; 32]), Role::A);
        let signer_b = Signer::new(Root::new([22; 32]), Role::B);
        let reg = register(
            ns.clone(),
            &signer_a.proof(&ns, &mut OsRng).unwrap(),
            &signer_b.proof(&ns, &mut OsRng).unwrap(),
        )
        .unwrap();
        let path = AccountPath {
            destination: [8; 32],
            path: vec![1],
        };
        let public = Public {
            proofs: [
                proof(&[11; 32], &reg, &path, Role::A).unwrap(),
                proof(&[22; 32], &reg, &path, Role::B).unwrap(),
            ],
        };
        let sighash = [42u8; 32];
        let alpha = pallas::Scalar::from(7u64).to_repr();
        let (round_a, pending_a) =
            Pending::begin_orchard(&[11; 32], &reg, &path, &public, Role::A, &sighash, &alpha)
                .unwrap();
        let (round_b, pending_b) =
            Pending::begin_orchard(&[22; 32], &reg, &path, &public, Role::B, &sighash, &alpha)
                .unwrap();
        let rounds = [round_a, round_b];
        let shares = [
            pending_a.finish(&rounds).unwrap(),
            pending_b.finish(&rounds).unwrap(),
        ];
        let signature =
            aggregate_orchard(&reg, &path, &public, &sighash, &alpha, &rounds, &shares).unwrap();
        assert_eq!(signature.len(), 64);
    }
}
