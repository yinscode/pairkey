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
        let key = Zeroizing::new(frost::keys::KeyPackage::new(
            id(role),
            signing,
            frost::keys::VerifyingShare::deserialize(&points[role.index()].to_bytes())?,
            frost::VerifyingKey::deserialize(&public.key(reg, path)?.public_key)?,
            2,
        ));
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
            },
        ))
    }
    pub fn finish(self, rounds: &[Vec<u8>; 2]) -> Result<Vec<u8>> {
        ensure!(
            rounds[self.role.index()] == self.commitment,
            "own commitment substituted"
        );
        let package = signing_package(&self.message, rounds)?;
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
