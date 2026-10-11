//! Independent root-derived 2-of-2 shares, using the BIP-340 FROST suite.
//! Custom setup remains experimental. Apply the BIP-341 no-script TapTweak to both packages.
use anyhow::{ensure, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use frost::{
    keys::{EvenY, Tweak},
    Group,
};
use frost_secp256k1_tr as frost;
use hkdf::Hkdf;
use k256::{
    elliptic_curve::{
        bigint::U256,
        ff::{Field, PrimeField},
        ops::Reduce,
        sec1::ToEncodedPoint,
    },
    ProjectivePoint as Point, Scalar,
};
use pairkey_types::{AccountPath, Registration, Role};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};
fn encode(point: Point) -> Vec<u8> {
    point.to_affine().to_encoded_point(true).as_bytes().to_vec()
}
fn generator() -> Point {
    frost::Secp256K1Group::generator()
}
fn point(bytes: &[u8]) -> Result<Point> {
    Ok(frost::Secp256K1Group::deserialize(&bytes.try_into()?)?)
}
pub fn validate_key(bytes: &[u8]) -> Result<()> {
    k256::schnorr::VerifyingKey::from_bytes(bytes)?;
    Ok(())
}
fn id(role: Role) -> frost::Identifier {
    frost::Identifier::try_from(role.id()).unwrap()
}
fn scalar(root: &[u8; 32], reg: &Registration, path: &AccountPath, role: Role) -> Result<Scalar> {
    reg.validate()?;
    path.validate()?;
    let context = pairkey_types::digest(
        b"pairkey/bitcoin-bip340/contribution/v1",
        &(reg.digest(), path, role),
    );
    let mut wide = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha512>::new(Some(b"pairkey/bitcoin-bip340/provider-root/v1"), root)
        .expand(&context, wide.as_mut())
        .unwrap();
    let s = <Scalar as Reduce<U256>>::reduce_bytes(&Sha256::digest(&wide[..]));
    ensure!(s != Scalar::ZERO, "zero contribution");
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
fn challenge(reg: &Registration, path: &AccountPath, p: &Proof) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"pairkey/bitcoin-bip340/possession/v1");
    h.update(borsh::to_vec(&(reg.digest(), path, p.role, &p.point, &p.commitment)).unwrap());
    <Scalar as Reduce<U256>>::reduce_bytes(&Sha256::digest(h.finalize()))
}
pub fn proof(root: &[u8; 32], reg: &Registration, path: &AccountPath, role: Role) -> Result<Proof> {
    let mut s = scalar(root, reg, path, role)?;
    let mut r = Scalar::random(&mut OsRng);
    let mut p = Proof {
        role,
        point: encode(generator() * s),
        commitment: encode(generator() * r),
        response: vec![],
    };
    p.response = (r + challenge(reg, path, &p) * s).to_repr().to_vec();
    s = Scalar::ZERO;
    r = Scalar::ZERO;
    std::hint::black_box((s, r));
    Ok(p)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Public {
    pub proofs: [Proof; 2],
}
impl Public {
    fn points(&self, reg: &Registration, path: &AccountPath) -> Result<[Point; 2]> {
        let mut points = [Point::default(); 2];
        for (i, p) in self.proofs.iter().enumerate() {
            ensure!(p.role.index() == i, "Bitcoin role order");
            ensure!(p.response.len() == 32, "response length");
            let s = Option::<Scalar>::from(Scalar::from_repr(k256::FieldBytes::clone_from_slice(
                &p.response,
            )))
            .ok_or_else(|| anyhow::anyhow!("noncanonical response"))?;
            points[i] = point(&p.point)?;
            ensure!(
                generator() * s == point(&p.commitment)? + points[i] * challenge(reg, path, p),
                "Bitcoin possession proof"
            );
        }
        ensure!(points[0] != points[1], "constant sharing");
        Ok(points)
    }
    pub fn key(&self, reg: &Registration, path: &AccountPath) -> Result<crate::Key> {
        let pts = self.points(reg, path)?;
        let public = self.package_from_points(pts)?.verifying_key().serialize()?[1..].to_vec();
        validate_key(&public)?;
        // Registration identity depends on stable public shares, not fresh proof nonces.
        let registration = pairkey_types::digest(
            b"pairkey/bitcoin-bip340/registration/v1",
            &(
                reg.digest(),
                path,
                &self.proofs[0].point,
                &self.proofs[1].point,
            ),
        );
        Ok(crate::Key {
            version: 1,
            suite: crate::Suite::FrostSecp256k1Tr,
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
        self.package_from_points(pts)
    }
    fn package_from_points(&self, pts: [Point; 2]) -> Result<frost::keys::PublicKeyPackage> {
        let shares = [Role::A, Role::B]
            .into_iter()
            .map(|r| {
                Ok((
                    id(r),
                    frost::keys::VerifyingShare::deserialize(&encode(pts[r.index()]))?,
                ))
            })
            .collect::<Result<_>>()?;
        Ok(frost::keys::PublicKeyPackage::new(
            shares,
            frost::VerifyingKey::deserialize(&encode(pts[0] * Scalar::from(2u64) - pts[1]))?,
        )
        .tweak(None::<&[u8]>)
        .into_even_y(None))
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
        ensure!(message.len() == 32, "Bitcoin digest length");
        let points = public.points(reg, path)?;
        let mut secret = scalar(root, reg, path, role)?;
        ensure!(
            generator() * secret == points[role.index()],
            "own Bitcoin share mismatch"
        );
        let mut bytes = secret.to_repr();
        let signing = frost::keys::SigningShare::deserialize(&bytes)?;
        bytes.zeroize();
        secret = Scalar::ZERO;
        std::hint::black_box(secret);
        let key = Zeroizing::new(
            frost::keys::KeyPackage::new(
                id(role),
                signing,
                frost::keys::VerifyingShare::deserialize(&encode(points[role.index()]))?,
                frost::VerifyingKey::deserialize(&encode(
                    points[0] * Scalar::from(2u64) - points[1],
                ))?,
                2,
            )
            .tweak(None::<&[u8]>)
            .into_even_y(None),
        );
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
/// Independent BIP-340 verifier. `message` is the already-computed 32-byte digest.
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    ensure!(message.len() == 32, "Bitcoin digest length");
    ensure!(public.len() == 32, "Bitcoin public key length");
    ensure!(signature.len() == 64, "Bitcoin signature length");
    k256::schnorr::VerifyingKey::from_bytes(public)?
        .verify_raw(message, &k256::schnorr::Signature::try_from(signature)?)?;
    Ok(())
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Mainnet,
    Testnet,
}
pub fn destination(network: Network) -> [u8; 32] {
    pairkey_types::digest(b"pairkey/bitcoin-bip340-destination/v1", &network)
}
/// PairKey's typed message digest, not BIP-322 or a Bitcoin transaction sighash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub network: Network,
    pub message: Vec<u8>,
}
impl Message {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.message.is_empty() && self.message.len() <= 512,
            "Bitcoin message bounds"
        );
        Ok(())
    }
    pub fn prehash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let tag = Sha256::digest(b"PairKey/BitcoinMessage/v1");
        let mut h = Sha256::new();
        h.update(tag);
        h.update(tag);
        h.update(borsh::to_vec(&(self.network, &self.message))?);
        Ok(h.finalize().into())
    }
    pub fn verify(&self, public: &[u8], signature: &[u8]) -> Result<()> {
        verify(public, &self.prehash()?, signature)
    }
}

#[cfg(test)]
mod malformed_tests {
    use super::*;
    #[test]
    fn invalid_signature_lengths_are_errors_not_panics() {
        for len in [0, 1, 31, 32, 63, 65, 128] {
            assert!(verify(&[1; 32], &[2; 32], &vec![3; len]).is_err());
        }
        assert!(verify(&[], &[2; 32], &[3; 64]).is_err());
    }
}
