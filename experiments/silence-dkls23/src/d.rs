//! Spike D: root-derived wallets, public registration and a RAM-only DKG donor.
//! Custom composition remains experimental. Native parameters/patches unchanged.
mod guard;
mod journal;
mod material;
use crate::{digest, point, pool, public, Root};
use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
pub use guard::R1Guard;
use hkdf::Hkdf;
pub use journal::{Counter, Journal, WriteStep};
use k256::{
    elliptic_curve::{bigint::U512, ops::Reduce},
    Scalar, WideBytes,
};
pub use material::{Donor, Limits};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::Zeroizing;

pub type Hash = [u8; 32];
pub fn pairing(peers: [Hash; 2]) -> Hash {
    pool::hash("pairkey/d/pairing/v2", &[&peers[0], &peers[1]])
}
pub fn configuration() -> Hash {
    pool::hash(
        "pairkey/d/configuration/v2",
        &[
            &pool::configuration(),
            include_bytes!("d.rs"),
            include_bytes!("d/journal.rs"),
            include_bytes!("d/material.rs"),
            include_bytes!("d/guard.rs"),
            include_bytes!("d_worker.rs"),
        ],
    )
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wallet {
    pub version: u16,
    pub identities: [Hash; 2],
    pub namespace: String,
    pub epoch: u64,
    pub key_id: Hash,
}
impl Wallet {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 2
                && self.namespace.len() <= 96
                && !self.namespace.is_empty()
                && self.identities[0] != self.identities[1],
            "invalid D wallet domain"
        );
        for id in self.identities {
            VerifyingKey::from_bytes(&id)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Hash {
        digest(b"pairkey/d/wallet-domain/v2", self)
    }
}
impl Root {
    pub fn derive_v2(&self, role: u8, wallet: &Wallet) -> Result<Zeroizing<Scalar>> {
        wallet.validate()?;
        ensure!(
            role < 2
                && self.identity(role).verifying_key().to_bytes()
                    == wallet.identities[role as usize],
            "D root/role mismatch"
        );
        let info = pool::hash(
            "pairkey/d/contribution/v2",
            &[
                &pairing(wallet.identities),
                wallet.namespace.as_bytes(),
                &wallet.epoch.to_be_bytes(),
                &wallet.version.to_be_bytes(),
                &[role],
                &wallet.key_id,
            ],
        );
        let hk = Hkdf::<Sha512>::new(Some(b"pairkey/d/root/v2"), self.0.as_ref());
        let mut wide = Zeroizing::new([0; 64]);
        hk.expand(&info, wide.as_mut()).expect("fixed KDF size");
        let value = Zeroizing::new(<Scalar as Reduce<U512>>::reduce_bytes(
            WideBytes::from_slice(wide.as_ref()),
        ));
        ensure!(*value != Scalar::ZERO, "zero D contribution");
        Ok(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opening {
    pub point: Vec<u8>,
    pub salt: Hash,
}
impl Opening {
    pub fn commitment(&self, wallet: &Wallet, role: u8) -> Hash {
        digest(b"pairkey/d/registration-commit/v2", &(wallet, role, self))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub wallet: Wallet,
    pub configuration: Hash,
    pub commitments: [Hash; 2],
    pub openings: [Opening; 2],
    pub public_key: Vec<u8>,
    pub chain_code: Hash,
}
impl Record {
    pub fn new(wallet: Wallet, commitments: [Hash; 2], openings: [Opening; 2]) -> Result<Self> {
        let q = (point(&openings[0].point)? + point(&openings[1].point)?)
            .to_bytes()
            .to_vec();
        let chain_code = digest(
            b"pairkey/dkls-research/public-chain-code/v1",
            &(wallet.key_id, q.clone()),
        );
        let r = Self {
            wallet,
            configuration: configuration(),
            commitments,
            openings,
            public_key: q,
            chain_code,
        };
        r.validate()?;
        Ok(r)
    }
    pub fn validate(&self) -> Result<()> {
        self.wallet.validate()?;
        ensure!(
            self.configuration == configuration(),
            "unapproved D configuration"
        );
        for role in 0..2 {
            ensure!(
                self.openings[role].commitment(&self.wallet, role as u8) == self.commitments[role],
                "D commitment opening mismatch"
            );
        }
        ensure!(
            point(&self.openings[0].point)? + point(&self.openings[1].point)?
                == point(&self.public_key)?,
            "D aggregate mismatch"
        );
        ensure!(
            self.chain_code
                == digest(
                    b"pairkey/dkls-research/public-chain-code/v1",
                    &(self.wallet.key_id, self.public_key.clone())
                ),
            "D chain code mismatch"
        );
        Ok(())
    }
    pub fn digest(&self) -> Hash {
        digest(b"pairkey/d/record/v2", self)
    }
    pub fn local(&self, root: &Root, role: u8) -> Result<Zeroizing<Scalar>> {
        self.validate()?;
        let x = root.derive_v2(role, &self.wallet)?;
        ensure!(
            public(&x) == self.openings[role as usize].point,
            "D local contribution mismatch"
        );
        Ok(x)
    }
}
use k256::elliptic_curve::group::GroupEncoding;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endorsement {
    pub role: u8,
    pub record: Hash,
    pub commitment: Vec<u8>,
    pub response: Hash,
    pub signature: Vec<u8>,
}
impl Endorsement {
    fn challenge(&self) -> Scalar {
        <Scalar as Reduce<k256::elliptic_curve::bigint::U256>>::reduce_bytes(
            &pool::hash(
                "pairkey/d/possession-proof/v2",
                &[&self.record, &[self.role], &self.commitment],
            )
            .into(),
        )
    }
    fn message(&self) -> Hash {
        digest(
            b"pairkey/d/endorsement/v2",
            &(self.record, self.role, &self.commitment, self.response),
        )
    }
    pub fn new(record: &Record, root: &Root, role: u8) -> Result<Self> {
        let x = record.local(root, role)?;
        let mut wide = Zeroizing::new([0; 64]);
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(wide.as_mut());
        let k = Zeroizing::new(<Scalar as Reduce<U512>>::reduce_bytes(
            WideBytes::from_slice(wide.as_ref()),
        ));
        ensure!(*k != Scalar::ZERO, "zero D proof nonce");
        let mut e = Self {
            role,
            record: record.digest(),
            commitment: public(&k),
            response: [0; 32],
            signature: vec![],
        };
        e.response = (*k + e.challenge() * *x).to_bytes().into();
        e.signature = root.identity(role).sign(&e.message()).to_bytes().to_vec();
        Ok(e)
    }
    pub fn validate(&self, record: &Record) -> Result<()> {
        record.validate()?;
        ensure!(
            self.role < 2 && self.record == record.digest(),
            "D endorsement context"
        );
        VerifyingKey::from_bytes(&record.wallet.identities[self.role as usize])?
            .verify_strict(&self.message(), &Signature::from_slice(&self.signature)?)?;
        let violation = || {
            crate::lifecycle::Failure::violation(
                crate::lifecycle::Phase::Admission,
                record.wallet.identities[self.role as usize],
                "D authenticated possession proof failed",
            )
        };
        use k256::elliptic_curve::PrimeField;
        let z = Option::<Scalar>::from(Scalar::from_repr(self.response.into()))
            .ok_or_else(violation)?;
        let k = point(&self.commitment).map_err(|_| violation())?;
        ensure!(
            k256::ProjectivePoint::GENERATOR * z
                == k + point(&record.openings[self.role as usize].point)? * self.challenge(),
            violation()
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    pub record: Record,
    pub endorsements: [Endorsement; 2],
}
impl Certificate {
    pub fn validate(&self) -> Result<()> {
        self.record.validate()?;
        for (role, e) in self.endorsements.iter().enumerate() {
            ensure!(e.role as usize == role, "D endorsement order");
            e.validate(&self.record)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub wallet: Wallet,
    pub record: Hash,
    pub generation: Hash,
    pub path: String,
    pub prehash: Hash,
    pub attempt: Hash,
    pub fault: Option<String>,
}
impl Request {
    pub fn instance(&self) -> Hash {
        digest(
            b"pairkey/d/sign-instance/v2",
            &(
                self.wallet.digest(),
                self.record,
                self.generation,
                &self.path,
                self.prehash,
                self.attempt,
            ),
        )
    }
}
pub fn hedged_seed(
    entropy: &Hash,
    context: Hash,
    counter: u64,
    role: u8,
    operation: &str,
) -> Zeroizing<Hash> {
    Zeroizing::new(pool::hash(
        "pairkey/d/protocol-seed/v2",
        &[
            entropy,
            &context,
            &counter.to_be_bytes(),
            &[role],
            operation.as_bytes(),
        ],
    ))
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Command {
    Enroll([pool::Boot; 2]),
    Register {
        wallet: Wallet,
        attempt: Hash,
        fault: Option<String>,
    },
    Prepare {
        attempt: Hash,
        fault: Option<String>,
    },
    Sign(Request),
    Discard,
    Incident(Hash),
    Stop,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Reply {
    Registered(Box<Certificate>),
    Donor {
        role: u8,
        generation: Hash,
        unused_public_key: Vec<u8>,
        elapsed_ms: f64,
    },
    Signed {
        role: u8,
        instance: Hash,
        generation: Hash,
        final_session: Hash,
        signature: Vec<u8>,
        public_key: Vec<u8>,
        recovery_id: u8,
        uses: u64,
        elapsed_ms: f64,
    },
    Discarded,
}
#[cfg(test)]
mod tests;
