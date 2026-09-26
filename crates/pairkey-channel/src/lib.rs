//! Attestation-bound peer envelopes. Development issuer is explicitly gated.
#[cfg(all(feature = "dev-simulation", not(debug_assertions)))]
compile_error!("development attestation must not enter release artifacts");

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use pairkey_types::Role;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub use pairkey_types::attestation::{Attestation, Evidence, DEV_MEASUREMENT};
pub const MAX_ENVELOPE: usize = 8192;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid identity, attestation, boot binding, or context")]
    Identity,
    #[error("invalid or oversized authenticated envelope")]
    Envelope,
}
pub fn verify_attestation(
    cert: &Attestation,
    identity: [u8; 32],
    role: Role,
    challenge: [u8; 32],
    allow_development: bool,
) -> Result<(), Error> {
    let e = &cert.evidence;
    if !allow_development
        || !e.development
        || e.measurement != DEV_MEASUREMENT
        || e.role != role
        || e.identity != identity
        || e.challenge != challenge
    {
        return Err(Error::Identity);
    }
    let key = VerifyingKey::from_bytes(&identity).map_err(|_| Error::Identity)?;
    let sig = Signature::from_slice(&cert.signature).map_err(|_| Error::Identity)?;
    key.verify_strict(&attestation_message(e), &sig)
        .map_err(|_| Error::Identity)
}
fn attestation_message(e: &Evidence) -> Vec<u8> {
    let mut m = b"pairkey/dev-attestation/v1".to_vec();
    m.extend(borsh::to_vec(e).unwrap());
    m
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub sender: Role,
    pub sender_boot: [u8; 32],
    pub receiver_boot: [u8; 32],
    pub context: [u8; 32],
    pub kind: u8,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}
fn aad(e: &Envelope) -> Vec<u8> {
    let mut data = Vec::from(b"pairkey/confidential-mpc/v1".as_slice());
    data.extend(
        borsh::to_vec(&(e.sender, e.sender_boot, e.receiver_boot, e.context, e.kind)).unwrap(),
    );
    data
}

/// Created only through an explicitly nonproduction development provisioner.
pub struct Channel {
    role: Role,
    identity: SigningKey,
    secret: StaticSecret,
    boot_id: [u8; 32],
    peer_identity: [u8; 32],
}
impl Channel {
    #[cfg(feature = "dev-simulation")]
    pub fn development(role: Role, identity_seed: [u8; 32], peer_identity: [u8; 32]) -> Self {
        let mut random = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(random.as_mut());
        let secret = StaticSecret::from(*random);
        let mut boot_id = [0; 32];
        OsRng.fill_bytes(&mut boot_id);
        Self {
            role,
            identity: SigningKey::from_bytes(&identity_seed),
            secret,
            boot_id,
            peer_identity,
        }
    }
    pub fn boot_id(&self) -> [u8; 32] {
        self.boot_id
    }
    pub fn identity(&self) -> [u8; 32] {
        self.identity.verifying_key().to_bytes()
    }
    #[cfg(feature = "dev-simulation")]
    pub fn attest(&self, challenge: [u8; 32]) -> Attestation {
        let evidence = Evidence {
            role: self.role,
            identity: self.identity(),
            ephemeral: PublicKey::from(&self.secret).to_bytes(),
            boot_id: self.boot_id,
            challenge,
            measurement: DEV_MEASUREMENT,
            development: true,
        };
        let signature = self
            .identity
            .sign(&attestation_message(&evidence))
            .to_bytes()
            .to_vec();
        Attestation {
            evidence,
            signature,
        }
    }
    pub fn authenticate_peer(&self, peer: &Attestation) -> Result<(), Error> {
        verify_attestation(
            peer,
            self.peer_identity,
            self.role.peer(),
            self.boot_id,
            true,
        )
    }
    pub fn sign_public(&self, message: &[u8]) -> Vec<u8> {
        self.identity.sign(message).to_bytes().to_vec()
    }
    fn cipher(&self, peer: &Attestation) -> Result<ChaCha20Poly1305, Error> {
        self.authenticate_peer(peer)?;
        let shared = self
            .secret
            .diffie_hellman(&PublicKey::from(peer.evidence.ephemeral));
        if !shared.was_contributory() {
            return Err(Error::Identity);
        }
        let (a, b) = if self.role == Role::A {
            (self.boot_id, peer.evidence.boot_id)
        } else {
            (peer.evidence.boot_id, self.boot_id)
        };
        let mut info = b"pairkey/peer-channel-key/v1".to_vec();
        info.extend(a);
        info.extend(b);
        let hk = Hkdf::<Sha256>::new(Some(b"pairkey/channel/v1"), shared.as_bytes());
        let mut key = Zeroizing::new([0; 32]);
        hk.expand(&info, key.as_mut())
            .map_err(|_| Error::Envelope)?;
        Ok(ChaCha20Poly1305::new(key.as_ref().into()))
    }
    pub fn seal<T: Serialize>(
        &self,
        peer: &Attestation,
        context: [u8; 32],
        kind: u8,
        data: &T,
    ) -> Result<Envelope, Error> {
        let cipher = self.cipher(peer)?;
        let plaintext = serde_json::to_vec(data).map_err(|_| Error::Envelope)?;
        if plaintext.len() > MAX_ENVELOPE {
            return Err(Error::Envelope);
        }
        let mut e = Envelope {
            sender: self.role,
            sender_boot: self.boot_id,
            receiver_boot: peer.evidence.boot_id,
            context,
            kind,
            nonce: [0; 12],
            ciphertext: vec![],
        };
        OsRng.fill_bytes(&mut e.nonce);
        e.ciphertext = cipher
            .encrypt(
                (&e.nonce).into(),
                Payload {
                    msg: &plaintext,
                    aad: &aad(&e),
                },
            )
            .map_err(|_| Error::Envelope)?;
        Ok(e)
    }
    /// Opens peer envelopes or this process's own previously emitted envelope.
    pub fn open<T: for<'de> Deserialize<'de>>(
        &self,
        peer: &Attestation,
        context: [u8; 32],
        kind: u8,
        e: &Envelope,
    ) -> Result<T, Error> {
        let cipher = self.cipher(peer)?;
        let (sender_boot, receiver_boot) = if e.sender == self.role {
            (self.boot_id, peer.evidence.boot_id)
        } else {
            (peer.evidence.boot_id, self.boot_id)
        };
        if e.sender_boot != sender_boot
            || e.receiver_boot != receiver_boot
            || e.context != context
            || e.kind != kind
            || e.ciphertext.len() > MAX_ENVELOPE + 16
        {
            return Err(Error::Envelope);
        }
        let plaintext = cipher
            .decrypt(
                (&e.nonce).into(),
                Payload {
                    msg: &e.ciphertext,
                    aad: &aad(e),
                },
            )
            .map_err(|_| Error::Envelope)?;
        serde_json::from_slice(&plaintext).map_err(|_| Error::Envelope)
    }
}

#[cfg(all(test, feature = "dev-simulation"))]
mod tests {
    use super::*;
    #[test]
    fn bound_peer_channels_reject_tampering_context_and_restarts() {
        let akey = SigningKey::from_bytes(&[11; 32]);
        let bkey = SigningKey::from_bytes(&[22; 32]);
        let a = Channel::development(Role::A, [11; 32], bkey.verifying_key().to_bytes());
        let b = Channel::development(Role::B, [22; 32], akey.verifying_key().to_bytes());
        let ac = a.attest(b.boot_id());
        let bc = b.attest(a.boot_id());
        let mut e = a.seal(&bc, [3; 32], 1, &vec![1u8, 2, 3]).unwrap();
        let got: Vec<u8> = b.open(&ac, [3; 32], 1, &e).unwrap();
        assert_eq!(got, vec![1, 2, 3]);
        assert!(b.open::<Vec<u8>>(&ac, [4; 32], 1, &e).is_err());
        assert!(b.open::<Vec<u8>>(&ac, [3; 32], 2, &e).is_err());
        assert!(verify_attestation(&ac, a.identity(), Role::A, b.boot_id(), false).is_err());
        e.ciphertext[0] ^= 1;
        assert!(b.open::<Vec<u8>>(&ac, [3; 32], 1, &e).is_err());
        let replacement = Channel::development(Role::B, [22; 32], akey.verifying_key().to_bytes());
        assert!(replacement.authenticate_peer(&ac).is_err());
        let mut fake = ac.clone();
        fake.evidence.ephemeral[0] ^= 1;
        assert!(b.authenticate_peer(&fake).is_err());
    }
}
