//! Pinned signed-R1 observer: journals authenticated peer session IDs before
//! native receives them. It never decrypts native messages or changes arithmetic.
use super::*;
use crate::lifecycle::{Failure, FailureKind, Phase};
use sha2::{Digest, Sha256};
use sl_mpc_mate::message::MESSAGE_HEADER_SIZE;
use std::{path::PathBuf, sync::Mutex};
pub struct R1Guard {
    pub r1: [Hash; 2],
    pub package_sid: Hash,
    role: u8,
    identities: [Hash; 2],
    dir: PathBuf,
    #[cfg(feature = "research-faults")]
    tamper: Mutex<Option<ed25519_dalek::SigningKey>>,
    sessions: Mutex<[Option<Hash>; 2]>,
    failure: Mutex<Option<Failure>>,
}
impl R1Guard {
    pub fn new(
        r1: [Hash; 2],
        package_sid: Hash,
        role: u8,
        identities: [Hash; 2],
        dir: PathBuf,
    ) -> Self {
        Self {
            r1,
            package_sid,
            role,
            identities,
            dir: dir.join(format!("observer-{role}")),
            #[cfg(feature = "research-faults")]
            tamper: Mutex::new(None),
            sessions: Mutex::new([None, None]),
            failure: Mutex::new(None),
        }
    }
    #[cfg(feature = "research-faults")]
    pub fn inject_commitment_fault(&self, key: ed25519_dalek::SigningKey) {
        *self.tamper.lock().unwrap() = Some(key);
    }
    pub fn fault_outbound(&self, bytes: &mut [u8]) {
        #[cfg(not(feature = "research-faults"))]
        let _ = bytes;
        #[cfg(feature = "research-faults")]
        if bytes.get(..32) == Some(self.r1[self.role as usize].as_slice())
            && bytes.len() == MESSAGE_HEADER_SIZE + 97 + 64
        {
            if let Some(key) = self.tamper.lock().unwrap().take() {
                bytes[MESSAGE_HEADER_SIZE + 32] ^= 1;
                let len = bytes.len() - 64;
                let signature = key.sign(&bytes[..len]);
                bytes[len..].copy_from_slice(&signature.to_bytes());
            }
        }
    }
    pub fn observe(&self, bytes: &[u8], outbound: bool) -> Result<()> {
        let role = if outbound { self.role } else { 1 - self.role };
        if bytes.get(..32) != Some(self.r1[role as usize].as_slice()) {
            return Ok(());
        }
        // Native SignMsg1 is 97 bytes, Ed25519 signature 64 bytes, no trailer.
        if bytes.len() != MESSAGE_HEADER_SIZE + 97 + 64 {
            return Ok(());
        }
        let signed = &bytes[..bytes.len() - 64];
        let sig = Signature::from_slice(&bytes[bytes.len() - 64..])?;
        if VerifyingKey::from_bytes(&self.identities[role as usize])?
            .verify_strict(signed, &sig)
            .is_err()
        {
            return Ok(());
        }
        let session: Hash = bytes[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + 32]
            .try_into()
            .unwrap();
        let result = (|| {
            let mut sessions = self.sessions.lock().unwrap();
            ensure!(
                sessions[role as usize].is_none(),
                "repeated authenticated D R1"
            );
            crate::reserve(&self.dir, role, session, self.r1[role as usize])?;
            sessions[role as usize] = Some(session);
            Ok(())
        })();
        if let Err(error) = &result {
            *self.failure.lock().unwrap() = Some(Failure::burn(
                Phase::Signing,
                FailureKind::Context,
                format!("D R1 replay journal: {error:#}"),
            ));
        }
        result
    }
    pub fn failure(&self) -> Option<Failure> {
        self.failure.lock().unwrap().clone()
    }
    pub fn final_session(&self) -> Result<Hash> {
        let s = self.sessions.lock().unwrap();
        Ok(Sha256::new()
            .chain_update(s[0].ok_or_else(|| anyhow::anyhow!("missing D R1 role 0"))?)
            .chain_update(s[1].ok_or_else(|| anyhow::anyhow!("missing D R1 role 1"))?)
            .chain_update(self.package_sid)
            .finalize()
            .into())
    }
}
