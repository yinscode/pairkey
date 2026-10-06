//! EIP-191 personal_sign: workers compute the digest from bounded message bytes.
use anyhow::{ensure, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub chain_id: u64,
    pub message: Vec<u8>,
}
impl Message {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.chain_id > 0 && !self.message.is_empty() && self.message.len() <= 512,
            "EVM message bounds"
        );
        Ok(())
    }
    pub fn prehash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut bytes =
            format!("\x19Ethereum Signed Message:\n{}", self.message.len()).into_bytes();
        bytes.extend_from_slice(&self.message);
        Ok(Keccak256::digest(bytes).into())
    }
    pub fn verify(&self, public: &[u8], signature: &[u8]) -> Result<()> {
        crate::evm::verify_prehash(public, self.prehash()?, signature)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    #[test]
    fn personal_sign_binds_utf8_bytes_and_rejects_tampering() {
        let message = Message {
            chain_id: 84532,
            message: "hello 🌍".as_bytes().to_vec(),
        };
        let mut reference = b"\x19Ethereum Signed Message:\n10".to_vec();
        reference.extend_from_slice("hello 🌍".as_bytes());
        assert_eq!(
            message.prehash().unwrap(),
            <[u8; 32]>::from(Keccak256::digest(reference))
        );
        let key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let (sig, recovery) = key
            .sign_prehash_recoverable(&message.prehash().unwrap())
            .unwrap();
        let mut bytes = sig.to_bytes().to_vec();
        bytes.push(recovery.to_byte());
        let public = key.verifying_key().to_encoded_point(true);
        message.verify(public.as_bytes(), &bytes).unwrap();
        let mut changed = message.clone();
        changed.message.push(0);
        assert!(changed.verify(public.as_bytes(), &bytes).is_err());
        bytes[0] ^= 1;
        assert!(message.verify(public.as_bytes(), &bytes).is_err());
        assert!(Message {
            chain_id: 1,
            message: vec![0; 513]
        }
        .validate()
        .is_err());
    }
}
