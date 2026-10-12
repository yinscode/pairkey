//! Sui Ed25519 address and signature helpers.
use anyhow::{ensure, Result};

pub const ED25519_FLAG: u8 = 0;
pub const TRANSACTION_INTENT: [u8; 3] = [0, 0, 0];

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    let digest = blake2b_simd::Params::new().hash_length(32).hash(bytes);
    digest
        .as_bytes()
        .try_into()
        .expect("fixed Blake2b-256 length")
}

pub fn address(public_key: &[u8]) -> Result<[u8; 32]> {
    ensure!(public_key.len() == 32, "Sui Ed25519 public key length");
    let mut value = Vec::with_capacity(33);
    value.push(ED25519_FLAG);
    value.extend_from_slice(public_key);
    Ok(hash(&value))
}

pub fn transaction_digest(transaction: &[u8]) -> [u8; 32] {
    let mut intent = Vec::with_capacity(TRANSACTION_INTENT.len() + transaction.len());
    intent.extend_from_slice(&TRANSACTION_INTENT);
    intent.extend_from_slice(transaction);
    hash(&intent)
}

pub fn serialized_signature(public_key: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    ensure!(public_key.len() == 32, "Sui Ed25519 public key length");
    ensure!(signature.len() == 64, "Sui Ed25519 signature length");
    let mut value = Vec::with_capacity(97);
    value.push(ED25519_FLAG);
    value.extend_from_slice(signature);
    value.extend_from_slice(public_key);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_and_serialized_signature_have_sui_layout() {
        let public_key = [7; 32];
        let signature = [9; 64];
        let serialized = serialized_signature(&public_key, &signature).unwrap();
        assert_eq!(serialized.len(), 97);
        assert_eq!(serialized[0], ED25519_FLAG);
        assert_eq!(&serialized[1..65], &signature);
        assert_eq!(&serialized[65..], &public_key);
        assert_eq!(
            address(&public_key).unwrap(),
            hash(&[&[0][..], &public_key].concat())
        );
    }
}
