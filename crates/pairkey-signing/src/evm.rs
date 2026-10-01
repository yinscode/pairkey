//! Canonical legacy EIP-155 native-value transfers. No arbitrary digest API.
use anyhow::{ensure, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u64,
}
pub fn destination(chain_id: u64) -> [u8; 32] {
    pairkey_types::digest(b"pairkey/evm-destination/v1", &chain_id)
}
impl Transfer {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.chain_id > 0 && self.chain_id <= (u64::MAX - 36) / 2,
            "chain id bounds"
        );
        ensure!(
            self.gas_limit == 21_000 && self.gas_price > 0 && self.to != [0; 20],
            "native transfer bounds"
        );
        Ok(())
    }
    fn fields(&self, s: &mut rlp::RlpStream) {
        s.append(&self.nonce)
            .append(&self.gas_price)
            .append(&self.gas_limit)
            .append(&self.to.as_slice())
            .append(&self.value)
            .append(&Vec::<u8>::new());
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut s = rlp::RlpStream::new_list(9);
        self.fields(&mut s);
        s.append(&self.chain_id).append(&0u8).append(&0u8);
        Ok(s.out().to_vec())
    }
    pub fn prehash(&self) -> Result<[u8; 32]> {
        Ok(Keccak256::digest(self.signing_bytes()?).into())
    }
    pub fn signed_bytes(&self, public: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        verify(public, self, signature)?;
        let mut s = rlp::RlpStream::new_list(9);
        self.fields(&mut s);
        s.append(&(self.chain_id * 2 + 35 + signature[64] as u64));
        for part in [&signature[..32], &signature[32..64]] {
            let first = part.iter().position(|x| *x != 0).unwrap_or(part.len());
            s.append(&&part[first..]);
        }
        Ok(s.out().to_vec())
    }
}
pub fn address(public: &[u8]) -> Result<[u8; 20]> {
    let vk = VerifyingKey::from_sec1_bytes(public)?;
    let p = vk.to_encoded_point(false);
    let hash = Keccak256::digest(&p.as_bytes()[1..]);
    Ok(hash[12..].try_into()?)
}
pub fn verify(public: &[u8], tx: &Transfer, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() == 65 && bytes[64] <= 1,
        "EVM signature encoding"
    );
    let sig = Signature::from_slice(&bytes[..64])?;
    ensure!(sig.normalize_s().is_none(), "high-S signature");
    let vk = VerifyingKey::from_sec1_bytes(public)?;
    let h = tx.prehash()?;
    vk.verify_prehash(&h, &sig)?;
    ensure!(
        VerifyingKey::recover_from_prehash(&h, &sig, RecoveryId::try_from(bytes[64])?)? == vk,
        "recovery mismatch"
    );
    Ok(())
}
