use crate::Role;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: u16,
    pub development: bool,
    pub role: Role,
    pub boot_id: [u8; 32],
    pub peer_boot: [u8; 32],
    pub attempt_digest: [u8; 32],
    pub public_key: [u8; 32],
    pub message_hash: [u8; 32],
    pub signature: Vec<u8>,
    pub finalized_slot: u64,
    pub provider_domain: String,
}
#[derive(Clone, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultResponse {
    pub attestation: crate::attestation::Attestation,
    pub receipt: Receipt,
    pub identity_signature: Vec<u8>,
}
pub fn receipt_message(receipt: &Receipt) -> Vec<u8> {
    let mut bytes = b"pairkey/signing-receipt/v1".to_vec();
    bytes.extend(borsh::to_vec(receipt).unwrap());
    bytes
}
