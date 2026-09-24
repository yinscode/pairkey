use crate::Role;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub const DEV_MEASUREMENT: [u8; 32] = *b"PAIRKEY-DEV-NO-HARDWARE-TRUST-01";

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub role: Role,
    pub identity: [u8; 32],
    pub ephemeral: [u8; 32],
    pub boot_id: [u8; 32],
    pub challenge: [u8; 32],
    pub measurement: [u8; 32],
    pub development: bool,
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub evidence: Evidence,
    pub signature: Vec<u8>,
}
