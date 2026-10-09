//! Program-source approval ABI. The program-controlled PDA remains the derivation authority.
use crate::{
    approval::{Identity, Request},
    digest, message_hash, AccountPath, Error, Namespace, MAX_MESSAGE,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub const MAX_PROGRAM_ACCOUNTS: usize = 6;
pub const APPROVE_PREFIX: &[u8] = b"pairkey_approve/v1\0";
pub const COMMIT_PREFIX: &[u8] = b"pairkey_approve_commit/v1\0";
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub enum Mode {
    Offchain,
    Onchain,
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub program: [u8; 32],
    /// Must be the PDA derived by `seeds` under `program`; checked by the gateway/workers.
    pub authority: [u8; 32],
    pub seeds: Vec<Vec<u8>>,
    /// Off-chain evaluation pins immutable deployed code (including finalized loader-v3 programs).
    /// On-chain approval uses zero: the committed PDA authorization is authoritative.
    pub code_hash: [u8; 32],
    /// Ordered application accounts. Simulation exposes these as read-only, without signer flags.
    pub accounts: Vec<[u8; 32]>,
    pub mode: Mode,
}
impl Source {
    pub fn validate(&self) -> Result<(), Error> {
        if self.program == [0; 32]
            || self.authority == [0; 32]
            || (self.mode == Mode::Offchain && self.code_hash == [0; 32])
            || (self.mode == Mode::Onchain && self.code_hash != [0; 32])
            || self.seeds.len() > 15
            || self.seeds.iter().any(|s| s.len() > 32)
            || self.accounts.len() > MAX_PROGRAM_ACCOUNTS
            || self
                .accounts
                .iter()
                .enumerate()
                .any(|(i, a)| self.accounts[..i].contains(a))
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountState {
    pub address: [u8; 32],
    pub owner: [u8; 32],
    pub lamports: u64,
    pub executable: bool,
    pub data: Vec<u8>,
}
pub fn state_digest(accounts: &[AccountState]) -> [u8; 32] {
    digest(b"pairkey/program-state/v1", &accounts)
}
/// Independently constructed and attested by a signer after caller authentication.
/// Includes enough data for application rules without duplicating the full namespace metadata.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub version: u16,
    pub namespace_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub authority: [u8; 32],
    pub caller: [u8; 32],
    pub account: AccountPath,
    pub request_id: [u8; 32],
    pub payload: Vec<u8>,
    pub expires_at: i64,
    pub state_digest: [u8; 32],
}
impl Input {
    pub fn validate(&self) -> Result<(), Error> {
        self.account.validate()?;
        if self.version != 1
            || self.caller == [0; 32]
            || self.authority == [0; 32]
            || self.request_id == [0; 32]
            || self.payload.is_empty()
            || self.payload.len() > MAX_MESSAGE
            || self.expires_at <= 0
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/program-input/v1", self)
    }
    pub fn attestation_message(&self) -> Vec<u8> {
        let mut b = b"pairkey/authenticated-program-input/v1".to_vec();
        b.extend_from_slice(&self.digest());
        b
    }
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub input_digest: [u8; 32],
    pub allowed: bool,
}

/// Sent through the developer program, which authenticates its transaction caller,
/// applies state changes, then CPIs to the gateway with `CommitApproval`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitCall {
    pub namespace: Namespace,
    pub request: Request,
    pub payload: Vec<u8>,
}
impl CommitCall {
    pub fn validate(&self, now: i64) -> Result<&Source, Error> {
        self.namespace.validate()?;
        self.request.identity.validate()?;
        let Identity::Program(source) = &self.request.identity else {
            return Err(Error::Metadata);
        };
        let r = &self.request;
        if source.mode != Mode::Onchain
            || source.authority != self.namespace.derivation_authority
            || r.version != 1
            || r.commit.request_id == [0; 32]
            || r.issued_at < 0
            || r.issued_at > now
            || r.expires_at <= now
            || r.expires_at <= r.issued_at
            || r.expires_at.saturating_sub(r.issued_at) > crate::approval::MAX_APPROVAL_LIFETIME
            || self.payload.is_empty()
            || self.payload.len() > MAX_MESSAGE
            || r.commit.message_len as usize != self.payload.len()
            || r.commit.message_hash != message_hash(&self.payload)
        {
            return Err(Error::Metadata);
        }
        r.commit.account.validate()?;
        Ok(source)
    }
    pub fn approval(&self) -> CommitApproval {
        CommitApproval {
            namespace: self.namespace.clone(),
            request_id: self.request.commit.request_id,
            request_digest: self.request.digest(),
            expires_at: self.request.expires_at,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitApproval {
    pub namespace: Namespace,
    pub request_id: [u8; 32],
    pub request_digest: [u8; 32],
    pub expires_at: i64,
}
