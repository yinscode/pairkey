//! Registered authorization rules and proofs. All limits are per operation.
use crate::{digest, AccountPath, Commit, Error};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Credential {
    Service {
        public_key: [u8; 32],
    },
    /// Controller-enrolled ES256 credential; registration/attestation ceremony is external.
    Passkey {
        public_key: Vec<u8>,
        rp_id: String,
        origin: String,
    },
}
impl Credential {
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Service { public_key } if *public_key != [0; 32] => Ok(()),
            Self::Passkey {
                public_key,
                rp_id,
                origin,
            } if public_key.len() == 65
                && public_key[0] == 4
                && !rp_id.is_empty()
                && rp_id.len() <= 128
                && origin.len() <= 256
                && origin.starts_with("https://") =>
            {
                Ok(())
            }
            _ => Err(Error::Bounds),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AccessProof {
    Service {
        signature: Vec<u8>,
    },
    Passkey {
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
        signature_der: Vec<u8>,
    },
    /// Public commitment only. The actual proof travels privately to each signer.
    /// Appended to preserve existing authorization/attempt encodings and digests.
    Offchain {
        request: Box<crate::approval::Request>,
        proof_digest: [u8; 32],
    },
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationConfig {
    pub program: [u8; 32],
    /// Hash of immutable executable bytes, or verified immutable ProgramData bytes for loader-v3.
    pub code_hash: [u8; 32],
    pub max_lamports: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u64,
    pub allow_session: bool,
    pub require_commit: bool,
    pub require_session: bool,
    pub access: Option<Credential>,
    pub simulation: Option<SimulationConfig>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            version: 0,
            allow_session: false,
            require_commit: true,
            require_session: false,
            access: None,
            simulation: None,
        }
    }
}
impl Policy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version == 0
            || (!self.require_commit && !self.allow_session)
            || (self.require_session && !self.allow_session)
        {
            return Err(Error::Bounds);
        }
        if let Some(c) = &self.access {
            c.validate()?;
        }
        if let Some(s) = &self.simulation {
            if s.program == [0; 32] || s.code_hash == [0; 32] || s.max_lamports == 0 {
                return Err(Error::Bounds);
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/policy/v1", self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrant {
    pub session_id: [u8; 32],
    pub policy_version: u64,
    pub account: AccountPath,
    pub credential: Credential,
    pub not_before: i64,
    pub expires_at: i64,
    pub recipient: [u8; 32],
    pub max_lamports_per_operation: u64,
    /// Explicit absence of cumulative-budget guarantees.
    pub cumulative_budget: Option<u64>,
}
impl SessionGrant {
    pub fn validate(&self) -> Result<(), Error> {
        self.account.validate()?;
        self.credential.validate()?;
        if self.policy_version == 0
            || self.expires_at <= self.not_before
            || self.expires_at.saturating_sub(self.not_before) > 86400
            || self.recipient == [0; 32]
            || self.max_lamports_per_operation == 0
            || self.cumulative_budget.is_some()
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/session/v1", self)
    }
}
#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub policy_version: u64,
    /// Present for SESSION and COMMIT+SESSION. COMMIT requirement comes from registry policy.
    pub session_id: Option<[u8; 32]>,
    pub session_proof: Option<AccessProof>,
    pub access_proof: Option<AccessProof>,
}
impl Authorization {
    pub fn offchain(approval: &crate::approval::Approval) -> Self {
        Self {
            policy_version: approval.request.policy_revision,
            access_proof: Some(AccessProof::Offchain {
                request: Box::new(approval.request.clone()),
                proof_digest: digest(b"pairkey/approval-proof/v1", &approval.proof),
            }),
            ..Self::default()
        }
    }
    pub fn offchain_request(&self) -> Option<&crate::approval::Request> {
        match &self.access_proof {
            Some(AccessProof::Offchain { request, .. }) => Some(request),
            _ => None,
        }
    }
    pub fn with_offchain_proof(
        &self,
        proof: &crate::approval::Proof,
    ) -> Result<crate::approval::Approval, Error> {
        let Some(AccessProof::Offchain {
            request,
            proof_digest,
        }) = &self.access_proof
        else {
            return Err(Error::Metadata);
        };
        if self.session_id.is_some()
            || self.session_proof.is_some()
            || self.policy_version != request.policy_revision
            || *proof_digest != digest(b"pairkey/approval-proof/v1", proof)
        {
            return Err(Error::Metadata);
        }
        Ok(crate::approval::Approval {
            request: (**request).clone(),
            proof: proof.clone(),
        })
    }
    /// Operation identity is stable over transport retries; destination replay rules still apply.
    pub fn challenge(
        &self,
        commit: &Commit,
        session: Option<&SessionGrant>,
        label: &[u8],
    ) -> [u8; 32] {
        digest(
            label,
            &(
                commit,
                self.policy_version,
                self.session_id,
                session.map(SessionGrant::digest),
            ),
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SimulationInput {
    pub commit_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub authorization_digest: [u8; 32],
    pub state_digest: [u8; 32],
    pub recipient: [u8; 32],
    pub lamports: u64,
}
impl SimulationInput {
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/simulation-input/v1", self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SimulationOutput {
    pub input_digest: [u8; 32],
    pub allowed: bool,
}
pub fn simulation_message(input: &SimulationInput) -> Vec<u8> {
    let mut bytes = b"pairkey/authenticated-simulation/v1".to_vec();
    bytes.extend_from_slice(&input.digest());
    bytes
}
pub fn simulation_state(set: &[u8], namespace: &[u8], policy: &[u8]) -> [u8; 32] {
    digest(b"pairkey/simulation-state/v1", &(set, namespace, policy))
}

pub fn solana_destination(network: [u8; 32]) -> [u8; 32] {
    digest(b"pairkey/solana-destination/v1", &network)
}

/// Separate EVM schema; all monetary bounds are wei and apply per operation.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmSessionGrant {
    pub session_id: [u8; 32],
    pub policy_version: u64,
    pub account: AccountPath,
    /// Pins the complete versioned backend Key, including suite and registration.
    pub key_digest: [u8; 32],
    pub credential: Credential,
    pub not_before: i64,
    pub expires_at: i64,
    pub chain_id: u64,
    pub recipient: [u8; 20],
    pub max_value_wei: u64,
    pub max_gas_price_wei: u64,
    pub max_fee_wei: u64,
    /// Durable cumulative accounting is not implemented.
    pub cumulative_budget: Option<u64>,
}
impl EvmSessionGrant {
    pub fn validate(&self) -> Result<(), Error> {
        self.account.validate()?;
        self.credential.validate()?;
        if self.policy_version == 0
            || self.key_digest == [0; 32]
            || self.chain_id == 0
            || self.chain_id > (u64::MAX - 36) / 2
            || self.account.destination != evm_destination(self.chain_id)
            || self.expires_at <= self.not_before
            || self.expires_at.saturating_sub(self.not_before) > 86400
            || self.recipient == [0; 20]
            || self.max_value_wei == 0
            || self.max_gas_price_wei == 0
            || self.max_fee_wei == 0
            || self.cumulative_budget.is_some()
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/evm-session/v1", self)
    }
}
pub fn evm_destination(chain_id: u64) -> [u8; 32] {
    digest(b"pairkey/evm-destination/v1", &chain_id)
}
pub fn evm_session_challenge(
    auth: &Authorization,
    commit: &Commit,
    grant: &EvmSessionGrant,
) -> [u8; 32] {
    digest(
        b"pairkey/evm-session-request/v1",
        &(commit, auth.policy_version, auth.session_id, grant.digest()),
    )
}
