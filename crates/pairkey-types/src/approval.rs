//! Registration-free identity approvals. Legacy authorization encodings are unchanged.
//! These types describe per-request authentication, not delegated sessions.
use crate::{digest, message_hash, Commit, Error, Namespace, Registration, MAX_MESSAGE, MAX_PATH};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub const APPROVAL_VERSION: u16 = 1;
pub const MAX_APPROVAL_LIFETIME: i64 = 300;
pub const MAX_BINDING_LIFETIME: i64 = 600;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Identity {
    Account {
        public_key: [u8; 32],
    },
    Passkey {
        /// Canonical compressed SEC1 P-256 point, also used by Solana's precompile.
        public_key: Vec<u8>,
        rp_id: String,
        origin: String,
    },
    Oidc {
        issuer: String,
        audience: String,
        subject: String,
    },
}
impl Identity {
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Account { public_key } if *public_key != [0; 32] => Ok(()),
            Self::Passkey {
                public_key,
                rp_id,
                origin,
            } if public_key.len() == 33
                && matches!(public_key[0], 2 | 3)
                && !rp_id.is_empty()
                && rp_id.len() <= 128
                && origin.starts_with("https://")
                && origin.len() <= 256 =>
            {
                Ok(())
            }
            Self::Oidc {
                issuer,
                audience,
                subject,
            } if issuer.starts_with("https://")
                && issuer.len() <= 256
                && !audience.is_empty()
                && audience.len() <= 256
                && !subject.is_empty()
                && subject.len() <= 256 =>
            {
                Ok(())
            }
            _ => Err(Error::Bounds),
        }
    }
    /// Account derivation remains byte-for-byte compatible with existing namespaces.
    /// Other identity types have a distinct, stable, domain-separated authority.
    pub fn authority(&self) -> [u8; 32] {
        match self {
            Self::Account { public_key } => *public_key,
            _ => digest(b"pairkey/identity-authority/v1", self),
        }
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/approval-identity/v1", self)
    }
}

/// Standard restrictions over the exact bytes committed for signing. No transaction
/// parsing, cumulative spending guarantee or implicit policy delegation is claimed.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub revision: u64,
    /// None allows all destinations; Some([]) denies all.
    pub destinations: Option<Vec<[u8; 32]>>,
    /// Prefixes of derivation paths. None allows all; Some([]) denies all.
    pub path_prefixes: Option<Vec<Vec<u32>>>,
    pub max_payload_bytes: u32,
    pub payload_prefix: Vec<u8>,
    pub disabled: bool,
}
impl Default for Rules {
    fn default() -> Self {
        Self {
            revision: 0,
            destinations: None,
            path_prefixes: None,
            max_payload_bytes: MAX_MESSAGE as u32,
            payload_prefix: vec![],
            disabled: false,
        }
    }
}
impl Rules {
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_payload_bytes == 0
            || self.max_payload_bytes as usize > MAX_MESSAGE
            || self.payload_prefix.len() > 128
            || self.payload_prefix.len() > self.max_payload_bytes as usize
            || self.destinations.as_ref().is_some_and(|v| v.len() > 16)
            || self
                .path_prefixes
                .as_ref()
                .is_some_and(|v| v.len() > 16 || v.iter().any(|p| p.len() > MAX_PATH))
            || (self.revision == 0 && self != &Self::default())
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/approval-rules/v1", self)
    }
    pub fn allows(&self, commit: &Commit, payload: &[u8]) -> Result<(), Error> {
        self.validate()?;
        commit.account.validate()?;
        if self.disabled
            || payload.is_empty()
            || payload.len() > self.max_payload_bytes as usize
            || payload.len() != commit.message_len as usize
            || message_hash(payload) != commit.message_hash
            || !payload.starts_with(&self.payload_prefix)
            || self
                .destinations
                .as_ref()
                .is_some_and(|v| !v.contains(&commit.account.destination))
            || self
                .path_prefixes
                .as_ref()
                .is_some_and(|v| !v.iter().any(|p| commit.account.path.starts_with(p)))
        {
            return Err(Error::Metadata);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub identity: Identity,
    pub commit: Commit,
    pub policy_revision: u64,
    pub policy_digest: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
}
impl Request {
    pub fn validate(
        &self,
        registration: &Registration,
        payload: &[u8],
        rules: &Rules,
        now: i64,
    ) -> Result<(), Error> {
        self.identity.validate()?;
        self.commit.authorize(registration, payload)?;
        interval(self.issued_at, self.expires_at, now, MAX_APPROVAL_LIFETIME)?;
        if self.version != APPROVAL_VERSION
            || self.commit.request_id == [0; 32]
            || self.identity.authority() != registration.namespace.derivation_authority
            || self.policy_revision != rules.revision
            || self.policy_digest != rules.digest()
        {
            return Err(Error::Metadata);
        }
        rules.allows(&self.commit, payload)
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(b"pairkey/offchain-approval/v1", self)
    }
    /// ASCII domain separation prevents confusion with transactions or raw chain messages.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut out = b"PairKey off-chain approval v1\nRequest: ".to_vec();
        for byte in self.digest() {
            out.push(b"0123456789abcdef"[(byte >> 4) as usize]);
            out.push(b"0123456789abcdef"[(byte & 15) as usize]);
        }
        out
    }
}

/// The owner authenticates this binding; the ephemeral key authenticates requests.
/// It cannot change the owner identity, namespace or persistent policy.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub namespace_digest: [u8; 32],
    pub identity_digest: [u8; 32],
    pub public_key: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
}
impl Binding {
    pub fn challenge(&self) -> [u8; 32] {
        digest(b"pairkey/identity-binding/v1", self)
    }
    pub fn validate(
        &self,
        registration: &Registration,
        request: &Request,
        now: i64,
    ) -> Result<(), Error> {
        interval(self.issued_at, self.expires_at, now, MAX_BINDING_LIFETIME)?;
        if self.public_key == [0; 32]
            || self.namespace_digest != registration.namespace.digest()
            || self.identity_digest != request.identity.digest()
            || request.issued_at < self.issued_at
            || request.expires_at > self.expires_at
        {
            return Err(Error::Metadata);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature_der: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Proof {
    Account {
        signature: Vec<u8>,
    },
    Passkey {
        binding: Binding,
        assertion: Assertion,
        signature: Vec<u8>,
    },
    Oidc {
        binding: Binding,
        id_token: String,
        signature: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub request: Request,
    pub proof: Proof,
}

/// Private submission to both signers before the public signing protocol starts.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub registration: Registration,
    pub payload: Vec<u8>,
    pub approval: Approval,
}

/// Owner-authorized replacement of one persistent policy. Revisions start at one;
/// there is no delete instruction that could silently restore the absent default.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdate {
    pub namespace: Namespace,
    pub identity: Identity,
    pub rules: Rules,
    pub issued_at: i64,
    pub expires_at: i64,
}
impl PolicyUpdate {
    pub fn validate(&self, now: i64) -> Result<(), Error> {
        self.namespace.validate()?;
        self.identity.validate()?;
        self.rules.validate()?;
        interval(self.issued_at, self.expires_at, now, MAX_APPROVAL_LIFETIME)?;
        if self.rules.revision == 0
            || self.namespace.derivation_authority != self.identity.authority()
        {
            return Err(Error::Metadata);
        }
        Ok(())
    }
    pub fn challenge(&self) -> [u8; 32] {
        digest(b"pairkey/policy-update/v1", self)
    }
    pub fn attestation_message(&self) -> Vec<u8> {
        let mut message = b"pairkey/oidc-policy-update/v1".to_vec();
        message.extend_from_slice(&self.challenge());
        message
    }
}
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PolicyProof {
    Wallet,
    /// The signature itself is verified by the preceding native P-256 instruction.
    Passkey {
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
    },
    /// Both enrolled signer identities must attest the exact update, not a sign request.
    OidcAttested,
}

fn interval(issued_at: i64, expires_at: i64, now: i64, maximum: i64) -> Result<(), Error> {
    if issued_at < 0
        || issued_at > now
        || expires_at <= now
        || expires_at <= issued_at
        || expires_at.saturating_sub(issued_at) > maximum
    {
        Err(Error::Bounds)
    } else {
        Ok(())
    }
}
