use pairkey_channel::{Attestation, Envelope};
use pairkey_frost::Possession;
use pairkey_types::{Attempt, Registration, Role};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub challenge: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub role: Role,
    pub identity: [u8; 32],
    pub boot_id: [u8; 32],
    pub development: bool,
    pub incident: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub registration: Registration,
    pub proofs: [Possession; 2],
    pub controller: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Begin {
    pub registration: Registration,
    pub attempt: Attempt,
    /// Present when the approved typed transaction envelope differs from the
    /// destination chain's actual signing bytes (for example NEAR's tx hash).
    #[serde(default)]
    pub transaction: Option<pairkey_signing::transaction::Transaction>,
    pub message: Vec<u8>,
    pub peer: Attestation,
}
impl Begin {
    pub fn approval_payload(&self) -> anyhow::Result<Vec<u8>> {
        match &self.transaction {
            Some(transaction) => transaction.bytes(),
            None => Ok(self.message.clone()),
        }
    }
    pub fn validate_signing_payload(&self) -> anyhow::Result<()> {
        if let Some(transaction) = &self.transaction {
            let public =
                pairkey_types::derive_public(&self.registration, &self.attempt.commit.account)?;
            anyhow::ensure!(
                transaction.signing_bytes(&public)? == self.message,
                "transaction signing payload changed"
            );
            self.attempt
                .commit
                .authorize(&self.registration, &transaction.bytes()?)?;
        } else {
            self.attempt
                .commit
                .authorize(&self.registration, &self.message)?;
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    pub begin: Begin,
    pub rounds: [Envelope; 2],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultRequest {
    pub finish: Finish,
    pub shares: [Envelope; 2],
}
/// Public request reference used to recheck private, previously supplied authentication.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCheck {
    pub registration: Registration,
    pub attempt: Attempt,
    pub payload: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLookup {
    pub namespace_digest: [u8; 32],
    pub request_id: [u8; 32],
    pub approval_digest: [u8; 32],
}
pub use pairkey_types::receipt::{receipt_message, Receipt, ResultResponse};
