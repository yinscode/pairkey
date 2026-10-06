//! Versioned, exact-intent signing adapters. Local research integration only.
//! The existing Ed25519 registration remains the Solana authorization namespace.
//! Other signing keys are bound explicitly into each approved intent.
use anyhow::{ensure, Result};
use borsh::{BorshDeserialize, BorshSerialize};
pub use pairkey_dkls23_research as dkls;
use pairkey_types::{AccountPath, Registration};
use serde::{Deserialize, Serialize};
pub mod evm;
pub mod evm_message;
pub mod redpallas;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum Suite {
    Dkls23Secp256k1,
    FrostRedPallas,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub version: u16,
    pub suite: Suite,
    pub namespace: [u8; 32],
    pub account: AccountPath,
    pub public_key: Vec<u8>,
    pub registration: [u8; 32],
}
impl Key {
    pub fn validate(&self, reg: &Registration) -> Result<()> {
        reg.validate()?;
        self.account.validate()?;
        ensure!(
            self.version == 1 && self.namespace == reg.digest(),
            "signing key namespace/version"
        );
        match self.suite {
            Suite::Dkls23Secp256k1 => {
                dkls::point(&self.public_key)?;
            }
            Suite::FrostRedPallas => {
                redpallas::validate_key(&self.public_key)?;
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        pairkey_types::digest(b"pairkey/signing-key/v1", self)
    }
}
/// Exact bytes approved on Solana. Workers compute the signing hash themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub version: u16,
    pub key: Key,
    pub payload: Payload,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Payload {
    EvmTransfer(evm::Transfer),
    /// Raw RedPallas signing. Does not construct Orchard transactions.
    RedPallas {
        message: Vec<u8>,
    },
    /// Appended to preserve existing Borsh payload discriminants.
    EvmMessage(evm_message::Message),
}
pub const INTENT_PREFIX: &[u8] = b"pairkey/signing-intent/v1\0";
impl Intent {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= pairkey_types::MAX_MESSAGE,
            "intent too large"
        );
        let payload = bytes
            .strip_prefix(INTENT_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("intent prefix"))?;
        Ok(borsh::from_slice(payload)?)
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let mut b = INTENT_PREFIX.to_vec();
        b.extend(borsh::to_vec(self)?);
        ensure!(b.len() <= pairkey_types::MAX_MESSAGE, "intent too large");
        Ok(b)
    }
    pub fn validate(&self, reg: &Registration) -> Result<()> {
        self.key.validate(reg)?;
        ensure!(self.version == 1, "intent version");
        match (&self.key.suite, &self.payload) {
            (Suite::Dkls23Secp256k1, Payload::EvmTransfer(tx)) => {
                tx.validate()?;
                ensure!(
                    self.key.account.destination == evm::destination(tx.chain_id),
                    "EVM destination/chain mismatch"
                );
            }
            (Suite::Dkls23Secp256k1, Payload::EvmMessage(message)) => {
                message.validate()?;
                ensure!(
                    self.key.account.destination == evm::destination(message.chain_id),
                    "EVM message destination mismatch"
                );
            }
            (Suite::FrostRedPallas, Payload::RedPallas { message }) => {
                ensure!(
                    !message.is_empty() && message.len() <= 512,
                    "RedPallas message bounds"
                );
            }
            _ => anyhow::bail!("suite/payload mismatch"),
        }
        self.bytes()?;
        Ok(())
    }
    pub fn verify(&self, signature: &[u8]) -> Result<()> {
        match &self.payload {
            Payload::EvmTransfer(tx) => evm::verify(&self.key.public_key, tx, signature),
            Payload::EvmMessage(message) => message.verify(&self.key.public_key, signature),
            Payload::RedPallas { message } => {
                redpallas::verify(&self.key.public_key, message, signature)
            }
        }
    }
}
pub fn wallet(
    reg: &Registration,
    account: &AccountPath,
    identities: [[u8; 32]; 2],
) -> dkls::d::Wallet {
    dkls::d::Wallet {
        version: 2,
        identities,
        namespace: hex(&reg.digest()),
        epoch: 0,
        key_id: pairkey_types::digest(
            b"pairkey/dkls23/platform-account/v1",
            &(reg.digest(), account),
        ),
    }
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub mod wire;
