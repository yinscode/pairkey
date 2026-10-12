//! Canonical Ed25519 transaction adapters. The approved envelope contains the
//! complete transaction while `signing_bytes` applies the destination chain's
//! signing rule. Workers run this conversion independently before signing.
use anyhow::{ensure, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PREFIX: &[u8] = b"pairkey/transaction-intent/v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub enum Transaction {
    /// Canonical serialized Solana legacy or v0 transaction message.
    Solana { message: Vec<u8> },
    /// Canonical Borsh-serialized NEAR `Transaction`, without its signature.
    Near { transaction: Vec<u8> },
}

impl Transaction {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let mut out = PREFIX.to_vec();
        out.extend(borsh::to_vec(self)?);
        ensure!(
            out.len() <= pairkey_types::MAX_MESSAGE,
            "transaction intent too large"
        );
        Ok(out)
    }

    pub fn signing_bytes(&self, expected_public_key: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            expected_public_key.len() == 32,
            "Ed25519 public key required"
        );
        match self {
            Self::Solana { message } => {
                ensure!(
                    !message.is_empty() && message.len() <= 1232,
                    "Solana message bounds"
                );
                let parsed: solana_sdk::message::VersionedMessage =
                    bincode::deserialize(message).context("invalid Solana transaction message")?;
                ensure!(
                    bincode::serialize(&parsed)? == *message,
                    "noncanonical Solana message"
                );
                let required = usize::from(parsed.header().num_required_signatures);
                ensure!(
                    required > 0 && required <= parsed.static_account_keys().len(),
                    "invalid Solana signer header"
                );
                ensure!(
                    parsed.static_account_keys()[..required]
                        .iter()
                        .any(|key| key.as_ref() == expected_public_key),
                    "derived key is not a required Solana signer"
                );
                Ok(message.clone())
            }
            Self::Near { transaction } => {
                ensure!(
                    !transaction.is_empty() && transaction.len() <= 1024,
                    "NEAR transaction bounds"
                );
                let parsed: NearTransaction =
                    borsh::from_slice(transaction).context("invalid NEAR transaction")?;
                parsed.validate(expected_public_key)?;
                ensure!(
                    borsh::to_vec(&parsed)? == *transaction,
                    "noncanonical NEAR transaction"
                );
                Ok(Sha256::digest(transaction).to_vec())
            }
        }
    }

    pub fn signed_bytes(&self, expected_public_key: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        ensure!(signature.len() == 64, "Ed25519 signature length");
        self.signing_bytes(expected_public_key)?;
        match self {
            Self::Near { transaction } => {
                let mut out = transaction.clone();
                // near-crypto Signature::ED25519 Borsh discriminant.
                out.push(0);
                out.extend_from_slice(signature);
                Ok(out)
            }
            Self::Solana { .. } => anyhow::bail!(
                "Solana assembly needs all signer positions; attach this signature in the client"
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NearPublicKey {
    Ed25519([u8; 32]),
    Secp256k1([u8; 64]),
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NearTransaction {
    pub signer_id: String,
    pub public_key: NearPublicKey,
    pub nonce: u64,
    pub receiver_id: String,
    pub block_hash: [u8; 32],
    pub actions: Vec<NearAction>,
}

impl NearTransaction {
    fn validate(&self, expected_public_key: &[u8]) -> Result<()> {
        ensure!(
            valid_account_id(&self.signer_id) && valid_account_id(&self.receiver_id),
            "invalid NEAR account ID"
        );
        ensure!(
            self.nonce > 0 && self.block_hash != [0; 32],
            "invalid NEAR nonce or block hash"
        );
        ensure!(
            !self.actions.is_empty() && self.actions.len() <= 16,
            "invalid NEAR actions"
        );
        let NearPublicKey::Ed25519(public_key) = self.public_key else {
            anyhow::bail!("PairKey NEAR transactions require an Ed25519 access key")
        };
        ensure!(
            public_key.as_slice() == expected_public_key,
            "NEAR access key does not match derived key"
        );
        for action in &self.actions {
            action.validate()?;
        }
        Ok(())
    }
}

fn valid_account_id(value: &str) -> bool {
    (2..=64).contains(&value.len())
        && value.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_' | b'.')
        })
        && !value.starts_with(['-', '_', '.'])
        && !value.ends_with(['-', '_', '.'])
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NearAction {
    CreateAccount,
    DeployContract {
        code: Vec<u8>,
    },
    FunctionCall {
        method_name: String,
        args: Vec<u8>,
        gas: u64,
        deposit: u128,
    },
    Transfer {
        deposit: u128,
    },
    Stake {
        stake: u128,
        public_key: NearPublicKey,
    },
    AddKey {
        public_key: NearPublicKey,
        access_key: NearAccessKey,
    },
    DeleteKey {
        public_key: NearPublicKey,
    },
    DeleteAccount {
        beneficiary_id: String,
    },
}

impl NearAction {
    fn validate(&self) -> Result<()> {
        match self {
            Self::DeployContract { code } => ensure!(
                !code.is_empty() && code.len() <= 768,
                "NEAR contract code bounds"
            ),
            Self::FunctionCall {
                method_name,
                args,
                gas,
                ..
            } => ensure!(
                !method_name.is_empty()
                    && method_name.len() <= 64
                    && method_name.is_ascii()
                    && args.len() <= 768
                    && *gas > 0,
                "NEAR function-call bounds"
            ),
            Self::Transfer { deposit } => ensure!(*deposit > 0, "NEAR transfer must be positive"),
            Self::Stake { stake, .. } => ensure!(*stake > 0, "NEAR stake must be positive"),
            Self::DeleteAccount { beneficiary_id } => {
                ensure!(valid_account_id(beneficiary_id), "invalid NEAR beneficiary")
            }
            _ => (),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NearAccessKey {
    pub nonce: u64,
    pub permission: NearAccessKeyPermission,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NearAccessKeyPermission {
    FunctionCall {
        allowance: Option<u128>,
        receiver_id: String,
        method_names: Vec<String>,
    },
    FullAccess,
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::{hash::Hash, message::Message, pubkey::Pubkey, system_instruction};

    #[test]
    fn solana_requires_the_derived_key_as_a_signer() {
        let signer = Pubkey::new_unique();
        let message = Message::new_with_blockhash(
            &[system_instruction::transfer(
                &signer,
                &Pubkey::new_unique(),
                1,
            )],
            Some(&signer),
            &Hash::new_unique(),
        );
        let bytes =
            bincode::serialize(&solana_sdk::message::VersionedMessage::Legacy(message)).unwrap();
        let tx = Transaction::Solana {
            message: bytes.clone(),
        };
        assert_eq!(tx.signing_bytes(signer.as_ref()).unwrap(), bytes);
        assert!(tx.signing_bytes(Pubkey::new_unique().as_ref()).is_err());
    }

    #[test]
    fn near_binds_access_key_and_hashes_the_canonical_transaction() {
        let public = [7; 32];
        let tx = NearTransaction {
            signer_id: "alice.near".into(),
            public_key: NearPublicKey::Ed25519(public),
            nonce: 1,
            receiver_id: "bob.near".into(),
            block_hash: [8; 32],
            actions: vec![NearAction::Transfer { deposit: 1 }],
        };
        let bytes = borsh::to_vec(&tx).unwrap();
        let intent = Transaction::Near {
            transaction: bytes.clone(),
        };
        assert_eq!(
            intent.signing_bytes(&public).unwrap(),
            Sha256::digest(&bytes).to_vec()
        );
        assert_eq!(
            intent.signed_bytes(&public, &[9; 64]).unwrap().len(),
            bytes.len() + 65
        );
        assert!(intent.signing_bytes(&[6; 32]).is_err());
    }
}
