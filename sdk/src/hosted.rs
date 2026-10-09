//! Hosted devnet gateway. Wallets/programs authorize on Solana; this client never holds shares.
use anyhow::{ensure, Result};
use pairkey_types::{AccountPath, Commit, Registration};
use serde::{Deserialize, Serialize};
use solana_sdk::{instruction::Instruction, pubkey::Pubkey};
pub mod offchain;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, borsh::BorshSerialize)]
#[serde(rename_all = "snake_case")]
pub enum Chain {
    Solana,
    Evm,
    Zcash,
    Near,
    Bitcoin,
}
impl Chain {
    pub fn account(self, path: Vec<u32>) -> Result<AccountPath> {
        let destination = match self {
            Self::Evm => pairkey_signing::evm::destination(84532),
            Self::Bitcoin => {
                pairkey_signing::bitcoin::destination(pairkey_signing::bitcoin::Network::Testnet)
            }
            _ => pairkey_types::digest(b"pairkey/hosted-message-destination/v1", &self),
        };
        let account = AccountPath { destination, path };
        account.validate()?;
        Ok(account)
    }
    pub fn suite(self) -> Option<pairkey_signing::Suite> {
        use pairkey_signing::Suite;
        match self {
            Self::Evm => Some(Suite::Dkls23Secp256k1),
            Self::Zcash => Some(Suite::FrostRedPallas),
            Self::Bitcoin => Some(Suite::FrostSecp256k1Tr),
            _ => None,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceRequest {
    pub authority: String,
    pub payer: String,
    #[serde(default)]
    pub namespace_id: [u8; 32],
}
/// JSON instruction compatible with @solana/web3.js TransactionInstruction.
#[derive(Clone, Serialize, Deserialize)]
pub struct InstructionData {
    pub program_id: String,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct AccountMeta {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}
impl From<Instruction> for InstructionData {
    fn from(i: Instruction) -> Self {
        Self {
            program_id: i.program_id.to_string(),
            data: i.data,
            accounts: i
                .accounts
                .into_iter()
                .map(|a| AccountMeta {
                    pubkey: a.pubkey.to_string(),
                    is_signer: a.is_signer,
                    is_writable: a.is_writable,
                })
                .collect(),
        }
    }
}
impl InstructionData {
    pub fn instruction(&self) -> Result<Instruction> {
        Ok(Instruction {
            program_id: self.program_id.parse()?,
            data: self.data.clone(),
            accounts: self
                .accounts
                .iter()
                .map(|a| {
                    Ok(solana_sdk::instruction::AccountMeta {
                        pubkey: a.pubkey.parse()?,
                        is_signer: a.is_signer,
                        is_writable: a.is_writable,
                    })
                })
                .collect::<Result<_>>()?,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct NamespaceResponse {
    pub proposal: crate::service::RegistrationProposal,
    pub namespace_address: String,
    pub instructions: Vec<InstructionData>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRequest {
    pub registration: Registration,
    pub chain: Chain,
    pub path: Vec<u32>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyResponse {
    pub account: AccountPath,
    pub public_key: Vec<u8>,
    pub public_key_hex: String,
    pub address: Option<String>,
    pub multi: Option<crate::multi::KeyResponse>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub key: KeyRequest,
    pub payer: String,
    pub request_id: [u8; 32],
    pub message: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub key: KeyRequest,
    pub request_id: [u8; 32],
    pub message: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Approval {
    pub commit: Commit,
    pub instructions: Vec<InstructionData>,
    pub signing_request: SigningRequest,
}
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
}
impl Client {
    pub fn new(base: String) -> Result<Self> {
        let url = reqwest::Url::parse(&base)?;
        ensure!(
            url.scheme() == "https" || url.host_str() == Some("127.0.0.1"),
            "HTTPS required"
        );
        Ok(Self {
            base: base.trim_end_matches('/').into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()?,
        })
    }
    pub async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let r = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        crate::http::bounded_json(r, 256 * 1024).await
    }
    pub async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        value: &impl Serialize,
    ) -> Result<T> {
        let r = self
            .http
            .post(format!("{}{path}", self.base))
            .header("x-pairkey-client", "1")
            .json(value)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        crate::http::bounded_json(r, 256 * 1024).await
    }
    pub async fn namespace(
        &self,
        q: &NamespaceRequest,
        identities: [[u8; 32]; 2],
        registry: Pubkey,
    ) -> Result<NamespaceResponse> {
        let r: NamespaceResponse = self.post("/namespaces", q).await?;
        let authority: Pubkey = q.authority.parse()?;
        ensure!(
            r.proposal.registration.namespace.derivation_authority == authority.to_bytes()
                && r.proposal.registration.namespace.namespace_id == q.namespace_id
                && r.proposal.registration.namespace.registry == registry.to_bytes(),
            "namespace context mismatch"
        );
        r.proposal.registration.validate()?;
        let message = pair_registry::registration_message(&r.proposal.registration, &authority);
        for (i, key) in identities.iter().enumerate() {
            ed25519_dalek::VerifyingKey::from_bytes(key)?.verify_strict(
                &message,
                &ed25519_dalek::Signature::from_slice(&r.proposal.identity_signatures[i])?,
            )?;
        }
        Ok(r)
    }
}

/// Verify a hosted result locally, including both signer receipts and the exact approval.
pub fn verify_result(
    q: &SigningRequest,
    key: &KeyResponse,
    result: &serde_json::Value,
    identities: [[u8; 32]; 2],
) -> Result<()> {
    use crate::multi;
    ensure!(
        result["signed_message"] == q.message
            && result["chain"] == serde_json::to_value(q.key.chain)?
            && result["public_key_hex"] == key.public_key_hex,
        "hosted result context mismatch"
    );
    let signature_text = result["signature_hex"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("signature missing"))?;
    let signature = decode_hex(signature_text)?;
    ensure!(
        decode_hex(&key.public_key_hex)? == key.public_key,
        "public key encoding mismatch"
    );
    ensure!(
        key.account == q.key.chain.account(q.key.path.clone())?,
        "key path mismatch"
    );
    if let Some(k) = &key.multi {
        let suite = q
            .key
            .chain
            .suite()
            .ok_or_else(|| anyhow::anyhow!("unexpected multi-suite key"))?;
        multi::verify_key(
            &multi::KeyRequest {
                registration: q.key.registration.clone(),
                account: key.account.clone(),
                suite,
            },
            k,
            identities,
        )?;
        ensure!(k.key.public_key == key.public_key, "public key mismatch");
        let receipts: [multi::Receipt; 2] = serde_json::from_value(result["receipts"].clone())?;
        let request = &receipts[0].request;
        let payload = match q.key.chain {
            Chain::Evm => {
                pairkey_signing::Payload::EvmMessage(pairkey_signing::evm_message::Message {
                    chain_id: 84532,
                    message: q.message.as_bytes().to_vec(),
                })
            }
            Chain::Bitcoin => {
                pairkey_signing::Payload::BitcoinMessage(pairkey_signing::bitcoin::Message {
                    network: pairkey_signing::bitcoin::Network::Testnet,
                    message: q.message.as_bytes().to_vec(),
                })
            }
            Chain::Zcash => pairkey_signing::Payload::RedPallas {
                message: q.message.as_bytes().to_vec(),
            },
            _ => anyhow::bail!("unexpected signing suite"),
        };
        let intent = pairkey_signing::Intent {
            version: 1,
            key: k.key.clone(),
            payload,
        };
        let commit = Commit::new(
            &q.key.registration,
            q.request_id,
            key.account.clone(),
            &intent.bytes()?,
        )?;
        ensure!(
            request.registration == q.key.registration
                && request.intent == intent
                && request.attempt.commit == commit,
            "receipt approval mismatch"
        );
        multi::verify_result(
            request,
            &multi::Signed {
                signature,
                receipts: receipts.clone(),
            },
            identities,
        )?;
    } else {
        ensure!(
            q.key.chain.suite().is_none(),
            "missing multi-suite certificate"
        );
        let commit = Commit::new(
            &q.key.registration,
            q.request_id,
            key.account.clone(),
            q.message.as_bytes(),
        )?;
        ensure!(
            crate::derive_public(&q.key.registration, &key.account)?.as_slice() == key.public_key,
            "derived key mismatch"
        );
        let receipts: [pairkey_types::receipt::ResultResponse; 2] =
            serde_json::from_value(result["receipts"].clone())?;
        for (i, role) in [pairkey_types::Role::A, pairkey_types::Role::B]
            .into_iter()
            .enumerate()
        {
            // Ed25519 receipts bind the attempt digest; the returned result must include its attempt.
            let attempt: pairkey_types::Attempt =
                serde_json::from_value(result["attempt"].clone())?;
            ensure!(attempt.commit == commit, "receipt approval mismatch");
            crate::service::verify_receipt(
                &q.key.registration,
                &attempt,
                q.message.as_bytes(),
                &receipts[i],
                identities[i],
                role,
                true,
            )?;
            ensure!(
                receipts[i].receipt.signature == signature
                    && receipts[i].receipt.peer_boot == receipts[1 - i].receipt.boot_id,
                "signature or peer binding mismatch"
            );
        }
    }
    Ok(())
}
fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("hex prefix"))?;
    ensure!(value.len() % 2 == 0 && value.is_ascii(), "invalid hex");
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(Into::into))
        .collect()
}
