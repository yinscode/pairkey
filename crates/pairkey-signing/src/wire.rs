pub const PROTOCOL_VERSION: u16 = 2;
use crate::{bitcoin, dkls, redpallas, Intent, Key, Suite};
use pairkey_types::{attestation::Attestation, AccountPath, Attempt, Registration, Role};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRequest {
    pub registration: Registration,
    pub account: AccountPath,
    pub suite: Suite,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub protocol: u16,
    pub request: KeyRequest,
    pub role: Role,
    pub boot: [u8; 32],
    pub dkls_identity: [u8; 32],
    pub redpallas: Option<redpallas::Proof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitcoin: Option<bitcoin::Proof>,
    pub signature: Vec<u8>,
}
impl Info {
    pub fn message(&self) -> Vec<u8> {
        let mut b = b"pairkey/backend-info/v1".to_vec();
        b.extend(
            serde_json::to_vec(&(
                self.protocol,
                &self.request,
                self.role,
                self.boot,
                self.dkls_identity,
                &self.redpallas,
            ))
            .unwrap(),
        );
        if let Some(proof) = &self.bitcoin {
            b.extend(b"/bitcoin-bip340/v1");
            b.extend(serde_json::to_vec(proof).unwrap());
        }
        b
    }
    pub fn verify(&self, identity: [u8; 32]) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.protocol == PROTOCOL_VERSION,
            "unsupported signing protocol"
        );
        ed25519_dalek::VerifyingKey::from_bytes(&identity)?.verify_strict(
            &self.message(),
            &ed25519_dalek::Signature::from_slice(&self.signature)?,
        )?;
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Certificate {
    Dkls(Box<dkls::d::Certificate>),
    RedPallas(redpallas::Public),
    Bitcoin(bitcoin::Public),
}
impl Certificate {
    pub fn key(&self, req: &KeyRequest) -> anyhow::Result<Key> {
        Ok(match self {
            Self::Dkls(c) => {
                c.validate()?;
                anyhow::ensure!(
                    req.suite == Suite::Dkls23Secp256k1
                        && c.record.wallet
                            == crate::wallet(
                                &req.registration,
                                &req.account,
                                c.record.wallet.identities
                            ),
                    "wallet mismatch"
                );
                Key {
                    version: 1,
                    suite: req.suite,
                    namespace: req.registration.digest(),
                    account: req.account.clone(),
                    public_key: c.record.public_key.clone(),
                    registration: c.record.digest(),
                }
            }
            Self::Bitcoin(p) => {
                anyhow::ensure!(req.suite == Suite::FrostSecp256k1Tr, "suite mismatch");
                p.key(&req.registration, &req.account)?
            }
            Self::RedPallas(p) => {
                anyhow::ensure!(req.suite == Suite::FrostRedPallas, "suite mismatch");
                p.key(&req.registration, &req.account)?
            }
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyResponse {
    pub key: Key,
    pub certificate: Certificate,
    pub infos: [Info; 2],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub protocol: u16,
    pub registration: Registration,
    pub attempt: Attempt,
    pub intent: Intent,
    pub certificate: Certificate,
}
impl SignRequest {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.protocol == PROTOCOL_VERSION,
            "unsupported signing protocol"
        );
        self.intent.validate(&self.registration)?;
        self.attempt
            .commit
            .authorize(&self.registration, &self.intent.bytes()?)?;
        anyhow::ensure!(
            self.attempt.commit.account == self.intent.key.account,
            "account path mismatch"
        );
        // Only the EVM adapter accepts sessions; FROST adapters require exact COMMIT.
        anyhow::ensure!(
            self.attempt.authorization.session_id.is_none()
                || self.intent.key.suite == Suite::Dkls23Secp256k1,
            "FROST requires COMMIT"
        );
        let key = self.certificate.key(&KeyRequest {
            registration: self.registration.clone(),
            account: self.intent.key.account.clone(),
            suite: self.intent.key.suite,
        })?;
        anyhow::ensure!(key == self.intent.key, "certificate/key mismatch");
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorized {
    pub request: SignRequest,
    pub peer: Attestation,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: u16,
    pub development: bool,
    pub hardware_backed: bool,
    pub request: SignRequest,
    pub signature: Vec<u8>,
    pub role: Role,
    pub boot: [u8; 32],
    pub peer_boot: [u8; 32],
    pub finalized_slot: u64,
    pub identity_signature: Vec<u8>,
}
impl Receipt {
    pub fn message(&self) -> Vec<u8> {
        let mut b = b"pairkey/multi-receipt/v1".to_vec();
        b.extend(
            serde_json::to_vec(&(
                self.version,
                self.development,
                self.hardware_backed,
                &self.request,
                &self.signature,
                self.role,
                self.boot,
                self.peer_boot,
                self.finalized_slot,
            ))
            .unwrap(),
        );
        b
    }
    pub fn verify(&self, identity: [u8; 32]) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == PROTOCOL_VERSION && self.development && !self.hardware_backed,
            "unsupported receipt mode/version"
        );
        self.request.validate()?;
        self.request.intent.verify(&self.signature)?;
        ed25519_dalek::VerifyingKey::from_bytes(&identity)?.verify_strict(
            &self.message(),
            &ed25519_dalek::Signature::from_slice(&self.identity_signature)?,
        )?;
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub signature: Vec<u8>,
    pub receipts: [Receipt; 2],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    pub peer: Info,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DOperation {
    Register(Box<KeyRequest>),
    Prepare,
    Sign {
        authorized: Box<Authorized>,
        generation: [u8; 32],
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DStart {
    pub id: [u8; 32],
    pub operation: DOperation,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    pub id: [u8; 32],
    pub frames: Vec<dkls::Frame>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DOutput {
    pub frames: Vec<dkls::Frame>,
    pub receipt: Option<Receipt>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DStatus {
    pub generation: Option<[u8; 32]>,
    pub uses: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RBegin {
    pub authorized: Authorized,
}
