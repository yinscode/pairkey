//! Hosted v2: lazy public metadata, exact private approval, public result recovery.
use super::*;
use pairkey_types::approval::{Identity, Proof, Request, Rules};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceRequest {
    pub identity: Identity,
    #[serde(default)]
    pub namespace_id: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceResponse {
    pub proposal: crate::service::RegistrationProposal,
    pub identity: Identity,
    pub namespace_address: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub signing_request: SigningRequest,
    pub identity: Identity,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub signing_request: SigningRequest,
    pub request: Request,
    pub rules: Rules,
    pub payload: Vec<u8>,
    pub signing_message: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitRequest {
    pub signing_request: SigningRequest,
    pub approval: pairkey_types::approval::Approval,
}
impl super::Client {
    /// Configure this client with `/api/v2`. Namespace setup exchanges public
    /// metadata only; it never returns a transaction to register on Solana.
    pub async fn offchain_namespace(
        &self,
        q: &NamespaceRequest,
        network: [u8; 32],
        registry: Pubkey,
        set: [u8; 32],
        identities: [[u8; 32]; 2],
    ) -> Result<NamespaceResponse> {
        let response = self.post("/namespaces", q).await?;
        verify_namespace(q, &response, network, registry, set, identities)?;
        Ok(response)
    }
    pub async fn offchain_key(
        &self,
        q: &KeyRequest,
        identities: [[u8; 32]; 2],
    ) -> Result<KeyResponse> {
        let response = self.post("/keys", q).await?;
        verify_key(q, &response, identities)?;
        Ok(response)
    }
    pub async fn prepare_offchain(
        &self,
        q: &PrepareRequest,
        key: &KeyResponse,
        identities: [[u8; 32]; 2],
        now: i64,
    ) -> Result<Prepared> {
        let response: Prepared = self.post("/approvals", q).await?;
        response.verify(q, key, identities, now)?;
        Ok(response)
    }
    pub async fn submit_offchain(&self, q: &SubmitRequest) -> Result<String> {
        let expected =
            crate::approval::job_id(&pairkey_types::policy::Authorization::offchain(&q.approval))?;
        let response: serde_json::Value = self.post("/jobs", q).await?;
        ensure!(response["job_id"] == expected, "hosted job ID changed");
        Ok(expected)
    }
    /// Reads saved receipts only. Call `verify_result` with the original request.
    pub async fn recover_offchain(&self, id: &str) -> Result<serde_json::Value> {
        ensure!(id.parse::<Pubkey>().is_ok(), "invalid job ID");
        self.post(&format!("/jobs/{id}/recover"), &serde_json::json!({}))
            .await
    }
}
impl Prepared {
    /// Recompute the request from the user's original inputs before asking for consent.
    pub fn verify(
        &self,
        expected: &PrepareRequest,
        key: &KeyResponse,
        identities: [[u8; 32]; 2],
        now: i64,
    ) -> Result<()> {
        ensure!(
            serde_json::to_value(&self.signing_request)?
                == serde_json::to_value(&expected.signing_request)?,
            "prepared message changed"
        );
        verify_key(&expected.signing_request.key, key, identities)?;
        let (commit, payload, _) = prepare_message(&expected.signing_request, key)?;
        ensure!(
            self.request.identity == expected.identity
                && self.request.commit == commit
                && self.payload == payload
                && self.signing_message == self.request.signing_message(),
            "prepared approval changed"
        );
        self.request.validate(
            &expected.signing_request.key.registration,
            &payload,
            &self.rules,
            now,
        )?;
        Ok(())
    }
    pub fn submission(self, proof: Proof) -> SubmitRequest {
        SubmitRequest {
            signing_request: self.signing_request,
            approval: pairkey_types::approval::Approval {
                request: self.request,
                proof,
            },
        }
    }
}
pub fn verify_namespace(
    expected: &NamespaceRequest,
    response: &NamespaceResponse,
    network: [u8; 32],
    registry: Pubkey,
    set: [u8; 32],
    identities: [[u8; 32]; 2],
) -> Result<()> {
    expected.identity.validate()?;
    let reg = &response.proposal.registration;
    reg.validate()?;
    ensure!(
        identities[0] != identities[1]
            && response.identity == expected.identity
            && reg.namespace.network == network
            && reg.namespace.registry == registry.to_bytes()
            && reg.namespace.enclave_set == set
            && reg.namespace.derivation_authority == expected.identity.authority()
            && reg.namespace.namespace_id == expected.namespace_id
            && response.namespace_address
                == pair_registry::namespace_address(&registry, reg)
                    .0
                    .to_string(),
        "namespace metadata changed"
    );
    let message = pair_registry::registration_message(
        reg,
        &Pubkey::new_from_array(expected.identity.authority()),
    );
    for (key, signature) in identities
        .iter()
        .zip(&response.proposal.identity_signatures)
    {
        ed25519_dalek::VerifyingKey::from_bytes(key)?
            .verify_strict(&message, &ed25519_dalek::Signature::from_slice(signature)?)?;
    }
    Ok(())
}
pub fn verify_key(q: &KeyRequest, key: &KeyResponse, identities: [[u8; 32]; 2]) -> Result<()> {
    ensure!(
        key.account == q.chain.account(q.path.clone())?
            && decode_hex(&key.public_key_hex)? == key.public_key,
        "key metadata changed"
    );
    match (q.chain.suite(), &key.multi) {
        (Some(suite), Some(m)) => {
            crate::multi::verify_key(
                &crate::multi::KeyRequest {
                    registration: q.registration.clone(),
                    account: key.account.clone(),
                    suite,
                },
                m,
                identities,
            )?;
            ensure!(
                m.key.public_key == key.public_key,
                "key certificate mismatch"
            );
        }
        (None, None) => ensure!(
            crate::derive_public(&q.registration, &key.account)?.as_slice() == key.public_key,
            "derived key mismatch"
        ),
        _ => anyhow::bail!("key suite mismatch"),
    }
    Ok(())
}
/// Canonical message adapter shared by hosted API and clients. Policy limits apply to
/// these exact bytes (serialized Intent for EVM, Zcash and Bitcoin).
pub fn prepare_message(
    q: &SigningRequest,
    key: &KeyResponse,
) -> Result<(Commit, Vec<u8>, Option<pairkey_signing::Intent>)> {
    ensure!(
        !q.message.trim().is_empty() && q.message.len() <= 256,
        "message must contain 1–256 UTF-8 bytes"
    );
    ensure!(
        key.account == q.key.chain.account(q.key.path.clone())?,
        "key path mismatch"
    );
    ensure!(
        key.multi.as_ref().map(|k| k.key.suite) == q.key.chain.suite(),
        "key suite mismatch"
    );
    let intent = key.multi.as_ref().map(|k| pairkey_signing::Intent {
        version: 1,
        key: k.key.clone(),
        payload: match q.key.chain {
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
            _ => unreachable!("suite checked above"),
        },
    });
    let bytes = match &intent {
        Some(intent) => {
            intent.validate(&q.key.registration)?;
            intent.bytes()?
        }
        None => q.message.as_bytes().to_vec(),
    };
    let commit = Commit::new(
        &q.key.registration,
        q.request_id,
        key.account.clone(),
        &bytes,
    )?;
    Ok((commit, bytes, intent))
}
/// Verify both receipt signatures, the chain signature, and the exact off-chain request.
/// Recovery remains verifiable after the request expires.
pub fn verify_result(
    q: &SigningRequest,
    request: &Request,
    key: &KeyResponse,
    result: &serde_json::Value,
    identities: [[u8; 32]; 2],
) -> Result<()> {
    super::verify_result(q, key, result, identities)?;
    let attempt: pairkey_types::Attempt = if key.multi.is_some() {
        let receipts: [crate::multi::Receipt; 2] =
            serde_json::from_value(result["receipts"].clone())?;
        receipts[0].request.attempt.clone()
    } else {
        serde_json::from_value(result["attempt"].clone())?
    };
    ensure!(
        attempt.authorization.offchain_request() == Some(request),
        "receipt off-chain approval mismatch"
    );
    crate::approval::job_id(&attempt.authorization)?;
    Ok(())
}
