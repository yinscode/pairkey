//! Consumer API: permanent approvals are submitted on Solana separately.
use anyhow::{ensure, Context};
use pairkey_types::{
    receipt::{receipt_message, ResultResponse},
    Attempt, Commit, Registration, Role,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    pub namespace: pairkey_types::Namespace,
    pub controller: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationProposal {
    pub registration: Registration,
    pub identity_signatures: [Vec<u8>; 2],
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    endpoint: String,
}
impl Client {
    pub fn new(endpoint: String) -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()?,
            endpoint,
        })
    }
    pub async fn submit(
        &self,
        reg: &Registration,
        commit: &Commit,
        message: &[u8],
    ) -> anyhow::Result<String> {
        commit.authorize(reg, message)?;
        let response = self
            .http
            .post(format!("{}/jobs", self.endpoint))
            .json(&json!({"registration":reg,"commit":commit,"message":message}))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let result: Value =
            crate::http::bounded_json(response, crate::http::MAX_SERVICE_RESPONSE).await?;
        Ok(result["job_id"].as_str().context("invalid job id")?.into())
    }
    pub async fn namespace(
        &self,
        namespace: pairkey_types::Namespace,
        controller: [u8; 32],
        identities: [[u8; 32]; 2],
    ) -> anyhow::Result<RegistrationProposal> {
        namespace.validate()?;
        let request = RegistrationRequest {
            namespace: namespace.clone(),
            controller,
        };
        let response = self
            .http
            .post(format!("{}/registrations", self.endpoint))
            .json(&request)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let proposal: RegistrationProposal =
            crate::http::bounded_json(response, crate::http::MAX_SERVICE_RESPONSE).await?;
        ensure!(
            proposal.registration.namespace == namespace
                && namespace.derivation_authority == controller,
            "registration namespace mismatch"
        );
        proposal.registration.validate()?;
        let message = pair_registry::registration_message(
            &proposal.registration,
            &solana_sdk::pubkey::Pubkey::new_from_array(controller),
        );
        for (key, sig) in identities.iter().zip(&proposal.identity_signatures) {
            ed25519_dalek::VerifyingKey::from_bytes(key)?
                .verify_strict(&message, &ed25519_dalek::Signature::from_slice(sig)?)?;
        }
        Ok(proposal)
    }
    pub async fn poll(&self, id: &str) -> anyhow::Result<Value> {
        ensure!(
            id.parse::<solana_sdk::pubkey::Pubkey>().is_ok(),
            "invalid job id"
        );
        let response = self
            .http
            .get(format!("{}/jobs/{id}", self.endpoint))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        crate::http::bounded_json(response, crate::http::MAX_SERVICE_RESPONSE).await
    }
    /// Response body is SSE; callers consume incremental events with `chunk().await`.
    pub async fn subscribe(&self, id: &str) -> anyhow::Result<reqwest::Response> {
        ensure!(
            id.parse::<solana_sdk::pubkey::Pubkey>().is_ok(),
            "invalid job id"
        );
        Ok(self
            .http
            .get(format!("{}/jobs/{id}/events", self.endpoint))
            .send()
            .await?
            .error_for_status()?)
    }
}
pub fn verify_receipt(
    reg: &Registration,
    attempt: &Attempt,
    message: &[u8],
    response: &ResultResponse,
    identity: [u8; 32],
    role: Role,
    allow_development: bool,
) -> anyhow::Result<()> {
    let r = &response.receipt;
    pairkey_channel::verify_attestation(
        &response.attestation,
        identity,
        role,
        r.peer_boot,
        allow_development,
    )?;
    ensure!(
        response.attestation.evidence.boot_id == r.boot_id,
        "receipt boot does not match attestation"
    );
    ensure!(
        r.version == 1
            && r.development == allow_development
            && r.role == role
            && r.attempt_digest == attempt.digest()
            && r.message_hash == attempt.commit.message_hash
            && r.public_key == crate::derive_public(reg, &attempt.commit.account)?,
        "receipt context mismatch"
    );
    let sig: [u8; 64] = r
        .signature
        .as_slice()
        .try_into()
        .context("signature length")?;
    ensure!(
        crate::verify_signature(reg, &attempt.commit, message, &sig),
        "invalid native signature"
    );
    ed25519_dalek::VerifyingKey::from_bytes(&identity)?.verify_strict(
        &receipt_message(r),
        &ed25519_dalek::Signature::from_slice(&response.identity_signature)?,
    )?;
    Ok(())
}
