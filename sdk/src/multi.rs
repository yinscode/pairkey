//! Local multi-suite API. Registry policy authorizes each exact intent via COMMIT or scoped EVM SESSION.
use anyhow::{ensure, Result};
pub use pairkey_signing::{evm, wire::*, Intent, Key, Payload, Suite};
impl crate::service::Client {
    pub async fn signing_key(
        &self,
        q: &KeyRequest,
        identities: [[u8; 32]; 2],
    ) -> Result<KeyResponse> {
        let response = self
            .http
            .post(format!("{}/multi/keys", self.endpoint))
            .json(q)
            .timeout(std::time::Duration::from_secs(90))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let key: KeyResponse = read_response(response).await?;
        verify_key(q, &key, identities)?;
        Ok(key)
    }
    pub async fn sign_intent(&self, q: &SignRequest, identities: [[u8; 32]; 2]) -> Result<Signed> {
        q.validate()?;
        let response = self
            .http
            .post(format!("{}/multi/sign", self.endpoint))
            .json(q)
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let result: Signed = read_response(response).await?;
        verify_result(q, &result, identities)?;
        Ok(result)
    }
}
pub fn verify_key(q: &KeyRequest, r: &KeyResponse, identities: [[u8; 32]; 2]) -> Result<()> {
    for (i, info) in r.infos.iter().enumerate() {
        info.verify(identities[i])?;
        ensure!(
            info.role.index() == i
                && info.request.registration == q.registration
                && info.request.account == q.account
                && info.request.suite == q.suite,
            "key info binding"
        );
    }
    match &r.certificate {
        Certificate::Dkls(c) => ensure!(
            c.record.wallet.identities == r.infos.clone().map(|i| i.dkls_identity),
            "DKLS enrollment mismatch"
        ),
        Certificate::RedPallas(p) => {
            for i in 0..2 {
                ensure!(
                    serde_json::to_vec(&p.proofs[i])?
                        == serde_json::to_vec(
                            &r.infos[i]
                                .redpallas
                                .as_ref()
                                .ok_or_else(|| anyhow::anyhow!("missing proof"))?
                        )?,
                    "RedPallas enrollment mismatch"
                );
            }
        }
    }
    ensure!(r.certificate.key(q)? == r.key, "key certificate mismatch");
    r.key.validate(&q.registration)
}
pub fn verify_result(q: &SignRequest, r: &Signed, identities: [[u8; 32]; 2]) -> Result<()> {
    q.validate()?;
    q.intent.verify(&r.signature)?;
    for (i, receipt) in r.receipts.iter().enumerate() {
        receipt.verify(identities[i])?;
        ensure!(
            receipt.role.index() == i
                && receipt.request.registration == q.registration
                && receipt.request.attempt.digest() == q.attempt.digest()
                && receipt.request.intent == q.intent
                && receipt.signature == r.signature
                && receipt.finalized_slot > 0,
            "receipt request mismatch"
        );
        ensure!(
            receipt.peer_boot == r.receipts[1 - i].boot,
            "receipt peer boot mismatch"
        );
    }
    Ok(())
}

async fn read_response<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let bytes = crate::http::bounded_body(response, 128 * 1024).await?;
    ensure!(
        status.is_success(),
        "multi-suite request rejected ({status}): {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(serde_json::from_slice(&bytes)?)
}

/// Durable transport status. A terminal failure does not prove that no signature escaped.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentJob {
    Queued,
    Working,
    Complete {
        result: Box<Signed>,
    },
    Failed {
        code: String,
        error: String,
        may_have_signed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_secs: Option<u64>,
    },
}
impl IntentJob {
    pub fn terminal(&self) -> bool {
        matches!(self, Self::Complete { .. } | Self::Failed { .. })
    }
}
/// The same exact submission has one job ID during the coordinator's retention window.
pub fn intent_job_id(q: &SignRequest) -> Result<String> {
    q.validate()?;
    Ok(
        solana_sdk::pubkey::Pubkey::new_from_array(pairkey_types::digest(
            b"pairkey/intent-job/v2",
            &serde_json::to_vec(q)?,
        ))
        .to_string(),
    )
}
impl crate::service::Client {
    pub async fn submit_intent(&self, q: &SignRequest) -> Result<String> {
        let expected = intent_job_id(q)?;
        let response = self
            .http
            .post(format!("{}/jobs", self.endpoint))
            .json(&serde_json::json!({"signing": q}))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let value: serde_json::Value = read_response(response).await?;
        ensure!(value["job_id"] == expected, "job identifier mismatch");
        Ok(expected)
    }
    pub async fn poll_intent(
        &self,
        q: &SignRequest,
        identities: [[u8; 32]; 2],
    ) -> Result<IntentJob> {
        let id = intent_job_id(q)?;
        let response = self
            .http
            .get(format!("{}/jobs/{id}", self.endpoint))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let job: IntentJob = read_response(response).await?;
        if let IntentJob::Complete { result } = &job {
            verify_result(q, result, identities)?;
        }
        Ok(job)
    }
    /// Cancels coordinator delivery, not Solana authority or an already issued signature.
    pub async fn cancel_intent(&self, q: &SignRequest) -> Result<()> {
        let id = intent_job_id(q)?;
        let response = self
            .http
            .post(format!("{}/jobs/{id}/cancel", self.endpoint))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let _: serde_json::Value = read_response(response).await?;
        Ok(())
    }
    pub async fn wait_intent(
        &self,
        q: &SignRequest,
        identities: [[u8; 32]; 2],
        timeout: std::time::Duration,
    ) -> Result<Signed> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match tokio::time::timeout_at(deadline, self.poll_intent(q, identities)).await?? {
                IntentJob::Complete { result } => return Ok(*result),
                IntentJob::Failed {
                    code,
                    error,
                    may_have_signed,
                    ..
                } => anyhow::bail!("{code}: {error}; may_have_signed={may_have_signed}"),
                _ => (),
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "job wait timeout; poll the same job before retrying"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

/// Explicit retry changes only the signing attempt; Solana approval and delegate scope stay bound.
pub fn fresh_attempt(q: &SignRequest, random_id: [u8; 32]) -> Result<SignRequest> {
    ensure!(
        random_id != q.attempt.random_id,
        "retry requires a fresh attempt ID"
    );
    let mut next = q.clone();
    next.attempt.random_id = random_id;
    next.validate()?;
    Ok(next)
}
