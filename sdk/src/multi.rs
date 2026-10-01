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
