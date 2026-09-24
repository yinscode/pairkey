use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use solana_sdk::signature::Signature;

#[derive(Clone)]
pub struct Rpc {
    client: reqwest::Client,
    url: String,
}
impl Rpc {
    pub fn new(url: String) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .build()?,
            url,
        })
    }
    pub async fn call(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let response = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?
            .error_for_status()
            .map_err(reqwest::Error::without_url)?;
        let body = crate::http::bounded_body(response, crate::http::MAX_RPC_RESPONSE).await?;
        let value: Value = serde_json::from_slice(&body)?;
        if let Some(error) = value.get("error") {
            anyhow::bail!("RPC {method}: {error}");
        }
        Ok(value
            .get("result")
            .ok_or_else(|| anyhow::anyhow!("missing RPC result"))?
            .clone())
    }
    pub async fn send_bytes(&self, bytes: &[u8]) -> anyhow::Result<Signature> {
        let result = self.call("sendTransaction", json!([STANDARD.encode(bytes), {"encoding":"base64", "preflightCommitment":"finalized"}])).await?;
        Ok(result
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid signature response"))?
            .parse()?)
    }
}
