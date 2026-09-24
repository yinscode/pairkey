//! Bounded HTTP reads shared by RPC, relay and consumer clients.
use anyhow::ensure;
use serde::de::DeserializeOwned;

pub const MAX_SERVICE_RESPONSE: usize = 32_768;
pub const MAX_RPC_RESPONSE: usize = 100_000;

pub async fn bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> anyhow::Result<Vec<u8>> {
    if let Some(length) = response.content_length() {
        ensure!(length <= limit as u64, "HTTP response exceeds limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)?
    {
        ensure!(
            chunk.len() <= limit.saturating_sub(body.len()),
            "HTTP response exceeds limit"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub async fn bounded_json<T: DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
) -> anyhow::Result<T> {
    let response = response
        .error_for_status()
        .map_err(reqwest::Error::without_url)?;
    Ok(serde_json::from_slice(
        &bounded_body(response, limit).await?,
    )?)
}
