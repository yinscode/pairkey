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
        self.call_bounded(method, params, crate::http::MAX_RPC_RESPONSE)
            .await
    }
    /// Larger bound is used only for immutable executable bytes; streaming remains bounded.
    pub async fn call_bounded(
        &self,
        method: &str,
        params: Value,
        limit: usize,
    ) -> anyhow::Result<Value> {
        anyhow::ensure!(
            limit <= 4 * 1024 * 1024,
            "RPC bound exceeds platform maximum"
        );
        let response = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?
            .error_for_status()
            .map_err(reqwest::Error::without_url)?;
        let body = crate::http::bounded_body(response, limit).await?;
        let value: Value = serde_json::from_slice(&body)?;
        if let Some(error) = value.get("error") {
            anyhow::bail!("RPC {method}: {error}");
        }
        Ok(value
            .get("result")
            .ok_or_else(|| anyhow::anyhow!("missing RPC result"))?
            .clone())
    }

    /// Resolve immutable loader code from independently fetched finalized accounts.
    pub async fn executable(
        &self,
        program: solana_sdk::pubkey::Pubkey,
        minimum_slot: u64,
    ) -> anyhow::Result<pairkey_core::ExecutableObservation> {
        use solana_sdk::{
            bpf_loader_upgradeable::{self, UpgradeableLoaderState},
            pubkey::Pubkey,
        };
        async fn account(
            rpc: &Rpc,
            key: Pubkey,
            minimum_slot: u64,
        ) -> anyhow::Result<(pairkey_core::ObservedAccount, bool)> {
            let response=rpc.call_bounded("getAccountInfo",json!([key.to_string(),{"encoding":"base64","commitment":"finalized","minContextSlot":minimum_slot}]),4*1024*1024).await?;
            anyhow::ensure!(
                response["context"]["slot"]
                    .as_u64()
                    .is_some_and(|s| s >= minimum_slot),
                "stale executable observation"
            );
            let value = &response["value"];
            anyhow::ensure!(value["data"][1] == "base64", "invalid executable encoding");
            Ok((
                pairkey_core::ObservedAccount {
                    address: key,
                    owner: value["owner"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("executable owner"))?
                        .parse()?,
                    data: STANDARD.decode(
                        value["data"][0]
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("executable bytes"))?,
                    )?,
                },
                value["executable"]
                    .as_bool()
                    .ok_or_else(|| anyhow::anyhow!("executable flag"))?,
            ))
        }
        let (code, executable) = account(self, program, minimum_slot).await?;
        let program_data = if code.owner == bpf_loader_upgradeable::id() {
            let state: UpgradeableLoaderState = bincode::deserialize(&code.data)?;
            let UpgradeableLoaderState::Program {
                programdata_address,
            } = state
            else {
                anyhow::bail!("invalid program pointer");
            };
            Some(account(self, programdata_address, minimum_slot).await?.0)
        } else {
            None
        };
        let observation = pairkey_core::ExecutableObservation {
            program,
            owner: code.owner,
            executable,
            code: code.data,
            program_data,
        };
        observation.hash().map_err(|error| anyhow::anyhow!("executable verification failed: {error}; owner={}, executable={}, program_len={}, program_data={:?}", observation.owner, observation.executable, observation.code.len(), observation.program_data.as_ref().map(|data|(data.address,data.owner,data.data.len(), bincode::deserialize::<UpgradeableLoaderState>(&data.data[..data.data.len().min(45)]).ok()))))?;
        Ok(observation)
    }
    pub async fn send_bytes(&self, bytes: &[u8]) -> anyhow::Result<Signature> {
        let result = self.call("sendTransaction", json!([STANDARD.encode(bytes), {"encoding":"base64", "preflightCommitment":"finalized"}])).await?;
        Ok(result
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid signature response"))?
            .parse()?)
    }
}
