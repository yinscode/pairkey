//! Time a hosted account message-signing path without sending an on-chain transaction.
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use pairkey_sdk::hosted::{
    offchain::{self, NamespaceRequest, PrepareRequest},
    Chain, Client, KeyRequest, SigningRequest,
};
use pairkey_types::approval::{Identity, Proof};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use solana_sdk::pubkey::Pubkey;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn ms(start: Instant) -> u128 {
    start.elapsed().as_millis()
}

#[tokio::main]
async fn main() -> Result<()> {
    let endpoint = std::env::var("PAIRKEY_LATENCY_ENDPOINT")
        .unwrap_or_else(|_| "https://pairkey.com/api/v2".into());
    let attempts: usize = std::env::var("PAIRKEY_LATENCY_ATTEMPTS")
        .ok()
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(2);
    anyhow::ensure!((1..=5).contains(&attempts), "attempts must be 1–5");
    let chain: Chain = serde_json::from_value(Value::String(
        std::env::var("PAIRKEY_LATENCY_CHAIN").unwrap_or_else(|_| "evm".into()),
    ))?;
    let client = Client::new(endpoint)?;
    let config: Value = client.get("/config").await?;
    anyhow::ensure!(config["ready"] == true, "hosted demo is not ready");
    let network: Pubkey = config["genesis_hash"]
        .as_str()
        .context("genesis_hash")?
        .parse()?;
    let registry: Pubkey = config["registry"].as_str().context("registry")?.parse()?;
    let set: [u8; 32] = serde_json::from_value(config["enclave_set"].clone())?;
    let identities: [[u8; 32]; 2] = serde_json::from_value(config["signer_identities"].clone())?;
    let mut seed = [0; 32];
    if let Ok(path) = std::env::var("PAIRKEY_LATENCY_SIGNING_KEY_PATH") {
        let keypair: Vec<u8> = serde_json::from_slice(&std::fs::read(path)?)?;
        anyhow::ensure!(keypair.len() == 64, "expected a Solana keypair file");
        seed.copy_from_slice(&keypair[..32]);
    } else {
        OsRng.fill_bytes(&mut seed);
    }
    let caller = SigningKey::from_bytes(&seed);
    let identity = Identity::Account {
        public_key: caller.verifying_key().to_bytes(),
    };
    let namespace = client
        .offchain_namespace(
            &NamespaceRequest {
                identity: identity.clone(),
                namespace_id: [0; 32],
            },
            network.to_bytes(),
            registry,
            set,
            identities,
        )
        .await?;
    let key_request = KeyRequest {
        registration: namespace.proposal.registration,
        chain,
        path: vec![0],
    };
    let key = client.offchain_key(&key_request, identities).await?;
    for index in 0..attempts {
        let total = Instant::now();
        let mut request_id = [0; 32];
        OsRng.fill_bytes(&mut request_id);
        let prepare_request = PrepareRequest {
            signing_request: SigningRequest {
                key: key_request.clone(),
                request_id,
                message: format!("PairKey {chain:?} latency probe {}", index + 1),
            },
            identity: identity.clone(),
        };
        let t = Instant::now();
        let mut retries = 0;
        let prepared = loop {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            match client
                .prepare_offchain(&prepare_request, &key, identities, now)
                .await
            {
                Ok(prepared) => break prepared,
                Err(error) if retries < 3 => {
                    retries += 1;
                    eprintln!("approval preparation retry {retries}: {error}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(error) => return Err(error).context("prepare hosted approval"),
            }
        };
        let prepare_ms = ms(t);
        let submission = prepared.clone().submission(Proof::Account {
            signature: caller.sign(&prepared.signing_message).to_bytes().to_vec(),
        });
        let t = Instant::now();
        let id = client.submit_offchain(&submission).await?;
        let submit_ms = ms(t);
        let t = Instant::now();
        let mut polls = 0;
        let result = loop {
            polls += 1;
            let status: Value = client.get(&format!("/jobs/{id}")).await?;
            if status["status"] == "complete" {
                break status["result"].clone();
            }
            if status["status"] == "failed" {
                bail!("signing failed: {}", status["error"]);
            }
            anyhow::ensure!(t.elapsed() < Duration::from_secs(90), "signing timed out");
            tokio::time::sleep(Duration::from_millis(750)).await;
        };
        let wait_ms = ms(t);
        let t = Instant::now();
        offchain::verify_result(
            &prepared.signing_request,
            &prepared.request,
            &key,
            &result,
            identities,
        )?;
        println!(
            "{}",
            json!({"chain":chain,"attempt":index+1,"prepare_ms":prepare_ms,"preparation_retries":retries,"submit_ms":submit_ms,"wait_ms":wait_ms,"verify_ms":ms(t),"total_ms":ms(total),"polls":polls})
        );
    }
    Ok(())
}
