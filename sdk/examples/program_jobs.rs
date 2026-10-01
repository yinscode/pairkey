//! Minimal CPI-controlled COMMIT -> durable job client. Run with an application JSON config.
//! Namespace registration and the example-controller owner must already be enrolled on Solana.
use anyhow::{ensure, Context};
use pairkey_sdk::{
    multi::{self, Intent, KeyRequest},
    rpc::Rpc,
    service::Client,
};
use pairkey_types::{Attempt, Commit};
use serde::Deserialize;
use serde_json::json;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    hash::Hash,
    signature::{read_keypair_file, Signer},
    transaction::Transaction,
};
use std::time::Duration;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    coordinator: String,
    solana_rpc: String,
    owner_keypair: String,
    identities: [[u8; 32]; 2],
    key: KeyRequest,
    payload: multi::Payload,
    request_id: [u8; 32],
    /// Use a new unpredictable ID for each explicit signing retry.
    attempt_id: [u8; 32],
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::env::args()
        .nth(1)
        .context("usage: program_jobs APP_CONFIG.json")?;
    let cfg: Config = serde_json::from_slice(&std::fs::read(file)?)?;
    let owner =
        read_keypair_file(&cfg.owner_keypair).map_err(|e| anyhow::anyhow!("owner keypair: {e}"))?;
    let controller = example_controller::authority(&example_controller::id(), &owner.pubkey()).0;
    ensure!(
        cfg.key.registration.namespace.derivation_authority == controller.to_bytes(),
        "namespace must be controlled by this program PDA"
    );
    let client = Client::new(cfg.coordinator)?;
    let key = client.signing_key(&cfg.key, cfg.identities).await?;
    let intent = Intent {
        version: 1,
        key: key.key,
        payload: cfg.payload,
    };
    let commit = Commit::new(
        &cfg.key.registration,
        cfg.request_id,
        cfg.key.account,
        &intent.bytes()?,
    )?;
    let rpc = Rpc::new(cfg.solana_rpc)?;
    let blockhash = rpc
        .call("getLatestBlockhash", json!([{"commitment":"finalized"}]))
        .await?;
    let blockhash: Hash = blockhash["value"]["blockhash"]
        .as_str()
        .context("blockhash")?
        .parse()?;
    let approval = pairkey_sdk::through_controller(
        owner.pubkey(),
        pairkey_sdk::commit(
            owner.pubkey(),
            controller,
            &cfg.key.registration,
            commit.clone(),
        ),
    );
    let tx = Transaction::new_signed_with_payer(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            approval,
        ],
        Some(&owner.pubkey()),
        &[&owner],
        blockhash,
    );
    let signature = rpc.send_bytes(&bincode::serialize(&tx)?).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let statuses = rpc
            .call(
                "getSignatureStatuses",
                json!([[signature.to_string()],{"searchTransactionHistory":true}]),
            )
            .await?;
        let status = &statuses["value"][0];
        if !status.is_null() {
            ensure!(status["err"].is_null(), "program approval failed: {status}");
            if status["confirmationStatus"] == "finalized" {
                break;
            }
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "approval finalization timeout; reconcile transaction before retrying"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let request = multi::SignRequest {
        protocol: multi::PROTOCOL_VERSION,
        registration: cfg.key.registration,
        attempt: Attempt {
            commit,
            random_id: cfg.attempt_id,
            authorization: Default::default(),
        },
        intent,
        certificate: key.certificate,
    };
    let job_id = client.submit_intent(&request).await?;
    eprintln!("job_id={job_id}");
    // Persist the request and job ID in application state. A wait timeout is not a signing failure.
    let result = client
        .wait_intent(&request, cfg.identities, Duration::from_secs(180))
        .await?;
    println!("{}", serde_json::to_string(&result)?);
    // Submit to the selected destination separately; see demo-program-jobs.sh for execution,
    // scoped EVM grants and program-driven revocation. Never auto-retry a destination transfer.
    Ok(())
}
