//! Offline verification of a hosted signing transcript.
//! cargo run -p pairkey-sdk --example verify_hosted -- transcript.json
//! JSON: {"request": SigningRequest, "key": KeyResponse, "result": hosted_result,
//!        "identities": [[u8;32];2]}
use anyhow::Result;
use serde::Deserialize;
#[derive(Deserialize)]
struct Transcript {
    request: pairkey_sdk::hosted::SigningRequest,
    key: pairkey_sdk::hosted::KeyResponse,
    result: serde_json::Value,
    identities: [[u8; 32]; 2],
}
fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: verify_hosted TRANSCRIPT.json"))?;
    let t: Transcript = serde_json::from_slice(&std::fs::read(path)?)?;
    pairkey_sdk::hosted::verify_result(&t.request, &t.key, &t.result, t.identities)?;
    println!("Signature and both signer receipts verified locally against the requested message and key.");
    Ok(())
}
