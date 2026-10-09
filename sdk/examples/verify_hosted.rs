//! Offline verification of a hosted signing transcript.
//! cargo run -p pairkey-sdk --example verify_hosted -- transcript.json
//! JSON: {"request": SigningRequest, "key": KeyResponse, "result": hosted_result,
//!        "identities": [[u8;32];2], "approval": Request (required for v2)}
use anyhow::Result;
use serde::Deserialize;
#[derive(Deserialize)]
struct Transcript {
    request: pairkey_sdk::hosted::SigningRequest,
    key: pairkey_sdk::hosted::KeyResponse,
    result: serde_json::Value,
    identities: [[u8; 32]; 2],
    approval: Option<pairkey_types::approval::Request>,
}
fn verify(t: &Transcript) -> Result<()> {
    if let Some(approval) = &t.approval {
        pairkey_sdk::hosted::offchain::verify_result(
            &t.request,
            approval,
            &t.key,
            &t.result,
            t.identities,
        )
    } else {
        let attempt: pairkey_types::Attempt = serde_json::from_value(if t.key.multi.is_some() {
            t.result["receipts"][0]["request"]["attempt"].clone()
        } else {
            t.result["attempt"].clone()
        })?;
        anyhow::ensure!(
            attempt.authorization.offchain_request().is_none(),
            "v2 verification requires the original approval request"
        );
        pairkey_sdk::hosted::verify_result(&t.request, &t.key, &t.result, t.identities)
    }
}
fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: verify_hosted TRANSCRIPT.json"))?;
    let t: Transcript = serde_json::from_slice(&std::fs::read(path)?)?;
    verify(&t)?;
    println!("Signature and both signer receipts verified locally against the requested message and key.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_transcripts_still_verify_and_offchain_approvals_cannot_be_omitted() {
        let cases: Vec<Transcript> =
            serde_json::from_str(include_str!("../tests/fixtures/hosted-devnet.json")).unwrap();
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../website/fixtures/offchain-vectors.json"))
                .unwrap();
        for (i, mut t) in cases.into_iter().enumerate() {
            verify(&t).unwrap();
            let attempt = if t.key.multi.is_some() {
                &mut t.result["receipts"][0]["request"]["attempt"]
            } else {
                &mut t.result["attempt"]
            };
            attempt["authorization"]["access_proof"] = serde_json::json!({"Offchain":{"request":vectors["cases"][i]["prepared"]["request"],"proof_digest":vec![0;32]}});
            assert!(verify(&t)
                .unwrap_err()
                .to_string()
                .contains("requires the original approval"));
        }
    }
}
