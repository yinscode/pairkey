//! Public transcripts from the hosted devnet controller test; no secret material.
use pairkey_sdk::hosted::{verify_result, KeyResponse, SigningRequest};
use serde::Deserialize;
#[derive(Clone, Deserialize)]
struct Transcript {
    request: SigningRequest,
    key: KeyResponse,
    result: serde_json::Value,
    identities: [[u8; 32]; 2],
}
#[test]
fn public_transcripts_verify_and_reject_tampering_for_every_suite() {
    let cases: Vec<Transcript> =
        serde_json::from_str(include_str!("fixtures/hosted-devnet.json")).unwrap();
    for t in cases {
        let verify = |t: &Transcript| verify_result(&t.request, &t.key, &t.result, t.identities);
        verify(&t).unwrap();
        let mut changed = t.clone();
        changed.request.message.push('!');
        assert!(verify(&changed).is_err());
        let mut changed = t.clone();
        changed.request.key.path[0] ^= 1;
        assert!(verify(&changed).is_err());
        let mut changed = t.clone();
        changed.identities[0][0] ^= 1;
        assert!(verify(&changed).is_err());
        let mut changed = t.clone();
        changed.result["signature_hex"] = serde_json::json!("0x00");
        assert!(verify(&changed).is_err());
        let mut changed = t.clone();
        changed.result["receipts"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(verify(&changed).is_err());
        let mut changed = t.clone();
        changed.key.public_key_hex = "0x00".into();
        changed.result["public_key_hex"] = serde_json::json!("0x00");
        assert!(verify(&changed).is_err());
    }
}
