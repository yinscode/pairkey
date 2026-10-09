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

#[test]
fn offchain_preparation_preserves_all_existing_chain_encodings_and_checks_exact_inputs() {
    use pairkey_sdk::hosted::offchain::{prepare_message, PrepareRequest, Prepared};
    use pairkey_types::approval::{Identity, Request, Rules};
    let cases: Vec<Transcript> =
        serde_json::from_str(include_str!("fixtures/hosted-devnet.json")).unwrap();
    for t in cases {
        let (commit, payload, _) = prepare_message(&t.request, &t.key).unwrap();
        let previous: pairkey_types::Attempt = serde_json::from_value(if t.key.multi.is_some() {
            t.result["receipts"][0]["request"]["attempt"].clone()
        } else {
            t.result["attempt"].clone()
        })
        .unwrap();
        assert_eq!(
            commit, previous.commit,
            "legacy key/message encoding must not change"
        );
        let identity = Identity::Account {
            public_key: t.request.key.registration.namespace.derivation_authority,
        };
        let expected = PrepareRequest {
            signing_request: t.request.clone(),
            identity: identity.clone(),
        };
        let rules = Rules::default();
        let request = Request {
            version: 1,
            identity,
            commit,
            policy_revision: 0,
            policy_digest: rules.digest(),
            issued_at: 100,
            expires_at: 300,
        };
        let prepared = Prepared {
            signing_request: t.request.clone(),
            signing_message: request.signing_message(),
            request,
            rules,
            payload,
        };
        prepared
            .verify(&expected, &t.key, t.identities, 100)
            .unwrap();
        let mut changed = prepared.clone();
        changed.payload[0] ^= 1;
        assert!(changed
            .verify(&expected, &t.key, t.identities, 100)
            .is_err());
        let mut changed = prepared.clone();
        changed.signing_request.message.push('!');
        assert!(changed
            .verify(&expected, &t.key, t.identities, 100)
            .is_err());
        let mut changed = prepared.clone();
        changed.signing_message[0] ^= 1;
        assert!(changed
            .verify(&expected, &t.key, t.identities, 100)
            .is_err());
        let mut changed = prepared.clone();
        changed.request.policy_digest[0] ^= 1;
        changed.signing_message = changed.request.signing_message();
        assert!(changed
            .verify(&expected, &t.key, t.identities, 100)
            .is_err());
        assert!(prepared
            .verify(&expected, &t.key, t.identities, 300)
            .is_err());
        assert!(
            pairkey_sdk::hosted::offchain::verify_result(
                &t.request,
                &prepared.request,
                &t.key,
                &t.result,
                t.identities
            )
            .is_err(),
            "legacy receipts cannot be substituted for an off-chain approval"
        );
    }
}
