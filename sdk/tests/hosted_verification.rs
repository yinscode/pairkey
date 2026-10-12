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

#[test]
fn typed_transaction_preparation_binds_solana_evm_and_near_signing_payloads() {
    use pairkey_sdk::hosted::{offchain::prepare_message, Chain, TransactionRequest};
    use pairkey_signing::transaction::{NearAction, NearPublicKey, NearTransaction, Transaction};
    use solana_sdk::{
        hash::Hash,
        message::{Message, VersionedMessage},
        pubkey::Pubkey,
        system_instruction,
    };
    let cases: Vec<Transcript> =
        serde_json::from_str(include_str!("fixtures/hosted-devnet.json")).unwrap();
    let find = |chain| {
        cases
            .iter()
            .find(|case| case.request.key.chain == chain)
            .unwrap()
            .clone()
    };

    let mut sol = find(Chain::Solana);
    let signer = Pubkey::new_from_array(sol.key.public_key.clone().try_into().unwrap());
    let message = Message::new_with_blockhash(
        &[system_instruction::transfer(
            &signer,
            &Pubkey::new_unique(),
            1,
        )],
        Some(&signer),
        &Hash::new_unique(),
    );
    let serialized = bincode::serialize(&VersionedMessage::Legacy(message)).unwrap();
    sol.request.message.clear();
    sol.request.transaction = Some(TransactionRequest::Solana {
        message: serialized.clone(),
    });
    let (commit, payload, intent) = prepare_message(&sol.request, &sol.key).unwrap();
    assert!(intent.is_none());
    assert_eq!(
        payload,
        Transaction::Solana {
            message: serialized.clone()
        }
        .bytes()
        .unwrap()
    );
    commit
        .authorize(&sol.request.key.registration, &payload)
        .unwrap();

    let mut near = find(Chain::Near);
    let public: [u8; 32] = near.key.public_key.clone().try_into().unwrap();
    let tx = NearTransaction {
        signer_id: "alice.near".into(),
        public_key: NearPublicKey::Ed25519(public),
        nonce: 1,
        receiver_id: "bob.near".into(),
        block_hash: [9; 32],
        actions: vec![NearAction::Transfer { deposit: 1 }],
    };
    let serialized = borsh::to_vec(&tx).unwrap();
    near.request.message.clear();
    near.request.transaction = Some(TransactionRequest::Near {
        transaction: serialized.clone(),
    });
    let (_, near_payload, intent) = prepare_message(&near.request, &near.key).unwrap();
    assert!(intent.is_none());
    assert_eq!(
        near_payload,
        Transaction::Near {
            transaction: serialized
        }
        .bytes()
        .unwrap()
    );

    let mut evm = find(Chain::Evm);
    let transfer = pairkey_signing::evm::Transfer {
        chain_id: 84532,
        nonce: 1,
        gas_price: 2,
        gas_limit: 21_000,
        to: [3; 20],
        value: 4,
    };
    evm.request.message.clear();
    evm.request.transaction = Some(TransactionRequest::EvmLegacy {
        transfer: transfer.clone(),
    });
    let (_, evm_payload, intent) = prepare_message(&evm.request, &evm.key).unwrap();
    assert!(
        matches!(intent.unwrap().payload,pairkey_signing::Payload::EvmTransfer(t) if t==transfer)
    );
    let mut changed = evm.request.clone();
    if let Some(TransactionRequest::EvmLegacy { transfer }) = &mut changed.transaction {
        transfer.value += 1;
    }
    assert_ne!(evm_payload, prepare_message(&changed, &evm.key).unwrap().1);
}
