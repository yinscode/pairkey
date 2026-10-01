//! Public unfunded encoding vectors. Run only from the isolated copied crate.
use ed25519_dalek::{Signer, SigningKey};
use k256::Scalar;
use pairkey_dkls23_research::{d, digest, pool, public};

fn main() {
    let identities = [
        SigningKey::from_bytes(&[41; 32]),
        SigningKey::from_bytes(&[42; 32]),
    ];
    let wallet = d::Wallet {
        version: 2,
        identities: identities.each_ref().map(|k| k.verifying_key().to_bytes()),
        namespace: "pairkey/registration/model/λ".into(),
        epoch: 17,
        key_id: [11; 32],
    };
    let openings = [
        d::Opening {
            point: public(&Scalar::from(7u64)),
            salt: [9; 32],
        },
        d::Opening {
            point: public(&Scalar::from(13u64)),
            salt: [10; 32],
        },
    ];
    let commitments = std::array::from_fn(|r| openings[r].commitment(&wallet, r as u8));
    let record = d::Record::new(wallet.clone(), commitments, openings.clone()).unwrap();
    let nonce = Scalar::from(19u64);
    let nonce_point = public(&nonce);
    let raw_challenge = pool::hash(
        "pairkey/d/possession-proof/v2",
        &[&record.digest(), &[0], &nonce_point],
    );
    use k256::elliptic_curve::{bigint::U256, ops::Reduce};
    let challenge = <Scalar as Reduce<U256>>::reduce_bytes(&raw_challenge.into());
    let response = (nonce + challenge * Scalar::from(7u64)).to_bytes().into();
    let mut endorsement = d::Endorsement {
        role: 0,
        record: record.digest(),
        commitment: nonce_point,
        response,
        signature: vec![],
    };
    let message = digest(
        b"pairkey/d/endorsement/v2",
        &(
            endorsement.record,
            endorsement.role,
            &endorsement.commitment,
            endorsement.response,
        ),
    );
    endorsement.signature = identities[0].sign(&message).to_bytes().to_vec();
    endorsement.validate(&record).unwrap();
    println!(
        "{}",
        serde_json::json!({
            "wallet_json": serde_json::to_string(&wallet).unwrap(),
            "opening_json": serde_json::to_string(&openings[0]).unwrap(),
            "record_json": serde_json::to_string(&record).unwrap(),
            "endorsement_json": serde_json::to_string(&endorsement).unwrap(),
            "wallet_digest": wallet.digest(), "commitment": commitments[0],
            "record_digest": record.digest(), "proof_challenge": raw_challenge,
            "endorsement_message": message, "native_endorsement_validation": true,
            "scope": "fixed-hash encoding and verification vectors; not programmed SHA256"
        })
    );
}
