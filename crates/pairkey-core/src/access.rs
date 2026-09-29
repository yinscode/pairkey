//! Proof-of-possession for controller-enrolled credentials, not an identity-provider grant.
use crate::Error;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::signature::Verifier;
use pairkey_types::policy::{AccessProof, Credential};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub fn verify(
    credential: &Credential,
    proof: &AccessProof,
    challenge: [u8; 32],
) -> Result<(), Error> {
    credential.validate().map_err(|_| Error::Authorization)?;
    match (credential, proof) {
        (Credential::Service { public_key }, AccessProof::Service { signature }) => {
            ed25519_dalek::VerifyingKey::from_bytes(public_key)
                .and_then(|key| {
                    key.verify_strict(
                        &challenge,
                        &ed25519_dalek::Signature::from_slice(signature)?,
                    )
                })
                .map_err(|_| Error::Authorization)
        }
        (
            Credential::Passkey {
                public_key,
                rp_id,
                origin,
            },
            AccessProof::Passkey {
                authenticator_data,
                client_data_json,
                signature_der,
            },
        ) => {
            // Bounded ES256 assertions. Extensions are unsupported and refused.
            if authenticator_data.len() != 37
                || client_data_json.len() > 2048
                || signature_der.len() > 80
            {
                return Err(Error::Authorization);
            }
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct ClientData {
                #[serde(rename = "type")]
                kind: String,
                challenge: String,
                origin: String,
                #[serde(default)]
                cross_origin: bool,
                top_origin: Option<String>,
            }
            let client: ClientData =
                serde_json::from_slice(client_data_json).map_err(|_| Error::Authorization)?;
            let flags = authenticator_data[32];
            if client.kind != "webauthn.get"
                || client.origin != *origin
                || client.cross_origin
                || client.top_origin.is_some()
                || client.challenge != URL_SAFE_NO_PAD.encode(challenge)
                || authenticator_data[..32] != Sha256::digest(rp_id.as_bytes())[..]
                || flags & 0x05 != 0x05
                || flags & 0xe2 != 0
                || (flags & 0x10 != 0 && flags & 0x08 == 0)
            {
                return Err(Error::Authorization);
            }
            let mut signed = authenticator_data.clone();
            signed.extend_from_slice(&Sha256::digest(client_data_json));
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| Error::Authorization)?;
            let sig = p256::ecdsa::Signature::from_der(signature_der)
                .map_err(|_| Error::Authorization)?;
            key.verify(&signed, &sig).map_err(|_| Error::Authorization)
        }
        _ => Err(Error::Authorization),
    }
}
