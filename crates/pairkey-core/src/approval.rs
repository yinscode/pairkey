//! Identity authentication for the new approval format. Chain observations and durable
//! request claims must still be checked by each worker before any signing round.
use crate::{access, Error};
use pairkey_types::{
    approval::{Approval, Identity, Proof, Rules},
    policy::{AccessProof, Credential},
    Registration,
};

pub fn verify(
    registration: &Registration,
    payload: &[u8],
    rules: &Rules,
    approval: &Approval,
    now: i64,
) -> Result<(), Error> {
    let request = &approval.request;
    request
        .validate(registration, payload, rules, now)
        .map_err(|_| Error::Authorization)?;
    let message = request.signing_message();
    match (&request.identity, &approval.proof) {
        (Identity::Account { public_key }, Proof::Account { signature }) => {
            ed25519(public_key, signature, &message)
        }
        (
            Identity::Passkey {
                public_key,
                rp_id,
                origin,
            },
            Proof::Passkey {
                binding,
                assertion,
                signature,
            },
        ) => {
            binding
                .validate(registration, request, now)
                .map_err(|_| Error::Authorization)?;
            access::verify(
                &Credential::Passkey {
                    public_key: public_key.clone(),
                    rp_id: rp_id.clone(),
                    origin: origin.clone(),
                },
                &AccessProof::Passkey {
                    authenticator_data: assertion.authenticator_data.clone(),
                    client_data_json: assertion.client_data_json.clone(),
                    signature_der: assertion.signature_der.clone(),
                },
                binding.challenge(),
            )?;
            ed25519(&binding.public_key, signature, &message)
        }
        // A JWT is never accepted without a configured, independently verified issuer.
        // The OIDC adapter is added separately; mismatched proof variants also fail closed.
        _ => Err(Error::Authorization),
    }
}

fn ed25519(public_key: &[u8; 32], signature: &[u8], message: &[u8]) -> Result<(), Error> {
    ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .and_then(|key| {
            key.verify_strict(message, &ed25519_dalek::Signature::from_slice(signature)?)
        })
        .map_err(|_| Error::Authorization)
}

#[cfg(test)]
mod tests;
