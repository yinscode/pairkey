//! Build operation-bound proofs. Enrollment/revocation require the actual controller.
use ed25519_dalek::Signer;
pub use pairkey_types::policy::solana_destination;
use pairkey_types::{
    policy::{AccessProof, Authorization, SessionGrant},
    Commit,
};
pub fn session_challenge(auth: &Authorization, commit: &Commit, grant: &SessionGrant) -> [u8; 32] {
    auth.challenge(commit, Some(grant), b"pairkey/session-request/v1")
}
pub fn access_challenge(auth: &Authorization, commit: &Commit) -> [u8; 32] {
    auth.challenge(commit, None, b"pairkey/access-request/v1")
}
pub fn service_proof(key: &ed25519_dalek::SigningKey, challenge: [u8; 32]) -> AccessProof {
    AccessProof::Service {
        signature: key.sign(&challenge).to_bytes().to_vec(),
    }
}
