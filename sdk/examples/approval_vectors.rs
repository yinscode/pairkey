//! Cross-language browser fixtures from Rust's canonical encoders and public keys.
//! cargo run -p pairkey-sdk --example approval_vectors -- --write
use anyhow::{ensure, Result};
use pairkey_sdk::hosted::{offchain, KeyResponse, SigningRequest};
use pairkey_types::approval::{Binding, Identity, PolicyUpdate, Request, Rules};
use serde_json::json;
fn main() -> Result<()> {
    let transcripts: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../tests/fixtures/hosted-devnet.json"))?;
    let mut cases = vec![];
    for t in transcripts {
        let signing_request: SigningRequest = serde_json::from_value(t["request"].clone())?;
        let key: KeyResponse = serde_json::from_value(t["key"].clone())?;
        let reg = &signing_request.key.registration;
        let identity = Identity::Account {
            public_key: reg.namespace.derivation_authority,
        };
        let (commit, payload, _) = offchain::prepare_message(&signing_request, &key)?;
        let rules = Rules::default();
        let request = Request {
            version: 1,
            identity: identity.clone(),
            commit,
            policy_revision: 0,
            policy_digest: rules.digest(),
            issued_at: 100,
            expires_at: 300,
        };
        let prepared = offchain::Prepared {
            signing_request: signing_request.clone(),
            signing_message: request.signing_message(),
            request: request.clone(),
            rules: rules.clone(),
            payload,
        };
        let binding = Binding {
            namespace_digest: reg.namespace.digest(),
            identity_digest: identity.digest(),
            public_key: [3; 32],
            issued_at: 99,
            expires_at: 400,
        };
        let update = PolicyUpdate {
            namespace: reg.namespace.clone(),
            identity: identity.clone(),
            rules: Rules {
                revision: 1,
                destinations: Some(vec![key.account.destination]),
                path_prefixes: Some(vec![vec![0]]),
                ..rules
            },
            issued_at: 100,
            expires_at: 300,
        };
        cases.push(json!({"prepared":prepared,"key":key,"namespace_digest":reg.namespace.digest(),"registration_digest":reg.digest(),"request_digest":request.digest(),"job_digest":pairkey_types::digest(b"pairkey/offchain-job/v1",&request.digest()),"binding":binding,"binding_challenge":binding.challenge(),"policy_update":update,"policy_challenge":update.challenge()}));
    }
    let sources = vec![
        Identity::Passkey {
            public_key: vec![2; 33],
            rp_id: "pairkey.example".into(),
            origin: "https://pairkey.example".into(),
        },
        Identity::Oidc {
            issuer: "https://issuer.example".into(),
            audience: "client".into(),
            subject: "user".into(),
        },
        offchain::management::example_source(
            example_controller::id(),
            solana_sdk::pubkey::Pubkey::new_from_array(
                ed25519_dalek::SigningKey::from_bytes(&[8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            pairkey_types::program_approval::Mode::Offchain,
            [9; 32],
        )?
        .identity,
    ];
    let identities:Vec<_>=sources.into_iter().map(|identity|json!({"identity":identity,"encoded":borsh::to_vec(&identity).unwrap(),"digest":identity.digest(),"authority":identity.authority()})).collect();
    let mut prepared: offchain::Prepared = serde_json::from_value(cases[0]["prepared"].clone())?;
    let owner = solana_sdk::pubkey::Pubkey::new_from_array(
        ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let program = example_controller::id();
    let source = offchain::management::example_source(
        program,
        owner,
        pairkey_types::program_approval::Mode::Onchain,
        [0; 32],
    )?;
    let mut update: PolicyUpdate = serde_json::from_value(cases[0]["policy_update"].clone())?;
    update.namespace.derivation_authority = owner.to_bytes();
    update.identity = Identity::Account {
        public_key: owner.to_bytes(),
    };
    let wallet_update = update.clone();
    let wallet_policy = pairkey_sdk::approval::set_rules(
        owner,
        update,
        pairkey_types::approval::PolicyProof::Wallet,
    );
    prepared.request.identity = source.identity.clone();
    prepared
        .signing_request
        .key
        .registration
        .namespace
        .derivation_authority = source.identity.authority();
    prepared.request.commit.registration_digest =
        prepared.signing_request.key.registration.digest();
    prepared.signing_message = prepared.request.signing_message();
    let example_policy = offchain::management::ExamplePolicyRequest {
        program: program.to_string(),
        owner: owner.to_string(),
        revision: 1,
        enabled: true,
        chain: pairkey_sdk::hosted::Chain::Solana,
        path_prefix: vec![0],
        max_payload_bytes: 256,
        require_commit: true,
        remaining_approvals: 5,
    };
    let policy_ix = pairkey_sdk::program_approval::example_policy(
        program,
        example_policy.policy(
            prepared
                .signing_request
                .key
                .registration
                .namespace
                .enclave_set,
        )?,
    );
    let commit_ix = pairkey_sdk::program_approval::example_commit(
        owner,
        prepared.signing_request.key.registration.namespace.clone(),
        prepared.request.clone(),
        prepared.payload.clone(),
    )?;
    let instruction = |ix| pairkey_sdk::hosted::InstructionData::from(ix);
    let management = json!({"wallet_update":wallet_update,"wallet_policy":instruction(wallet_policy),"program_policy_request":example_policy,"program_policy":instruction(policy_ix),"program_prepared":prepared,"program_commit":instruction(commit_ix),"program_source":source});
    let bytes = serde_json::to_vec_pretty(
        &json!({"cases":cases,"identities":identities,"management":management}),
    )?;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../website/fixtures/offchain-vectors.json");
    match std::env::args().nth(1).as_deref() {
        Some("--write") => {
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(path, bytes)?;
        }
        Some("--check") => ensure!(
            std::fs::read(path)? == bytes,
            "browser approval vectors are stale"
        ),
        _ => anyhow::bail!("use --write or --check"),
    }
    Ok(())
}
