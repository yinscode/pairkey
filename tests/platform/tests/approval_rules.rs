use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use litesvm::LiteSVM;
use p256::ecdsa::signature::Signer as _;
use pair_registry::approval::{rules_address, RulesRecord};
use pairkey_types::{approval::*, Namespace, Scheme};
use sha2::{Digest, Sha256};
use solana_sdk::{
    clock::Clock,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

struct Fixture {
    svm: LiteSVM,
    payer: Keypair,
    identities: [Keypair; 2],
}
impl Fixture {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let root = std::env::var_os("PAIRKEY_PROGRAM_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy")
            });
        svm.add_program_from_file(pair_registry::id(), root.join("pair_registry.so"))
            .unwrap();
        let mut clock = svm.get_sysvar::<Clock>();
        clock.unix_timestamp = 1000;
        svm.set_sysvar(&clock);
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();
        let mut f = Self {
            svm,
            payer,
            identities: [Keypair::new(), Keypair::new()],
        };
        f.send(vec![pairkey_sdk::create_set(
            f.payer.pubkey(),
            [5; 32],
            f.identities.each_ref().map(|k| k.pubkey().to_bytes()),
            true,
        )])
        .unwrap();
        f
    }
    fn send(&mut self, ixs: Vec<Instruction>) -> Result<u64, String> {
        self.svm.expire_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &ixs,
            Some(&self.payer.pubkey()),
            &[&self.payer],
            self.svm.latest_blockhash(),
        );
        assert!(
            bincode::serialize(&tx).unwrap().len() <= 1232,
            "must fit a real Solana transaction"
        );
        self.svm
            .send_transaction(tx)
            .map(|v| v.compute_units_consumed)
            .map_err(|e| format!("{e:?}"))
    }
    fn update(&self, identity: Identity) -> PolicyUpdate {
        PolicyUpdate {
            namespace: Namespace {
                version: 1,
                scheme: Scheme::FrostEd25519,
                network: [1; 32],
                registry: pair_registry::id().to_bytes(),
                derivation_authority: identity.authority(),
                namespace_id: [0; 32],
                enclave_set: [5; 32],
            },
            identity,
            rules: Rules {
                revision: 1,
                ..Default::default()
            },
            issued_at: 990,
            expires_at: 1100,
        }
    }
    fn account(&self) -> PolicyUpdate {
        self.update(Identity::Account {
            public_key: self.payer.pubkey().to_bytes(),
        })
    }
}

#[test]
#[ignore = "requires SBF programs"]
fn account_updates_without_registration_reuse_rent_and_reject_stale_revisions() {
    let mut f = Fixture::new();
    let mut update = f.account();
    let target = rules_address(&pair_registry::id(), &update.namespace.digest()).0;
    let namespace = Pubkey::find_program_address(
        &[b"namespace", &update.namespace.digest()],
        &pair_registry::id(),
    )
    .0;
    assert!(f.svm.get_account(&namespace).is_none());
    f.send(vec![pairkey_sdk::approval::set_rules(
        f.payer.pubkey(),
        update.clone(),
        PolicyProof::Wallet,
    )])
    .unwrap();
    let initial = f.svm.get_account(&target).unwrap();
    update.rules.revision = 2;
    update.rules.disabled = true;
    f.send(vec![pairkey_sdk::approval::set_rules(
        f.payer.pubkey(),
        update.clone(),
        PolicyProof::Wallet,
    )])
    .unwrap();
    let changed = f.svm.get_account(&target).unwrap();
    assert_eq!(initial.lamports, changed.lamports);
    assert_eq!(initial.data.len(), changed.data.len());
    let rules: RulesRecord = borsh::from_slice(&changed.data).unwrap();
    assert_eq!(rules.rules, update.rules);
    assert!(f
        .send(vec![pairkey_sdk::approval::set_rules(
            f.payer.pubkey(),
            update.clone(),
            PolicyProof::Wallet
        )])
        .is_err());
    update.rules.revision = 4;
    assert!(f
        .send(vec![pairkey_sdk::approval::set_rules(
            f.payer.pubkey(),
            update,
            PolicyProof::Wallet
        )])
        .is_err());
    assert!(f.svm.get_account(&namespace).is_none());
}

#[test]
#[ignore = "requires SBF programs"]
fn wallet_policy_rejects_forged_owner_expiry_and_nondefault_zero_revision() {
    let mut f = Fixture::new();
    let update = f.update(Identity::Account {
        public_key: Keypair::new().pubkey().to_bytes(),
    });
    let mut ix = pairkey_sdk::approval::set_rules(f.payer.pubkey(), update, PolicyProof::Wallet);
    ix.accounts[1].is_signer = false;
    assert!(f.send(vec![ix]).is_err());
    for (issued_at, expires_at, revision) in [
        (990, 1000, 1),
        (1001, 1100, 1),
        (990, 1400, 1),
        (990, 1100, 0),
    ] {
        let mut update = f.account();
        update.issued_at = issued_at;
        update.expires_at = expires_at;
        update.rules.revision = revision;
        assert!(f
            .send(vec![pairkey_sdk::approval::set_rules(
                f.payer.pubkey(),
                update,
                PolicyProof::Wallet
            )])
            .is_err());
    }
}

fn passkey_identity(key: &p256::ecdsa::SigningKey) -> Identity {
    Identity::Passkey {
        public_key: key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        rp_id: "pairkey.com".into(),
        origin: "https://pairkey.com".into(),
    }
}
fn assertion(update: &PolicyUpdate) -> Assertion {
    let mut auth = Sha256::digest(b"pairkey.com").to_vec();
    auth.extend([5, 0, 0, 0, 0]);
    Assertion { authenticator_data:auth,client_data_json:serde_json::to_vec(&serde_json::json!({"type":"webauthn.get",
        "origin":"https://pairkey.com","challenge":URL_SAFE_NO_PAD.encode(update.challenge()),"crossOrigin":false})).unwrap(),signature_der:vec![] }
}
fn passkey_ixs(
    payer: Pubkey,
    update: PolicyUpdate,
    key: &p256::ecdsa::SigningKey,
    assertion: Assertion,
) -> Vec<Instruction> {
    // Deliberately bypass the SDK context validation so negative tests exercise the gateway.
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&Sha256::digest(&assertion.client_data_json));
    let sig: p256::ecdsa::Signature = key.sign(&message);
    vec![
        pairkey_sdk::approval::p256_instruction(
            key.verifying_key().to_encoded_point(true).as_bytes(),
            sig.to_der().as_bytes(),
            &message,
        )
        .unwrap(),
        pairkey_sdk::approval::set_rules(
            payer,
            update,
            PolicyProof::Passkey {
                authenticator_data: assertion.authenticator_data,
                client_data_json: assertion.client_data_json,
            },
        ),
    ]
}

#[test]
#[ignore = "requires SBF programs"]
fn native_passkey_policy_requires_real_signature_and_webauthn_context() {
    let mut f = Fixture::new();
    let key = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
    let update = f.update(passkey_identity(&key));
    for mutation in 0..6 {
        let mut proof = assertion(&update);
        if mutation == 0 {
            proof.authenticator_data[32] = 1;
        }
        if mutation == 1 {
            proof.authenticator_data[0] ^= 1;
        }
        if mutation >= 2 {
            let mut json: serde_json::Value =
                serde_json::from_slice(&proof.client_data_json).unwrap();
            match mutation {
                2 => json["origin"] = serde_json::json!("https://evil.example"),
                3 => json["challenge"] = serde_json::json!("unbound"),
                4 => json["crossOrigin"] = serde_json::json!(true),
                _ => json["type"] = serde_json::json!("webauthn.create"),
            }
            proof.client_data_json = serde_json::to_vec(&json).unwrap();
        }
        assert!(f
            .send(passkey_ixs(f.payer.pubkey(), update.clone(), &key, proof))
            .is_err());
    }
    let mut bad = passkey_ixs(f.payer.pubkey(), update.clone(), &key, assertion(&update));
    bad[0].data[49] ^= 1;
    assert!(f.send(bad).is_err());
    let mut reversed = passkey_ixs(f.payer.pubkey(), update.clone(), &key, assertion(&update));
    reversed.reverse();
    assert!(f.send(reversed).is_err());
    let used = f
        .send(passkey_ixs(
            f.payer.pubkey(),
            update.clone(),
            &key,
            assertion(&update),
        ))
        .unwrap();
    assert!(
        used < 200_000,
        "default compute budget should suffice: {used}"
    );
    let record = f
        .svm
        .get_account(&rules_address(&pair_registry::id(), &update.namespace.digest()).0)
        .unwrap();
    assert_eq!(
        borsh::from_slice::<RulesRecord>(&record.data)
            .unwrap()
            .rules,
        update.rules
    );
}

#[test]
#[ignore = "requires SBF programs"]
fn oidc_policy_needs_two_distinct_enrolled_attestations_bound_to_update() {
    let mut f = Fixture::new();
    let update = f.update(Identity::Oidc {
        issuer: "https://issuer.example".into(),
        audience: "pairkey".into(),
        subject: "user-123".into(),
    });
    let message = update.attestation_message();
    let proofs: Vec<_> = f
        .identities
        .iter()
        .map(|k| {
            pairkey_sdk::ed25519_instruction(
                k.pubkey().to_bytes(),
                k.sign_message(&message).as_ref().try_into().unwrap(),
                &message,
            )
        })
        .collect();
    let write = pairkey_sdk::approval::set_rules(
        f.payer.pubkey(),
        update.clone(),
        PolicyProof::OidcAttested,
    );
    assert!(f.send(vec![proofs[0].clone(), write.clone()]).is_err());
    assert!(f
        .send(vec![proofs[0].clone(), proofs[0].clone(), write.clone()])
        .is_err());
    let mut changed = update;
    changed.rules.disabled = true;
    assert!(f
        .send(vec![
            proofs[0].clone(),
            proofs[1].clone(),
            pairkey_sdk::approval::set_rules(f.payer.pubkey(), changed, PolicyProof::OidcAttested)
        ])
        .is_err());
    f.send(vec![proofs[0].clone(), proofs[1].clone(), write])
        .unwrap();
}
