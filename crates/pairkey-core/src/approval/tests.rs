use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use pairkey_types::{approval::*, AccountPath, Commit, Namespace, Scheme};
use sha2::{Digest, Sha256};

fn registration(identity: &Identity) -> Registration {
    // Public points for f(1)=3, f(2)=7, f(0)=-1, identical to the types fixture.
    Registration {
        namespace: Namespace {
            version: 1,
            scheme: Scheme::FrostEd25519,
            network: [1; 32],
            registry: [2; 32],
            derivation_authority: identity.authority(),
            namespace_id: [0; 32],
            enclave_set: [5; 32],
        },
        public_shares: [
            [
                212, 180, 245, 120, 72, 104, 195, 2, 4, 3, 36, 103, 23, 236, 22, 159, 247, 158, 38,
                96, 142, 161, 38, 161, 171, 105, 238, 119, 209, 177, 103, 18,
            ],
            [
                184, 98, 64, 159, 181, 196, 196, 18, 61, 242, 171, 247, 70, 43, 136, 240, 65, 173,
                54, 221, 104, 100, 206, 135, 47, 213, 71, 43, 227, 99, 197, 177,
            ],
        ],
        public_key: [
            88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
            102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 230,
        ],
    }
}
fn request(identity: Identity, rules: &Rules) -> (Registration, Request) {
    let reg = registration(&identity);
    let commit = Commit::new(
        &reg,
        [7; 32],
        AccountPath {
            destination: [8; 32],
            path: vec![1, 2],
        },
        b"hello",
    )
    .unwrap();
    let request = Request {
        version: APPROVAL_VERSION,
        identity,
        commit,
        policy_revision: rules.revision,
        policy_digest: rules.digest(),
        issued_at: 1000,
        expires_at: 1100,
    };
    (reg, request)
}
fn account() -> (Registration, Approval) {
    let key = SigningKey::from_bytes(&[42; 32]);
    let (reg, request) = request(
        Identity::Account {
            public_key: key.verifying_key().to_bytes(),
        },
        &Rules::default(),
    );
    let signature = key.sign(&request.signing_message()).to_bytes().to_vec();
    (
        reg,
        Approval {
            request,
            proof: Proof::Account { signature },
        },
    )
}

#[test]
fn account_binds_every_request_field_and_preserves_authority() {
    let (reg, a) = account();
    verify(&reg, b"hello", &Rules::default(), &a, 1000).unwrap();
    assert_eq!(
        reg.namespace.derivation_authority,
        SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes()
    );
    let changes: Vec<fn(&mut Request)> = vec![
        |r| r.version += 1,
        |r| r.commit.request_id[0] ^= 1,
        |r| r.commit.account.destination[0] ^= 1,
        |r| r.commit.account.path.push(3),
        |r| r.commit.message_hash[0] ^= 1,
        |r| r.commit.message_len += 1,
        |r| r.commit.registration_digest[0] ^= 1,
        |r| r.policy_revision += 1,
        |r| r.policy_digest[0] ^= 1,
        |r| r.issued_at -= 1,
        |r| r.expires_at += 1,
        |r| {
            r.identity = Identity::Account {
                public_key: [2; 32],
            }
        },
    ];
    for change in changes {
        let mut b = a.clone();
        change(&mut b.request);
        assert!(verify(&reg, b"hello", &Rules::default(), &b, 1000).is_err());
    }
    for time in [999, 1100, i64::MAX] {
        assert!(verify(&reg, b"hello", &Rules::default(), &a, time).is_err());
    }
    assert!(verify(&reg, b"other", &Rules::default(), &a, 1000).is_err());
    let mut other = reg.clone();
    other.namespace.network[0] ^= 1;
    assert!(verify(&other, b"hello", &Rules::default(), &a, 1000).is_err());
}

#[test]
fn rules_are_deny_by_match_and_revision_zero_is_only_the_default() {
    let (_, a) = account();
    let base = Rules {
        revision: 1,
        destinations: Some(vec![[8; 32]]),
        path_prefixes: Some(vec![vec![1]]),
        max_payload_bytes: 5,
        payload_prefix: b"hel".to_vec(),
        disabled: false,
    };
    base.allows(&a.request.commit, b"hello").unwrap();
    for rules in [
        Rules {
            destinations: Some(vec![]),
            ..base.clone()
        },
        Rules {
            path_prefixes: Some(vec![vec![2]]),
            ..base.clone()
        },
        Rules {
            path_prefixes: Some(vec![]),
            ..base.clone()
        },
        Rules {
            max_payload_bytes: 4,
            ..base.clone()
        },
        Rules {
            disabled: true,
            ..base.clone()
        },
        Rules {
            payload_prefix: b"bye".to_vec(),
            ..base.clone()
        },
        Rules {
            revision: 0,
            ..base.clone()
        },
    ] {
        assert!(rules.allows(&a.request.commit, b"hello").is_err());
    }
    assert!(Rules {
        destinations: Some(vec![[8; 32]; 17]),
        ..base.clone()
    }
    .validate()
    .is_err());
    assert!(Rules {
        path_prefixes: Some(vec![vec![0; 9]]),
        ..base
    }
    .validate()
    .is_err());
}

fn passkey() -> (Registration, Approval, p256::ecdsa::SigningKey) {
    let key = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
    let ephemeral = SigningKey::from_bytes(&[44; 32]);
    let (reg, request) = request(
        Identity::Passkey {
            public_key: key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            rp_id: "pairkey.com".into(),
            origin: "https://pairkey.com".into(),
        },
        &Rules::default(),
    );
    let binding = Binding {
        namespace_digest: reg.namespace.digest(),
        identity_digest: request.identity.digest(),
        public_key: ephemeral.verifying_key().to_bytes(),
        issued_at: 990,
        expires_at: 1200,
    };
    let mut authenticator_data = Sha256::digest(b"pairkey.com").to_vec();
    authenticator_data.extend([5, 0, 0, 0, 0]);
    let client_data_json = serde_json::to_vec(&serde_json::json!({"type":"webauthn.get",
        "origin":"https://pairkey.com","challenge":URL_SAFE_NO_PAD.encode(binding.challenge()),"crossOrigin":false})).unwrap();
    let mut assertion = Assertion {
        authenticator_data,
        client_data_json,
        signature_der: vec![],
    };
    sign_assertion(&key, &mut assertion);
    let signature = ephemeral
        .sign(&request.signing_message())
        .to_bytes()
        .to_vec();
    (
        reg,
        Approval {
            request,
            proof: Proof::Passkey {
                binding,
                assertion,
                signature,
            },
        },
        key,
    )
}
fn sign_assertion(key: &p256::ecdsa::SigningKey, assertion: &mut Assertion) {
    let mut bytes = assertion.authenticator_data.clone();
    bytes.extend_from_slice(&Sha256::digest(&assertion.client_data_json));
    let signature: p256::ecdsa::Signature = key.sign(&bytes);
    assertion.signature_der = signature.to_der().as_bytes().to_vec();
}

#[test]
fn passkey_requires_both_owner_binding_and_exact_ephemeral_signature() {
    let (reg, a, _) = passkey();
    verify(&reg, b"hello", &Rules::default(), &a, 1000).unwrap();
    let mut b = a.clone();
    if let Proof::Passkey { binding, .. } = &mut b.proof {
        binding.public_key = SigningKey::from_bytes(&[45; 32]).verifying_key().to_bytes();
    }
    assert!(verify(&reg, b"hello", &Rules::default(), &b, 1000).is_err());
    let mut b = a.clone();
    if let Proof::Passkey { signature, .. } = &mut b.proof {
        signature[0] ^= 1;
    }
    assert!(verify(&reg, b"hello", &Rules::default(), &b, 1000).is_err());
    let mut b = a.clone();
    if let Proof::Passkey { binding, .. } = &mut b.proof {
        binding.namespace_digest[0] ^= 1;
    }
    assert!(verify(&reg, b"hello", &Rules::default(), &b, 1000).is_err());
}

#[test]
fn cryptographically_valid_webauthn_proofs_still_require_correct_context() {
    let (reg, a, key) = passkey();
    for flags in [0, 1, 4, 0x15, 0x85] {
        let mut b = a.clone();
        if let Proof::Passkey { assertion, .. } = &mut b.proof {
            assertion.authenticator_data[32] = flags;
            sign_assertion(&key, assertion);
        }
        assert!(verify(&reg, b"hello", &Rules::default(), &b, 1000).is_err());
    }
    for (field, value) in [
        ("origin", serde_json::json!("https://evil.example")),
        ("type", serde_json::json!("webauthn.create")),
        ("challenge", serde_json::json!("unbound")),
        ("crossOrigin", serde_json::json!(true)),
        ("topOrigin", serde_json::json!("https://pairkey.com")),
    ] {
        let mut b = a.clone();
        if let Proof::Passkey { assertion, .. } = &mut b.proof {
            let mut client: serde_json::Value =
                serde_json::from_slice(&assertion.client_data_json).unwrap();
            client[field] = value;
            assertion.client_data_json = serde_json::to_vec(&client).unwrap();
            sign_assertion(&key, assertion);
        }
        assert!(verify(&reg, b"hello", &Rules::default(), &b, 1000).is_err());
    }
}

#[test]
fn binding_and_request_lifetimes_are_bounded_without_overflow() {
    let (reg, a, _) = passkey();
    let Proof::Passkey { binding, .. } = &a.proof else {
        unreachable!()
    };
    for (issued_at, expires_at) in [
        (0, i64::MAX),
        (1001, 1200),
        (-1, 1200),
        (990, 1000),
        (990, 1050),
    ] {
        let bad = Binding {
            issued_at,
            expires_at,
            ..binding.clone()
        };
        assert!(bad.validate(&reg, &a.request, 1000).is_err());
    }
    let mut b = a.request.clone();
    b.expires_at = 1301;
    assert!(b.validate(&reg, b"hello", &Rules::default(), 1000).is_err());
}

#[test]
fn oidc_requires_nonce_bound_owner_token_and_ephemeral_request_signature() {
    use ring::{
        rand::SystemRandom,
        signature::{RsaKeyPair, RSA_PKCS1_SHA256},
    };
    let identity = Identity::Oidc {
        issuer: "https://issuer.example".into(),
        audience: "pairkey".into(),
        subject: "user-123".into(),
    };
    let (reg, request) = request(identity.clone(), &Rules::default());
    let ephemeral = SigningKey::from_bytes(&[44; 32]);
    let binding = Binding {
        namespace_digest: reg.namespace.digest(),
        identity_digest: identity.digest(),
        public_key: ephemeral.verifying_key().to_bytes(),
        issued_at: 990,
        expires_at: 1200,
    };
    let claims = serde_json::json!({"iss":"https://issuer.example","aud":"pairkey","sub":"user-123","iat":990,"exp":1200,
        "nonce":URL_SAFE_NO_PAD.encode(binding.challenge())});
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test-only"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let issuer_key =
        RsaKeyPair::from_pkcs8(include_bytes!("../oidc/fixtures/test-only.pk8")).unwrap();
    let mut token_sig = vec![0; issuer_key.public().modulus_len()];
    issuer_key
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            message.as_bytes(),
            &mut token_sig,
        )
        .unwrap();
    let id_token = format!("{message}.{}", URL_SAFE_NO_PAD.encode(token_sig));
    let issuer = crate::oidc::TrustedIssuer::from_jwks(
        "https://issuer.example".into(),
        "pairkey".into(),
        include_bytes!("../oidc/fixtures/jwks.json"),
        999,
    )
    .unwrap();
    let signature = ephemeral
        .sign(&request.signing_message())
        .to_bytes()
        .to_vec();
    let a = Approval {
        request,
        proof: Proof::Oidc {
            binding,
            id_token,
            signature,
        },
    };
    let marker = pairkey_types::policy::Authorization::offchain(&a);
    let public = serde_json::to_string(&marker).unwrap();
    assert!(!public.contains("id_token"));
    let Proof::Oidc { id_token, .. } = &a.proof else {
        unreachable!()
    };
    assert!(!public.contains(id_token));
    assert_eq!(marker.with_offchain_proof(&a.proof).unwrap(), a);
    let mut session = marker.clone();
    session.session_id = Some([8; 32]);
    assert!(session.with_offchain_proof(&a.proof).is_err());
    assert!(verify(&reg, b"hello", &Rules::default(), &a, 1000).is_err());
    verify_with_oidc(&reg, b"hello", &Rules::default(), &a, 1000, Some(&issuer)).unwrap();
    let mut b = a.clone();
    if let Proof::Oidc { signature, .. } = &mut b.proof {
        signature[0] ^= 1;
    }
    assert!(verify_with_oidc(&reg, b"hello", &Rules::default(), &b, 1000, Some(&issuer)).is_err());
    let mut b = a.clone();
    if let Proof::Oidc { binding, .. } = &mut b.proof {
        binding.public_key = SigningKey::from_bytes(&[45; 32]).verifying_key().to_bytes();
    }
    assert!(verify_with_oidc(&reg, b"hello", &Rules::default(), &b, 1000, Some(&issuer)).is_err());
}
