use super::*;
use ring::{
    rand::SystemRandom,
    signature::{RsaKeyPair, RSA_PKCS1_SHA256},
};
use serde_json::{json, Value};

fn fixture() -> (TrustedIssuer, Identity, Binding, Value) {
    let identity = Identity::Oidc {
        issuer: "https://issuer.example".into(),
        audience: "pairkey".into(),
        subject: "user-123".into(),
    };
    let binding = Binding {
        namespace_digest: [1; 32],
        identity_digest: identity.digest(),
        public_key: [2; 32],
        issued_at: 990,
        expires_at: 1200,
    };
    let issuer = TrustedIssuer::from_jwks(
        "https://issuer.example".into(),
        "pairkey".into(),
        include_bytes!("fixtures/jwks.json"),
        999,
    )
    .unwrap();
    let claims = json!({"iss":"https://issuer.example","aud":"pairkey","sub":"user-123","iat":990,"exp":1200,
        "nonce":URL_SAFE_NO_PAD.encode(binding.challenge())});
    (issuer, identity, binding, claims)
}
fn token_raw(header: &str, claims: &str) -> String {
    let key = RsaKeyPair::from_pkcs8(include_bytes!("fixtures/test-only.pk8")).unwrap();
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        message.as_bytes(),
        &mut signature,
    )
    .unwrap();
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))
}
fn token(claims: &Value) -> String {
    token_raw(
        r#"{"alg":"RS256","kid":"test-only","typ":"JWT"}"#,
        &claims.to_string(),
    )
}

#[test]
fn verifies_only_configured_identity_and_bound_nonce_with_fresh_keys() {
    let (issuer, identity, binding, claims) = fixture();
    let jwt = token(&claims);
    issuer
        .verify(&identity, &binding, &jwt, 1100, 1000)
        .unwrap();
    let mut other = binding.clone();
    other.public_key[0] ^= 1;
    assert!(issuer.verify(&identity, &other, &jwt, 1100, 1000).is_err());
    for now in [998, 1200, 1299] {
        assert!(issuer.verify(&identity, &binding, &jwt, 1100, now).is_err());
    }
    let other = Identity::Oidc {
        issuer: "https://evil.example".into(),
        audience: "pairkey".into(),
        subject: "user-123".into(),
    };
    assert!(issuer.verify(&other, &binding, &jwt, 1100, 1000).is_err());
}

#[test]
fn valid_crypto_does_not_override_wrong_missing_or_mistyped_claims() {
    let (issuer, identity, binding, claims) = fixture();
    for (field, value) in [
        ("iss", json!("https://evil.example")),
        ("aud", json!("other-app")),
        ("sub", json!("other-user")),
        ("nonce", json!("unbound")),
        ("iat", json!(989)),
        ("iat", json!(1001)),
        ("exp", json!(1000)),
        ("exp", json!(1099)),
        ("nbf", json!(1001)),
        ("nbf", json!("99999999999")),
        ("nbf", Value::Null),
        ("exp", json!("never")),
        ("azp", json!("other-app")),
        ("aud", json!(["pairkey", "other-app"])),
        ("iat", Value::Null),
    ] {
        let mut changed = claims.clone();
        changed[field] = value;
        assert!(
            issuer
                .verify(&identity, &binding, &token(&changed), 1100, 1000)
                .is_err(),
            "claim {field}"
        );
    }
    for field in ["iss", "sub", "aud", "iat", "exp", "nonce"] {
        let mut changed = claims.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(
            issuer
                .verify(&identity, &binding, &token(&changed), 1100, 1000)
                .is_err(),
            "missing {field}"
        );
    }
    let mut good = claims.clone();
    good["aud"] = json!(["pairkey", "other-app"]);
    good["azp"] = json!("pairkey");
    issuer
        .verify(&identity, &binding, &token(&good), 1100, 1000)
        .unwrap();
    let duplicate = format!("{{\"exp\":999999,{}", &claims.to_string()[1..]);
    assert!(issuer
        .verify(
            &identity,
            &binding,
            &token_raw(r#"{"alg":"RS256","kid":"test-only"}"#, &duplicate),
            1100,
            1000
        )
        .is_err());
}

#[test]
fn refuses_algorithm_confusion_embedded_keys_extensions_and_invalid_signatures() {
    let (issuer, identity, binding, claims) = fixture();
    for header in [
        json!({"alg":"none","kid":"test-only"}),
        json!({"alg":"HS256","kid":"test-only"}),
        json!({"alg":"RS256","kid":"wrong"}),
        json!({"alg":"RS256","kid":"test-only","jku":"https://evil.example"}),
        json!({"alg":"RS256","kid":"test-only","crit":["b64"],"b64":false}),
        json!({"alg":"RS256","kid":"test-only","typ":"at+jwt"}),
    ] {
        assert!(issuer
            .verify(
                &identity,
                &binding,
                &token_raw(&header.to_string(), &claims.to_string()),
                1100,
                1000
            )
            .is_err());
    }
    let jwt = token(&claims);
    let mut parts: Vec<String> = jwt.split('.').map(str::to_owned).collect();
    let mut sig = decode(&parts[2]).unwrap();
    sig[0] ^= 1;
    parts[2] = URL_SAFE_NO_PAD.encode(sig);
    assert!(issuer
        .verify(&identity, &binding, &parts.join("."), 1100, 1000)
        .is_err());
}

#[test]
fn jwks_rejects_ambiguous_key_ids_wrong_usage_and_expired_cache() {
    let mut jwks: Value = serde_json::from_slice(include_bytes!("fixtures/jwks.json")).unwrap();
    let key = jwks["keys"][0].clone();
    jwks["keys"].as_array_mut().unwrap().push(key.clone());
    let build = |v: &Value| {
        TrustedIssuer::from_jwks(
            "https://issuer.example".into(),
            "pairkey".into(),
            &serde_json::to_vec(v).unwrap(),
            999,
        )
    };
    assert!(build(&jwks).is_err());
    for (field, value) in [
        ("use", json!("enc")),
        ("alg", json!("HS256")),
        ("e", json!("Aw")),
        ("key_ops", json!(["sign"])),
    ] {
        let mut changed = key.clone();
        changed[field] = value;
        assert!(build(&json!({"keys":[changed]})).is_err());
    }
    let (issuer, identity, binding, mut claims) = fixture();
    claims["exp"] = json!(5000);
    claims["iat"] = json!(1299);
    assert!(issuer
        .verify(&identity, &binding, &token(&claims), 1400, 1299)
        .is_err());
}
