//! Real HTTPS JWKS transport, real RS256 tokens and both hosted signing workers.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pairkey_types::approval::Binding;
use ring::{
    rand::SystemRandom,
    signature::{RsaKeyPair, RSA_PKCS1_SHA256},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

pub(super) struct Issuer {
    pub config: pairkey_sdk::approval::IssuerConfig,
    pub requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Issuer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Issuer {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let cert = CertificateDer::from(include_bytes!("fixtures/test-server.der").to_vec());
        let key = PrivatePkcs8KeyDer::from(include_bytes!("fixtures/test-server.pk8").to_vec());
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let count = count.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut data = Vec::new();
                    while !data.ends_with(b"\r\n\r\n") && data.len() < 8192 {
                        let mut byte = [0];
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        data.push(byte[0]);
                    }
                    let (status, headers, body) = if data.starts_with(b"GET /jwks ") {
                        count.fetch_add(1, Ordering::SeqCst);
                        (
                            "200 OK",
                            "",
                            include_bytes!(
                                "../../../../../pairkey-core/src/oidc/fixtures/jwks.json"
                            )
                            .as_slice(),
                        )
                    } else if data.starts_with(b"GET /redirect ") {
                        ("302 Found", "Location: /jwks\r\n", b"".as_slice())
                    } else {
                        ("404 Not Found", "", b"".as_slice())
                    };
                    let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n", body.len());
                    if stream.write_all(response.as_bytes()).await.is_ok() {
                        let _ = stream.write_all(body).await;
                        let _ = stream.shutdown().await;
                    }
                });
            }
        });
        Self {
            config: pairkey_sdk::approval::IssuerConfig {
                issuer: origin.clone(),
                audience: "pairkey-test".into(),
                jwks_url: format!("{origin}/jwks"),
            },
            requests,
            task,
        }
    }
    pub fn root() -> Vec<u8> {
        include_bytes!("fixtures/test-ca.der").to_vec()
    }
    pub fn identity(&self) -> Identity {
        Identity::Oidc {
            issuer: self.config.issuer.clone(),
            audience: self.config.audience.clone(),
            subject: "isolated-owner".into(),
        }
    }
    pub fn token(&self, binding: &Binding) -> String {
        self.token_claims(json!({"iss":self.config.issuer,"aud":self.config.audience,"sub":"isolated-owner",
            "iat":binding.issued_at,"exp":binding.expires_at,"nonce":URL_SAFE_NO_PAD.encode(binding.challenge())}))
    }
    fn token_claims(&self, claims: Value) -> String {
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test-only"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let key = RsaKeyPair::from_pkcs8(include_bytes!(
            "../../../../../pairkey-core/src/oidc/fixtures/test-only.pk8"
        ))
        .unwrap();
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
    pub async fn namespace(&self, f: &Fixture) -> wire::NamespaceResponse {
        let q = wire::NamespaceRequest {
            identity: self.identity(),
            namespace_id: [0; 32],
        };
        let ns: wire::NamespaceResponse = f.client.post("/namespaces", &q).await.unwrap();
        wire::verify_namespace(
            &q,
            &ns,
            GENESIS.parse::<Pubkey>().unwrap().to_bytes(),
            pair_registry::id(),
            f.app.journal.read().set_id,
            f.app.identities,
        )
        .unwrap();
        ns
    }
}
pub(super) fn binding(
    ns: &wire::NamespaceResponse,
    key: &SigningKey,
    issued: i64,
    expires: i64,
) -> Binding {
    Binding {
        namespace_digest: ns.proposal.registration.namespace.digest(),
        identity_digest: ns.identity.digest(),
        public_key: key.verifying_key().to_bytes(),
        issued_at: issued,
        expires_at: expires,
    }
}

#[tokio::test]
async fn hosted_oidc_fetches_https_keys_at_both_workers_and_binds_exact_request() {
    let issuer = Issuer::start().await;
    // The ordinary HTTPS client must reject our private CA, never disable TLS checks.
    assert!(reqwest::get(&issuer.config.jwks_url).await.is_err());
    let f = Fixture::with_oidc(vec![issuer.config.clone()], Some(Issuer::root())).await;
    let ns = issuer.namespace(&f).await;
    let (prepared, key) = f.prepared(&ns, Chain::Solana).await;
    let ephemeral = SigningKey::from_bytes(&fresh());
    let binding = binding(
        &ns,
        &ephemeral,
        prepared.request.issued_at,
        prepared.request.expires_at,
    );
    let token = issuer.token(&binding);
    let proof = Proof::Oidc {
        binding: binding.clone(),
        id_token: token.clone(),
        signature: ephemeral
            .sign(&prepared.signing_message)
            .to_bytes()
            .to_vec(),
    };
    let submission = prepared.clone().submission(proof);
    let mut wrong = submission.clone();
    if let Proof::Oidc { binding, .. } = &mut wrong.approval.proof {
        binding.public_key = fresh();
    }
    assert!(f.client.post::<Value>("/jobs", &wrong).await.is_err());
    for (field, value) in [
        ("sub", "other-owner"),
        ("aud", "other-client"),
        ("nonce", "unbound"),
    ] {
        let mut claims = json!({"iss":issuer.config.issuer,"aud":issuer.config.audience,"sub":"isolated-owner",
            "iat":binding.issued_at,"exp":binding.expires_at,"nonce":URL_SAFE_NO_PAD.encode(binding.challenge())});
        claims[field] = json!(value);
        let mut wrong = submission.clone();
        if let Proof::Oidc { id_token, .. } = &mut wrong.approval.proof {
            *id_token = issuer.token_claims(claims);
        }
        assert!(
            f.client.post::<Value>("/jobs", &wrong).await.is_err(),
            "invalid {field} accepted"
        );
    }
    let job: Value = f.client.post("/jobs", &submission).await.unwrap();
    let id = job["job_id"].as_str().unwrap();
    let result = f.wait(id).await;
    wire::verify_result(
        &prepared.signing_request,
        &prepared.request,
        &key,
        &result,
        f.app.identities,
    )
    .unwrap();
    assert_eq!(
        issuer.requests.load(Ordering::SeqCst),
        2,
        "each worker must fetch its own JWKS"
    );
    let recovered: Value = f
        .client
        .post(&format!("/jobs/{id}/recover"), &json!({}))
        .await
        .unwrap();
    assert_eq!(recovered["result"], result);
    assert_eq!(
        f.accounts.lock().unwrap().len(),
        1,
        "no registration or approval account"
    );
    for entry in std::fs::read_dir(&f.dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes.windows(token.len()).any(|w| w == token.as_bytes()),
                "token persisted in {}",
                path.display()
            );
        }
    }
    f.close().await;
}

#[tokio::test]
async fn hosted_oidc_refuses_untrusted_tls_and_jwks_redirects() {
    let issuer = Issuer::start().await;
    for redirect in [false, true] {
        let mut config = issuer.config.clone();
        if redirect {
            config.jwks_url = format!("{}/redirect", config.issuer);
        }
        let f = Fixture::with_oidc(vec![config], redirect.then(Issuer::root)).await;
        let ns = issuer.namespace(&f).await;
        let (prepared, _) = f.prepared(&ns, Chain::Solana).await;
        let key = SigningKey::from_bytes(&fresh());
        let binding = binding(
            &ns,
            &key,
            prepared.request.issued_at,
            prepared.request.expires_at,
        );
        let proof = Proof::Oidc {
            id_token: issuer.token(&binding),
            binding,
            signature: key.sign(&prepared.signing_message).to_bytes().to_vec(),
        };
        assert!(f
            .client
            .post::<Value>("/jobs", &prepared.submission(proof))
            .await
            .is_err());
        assert!(f
            .app
            .hosted
            .lock()
            .unwrap()
            .snapshot
            .offchain_jobs
            .values()
            .all(|j| !matches!(j.state, JobState::Working | JobState::Complete(_))));
        f.close().await;
    }
    assert_eq!(
        issuer.requests.load(Ordering::SeqCst),
        0,
        "redirect cannot retrieve JWKS"
    );
}
