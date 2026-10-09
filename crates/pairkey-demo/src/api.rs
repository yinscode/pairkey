use super::*;
use axum::{
    extract::{DefaultBodyLimit, Path as UrlPath, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
fn error(status: StatusCode, e: impl std::fmt::Display) -> Response {
    (status, Json(json!({"error":e.to_string()}))).into_response()
}
pub fn configured_origin(value: &str) -> Result<String> {
    if value == "http://127.0.0.1:4180" {
        return Ok(value.to_owned());
    }
    let url = reqwest::Url::parse(value).context("invalid demo origin")?;
    ensure!(
        url.scheme() == "https" && url.origin().ascii_serialization() == value,
        "demo origin must be an HTTPS origin without a path, credentials, or query"
    );
    Ok(value.to_owned())
}
fn origin_allowed(
    expected: &str,
    host: Option<&str>,
    origin: Option<&str>,
    fetch_site: Option<&str>,
) -> bool {
    let authority = expected.split_once("://").map(|(_, authority)| authority);
    host == authority
        && origin.is_none_or(|s| s == expected)
        && fetch_site.is_none_or(|s| s == "same-origin" || s == "none")
}
async fn protect(State(expected): State<String>, req: Request, next: Next) -> Response {
    let h = req.headers();
    let read = |name: &str| h.get(name).and_then(|v| v.to_str().ok());
    let hosted =
        req.uri().path().starts_with("/api/v1/") || req.uri().path().starts_with("/api/v2/");
    if hosted {
        return hosted_protect(expected, req, next).await;
    }
    if !origin_allowed(
        &expected,
        read("host"),
        read("origin"),
        read("sec-fetch-site"),
    ) {
        return error(
            StatusCode::FORBIDDEN,
            "configured same-origin requests only",
        );
    }
    if req.method() == "POST"
        && (read("x-pairkey-demo") != Some("1")
            || !read("content-type").is_some_and(|v| v.starts_with("application/json")))
    {
        return error(
            StatusCode::FORBIDDEN,
            "JSON and demo request header required",
        );
    }
    let mut response = next.run(req).await;
    for (name,value) in [("cache-control","no-store"),("x-content-type-options","nosniff"),("referrer-policy","no-referrer"),("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")] {response.headers_mut().insert(header::HeaderName::from_static(name),header::HeaderValue::from_static(value));}
    response
}
pub fn router(app: Arc<App>, origin: String) -> Router {
    Router::new()
        .route("/api/status", get(status))
        .route("/api/verify", post(verify_message))
        .route("/api/operations", post(submit))
        .route("/api/operations/:id", get(operation))
        .route("/", get(index))
        .route("/demo", get(demo))
        .route("/demo/", get(|| async { Redirect::permanent("/demo") }))
        .route(
            "/testnet.html",
            get(|| async { Redirect::permanent("/demo") }),
        )
        .route("/*path", get(asset))
        .merge(
            crate::hosted::router().layer(middleware::from_fn_with_state(
                app.clone(),
                hosted_admission,
            )),
        )
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn_with_state(origin, protect))
        .with_state(app)
}
async fn status(State(app): State<Arc<App>>) -> Json<Value> {
    let s = app.journal.read();
    let stage = app.stage.lock().unwrap().clone();
    let address = s
        .key
        .as_ref()
        .and_then(|k| pairkey_signing::evm::address(&k.key.public_key).ok())
        .map(|a| format!("0x{}", hex(&a)));
    // RPC failures remain unknown, never a fabricated zero balance.
    let sol = app
        .sol
        .call(
            "getBalance",
            json!([app.payer.pubkey().to_string(),{"commitment":"finalized"}]),
        )
        .await
        .ok()
        .and_then(|v| v["value"].as_u64())
        .map(|n| n.to_string());
    let eth = if let Some(a) = &address {
        app.evm
            .call("eth_getBalance", json!([a, "pending"]))
            .await
            .ok()
            .and_then(|v| quantity(&v).ok())
            .map(|n| n.to_string())
    } else {
        None
    };
    Json(
        json!({"message_keys":crate::messages::public_keys(&s),"setup":stage,"networks":{"solana":"devnet","evm":"Base Sepolia","chain_id":CHAIN},"owner":app.payer.pubkey().to_string(),"registry":pair_registry::id().to_string(),"controller_program":example_controller::id().to_string(),"controller":app.controller.to_string(),"address":address,"sol_balance_lamports":sol,"eth_balance_wei":eth,"recipients":s.recipients.map(|r|format!("0x{}",hex(&r))),"session":s.session,"revoked":s.revoked,"hardware_backed":false,"signer_identities":app.identities.map(|i|hex(&i)),"reserved_budget_wei":s.reserved_budget.to_string(),"lifetime_budget_wei":TOTAL_BUDGET.to_string(),"blocked":s.operations.iter().any(|o|o.uncertain),"operations":s.operations.iter().rev().take(20).map(public_operation).collect::<Vec<_>>()}),
    )
}
async fn submit(State(app): State<Arc<App>>, Json(command): Json<Command>) -> Response {
    if let Err(e) = command.validate() {
        return error(StatusCode::BAD_REQUEST, e);
    }
    let s = app.journal.read();
    if let Some(op) = s.operations.iter().find(|o| o.command.id() == command.id()) {
        return if op.command == command {
            Json(public_operation(op)).into_response()
        } else {
            error(StatusCode::CONFLICT, "ID already bound to another request")
        };
    }
    let Ok(lease) = app.gate.clone().try_lock_owned() else {
        return error(
            StatusCode::CONFLICT,
            "another operation is running; poll its ID",
        );
    };
    if app.stage.lock().unwrap()["ready"] != true {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "finish backend setup first",
        );
    }
    if s.operations.iter().any(|o| o.uncertain)
        && !matches!(
            command,
            Command::Retry { .. } | Command::Grant { .. } | Command::Revoke { .. }
        )
    {
        return error(
            StatusCode::CONFLICT,
            "operator reconciliation required; an earlier operation may have executed",
        );
    }
    if s.operations.len() >= 256 {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "demo operation limit reached",
        );
    }
    let op = Operation {
        ed_request: None,
        command: command.clone(),
        status: "working".into(),
        events: vec!["Request persisted".into()],
        result: Value::Null,
        uncertain: false,
        solana_tx: None,
        signing_request: None,
        raw_transaction: None,
        transaction_hash: None,
    };
    let response = public_operation(&op);
    if let Err(e) = app.journal.update(|s| {
        s.operations.push(op);
        Ok(())
    }) {
        return error(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    tokio::spawn(async move {
        let _lease = lease;
        let id = command.id().to_string();
        let result = app.execute(command).await;
        let saved = app.journal.op(&id, |o| match result {
            Ok(()) => o.status = "complete".into(),
            Err(e) => {
                o.status = if o.uncertain {
                    "needs_reconciliation"
                } else {
                    "rejected"
                }
                .into();
                o.events.push(format!("{e:#}"));
            }
        });
        if let Err(e) = saved {
            app.stage(&format!("Journal failed; stop and reconcile: {e}"));
        }
    });
    (StatusCode::ACCEPTED, Json(response)).into_response()
}
async fn operation(State(app): State<Arc<App>>, UrlPath(id): UrlPath<String>) -> Response {
    match app
        .journal
        .read()
        .operations
        .iter()
        .find(|o| o.command.id() == id)
    {
        Some(op) => Json(public_operation(op)).into_response(),
        None => error(StatusCode::NOT_FOUND, "unknown operation"),
    }
}
async fn index(State(app): State<Arc<App>>) -> Response {
    serve_asset(&app, "index.html")
}
async fn demo(State(app): State<Arc<App>>) -> Response {
    serve_asset(&app, "demo.html")
}
async fn asset(State(app): State<Arc<App>>, UrlPath(path): UrlPath<String>) -> Response {
    serve_asset(&app, &path)
}
fn serve_asset(app: &App, path: &str) -> Response {
    if path
        .split('/')
        .any(|part| part.starts_with('.') || part.is_empty())
        || path.contains('\\')
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mime = match Path::new(path).extension().and_then(|s| s.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css",
        Some("js" | "mjs") => "text/javascript",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        Some("zip") => "application/zip",
        Some("rs") => "text/plain; charset=utf-8",
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let base = app.root.join("website");
    let Ok(file) = base.join(path).canonicalize() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !file.starts_with(&base) || !file.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match std::fs::read(file) {
        Ok(bytes) => ([(header::CONTENT_TYPE, mime)], bytes).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

pub(crate) async fn verify_message(Json(request): Json<crate::messages::Verification>) -> Response {
    match request.check() {
        Ok(valid) => Json(json!({"valid":valid,"verification":"fresh cryptographic verification"}))
            .into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

async fn hosted_protect(expected: String, req: Request, next: Next) -> Response {
    if req.headers().get("host").and_then(|h| h.to_str().ok())
        != expected.split_once("://").map(|(_, h)| h)
    {
        return error(StatusCode::FORBIDDEN, "unexpected host");
    }
    let mut response = if req.method() == "OPTIONS" {
        StatusCode::NO_CONTENT.into_response()
    } else {
        if req.method() == "POST"
            && (req
                .headers()
                .get("x-pairkey-client")
                .and_then(|h| h.to_str().ok())
                != Some("1")
                || !req
                    .headers()
                    .get("content-type")
                    .and_then(|h| h.to_str().ok())
                    .is_some_and(|s| s.starts_with("application/json")))
        {
            return error(
                StatusCode::FORBIDDEN,
                "JSON and X-PairKey-Client: 1 required",
            );
        }
        next.run(req).await
    };
    for (name, value) in [
        ("access-control-allow-origin", "*"),
        ("access-control-allow-methods", "GET, POST, OPTIONS"),
        (
            "access-control-allow-headers",
            "content-type,x-pairkey-client",
        ),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
    ] {
        response.headers_mut().insert(
            header::HeaderName::from_static(name),
            header::HeaderValue::from_static(value),
        );
    }
    response
}

async fn hosted_admission(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    if req.method() != "OPTIONS" && !app.hosted.lock().unwrap().admit() {
        let mut response = error(
            StatusCode::TOO_MANY_REQUESTS,
            "Hosted devnet rate limit; retry after 60 seconds",
        );
        response
            .headers_mut()
            .insert("retry-after", header::HeaderValue::from_static("60"));
        return response;
    }
    if req.method() == "POST" && app.stage.lock().unwrap()["ready"] != true {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Hosted signers are starting; retry shortly",
        );
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_cross_origin_and_dns_rebinding() {
        assert!(origin_allowed(
            "http://127.0.0.1:4180",
            Some("127.0.0.1:4180"),
            Some("http://127.0.0.1:4180"),
            Some("same-origin")
        ));
        assert!(!origin_allowed(
            "http://127.0.0.1:4180",
            Some("attacker.test:4180"),
            None,
            None
        ));
        assert!(!origin_allowed(
            "http://127.0.0.1:4180",
            Some("127.0.0.1:4180"),
            Some("https://attacker.test"),
            None
        ));
        assert!(!origin_allowed(
            "http://127.0.0.1:4180",
            Some("127.0.0.1:4180"),
            None,
            Some("cross-site")
        ));
        assert!(!origin_allowed(
            "http://127.0.0.1:4180",
            Some("127.0.0.1:4180"),
            Some("null"),
            None
        ));
    }
    #[test]
    fn hosted_origin_is_explicit_and_exact() {
        let expected = configured_origin("https://pairkey.com").unwrap();
        assert!(origin_allowed(
            &expected,
            Some("pairkey.com"),
            Some(&expected),
            Some("same-origin")
        ));
        assert!(origin_allowed(&expected, Some("pairkey.com"), None, None));
        for origin in [
            "https://attacker.test",
            "http://pairkey.com",
            "null",
            "https://pairkey.com.attacker.test",
        ] {
            assert!(!origin_allowed(
                &expected,
                Some("pairkey.com"),
                Some(origin),
                None
            ));
        }
        assert!(!origin_allowed(
            &expected,
            Some("127.0.0.1:4180"),
            None,
            None
        ));
        assert!(!origin_allowed(
            &expected,
            Some("pairkey.com"),
            Some(&expected),
            Some("cross-site")
        ));
        for invalid in [
            "http://pairkey.com",
            "https://pairkey.com/",
            "https://pairkey.com/demo",
            "https://user:pass@pairkey.com",
            "https://pairkey.com?x=1",
            "null",
        ] {
            assert!(configured_origin(invalid).is_err(), "accepted {invalid}");
        }
    }
}
