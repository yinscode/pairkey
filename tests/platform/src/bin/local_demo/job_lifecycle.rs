//! Real process failures with a transport gate; no fault switches in worker binaries.
use super::*;
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, Response, StatusCode},
    Router,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use tokio::sync::Notify;
#[derive(Clone)]
struct Pause {
    phase: &'static str,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}
struct Gate {
    phase: Mutex<Option<Pause>>,
    calls: AtomicU64,
    backoffs: AtomicU64,
}
#[derive(Clone)]
struct Proxy {
    target: String,
    http: reqwest::Client,
    gate: Arc<Gate>,
    gated: bool,
}
fn matches(phase: &str, route: &str, input: &Value, output: &Value) -> bool {
    match phase {
        "register" => route == "/multi/d/start" && input["operation"]["Register"].is_object(),
        "prepare" => route == "/multi/d/start" && input["operation"] == "Prepare",
        "sign" => route == "/multi/d/start" && input["operation"]["Sign"].is_object(),
        "ecdsa_result" => route == "/multi/d/exchange" && output["receipt"].is_object(),
        "red_begin" => route == "/multi/r/begin",
        "red_finish" => route == "/multi/r/finish",
        "red_result" => route == "/multi/r/result",
        _ => false,
    }
}
async fn proxy(
    State(p): State<Proxy>,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, 12 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let route = parts.uri.path();
    p.gate.calls.fetch_add(1, Ordering::SeqCst);
    let response = p
        .http
        .request(parts.method, format!("{}{route}", p.target))
        .header("content-type", "application/json")
        .body(bytes.to_vec())
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status = response.status();
    let output = pairkey_sdk::http::bounded_body(response, 12 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let paused = if p.gated && status.is_success() {
        let input: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let out: Value = serde_json::from_slice(&output).unwrap_or(Value::Null);
        let mut phase = p.gate.phase.lock().unwrap();
        if phase
            .as_ref()
            .is_some_and(|phase| matches(phase.phase, route, &input, &out))
        {
            phase.take()
        } else {
            None
        }
    } else {
        None
    };
    if let Some(pause) = paused {
        pause.entered.notify_one();
        pause.release.notified().await;
    }
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(output))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
struct Servers(Vec<tokio::task::JoinHandle<()>>);
impl Drop for Servers {
    fn drop(&mut self) {
        for server in &self.0 {
            server.abort();
        }
    }
}
async fn ready(client: &reqwest::Client, endpoint: &str) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if client
            .get(format!("{endpoint}/health"))
            .send()
            .await
            .is_ok()
        {
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "job coordinator startup timeout");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
async fn terminal(
    sdk: &pairkey_sdk::service::Client,
    q: &multi::SignRequest,
    identities: [[u8; 32]; 2],
) -> anyhow::Result<multi::IntentJob> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let job = sdk.poll_intent(q, identities).await?;
        if job.terminal() {
            return Ok(job);
        }
        ensure!(Instant::now() < deadline, "job did not settle");
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}
fn retry(q: &multi::SignRequest) -> anyhow::Result<multi::SignRequest> {
    let mut id = [0; 32];
    OsRng.fill_bytes(&mut id);
    multi::fresh_attempt(q, id)
}
async fn backoff(gate: &Gate, seconds: u64) {
    gate.backoffs.fetch_add(1, Ordering::SeqCst);
    println!(
        "{}",
        json!({"event":"job_lifecycle_rate_limit","retry_after_secs":seconds})
    );
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}
async fn recover(
    sdk: &pairkey_sdk::service::Client,
    template: &multi::SignRequest,
    identities: [[u8; 32]; 2],
    gate: &Gate,
) -> anyhow::Result<(multi::SignRequest, multi::Signed, String)> {
    for _ in 0..3 {
        let q = retry(template)?;
        let id = sdk.submit_intent(&q).await?;
        match terminal(sdk, &q, identities).await? {
            multi::IntentJob::Complete { result } => return Ok((q, *result, id)),
            multi::IntentJob::Failed {
                code,
                retry_after_secs: Some(delay),
                ..
            } if code == "rate_limited" => backoff(gate, delay).await,
            other => anyhow::bail!("fresh recovery failed: {}", serde_json::to_string(&other)?),
        }
    }
    anyhow::bail!("recovery remained rate limited")
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    root: &Path,
    run: &Path,
    processes: &mut Processes,
    configs: &[PathBuf],
    relay: &Relay,
    rpc: &Rpc,
    payer: &Keypair,
    controller: Pubkey,
    identities: [[u8; 32]; 2],
    requests: &[multi::SignRequest],
) -> anyhow::Result<Value> {
    let gate = Arc::new(Gate {
        phase: Mutex::new(None),
        calls: AtomicU64::new(0),
        backoffs: AtomicU64::new(0),
    });
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()?;
    let mut servers = Servers(vec![]);
    let mut endpoints = vec![];
    for (i, config) in configs.iter().enumerate().take(2) {
        let config: Value = serde_json::from_slice(&std::fs::read(config)?)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        endpoints.push(format!("http://{}", listener.local_addr()?));
        let state = Proxy {
            target: format!("http://{}", config["bind"].as_str().context("worker bind")?),
            http: http.clone(),
            gate: gate.clone(),
            gated: i == 0,
        };
        servers.0.push(tokio::spawn(async move {
            axum::serve(listener, Router::new().fallback(proxy).with_state(state))
                .await
                .unwrap();
        }));
    }
    let endpoint = format!("http://127.0.0.1:{}", port()?);
    let config = pairkey_coordinator::Config {
        bind: endpoint.trim_start_matches("http://").into(),
        workers: endpoints.try_into().unwrap(),
        identities,
        jobs_file: Some(run.join("lifecycle-jobs.json").to_string_lossy().into()),
    };
    let path = run.join("lifecycle-coordinator.json");
    std::fs::write(&path, serde_json::to_vec(&config)?)?;
    let coordinator_bin = root.join("target/debug/pairkey-coordinator");
    let launch = || {
        spawn(
            &coordinator_bin,
            &[path.to_string_lossy().into()],
            &run.join("lifecycle-coordinator.log"),
        )
    };
    let index = processes.0.len();
    processes.0.push(Some(launch()?));
    ready(&http, &endpoint).await?;
    let sdk = pairkey_sdk::service::Client::new(endpoint.clone())?;
    let mut cases = vec![];
    for template in requests {
        let phases: &[&str] = match template.intent.key.suite {
            Suite::Dkls23Secp256k1 => &["register", "prepare", "sign", "ecdsa_result"],
            Suite::FrostRedPallas | Suite::FrostSecp256k1Tr => {
                &["red_begin", "red_finish", "red_result"]
            }
        };
        for phase in phases {
            for action in [
                "cancel",
                "coordinator_restart",
                "worker_restart",
                "policy_freeze",
            ] {
                if action == "policy_freeze" && phase.ends_with("result") {
                    continue;
                }
                let mut q = retry(template)?;
                let pause = Pause {
                    phase,
                    entered: Arc::new(Notify::new()),
                    release: Arc::new(Notify::new()),
                };
                *gate.phase.lock().unwrap() = Some(pause.clone());
                let mut id = sdk.submit_intent(&q).await?;
                ensure!(
                    sdk.submit_intent(&q).await? == id,
                    "duplicate created a new job"
                );
                let deadline = Instant::now() + Duration::from_secs(300);
                loop {
                    tokio::select! {
                        _ = pause.entered.notified()=>break,
                        _ = tokio::time::sleep(Duration::from_millis(100))=> {
                            match sdk.poll_intent(&q,identities).await? {
                                multi::IntentJob::Failed { code,retry_after_secs:Some(delay),.. } if code=="rate_limited"=>{
                                    backoff(&gate,delay).await;
                                    q=retry(template)?;
                                    id=sdk.submit_intent(&q).await?;
                                },
                                job if job.terminal()=>anyhow::bail!("job ended before stage {phase}: {}",serde_json::to_string(&job)?),
                                _=>(),
                            }
                        }
                    }
                    ensure!(
                        Instant::now() < deadline,
                        "transport stage {phase} not reached"
                    );
                }
                let mut subscription = sdk.subscribe(&id).await?;
                let event = subscription.chunk().await?.context("missing job event")?;
                ensure!(
                    String::from_utf8_lossy(&event).contains("data:"),
                    "missing SSE data"
                );
                drop(subscription);
                // Exercise cancellation while queued behind live protocol work once per suite.
                if action == "cancel" && *phase == phases[0] {
                    let queued = retry(template)?;
                    sdk.submit_intent(&queued).await?;
                    sdk.cancel_intent(&queued).await?;
                    ensure!(
                        matches!(
                            terminal(&sdk, &queued, identities).await?,
                            multi::IntentJob::Failed {
                                may_have_signed: false,
                                ..
                            }
                        ),
                        "queued cancellation started signing"
                    );
                }
                match action {
                    "cancel" => sdk.cancel_intent(&q).await?,
                    "policy_freeze" => {
                        send(
                            rpc,
                            payer,
                            vec![pairkey_sdk::through_controller(
                                payer.pubkey(),
                                pairkey_sdk::freeze(controller, &q.registration, true),
                            )],
                        )
                        .await?;
                    }
                    "coordinator_restart" => {
                        let mut child = processes.0[index].take().context("coordinator process")?;
                        child.kill()?;
                        child.wait()?;
                        processes.0[index] = Some(launch()?);
                        ready(&http, &endpoint).await?;
                    }
                    "worker_restart" => {
                        let mut child = processes.0[1].take().context("worker A")?;
                        child.kill()?;
                        child.wait()?;
                        processes.0[1] = Some(spawn(
                            &root.join("target/debug/pairkey-worker"),
                            &[configs[0].to_string_lossy().into()],
                            &run.join("worker-A-lifecycle.log"),
                        )?);
                        wait_worker(relay, 0).await?;
                    }
                    _ => unreachable!(),
                }
                pause.release.notify_one();
                let status = terminal(&sdk, &q, identities).await?;
                match (&status, action) {
                    (
                        multi::IntentJob::Failed {
                            code,
                            may_have_signed: true,
                            ..
                        },
                        "cancel",
                    ) => ensure!(code == "cancelled", "wrong cancellation result"),
                    (
                        multi::IntentJob::Failed {
                            code,
                            may_have_signed: true,
                            ..
                        },
                        "coordinator_restart",
                    ) => ensure!(code == "interrupted", "restart resumed an interrupted job"),
                    (multi::IntentJob::Failed { .. }, "worker_restart" | "policy_freeze") => (),
                    (multi::IntentJob::Complete { .. }, "worker_restart")
                        if phase.ends_with("result") => {} // signature already issued
                    _ => anyhow::bail!(
                        "unexpected terminal state at {phase}/{action}: {}",
                        serde_json::to_string(&status)?
                    ),
                }
                ensure!(
                    sdk.submit_intent(&q).await? == id,
                    "terminal retry was silently replayed"
                );
                if action == "policy_freeze" {
                    send(
                        rpc,
                        payer,
                        vec![pairkey_sdk::through_controller(
                            payer.pubkey(),
                            pairkey_sdk::freeze(controller, &q.registration, false),
                        )],
                    )
                    .await?;
                }
                let (fresh, result, fresh_id) = recover(&sdk, template, identities, &gate).await?;
                let before = gate.calls.load(Ordering::SeqCst);
                ensure!(
                    sdk.submit_intent(&fresh).await? == fresh_id,
                    "duplicate completed job"
                );
                let saved = sdk
                    .wait_intent(&fresh, identities, Duration::from_secs(5))
                    .await?;
                ensure!(
                    saved.signature == result.signature
                        && gate.calls.load(Ordering::SeqCst) == before,
                    "cached result started new signing"
                );
                cases.push(json!({"suite":template.intent.key.suite,"phase":phase,"action":action,"terminal_status":if matches!(status,multi::IntentJob::Complete{..}){"complete_before_crash"}else{"failed"},"explicit_fresh_retry_verified":true,"duplicate_submission_deduplicated":true,"cached_result_no_worker_calls":true}));
                println!(
                    "{}",
                    json!({"event":"job_lifecycle_case_passed","phase":phase,"action":action})
                );
            }
        }
        let (q, result, _) = recover(&sdk, template, identities, &gate).await?;
        let mut child = processes.0[index].take().context("coordinator process")?;
        child.kill()?;
        child.wait()?;
        processes.0[index] = Some(launch()?);
        ready(&http, &endpoint).await?;
        let before = gate.calls.load(Ordering::SeqCst);
        let saved = sdk
            .wait_intent(&q, identities, Duration::from_secs(5))
            .await?;
        ensure!(
            saved.signature == result.signature && gate.calls.load(Ordering::SeqCst) == before,
            "restart did not retain completed result"
        );
    }
    Ok(
        json!({"authorization":"program_cpi","cases":cases,"completed_results_survive_restart":true,"queued_cancellation_refused_before_start":true,"sse_observed":true,"rate_limit_backoffs":gate.backoffs.load(Ordering::SeqCst)}),
    )
}
