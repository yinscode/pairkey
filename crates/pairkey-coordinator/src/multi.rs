//! Multi-suite orchestration. The relay has no roots or signing authority.
use super::*;
use futures_util::{FutureExt, SinkExt, StreamExt};
use pairkey_signing::{self as signing, dkls, wire as mw, Suite};
use sl_mpc_mate::coord::SimpleMessageRelay;
fn fresh() -> [u8; 32] {
    let mut x = [0; 32];
    OsRng.fill_bytes(&mut x);
    x
}
impl Relay {
    async fn empty<T: Serialize + ?Sized>(
        &self,
        i: usize,
        path: &str,
        q: &T,
    ) -> anyhow::Result<()> {
        let response = self
            .client
            .post(format!("{}{}", self.config.workers[i], path))
            .json(q)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let status = response.status();
        let bytes = pairkey_sdk::http::bounded_body(response, 12 * 1024 * 1024).await?;
        ensure!(
            status.is_success(),
            "worker rejected {path}: {}",
            String::from_utf8_lossy(&bytes)
        );
        Ok(())
    }
    pub async fn multi_info(&self, q: &mw::KeyRequest) -> anyhow::Result<[mw::Info; 2]> {
        let (a, b) = tokio::join!(
            self.post::<_, mw::Info>(0, "/multi/info", q),
            self.post::<_, mw::Info>(1, "/multi/info", q)
        );
        let infos = [a?, b?];
        for (i, p) in infos.iter().enumerate() {
            p.verify(self.config.identities[i])?;
            ensure!(
                p.role.index() == i
                    && p.request.registration == q.registration
                    && p.request.account == q.account
                    && p.request.suite == q.suite,
                "backend info context"
            );
        }
        Ok(infos)
    }
    async fn d_open(&self, infos: &[mw::Info; 2]) -> anyhow::Result<()> {
        let opens = [
            mw::Open {
                peer: infos[1].clone(),
            },
            mw::Open {
                peer: infos[0].clone(),
            },
        ];
        let (a, b) = tokio::join!(
            self.post::<_, dkls::pool::Boot>(0, "/multi/d/open", &opens[0]),
            self.post::<_, dkls::pool::Boot>(1, "/multi/d/open", &opens[1])
        );
        let boots = [a?, b?];
        for (i, b) in boots.iter().enumerate() {
            b.validate()?;
            ensure!(
                b.role as usize == i && b.identity == infos[i].dkls_identity,
                "donor boot identity"
            );
        }
        let (a, b) = tokio::join!(
            self.empty(0, "/multi/d/enroll", &boots),
            self.empty(1, "/multi/d/enroll", &boots)
        );
        a?;
        b?;
        Ok(())
    }
    async fn d_command(
        &self,
        commands: [mw::DStart; 2],
    ) -> anyhow::Result<([Option<dkls::d::Reply>; 2], [Option<mw::Receipt>; 2])> {
        let trace = std::env::var_os("PAIRKEY_LATENCY_TRACE").is_some();
        let started = Instant::now();
        let mut exchanges = [0_u64; 2];
        let mut exchange_ms = [0_u128; 2];
        let id = commands[0].id;
        ensure!(commands[1].id == id, "operation ids");
        let (a, b) = tokio::join!(
            self.empty(0, "/multi/d/start", &commands[0]),
            self.empty(1, "/multi/d/start", &commands[1])
        );
        if matches!(&commands[0].operation, mw::DOperation::Sign { .. }) {
            if let Err(error) = a.and(b) {
                // No exchange frame has been sent to either signer yet.
                return Err(PreSignFailure(format!("DKLS signing start refused: {error}")).into());
            }
        } else {
            a?;
            b?;
        }
        let broker = SimpleMessageRelay::new();
        let mut relays = [broker.connect(), broker.connect()];
        let mut input: [Vec<dkls::Frame>; 2] = [vec![], vec![]];
        let mut done = [false; 2];
        let mut replies = [None, None];
        let mut receipts = [None, None];
        let deadline = Instant::now() + Duration::from_secs(40);
        while !done.iter().all(|x| *x) {
            ensure!(Instant::now() < deadline, "multi signing timeout");
            for i in 0..2 {
                while input[i].len() < 4 {
                    match relays[i].next().now_or_never() {
                        Some(Some(b)) => input[i].push(dkls::Frame::Relay(b)),
                        _ => break,
                    }
                }
            }
            let requests: [mw::Exchange; 2] = std::array::from_fn(|i| mw::Exchange {
                id,
                frames: std::mem::take(&mut input[i]),
            });
            let (a, b) = tokio::join!(
                async {
                    if done[0] {
                        Ok(None)
                    } else {
                        let started = Instant::now();
                        let out = self
                            .post::<_, mw::DOutput>(0, "/multi/d/exchange", &requests[0])
                            .await?;
                        Ok::<_, anyhow::Error>(Some((out, started.elapsed().as_millis())))
                    }
                },
                async {
                    if done[1] {
                        Ok(None)
                    } else {
                        let started = Instant::now();
                        let out = self
                            .post::<_, mw::DOutput>(1, "/multi/d/exchange", &requests[1])
                            .await?;
                        Ok::<_, anyhow::Error>(Some((out, started.elapsed().as_millis())))
                    }
                }
            );
            for (i, output) in [a?, b?].into_iter().enumerate() {
                let Some((out, elapsed_ms)) = output else {
                    continue;
                };
                exchanges[i] += 1;
                exchange_ms[i] += elapsed_ms;
                if let Some(r) = out.receipt {
                    r.verify(self.config.identities[i])?;
                    receipts[i] = Some(r);
                    done[i] = true;
                }
                for frame in out.frames {
                    match frame {
                        dkls::Frame::Relay(bytes) => relays[i]
                            .send(bytes)
                            .await
                            .map_err(|_| anyhow::anyhow!("native relay closed"))?,
                        dkls::Frame::Setup(bytes) => input[1 - i].push(dkls::Frame::Setup(bytes)),
                        dkls::Frame::DReply(r) => {
                            replies[i] = Some(r);
                            done[i] = true;
                        }
                        dkls::Frame::Ready(_) => {}
                        _ => anyhow::bail!("unexpected backend output"),
                    }
                }
                ensure!(
                    input[0].len() <= 16 && input[1].len() <= 16,
                    "relay queue bound"
                );
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        if trace {
            eprintln!(
                "pairkey_latency d_command total_ms={} exchanges={exchanges:?} exchange_ms={exchange_ms:?}",
                started.elapsed().as_millis()
            );
        }
        Ok((replies, receipts))
    }
    pub async fn multi_key(&self, q: mw::KeyRequest) -> anyhow::Result<mw::KeyResponse> {
        let work = async {
            let infos = self.multi_info(&q).await?;
            let certificate = match q.suite {
                Suite::FrostSecp256k1Tr => mw::Certificate::Bitcoin(signing::bitcoin::Public {
                    proofs: [
                        infos[0].bitcoin.clone().context("Bitcoin proof A")?,
                        infos[1].bitcoin.clone().context("Bitcoin proof B")?,
                    ],
                }),
                Suite::FrostRedPallas => mw::Certificate::RedPallas(signing::redpallas::Public {
                    proofs: [
                        infos[0].redpallas.clone().context("proof A")?,
                        infos[1].redpallas.clone().context("proof B")?,
                    ],
                }),
                Suite::Dkls23Secp256k1 => {
                    self.d_open(&infos).await?;
                    let id = fresh();
                    let commands = std::array::from_fn(|_| mw::DStart {
                        id,
                        operation: mw::DOperation::Register(Box::new(q.clone())),
                    });
                    let (replies, _) = self.d_command(commands).await?;
                    let certs = replies
                        .into_iter()
                        .map(|r| match r {
                            Some(dkls::d::Reply::Registered(c)) => Ok(*c),
                            _ => anyhow::bail!("registration reply"),
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    ensure!(certs[0] == certs[1], "registration disagreement");
                    mw::Certificate::Dkls(Box::new(certs[0].clone()))
                }
            };
            Ok::<_, anyhow::Error>(mw::KeyResponse {
                key: certificate.key(&q)?,
                certificate,
                infos,
            })
        }
        .await;
        if work.is_err() {
            self.multi_reset().await;
        }
        work
    }
    pub async fn multi_reset(&self) {
        let _ = self.multi_reset_checked().await;
    }
    pub async fn multi_reset_checked(&self) -> anyhow::Result<()> {
        let (a, b) = tokio::join!(
            self.empty(0, "/multi/reset", &()),
            self.empty(1, "/multi/reset", &())
        );
        a?;
        b?;
        Ok(())
    }
    pub async fn multi_clear_ephemeral_checked(&self) -> anyhow::Result<()> {
        let (a, b) = tokio::join!(
            self.empty(0, "/multi/clear-ephemeral", &()),
            self.empty(1, "/multi/clear-ephemeral", &())
        );
        a?;
        b?;
        Ok(())
    }
    pub async fn multi_sign(&self, q: mw::SignRequest) -> anyhow::Result<mw::Signed> {
        q.validate()?;
        let trace = std::env::var_os("PAIRKEY_LATENCY_TRACE").is_some();
        let started = Instant::now();
        let work = async {
            // Reopen/re-register after worker replacement; public identity must remain identical.
            let key = self
                .multi_key(mw::KeyRequest {
                    registration: q.registration.clone(),
                    account: q.intent.key.account.clone(),
                    suite: q.intent.key.suite,
                })
                .await?;
            if trace {
                eprintln!(
                    "pairkey_latency multi_sign registration_ms={}",
                    started.elapsed().as_millis()
                );
            }
            ensure!(key.key == q.intent.key, "registered key changed");
            let peers = self.peers().await?;
            let auths = std::array::from_fn::<_, 2, _>(|i| mw::Authorized {
                request: q.clone(),
                peer: peers[1 - i].clone(),
            });
            let receipts = match q.intent.key.suite {
                Suite::Dkls23Secp256k1 => {
                    let status_started = Instant::now();
                    let (a, b) = tokio::join!(
                        self.post::<_, mw::DStatus>(0, "/multi/d/status", &()),
                        self.post::<_, mw::DStatus>(1, "/multi/d/status", &())
                    );
                    let statuses = [a?, b?];
                    if trace {
                        eprintln!(
                            "pairkey_latency multi_sign donor_status_ms={} uses={}",
                            status_started.elapsed().as_millis(),
                            statuses[0].uses
                        );
                    }
                    let generation = if statuses[0].generation.is_some()
                        && statuses[0].generation == statuses[1].generation
                        && statuses[0].uses == statuses[1].uses
                        && statuses[0].uses < 100
                    {
                        statuses[0].generation.unwrap()
                    } else {
                        // Prepare retires any mismatched generation on both workers.
                        let id = fresh();
                        let (replies, _) = self
                            .d_command(std::array::from_fn(|_| mw::DStart {
                                id,
                                operation: mw::DOperation::Prepare,
                            }))
                            .await?;
                        let gens = replies
                            .into_iter()
                            .map(|r| match r {
                                Some(dkls::d::Reply::Donor { generation, .. }) => Ok(generation),
                                _ => anyhow::bail!("donor reply"),
                            })
                            .collect::<anyhow::Result<Vec<_>>>()?;
                        ensure!(gens[0] == gens[1], "donor disagreement");
                        gens[0]
                    };
                    let (_, receipts) = self
                        .d_command(std::array::from_fn(|i| mw::DStart {
                            id: q.attempt.digest(),
                            operation: mw::DOperation::Sign {
                                authorized: Box::new(auths[i].clone()),
                                generation,
                            },
                        }))
                        .await?;
                    if trace {
                        eprintln!(
                            "pairkey_latency multi_sign sign_total_ms={}",
                            started.elapsed().as_millis()
                        );
                    }
                    receipts
                        .map(|r| r.context("missing signing receipt"))
                        .into_iter()
                        .collect::<anyhow::Result<Vec<_>>>()?
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("receipt count"))?
                }
                Suite::FrostRedPallas | Suite::FrostSecp256k1Tr => {
                    let begins = [
                        mw::RBegin {
                            authorized: auths[0].clone(),
                        },
                        mw::RBegin {
                            authorized: auths[1].clone(),
                        },
                    ];
                    let (a, b) = tokio::join!(
                        self.post::<_, Envelope>(0, "/multi/r/begin", &begins[0]),
                        self.post::<_, Envelope>(1, "/multi/r/begin", &begins[1])
                    );
                    let rounds = match (a, b) {
                        (Ok(a), Ok(b)) => [a, b],
                        (a, b) => {
                            return Err(PreSignFailure(format!(
                                "FROST signing start refused: {}",
                                a.err().or_else(|| b.err()).unwrap()
                            ))
                            .into())
                        }
                    };
                    let finishes = std::array::from_fn::<_, 2, _>(
                        |i| json!({"authorized":auths[i],"rounds":rounds}),
                    );
                    let (a, b) = tokio::join!(
                        self.post::<_, Envelope>(0, "/multi/r/finish", &finishes[0]),
                        self.post::<_, Envelope>(1, "/multi/r/finish", &finishes[1])
                    );
                    let shares = [a?, b?];
                    let results = [
                        json!({"finish":finishes[0],"shares":shares}),
                        json!({"finish":finishes[1],"shares":shares}),
                    ];
                    let (a, b) = tokio::join!(
                        self.post::<_, mw::Receipt>(0, "/multi/r/result", &results[0]),
                        self.post::<_, mw::Receipt>(1, "/multi/r/result", &results[1])
                    );
                    [a?, b?]
                }
            };
            for (i, r) in receipts.iter().enumerate() {
                r.verify(self.config.identities[i])?;
                ensure!(
                    r.role.index() == i
                        && r.boot == peers[i].evidence.boot_id
                        && r.peer_boot == peers[1 - i].evidence.boot_id
                        && r.request.attempt.digest() == q.attempt.digest()
                        && r.request.intent == q.intent,
                    "receipt binding"
                );
            }
            ensure!(
                receipts[0].signature == receipts[1].signature,
                "signature disagreement"
            );
            Ok::<_, anyhow::Error>(mw::Signed {
                signature: receipts[0].signature.clone(),
                receipts,
            })
        }
        .await;
        if work.is_err() {
            self.multi_reset().await;
        }
        work
    }
}
pub(super) async fn key(
    State(s): State<S>,
    Json(q): Json<mw::KeyRequest>,
) -> Result<Json<mw::KeyResponse>, (StatusCode, Json<Value>)> {
    let guard = s.multi.clone().try_lock_owned().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"multi-suite worker busy"})),
        )
    })?;
    // The owner survives an HTTP disconnect and retains serialization through cleanup.
    tokio::spawn(async move {
        let work = async {
            s.relay.multi_clear_ephemeral_checked().await?;
            s.relay.multi_key(q).await
        };
        let result = tokio::time::timeout(Duration::from_secs(90), work).await;
        if matches!(&result, Ok(Ok(_))) {
            if let Err(e) = s.relay.multi_clear_ephemeral_checked().await {
                s.relay.multi_reset().await;
                eprintln!("multi-suite cleanup incomplete: {e}");
            }
        } else {
            s.relay.multi_reset().await;
        }
        drop(guard);
        result.map_err(anyhow::Error::from).and_then(|r| r)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":e.to_string()})),
        )
    })?
    .map(Json)
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":e.to_string()})),
        )
    })
}
pub(super) async fn sign(
    State(s): State<S>,
    Json(q): Json<mw::SignRequest>,
) -> Result<Json<mw::Signed>, (StatusCode, Json<Value>)> {
    let _waiter = s.subscriptions.clone().try_acquire_owned().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"result waiter capacity reached"})),
        )
    })?;
    let Json(submitted) = super::jobs::enqueue(s.clone(), q).await?;
    let id = submitted["job_id"].as_str().unwrap();
    loop {
        let job = match super::poll(State(s.clone()), Path(id.to_owned())).await {
            Ok(Json(value)) => Some(
                serde_json::from_value::<pairkey_sdk::multi::IntentJob>(value).map_err(|e| {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error":e.to_string()})),
                    )
                })?,
            ),
            Err(StatusCode::NOT_FOUND) => None,
            Err(code) => return Err((code, Json(json!({"error":"job store unavailable"})))),
        };
        match job {
            Some(pairkey_sdk::multi::IntentJob::Complete { result }) => return Ok(Json(*result)),
            Some(pairkey_sdk::multi::IntentJob::Failed {
                code,
                error,
                may_have_signed,
                retry_after_secs,
            }) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({"error":error,"code":code,"may_have_signed":may_have_signed,"retry_after_secs":retry_after_secs}),
                    ),
                ))
            }
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({"error":"job unavailable"})),
                ))
            }
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}
