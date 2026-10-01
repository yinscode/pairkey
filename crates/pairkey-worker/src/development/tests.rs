use super::*;
use pair_registry::{EnclaveSet, NamespaceRecord, RequestRecord};
use pairkey_types::{AccountPath, Commit, Scheme};

struct RpcState {
    observation: Observation,
    paused: AtomicBool,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
async fn rpc(State(state): State<Arc<RpcState>>, Json(q): Json<Value>) -> Json<Value> {
    let o = &state.observation;
    let result = match q["method"].as_str().unwrap() {
        "getMultipleAccounts" => {
            let accounts: Vec<_> = [&o.set, &o.namespace, &o.request].into_iter().map(|a| {
                json!({"owner":a.owner.to_string(), "data":[STANDARD.encode(&a.data), "base64"]})
            }).chain(std::iter::once(Value::Null)).collect();
            json!({"context":{"slot":o.slot},"value":accounts})
        }
        "getBlockTime" => {
            if state.paused.load(Ordering::SeqCst) {
                state.entered.notify_one();
                state.resume.notified().await;
            }
            json!(o.block_time)
        }
        other => panic!("unexpected test RPC {other}"),
    };
    Json(json!({"jsonrpc":"2.0", "id":1,"result":result}))
}
struct Fixture {
    worker: W,
    peer: Channel,
    peer_signer: Signer,
    begin: Begin,
    rpc: Arc<RpcState>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        Self::new_with(false).await
    }
    async fn new_with(red: bool) -> Self {
        let a_identity = Channel::development(Role::A, [31; 32], [0; 32]).identity();
        let peer = Channel::development(Role::B, [32; 32], a_identity);
        let channel = Channel::development(Role::A, [31; 32], peer.identity());
        let signer = Signer::new(Root::new([11; 32]), Role::A);
        let peer_signer = Signer::new(Root::new([22; 32]), Role::B);
        let program = pair_registry::id();
        let ns = Namespace {
            version: 1,
            scheme: Scheme::FrostEd25519,
            network: [1; 32],
            registry: program.to_bytes(),
            derivation_authority: [3; 32],
            namespace_id: [4; 32],
            enclave_set: [5; 32],
        };
        let reg = register(
            ns.clone(),
            &signer.proof(&ns, &mut OsRng).unwrap(),
            &peer_signer.proof(&ns, &mut OsRng).unwrap(),
        )
        .unwrap();
        let message = if red {
            let path = AccountPath {
                destination: [8; 32],
                path: vec![1],
            };
            let public = pairkey_signing::redpallas::Public {
                proofs: [
                    pairkey_signing::redpallas::proof(&[11; 32], &reg, &path, Role::A).unwrap(),
                    pairkey_signing::redpallas::proof(&[22; 32], &reg, &path, Role::B).unwrap(),
                ],
            };
            pairkey_signing::Intent {
                version: 1,
                key: public.key(&reg, &path).unwrap(),
                payload: pairkey_signing::Payload::RedPallas {
                    message: b"worker test".to_vec(),
                },
            }
            .bytes()
            .unwrap()
        } else {
            b"approved original bytes".to_vec()
        };
        let commit = Commit::new(
            &reg,
            [7; 32],
            AccountPath {
                destination: [8; 32],
                path: vec![1],
            },
            &message,
        )
        .unwrap();
        let namespace = pair_registry::namespace_address(&program, &reg).0;
        let set = pair_registry::set_address(&program, &ns.enclave_set).0;
        let identities = [channel.identity(), peer.identity()];
        let observation = Observation {
            policy: None,
            session: None,
            simulation: None,
            network: ns.network,
            finalized: true,
            slot: 100,
            block_time: now(),
            observed_at: now(),
            provider_domain: "test-A".into(),
            set: ObservedAccount {
                address: set,
                owner: program,
                data: borsh::to_vec(&EnclaveSet {
                    version: 1,
                    set_id: ns.enclave_set,
                    governor: [9; 32],
                    identities,
                    retired: false,
                    development: true,
                })
                .unwrap(),
            },
            namespace: ObservedAccount {
                address: namespace,
                owner: program,
                data: borsh::to_vec(&NamespaceRecord {
                    registration: reg.clone(),
                    controller: [3; 32],
                    frozen: false,
                })
                .unwrap(),
            },
            request: ObservedAccount {
                address: pair_registry::request_address(&program, &namespace, &commit.request_id).0,
                owner: program,
                data: borsh::to_vec(&RequestRecord {
                    namespace_address: namespace.to_bytes(),
                    commit: commit.clone(),
                    derived_key: derive_public(&reg, &commit.account).unwrap(),
                })
                .unwrap(),
            },
        };
        let trust = Trust {
            registry: program,
            network: ns.network,
            enclave_set: set,
            identity_keys: identities,
            set_governor: [9; 32],
            provider_domain: "test-A".into(),
            allow_development: true,
            max_observation_age_secs: 3,
            max_chain_lag_secs: 30,
        };
        let state = Arc::new(RpcState {
            observation,
            paused: AtomicBool::new(false),
            entered: Default::default(),
            resume: Default::default(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route("/", post(rpc))
            .with_state(Arc::clone(&state));
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let begin = Begin {
            registration: reg,
            attempt: Attempt {
                commit,
                random_id: [6; 32],
                authorization: Default::default(),
            },
            message,
            peer: peer.attest(channel.boot_id()),
        };
        let worker = Arc::new(Worker {
            multi: multi::Multi::new([11; 32], String::new(), None),
            signer,
            channel,
            rpc: Rpc::new(url).unwrap(),
            trust,
            pending: Mutex::new(BTreeMap::new()),
            release: Mutex::new(ReleaseState::default()),
            freshness: Default::default(),
            started: Instant::now(),
            capacity: Arc::new(tokio::sync::Semaphore::new(16)),
            nonce_capacity: Arc::new(tokio::sync::Semaphore::new(64)),
        });
        Self {
            worker,
            peer,
            peer_signer,
            begin,
            rpc: state,
            server,
        }
    }
    fn own_attestation(&self) -> pairkey_channel::Attestation {
        self.worker.channel.attest(self.peer.boot_id())
    }
    async fn rounds(&self) -> Finish {
        let a = begin(State(Arc::clone(&self.worker)), Json(self.begin.clone()))
            .await
            .unwrap()
            .0;
        let b = self
            .peer_signer
            .begin(
                &self.begin.registration,
                &self.begin.attempt,
                &self.begin.message,
                &mut OsRng,
            )
            .unwrap();
        let b = self
            .peer
            .seal(&self.own_attestation(), self.begin.attempt.digest(), 1, &b)
            .unwrap();
        Finish {
            begin: self.begin.clone(),
            rounds: [a, b],
        }
    }
    async fn shares(&self, rounds: &Finish) -> [Envelope; 2] {
        let a = finish(State(Arc::clone(&self.worker)), Json(rounds.clone()))
            .await
            .unwrap()
            .0;
        let decoded = self.worker.decode_rounds(rounds).unwrap();
        let b = self
            .peer_signer
            .finish(&self.begin.attempt, &decoded)
            .unwrap();
        let b = self
            .peer
            .seal(&self.own_attestation(), self.begin.attempt.digest(), 2, &b)
            .unwrap();
        [a, b]
    }
    async fn paused_finish(
        &self,
        request: Finish,
    ) -> tokio::task::JoinHandle<Result<Json<Envelope>, Failure>> {
        self.rpc.paused.store(true, Ordering::SeqCst);
        let w = Arc::clone(&self.worker);
        let task = tokio::spawn(async move { finish(State(w), Json(request)).await });
        tokio::time::timeout(Duration::from_secs(2), self.rpc.entered.notified())
            .await
            .unwrap();
        task
    }
}

#[tokio::test]
async fn transcript_splice_refuses_without_incident_but_authenticated_bad_share_stops_worker() {
    let f = Fixture::new().await;
    let first = f.rounds().await;
    let old = f.shares(&first).await;
    let _ = result(
        State(Arc::clone(&f.worker)),
        Json(ResultRequest {
            finish: first,
            shares: old.clone(),
        }),
    )
    .await
    .unwrap();
    let second = f.rounds().await;
    assert!(result(
        State(Arc::clone(&f.worker)),
        Json(ResultRequest {
            finish: second.clone(),
            shares: old
        })
    )
    .await
    .is_err());
    assert!(!f.worker.release.lock().unwrap().incident);
    let mut shares = f.shares(&second).await;
    let _ = result(
        State(Arc::clone(&f.worker)),
        Json(ResultRequest {
            finish: second.clone(),
            shares: shares.clone(),
        }),
    )
    .await
    .unwrap();
    let id = f.begin.attempt.digest();
    let mut bad: RoundTwo = f
        .peer
        .open(&f.own_attestation(), id, 2, &shares[1])
        .unwrap();
    bad.share = vec![0; 32];
    shares[1] = f.peer.seal(&f.own_attestation(), id, 2, &bad).unwrap();
    assert!(result(
        State(Arc::clone(&f.worker)),
        Json(ResultRequest {
            finish: second,
            shares
        })
    )
    .await
    .is_err());
    assert!(f.worker.release.lock().unwrap().incident);
    assert!(begin(State(Arc::clone(&f.worker)), Json(f.begin.clone()))
        .await
        .is_err());
}

#[tokio::test]
async fn cancelled_finish_drops_nonce_and_releases_admission() {
    let f = Fixture::new().await;
    let request = f.rounds().await;
    let task = f.paused_finish(request.clone()).await;
    assert_eq!(f.worker.nonce_capacity.available_permits(), 63);
    assert!(f.worker.claim(f.begin.attempt.digest()).is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(f.worker.pending.lock().unwrap().is_empty());
    assert_eq!(f.worker.nonce_capacity.available_permits(), 64);
    assert!(finish(State(Arc::clone(&f.worker)), Json(request))
        .await
        .is_err());
}

#[tokio::test]
async fn abort_and_reaping_cancel_in_flight_nonce_without_releasing_its_capacity_early() {
    for reap in [false, true] {
        let f = Fixture::new().await;
        let request = f.rounds().await;
        let task = f.paused_finish(request).await;
        if reap {
            f.worker
                .pending
                .lock()
                .unwrap()
                .get_mut(&f.begin.attempt.digest())
                .unwrap()
                .created = Instant::now() - ATTEMPT_TTL;
            f.worker.prune();
        } else {
            abort(State(Arc::clone(&f.worker)), Json(f.begin.attempt.clone())).await;
        }
        assert!(f.worker.pending.lock().unwrap().is_empty());
        assert_eq!(f.worker.nonce_capacity.available_permits(), 63);
        f.rpc.resume.notify_one();
        assert!(task.await.unwrap().is_err());
        assert_eq!(f.worker.nonce_capacity.available_permits(), 64);
        assert!(!f.worker.release.lock().unwrap().incident);
    }
}

#[tokio::test]
async fn finish_deadline_covers_rpc_wait_and_clears_owned_nonce() {
    let f = Fixture::new().await;
    let request = f.rounds().await;
    f.worker
        .pending
        .lock()
        .unwrap()
        .get_mut(&f.begin.attempt.digest())
        .unwrap()
        .created = Instant::now() - ATTEMPT_TTL + Duration::from_secs(1);
    let task = f.paused_finish(request).await;
    assert!(tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert!(f.worker.pending.lock().unwrap().is_empty());
    assert_eq!(f.worker.nonce_capacity.available_permits(), 64);
}

#[tokio::test]
async fn old_finish_cleanup_cannot_remove_new_generation() {
    let f = Fixture::new().await;
    f.rounds().await;
    let old = f.worker.claim(f.begin.attempt.digest()).unwrap();
    abort(State(Arc::clone(&f.worker)), Json(f.begin.attempt.clone())).await;
    let _ = begin(State(Arc::clone(&f.worker)), Json(f.begin.clone()))
        .await
        .unwrap();
    assert_eq!(f.worker.nonce_capacity.available_permits(), 62);
    drop(old);
    assert_eq!(f.worker.pending.lock().unwrap().len(), 1);
    assert_eq!(f.worker.nonce_capacity.available_permits(), 63);
}

#[tokio::test]
async fn known_controls_policy_incidents_and_elapsed_freshness_fence_prepared_release() {
    let f = Fixture::new().await;
    let mut view = f.worker.observe(&f.begin).await.unwrap();
    drop(f.worker.release_guard(&f.begin, &view).unwrap());
    f.worker.observe_inactive(view.observation.slot).unwrap();
    assert!(f.worker.release_guard(&f.begin, &view).is_err());
    // Fresh fixture for independent policy and incident transitions.
    let f = Fixture::new().await;
    view = f.worker.observe(&f.begin).await.unwrap();
    f.worker.release.lock().unwrap().policies.insert(
        view.observation.namespace.address,
        (1, view.observation.slot + 1),
    );
    assert!(f.worker.release_guard(&f.begin, &view).is_err());
    f.worker.release.lock().unwrap().policies.insert(
        view.observation.namespace.address,
        (0, view.observation.slot),
    );
    f.worker.release.lock().unwrap().incident = true;
    assert!(f.worker.release_guard(&f.begin, &view).is_err());
    f.worker.release.lock().unwrap().incident = false;
    view.observation.observed_at -= 4;
    assert!(f.worker.release_guard(&f.begin, &view).is_err());
}

#[tokio::test]
async fn local_issuance_and_negative_observation_have_a_single_order() {
    let f = Fixture::new().await;
    let rounds = f.rounds().await;
    let view = f.worker.observe(&f.begin).await.unwrap();
    let mut owned = f.worker.claim(f.begin.attempt.digest()).unwrap();
    let release = f.worker.release_guard(&f.begin, &view).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            started_tx.send(()).unwrap();
            f.worker.observe_inactive(view.observation.slot).unwrap();
            done_tx.send(()).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(f.worker.release.try_lock().is_err());
        let share = owned
            .sign(&f.worker.decode_rounds(&rounds).unwrap())
            .unwrap();
        f.worker
            .channel
            .seal(&f.begin.peer, f.begin.attempt.digest(), 2, &share)
            .unwrap();
        assert!(done_rx.try_recv().is_err());
        drop(release);
        done_rx.recv().unwrap();
    });
    assert!(f.worker.release_guard(&f.begin, &view).is_err());
}

fn red_request(f: &Fixture) -> pairkey_signing::wire::Authorized {
    use pairkey_signing::{redpallas, wire as mw, Intent, Payload};
    let reg = &f.begin.registration;
    let path = &f.begin.attempt.commit.account;
    let public = redpallas::Public {
        proofs: [
            redpallas::proof(&[11; 32], reg, path, Role::A).unwrap(),
            redpallas::proof(&[22; 32], reg, path, Role::B).unwrap(),
        ],
    };
    mw::Authorized {
        request: mw::SignRequest {
            registration: reg.clone(),
            attempt: f.begin.attempt.clone(),
            intent: Intent {
                version: 1,
                key: public.key(reg, path).unwrap(),
                payload: Payload::RedPallas {
                    message: b"worker test".to_vec(),
                },
            },
            certificate: mw::Certificate::RedPallas(public),
        },
        peer: f.begin.peer.clone(),
    }
}
async fn red_rounds(f: &Fixture) -> multi::RedFinish {
    use pairkey_signing::{redpallas, wire as mw};
    let a = red_request(f);
    let own = multi::rbegin(
        State(f.worker.clone()),
        Json(mw::RBegin {
            authorized: a.clone(),
        }),
    )
    .await
    .unwrap()
    .0;
    let mw::Certificate::RedPallas(public) = &a.request.certificate else {
        panic!()
    };
    let (round, _owned) = redpallas::Pending::begin(
        &[22; 32],
        &a.request.registration,
        &a.request.intent.key.account,
        public,
        Role::B,
        b"worker test",
    )
    .unwrap();
    let peer = f
        .peer
        .seal(&f.own_attestation(), a.request.attempt.digest(), 11, &round)
        .unwrap();
    multi::RedFinish {
        authorized: a,
        rounds: [own, peer],
    }
}
#[tokio::test]
async fn redpallas_duplicate_finish_and_stale_rounds_burn_without_false_incident() {
    let f = Fixture::new_with(true).await;
    let first = red_rounds(&f).await;
    let _ = multi::rfinish(State(f.worker.clone()), Json(first.clone()))
        .await
        .unwrap();
    assert!(multi::rfinish(State(f.worker.clone()), Json(first.clone()))
        .await
        .is_err());
    let second = red_rounds(&f).await;
    let mut stale = second.clone();
    stale.rounds[0] = first.rounds[0].clone();
    assert!(multi::rfinish(State(f.worker.clone()), Json(stale))
        .await
        .is_err());
    assert!(!f.worker.release.lock().unwrap().incident);
    assert!(multi::rfinish(State(f.worker.clone()), Json(second))
        .await
        .is_err());
    let third = red_rounds(&f).await;
    let _ = multi::rfinish(State(f.worker.clone()), Json(third))
        .await
        .unwrap();
}
#[tokio::test]
async fn redpallas_cancel_during_rpc_burns_nonce_and_retains_capacity_until_exit() {
    let f = Fixture::new_with(true).await;
    let rounds = red_rounds(&f).await;
    f.rpc.paused.store(true, Ordering::SeqCst);
    let w = f.worker.clone();
    let first = rounds.clone();
    let task = tokio::spawn(async move { multi::rfinish(State(w), Json(first)).await });
    f.rpc.entered.notified().await;
    assert!(
        multi::rfinish(State(f.worker.clone()), Json(rounds.clone()))
            .await
            .is_err()
    );
    f.rpc.paused.store(false, Ordering::SeqCst);
    assert!(multi::rbegin(
        State(f.worker.clone()),
        Json(pairkey_signing::wire::RBegin {
            authorized: rounds.authorized
        })
    )
    .await
    .is_err());
    assert_eq!(f.worker.nonce_capacity.available_permits(), 63);
    multi::reset(State(f.worker.clone())).await;
    assert_eq!(f.worker.nonce_capacity.available_permits(), 63);
    f.rpc.resume.notify_one();
    assert!(task.await.unwrap().is_err());
    assert_eq!(f.worker.nonce_capacity.available_permits(), 64);
}
