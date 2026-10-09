use super::*;
use pair_registry::{EnclaveSet, NamespaceRecord, RequestRecord};
use pairkey_types::approval::{
    Approval, Identity, Proof, Request, Rules, Submission, APPROVAL_VERSION,
};
use pairkey_types::{AccountPath, Commit, Scheme};

struct RpcState {
    observation: Mutex<Observation>,
    paused: AtomicBool,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
async fn rpc(State(state): State<Arc<RpcState>>, Json(q): Json<Value>) -> Json<Value> {
    let result = match q["method"].as_str().unwrap() {
        "getMultipleAccounts" => {
            let o = state.observation.lock().unwrap();
            let known = [&o.set, &o.namespace, &o.request]
                .into_iter()
                .chain(o.policy.as_ref())
                .chain(o.rules.as_ref())
                .chain(o.session.as_ref());
            let known: BTreeMap<_, _> = known.map(|a| (a.address.to_string(), a)).collect();
            let accounts:Vec<_>=q["params"][0].as_array().unwrap().iter().map(|key| {
                known.get(key.as_str().unwrap()).map(|a|json!({"owner":a.owner.to_string(),"data":[STANDARD.encode(&a.data),"base64"]})).unwrap_or(Value::Null)
            }).collect();
            json!({"context":{"slot":o.slot},"value":accounts})
        }
        "getBlockTime" => {
            if state.paused.load(Ordering::SeqCst) {
                state.entered.notify_one();
                state.resume.notified().await;
            }
            json!(state.observation.lock().unwrap().block_time)
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
    fn wallet_submission(&self) -> Submission {
        use ed25519_dalek::Signer as _;
        let request = Request {
            version: APPROVAL_VERSION,
            identity: Identity::Account {
                public_key: self.begin.registration.namespace.derivation_authority,
            },
            commit: self.begin.attempt.commit.clone(),
            policy_revision: 0,
            policy_digest: Rules::default().digest(),
            issued_at: now(),
            expires_at: now() + 120,
        };
        let proof = Proof::Account {
            signature: ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                .sign(&request.signing_message())
                .to_bytes()
                .to_vec(),
        };
        Submission {
            registration: self.begin.registration.clone(),
            payload: self.begin.message.clone(),
            approval: Approval { request, proof },
        }
    }
    async fn wallet() -> (Self, Submission) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let mut f = Self::new_source(
            false,
            Some(Identity::Account {
                public_key: key.verifying_key().to_bytes(),
            }),
        )
        .await;
        let q = f.wallet_submission();
        f.begin.attempt.authorization =
            offchain::approve(State(Arc::clone(&f.worker)), Json(q.clone()))
                .await
                .unwrap()
                .0;
        (f, q)
    }
    async fn new() -> Self {
        Self::new_with(false).await
    }
    async fn new_with(red: bool) -> Self {
        Self::new_source(red, None).await
    }
    async fn new_source(red: bool, identity: Option<pairkey_types::approval::Identity>) -> Self {
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
            derivation_authority: identity.as_ref().map(|i| i.authority()).unwrap_or([3; 32]),
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
        let mut observation = Observation {
            rules: None,
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
        if identity.is_some() {
            observation.namespace.owner = solana_sdk::system_program::id();
            observation.namespace.data.clear();
            observation.request.data.clear();
        }
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
            observation: Mutex::new(observation),
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
            offchain: offchain::Offchain::new(
                std::env::temp_dir()
                    .join(format!(
                        "pairkey-offchain-test-{}",
                        Pubkey::new_from_array(pairkey_signing::dkls::fresh())
                    ))
                    .to_str()
                    .unwrap(),
                &trust,
                Role::A,
                vec![],
            )
            .unwrap(),
            multi: multi::Multi::new([11; 32], String::new(), None),
            signer,
            channel,
            rpc: Rpc::new(url).unwrap(),
            trust,
            pending: Mutex::new(BTreeMap::new()),
            release: Mutex::new(
                ReleaseState::load(
                    std::env::temp_dir()
                        .join(format!(
                            "pairkey-worker-test-{}",
                            Pubkey::new_from_array(pairkey_signing::dkls::fresh())
                        ))
                        .to_str()
                        .unwrap(),
                )
                .unwrap(),
            ),
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
    assert_eq!(
        f.worker
            .release
            .lock()
            .unwrap()
            .incident_store
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .unwrap(),
        b"incident-v1\n"
    );
    assert!(begin(State(Arc::clone(&f.worker)), Json(f.begin.clone()))
        .await
        .is_err());
}

#[tokio::test]
async fn offchain_account_signs_without_registration_and_recovers_public_result() {
    let (f, q) = Fixture::wallet().await;
    assert!(f.rpc.observation.lock().unwrap().namespace.data.is_empty());
    let rounds = f.rounds().await;
    let shares = f.shares(&rounds).await;
    let output = result(
        State(Arc::clone(&f.worker)),
        Json(ResultRequest {
            finish: rounds,
            shares,
        }),
    )
    .await
    .unwrap()
    .0;
    pairkey_sdk::service::verify_receipt(
        &f.begin.registration,
        &f.begin.attempt,
        &f.begin.message,
        &output,
        f.worker.channel.identity(),
        Role::A,
        true,
    )
    .unwrap();
    assert!(begin(State(Arc::clone(&f.worker)), Json(f.begin.clone()))
        .await
        .is_err());
    let cached = offchain::lookup(
        State(Arc::clone(&f.worker)),
        Json(offchain::Lookup {
            namespace_digest: f.begin.registration.namespace.digest(),
            request_id: f.begin.attempt.commit.request_id,
            approval_digest: q.approval.request.digest(),
        }),
    )
    .await
    .unwrap()
    .0
    .unwrap();
    let pairkey_core::approval_store::Status::Complete(bytes) = cached else {
        panic!("missing persisted result")
    };
    let recovered: ResultResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(recovered.receipt.signature, output.receipt.signature);
}

#[tokio::test]
async fn invalid_private_proof_cannot_approve_or_start_a_request() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let mut f = Fixture::new_source(
        false,
        Some(Identity::Account {
            public_key: key.verifying_key().to_bytes(),
        }),
    )
    .await;
    let mut q = f.wallet_submission();
    if let Proof::Account { signature } = &mut q.approval.proof {
        signature[0] ^= 1;
    }
    f.begin.attempt.authorization = pairkey_types::policy::Authorization::offchain(&q.approval);
    assert!(offchain::approve(State(Arc::clone(&f.worker)), Json(q))
        .await
        .is_err());
    assert!(begin(State(Arc::clone(&f.worker)), Json(f.begin.clone()))
        .await
        .is_err());
    assert!(f.worker.pending.lock().unwrap().is_empty());
    assert!(!f
        .worker
        .offchain
        .store
        .lock()
        .unwrap()
        .knows_policy(f.begin.registration.namespace.digest())
        .unwrap());
}

#[tokio::test]
async fn denied_policy_update_fences_an_older_prepared_request() {
    let (f, q) = Fixture::wallet().await;
    let old = f.worker.observe(&f.begin).await.unwrap();
    {
        let mut o = f.rpc.observation.lock().unwrap();
        o.slot += 1;
        o.rules = Some(ObservedAccount {
            address: pair_registry::approval::rules_address(
                &f.worker.trust.registry,
                &f.begin.registration.namespace.digest(),
            )
            .0,
            owner: f.worker.trust.registry,
            data: borsh::to_vec(&pair_registry::approval::RulesRecord {
                namespace_digest: f.begin.registration.namespace.digest(),
                rules: Rules {
                    revision: 1,
                    disabled: true,
                    ..Default::default()
                },
            })
            .unwrap(),
        });
    }
    assert!(offchain::approve(State(Arc::clone(&f.worker)), Json(q))
        .await
        .is_err());
    assert!(f.worker.release_guard(&f.begin, &old).is_err());
    assert!(begin(State(Arc::clone(&f.worker)), Json(f.begin.clone()))
        .await
        .is_err());
}

#[tokio::test]
async fn cancelled_offchain_attempt_cannot_restart_with_new_randomness() {
    let (f, _) = Fixture::wallet().await;
    let _ = begin(State(Arc::clone(&f.worker)), Json(f.begin.clone()))
        .await
        .unwrap();
    abort(State(Arc::clone(&f.worker)), Json(f.begin.attempt.clone())).await;
    assert!(begin(State(Arc::clone(&f.worker)), Json(f.begin.clone()))
        .await
        .is_err());
    let mut another = f.begin.clone();
    another.attempt.random_id = [8; 32];
    assert!(begin(State(Arc::clone(&f.worker)), Json(another))
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
            protocol: pairkey_signing::wire::PROTOCOL_VERSION,
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

#[tokio::test]
async fn passkey_bound_ephemeral_key_authorizes_redpallas_without_exposing_assertion() {
    use ed25519_dalek::Signer as _;
    use pairkey_signing::{redpallas, wire as mw};
    use pairkey_types::approval::{Assertion, Binding};
    use sha2::{Digest, Sha256};
    let owner = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
    let identity = Identity::Passkey {
        public_key: owner
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        rp_id: "pairkey.com".into(),
        origin: "https://pairkey.com".into(),
    };
    let mut f = Fixture::new_source(true, Some(identity.clone())).await;
    let ephemeral = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
    let request = Request {
        version: APPROVAL_VERSION,
        identity: identity.clone(),
        commit: f.begin.attempt.commit.clone(),
        policy_revision: 0,
        policy_digest: Rules::default().digest(),
        issued_at: now(),
        expires_at: now() + 120,
    };
    let binding = Binding {
        namespace_digest: f.begin.registration.namespace.digest(),
        identity_digest: identity.digest(),
        public_key: ephemeral.verifying_key().to_bytes(),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
    };
    let mut authenticator_data = Sha256::digest(b"pairkey.com").to_vec();
    authenticator_data.extend([5, 0, 0, 0, 0]);
    let client_data_json=serde_json::to_vec(&json!({"type":"webauthn.get","origin":"https://pairkey.com","challenge":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(binding.challenge())})).unwrap();
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature: p256::ecdsa::Signature = owner.sign(&signed);
    let assertion = Assertion {
        authenticator_data,
        client_data_json,
        signature_der: signature.to_der().as_bytes().to_vec(),
    };
    let signature = ephemeral
        .sign(&request.signing_message())
        .to_bytes()
        .to_vec();
    let q = Submission {
        registration: f.begin.registration.clone(),
        payload: f.begin.message.clone(),
        approval: Approval {
            request,
            proof: Proof::Passkey {
                binding,
                assertion,
                signature,
            },
        },
    };
    f.begin.attempt.authorization = offchain::approve(State(f.worker.clone()), Json(q))
        .await
        .unwrap()
        .0;
    let a = red_request(&f);
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
        unreachable!()
    };
    let (peer_round, peer_pending) = redpallas::Pending::begin(
        &[22; 32],
        &a.request.registration,
        &a.request.intent.key.account,
        public,
        Role::B,
        b"worker test",
    )
    .unwrap();
    let peer_round = f
        .peer
        .seal(
            &f.own_attestation(),
            a.request.attempt.digest(),
            11,
            &peer_round,
        )
        .unwrap();
    let rounds = multi::RedFinish {
        authorized: a.clone(),
        rounds: [own, peer_round],
    };
    let decoded = multi::rounds(&f.worker, &rounds).unwrap();
    let own_share = multi::rfinish(State(f.worker.clone()), Json(rounds.clone()))
        .await
        .unwrap()
        .0;
    let peer_share = peer_pending.finish(&decoded).unwrap();
    let transcript = pairkey_types::digest(
        b"pairkey/redpallas/rounds/v1",
        &(a.request.attempt.digest(), &decoded),
    );
    let peer_share = f
        .peer
        .seal(
            &f.own_attestation(),
            a.request.attempt.digest(),
            12,
            &(transcript, peer_share),
        )
        .unwrap();
    let receipt = multi::rresult(
        State(f.worker.clone()),
        Json(multi::RedResult {
            finish: rounds,
            shares: [own_share, peer_share],
        }),
    )
    .await
    .unwrap()
    .0;
    receipt.verify(f.worker.channel.identity()).unwrap();
    a.request.intent.verify(&receipt.signature).unwrap();
    assert!(!serde_json::to_string(&receipt)
        .unwrap()
        .contains("client_data_json"));
    assert!(
        multi::rbegin(State(f.worker.clone()), Json(mw::RBegin { authorized: a }))
            .await
            .is_err()
    );
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

#[test]
fn incident_latch_survives_restart_and_unknown_state_fails_closed() {
    let path = std::env::temp_dir().join(format!(
        "pairkey-incident-{}",
        Pubkey::new_from_array(pairkey_signing::dkls::fresh())
    ));
    let name = path.to_str().unwrap();
    {
        let mut release = ReleaseState::load(name).unwrap();
        assert!(!release.incident);
        assert!(ReleaseState::load(name).is_err());
        release.record_incident().unwrap();
    }
    assert!(ReleaseState::load(name).unwrap().incident);
    for corrupt in [b"".as_slice(), b"ready-v2\n", b"partial"] {
        std::fs::write(&path, corrupt).unwrap();
        assert!(ReleaseState::load(name).unwrap().incident);
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(format!("{name}.lock")).unwrap();
}
