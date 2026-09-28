//! Disposable validator and separate service processes; test funding only.
use anyhow::{ensure, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use pairkey_coordinator::{Job, Relay, SignRequest, SignedResult};
use pairkey_sdk::rpc::Rpc;
use pairkey_types::{AccountPath, Attempt, Commit, Namespace, Role, Scheme};
use pairkey_worker::wire::{Begin, Finish, Health, ResultRequest, ResultResponse};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    hash::Hash,
    instruction::Instruction,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
    transaction::Transaction,
};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Processes(Vec<Option<Child>>);
impl Drop for Processes {
    fn drop(&mut self) {
        for child in self.0.iter_mut().flatten() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn port() -> anyhow::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}
fn spawn(program: &Path, args: &[String], log: &Path) -> anyhow::Result<Child> {
    let file = std::fs::File::create(log)?;
    Ok(Command::new(program)
        .args(args)
        .stdout(Stdio::from(file.try_clone()?))
        .stderr(Stdio::from(file))
        .spawn()?)
}
fn private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}
async fn blockhash(rpc: &Rpc) -> anyhow::Result<Hash> {
    Ok(rpc
        .call("getLatestBlockhash", json!([{"commitment":"finalized"}]))
        .await?["value"]["blockhash"]
        .as_str()
        .context("blockhash")?
        .parse()?)
}
async fn processed(rpc: &Rpc, signature: Signature) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let result = rpc
            .call("getSignatureStatuses", json!([[signature.to_string()]]))
            .await?;
        let status = &result["value"][0];
        if !status.is_null() {
            ensure!(status["err"].is_null(), "transaction failed: {status}");
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "processing timeout");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn confirmed(rpc: &Rpc, signature: Signature) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(35);
    loop {
        let result = rpc
            .call(
                "getSignatureStatuses",
                json!([[signature.to_string()],{"searchTransactionHistory":true}]),
            )
            .await?;
        let status = &result["value"][0];
        if !status.is_null() {
            ensure!(status["err"].is_null(), "transaction failed: {status}");
            if status["confirmationStatus"] == "finalized" {
                return Ok(());
            }
        }
        ensure!(Instant::now() < deadline, "finalization timeout");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
async fn send(rpc: &Rpc, payer: &Keypair, mut ixs: Vec<Instruction>) -> anyhow::Result<()> {
    ixs.insert(
        0,
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
    );
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[payer],
        blockhash(rpc).await?,
    );
    let signature = rpc.send_bytes(&bincode::serialize(&tx)?).await?;
    confirmed(rpc, signature).await
}
async fn balance(rpc: &Rpc, key: Pubkey) -> anyhow::Result<u64> {
    rpc.call(
        "getBalance",
        json!([key.to_string(),{"commitment":"finalized"}]),
    )
    .await?["value"]
        .as_u64()
        .context("balance")
}
async fn wait_worker(relay: &Relay, index: usize) -> anyhow::Result<Health> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(health) = relay.health(index).await {
            return Ok(health);
        }
        ensure!(Instant::now() < deadline, "worker startup timeout");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
async fn job(
    _client: &reqwest::Client,
    coordinator: &str,
    request: &SignRequest,
) -> anyhow::Result<SignedResult> {
    let sdk = pairkey_sdk::service::Client::new(coordinator.into())?;
    let id = sdk
        .submit(&request.registration, &request.commit, &request.message)
        .await?;
    let mut subscription = sdk.subscribe(&id).await?;
    let event = subscription
        .chunk()
        .await?
        .context("missing subscription event")?;
    ensure!(
        String::from_utf8_lossy(&event).contains("data:"),
        "invalid SSE event"
    );
    drop(subscription);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match serde_json::from_value::<Job>(sdk.poll(&id).await?)? {
            Job::Complete { result } => return Ok(*result),
            Job::Failed { error } => anyhow::bail!("job failed: {error}"),
            _ => {}
        }
        ensure!(Instant::now() < deadline, "job timeout");
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let mut run_id = [0; 32];
    OsRng.fill_bytes(&mut run_id);
    let run = root
        .join(".local")
        .join(Pubkey::new_from_array(run_id).to_string());
    std::fs::create_dir_all(&run)?;
    let rpc_port = loop {
        let p = port()?;
        if p < 65000 && std::net::TcpListener::bind(("127.0.0.1", p + 1)).is_ok() {
            break p;
        }
    };
    let mut processes = Processes(vec![]);
    let validator = Command::new("solana-test-validator")
        .args([
            "--ledger",
            run.join("ledger").to_str().unwrap(),
            "--rpc-port",
            &rpc_port.to_string(),
            "--bind-address",
            "127.0.0.1",
            "--gossip-port",
            &port()?.to_string(),
            "--faucet-port",
            &port()?.to_string(),
            "--ticks-per-slot",
            "8",
            "--log",
        ])
        .stdout(Stdio::from(std::fs::File::create(
            run.join("validator.log"),
        )?))
        .stderr(Stdio::from(std::fs::File::create(
            run.join("validator-stderr.log"),
        )?))
        .args([
            "--bpf-program",
            &pair_registry::id().to_string(),
            root.join("target/deploy/pair_registry.so")
                .to_str()
                .unwrap(),
            "--bpf-program",
            &example_controller::id().to_string(),
            root.join("target/deploy/example_controller.so")
                .to_str()
                .unwrap(),
        ])
        .spawn()?;
    processes.0.push(Some(validator));
    let rpc = Rpc::new(format!("http://127.0.0.1:{rpc_port}"))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let genesis = loop {
        if let Ok(v) = rpc.call("getGenesisHash", json!([])).await {
            break v
                .as_str()
                .context("genesis hash")?
                .parse::<Pubkey>()?
                .to_bytes();
        }
        ensure!(
            Instant::now() < deadline,
            "validator startup timeout; inspect {}",
            run.join("validator.log").display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let payer = Keypair::new();
    let sig: Signature = rpc
        .call(
            "requestAirdrop",
            json!([payer.pubkey().to_string(), 20_000_000_000u64]),
        )
        .await?
        .as_str()
        .context("airdrop signature")?
        .parse()?;
    confirmed(&rpc, sig).await?;
    let identities = [
        ed25519_dalek::SigningKey::from_bytes(&{
            let mut v = [0; 32];
            OsRng.fill_bytes(&mut v);
            v
        }),
        ed25519_dalek::SigningKey::from_bytes(&{
            let mut v = [0; 32];
            OsRng.fill_bytes(&mut v);
            v
        }),
    ];
    let identity_public = [
        identities[0].verifying_key().to_bytes(),
        identities[1].verifying_key().to_bytes(),
    ];
    send(
        &rpc,
        &payer,
        vec![pairkey_sdk::create_set(
            payer.pubkey(),
            [5; 32],
            identity_public,
            true,
        )],
    )
    .await?;
    let endpoints = [
        format!("http://127.0.0.1:{}", port()?),
        format!("http://127.0.0.1:{}", port()?),
    ];
    let worker_bin = root.join("target/debug/pairkey-worker");
    let coordinator_bin = root.join("target/debug/pairkey-coordinator");
    let mut configs = vec![];
    for i in 0..2 {
        let mut root_secret = [0; 32];
        OsRng.fill_bytes(&mut root_secret);
        let root_path = run.join(format!("root-{i}"));
        private_file(&root_path, &root_secret)?;
        let identity_path = run.join(format!("identity-{i}"));
        private_file(&identity_path, &identities[i].to_bytes())?;
        let config = run.join(format!("worker-{i}.json"));
        std::fs::write(
            &config,
            serde_json::to_vec_pretty(
                &json!({"role":if i==0 {Role::A}else{Role::B},"bind":endpoints[i].trim_start_matches("http://"),"root_file":root_path,"identity_file":identity_path,"peer_identity":identity_public[1-i],"rpc_url":format!("http://127.0.0.1:{rpc_port}"),"provider_domain":format!("local-domain-{i}"),"network":genesis,"set_governor":payer.pubkey().to_bytes(),"set_id":vec![5u8;32]}),
            )?,
        )?;
        processes.0.push(Some(spawn(
            &worker_bin,
            &[config.to_string_lossy().into()],
            &run.join(format!("worker-{i}.log")),
        )?));
        configs.push(config);
    }
    let coordinator_url = format!("http://127.0.0.1:{}", port()?);
    let relay_config = pairkey_coordinator::Config {
        bind: coordinator_url.trim_start_matches("http://").into(),
        workers: endpoints.clone(),
        identities: identity_public,
    };
    let relay = Relay::new(relay_config.clone())?;
    wait_worker(&relay, 0).await?;
    wait_worker(&relay, 1).await?;
    let coordinator_config = run.join("coordinator.json");
    std::fs::write(
        &coordinator_config,
        serde_json::to_vec_pretty(&relay_config)?,
    )?;
    processes.0.push(Some(spawn(
        &coordinator_bin,
        &[coordinator_config.to_string_lossy().into()],
        &run.join("coordinator.log"),
    )?));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .build()?;
    let coordinator_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(response) = client.get(format!("{coordinator_url}/health")).send().await {
            if response.status().is_success() {
                break;
            }
        }
        ensure!(
            Instant::now() < coordinator_deadline,
            "coordinator startup timeout"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut latency = Vec::new();
    let mut transfer_results = Vec::new();
    for (id, cpi) in [(1u8, false), (2, true)] {
        let controller = if cpi {
            example_controller::authority(&example_controller::id(), &payer.pubkey()).0
        } else {
            payer.pubkey()
        };
        let ns = Namespace {
            version: 1,
            scheme: Scheme::FrostEd25519,
            network: genesis,
            registry: pair_registry::id().to_bytes(),
            derivation_authority: controller.to_bytes(),
            namespace_id: [id; 32],
            enclave_set: [5; 32],
        };
        let sdk = pairkey_sdk::service::Client::new(coordinator_url.clone())?;
        let proposal = sdk
            .namespace(ns, controller.to_bytes(), identity_public)
            .await?;
        let reg = proposal.registration;
        let manifest = pair_registry::registration_message(&reg, &controller);
        let mut ixs = vec![
            pairkey_sdk::ed25519_instruction(
                identity_public[0],
                proposal.identity_signatures[0].as_slice().try_into()?,
                &manifest,
            ),
            pairkey_sdk::ed25519_instruction(
                identity_public[1],
                proposal.identity_signatures[1].as_slice().try_into()?,
                &manifest,
            ),
        ];
        let ix = pairkey_sdk::register(payer.pubkey(), controller, reg.clone());
        ixs.push(if cpi {
            pairkey_sdk::through_controller(payer.pubkey(), ix)
        } else {
            ix
        });
        send(&rpc, &payer, ixs).await?;
        let path = AccountPath {
            destination: genesis,
            path: vec![0],
        };
        let derived = pairkey_sdk::derived_address(&reg, &path)?;
        send(
            &rpc,
            &payer,
            vec![system_instruction::transfer(
                &payer.pubkey(),
                &derived,
                500_000_000,
            )],
        )
        .await?;
        let recipient = Pubkey::new_unique();
        let message = Message::new_with_blockhash(
            &[system_instruction::transfer(
                &derived, &recipient, 5_000_000,
            )],
            Some(&derived),
            &blockhash(&rpc).await?,
        );
        let bytes = message.serialize();
        let commit = Commit::new(&reg, [id; 32], path, &bytes)?;
        let ix = pairkey_sdk::commit(payer.pubkey(), controller, &reg, commit.clone());
        send(
            &rpc,
            &payer,
            vec![if cpi {
                pairkey_sdk::through_controller(payer.pubkey(), ix)
            } else {
                ix
            }],
        )
        .await?;
        let request = SignRequest {
            registration: reg.clone(),
            commit: commit.clone(),
            message: bytes.clone(),
        };
        let first = job(&client, &coordinator_url, &request).await?;
        let second = job(&client, &coordinator_url, &request).await?;
        ensure!(
            first.signature != second.signature,
            "repeat signing reused signature"
        );
        latency.extend([first.elapsed_ms, second.elapsed_ms]);
        let signature: [u8; 64] = first.signature.as_slice().try_into()?;
        send(
            &rpc,
            &payer,
            pairkey_sdk::respond(payer.pubkey(), &reg, &commit, bytes.clone(), signature),
        )
        .await?;
        let first_tx = Transaction {
            signatures: vec![Signature::from(signature)],
            message: message.clone(),
        };
        let signature = rpc.send_bytes(&bincode::serialize(&first_tx)?).await?;
        processed(&rpc, signature).await?;
        let repeated_tx = Transaction {
            signatures: vec![Signature::from(<[u8; 64]>::try_from(
                second.signature.as_slice(),
            )?)],
            message: message.clone(),
        };
        ensure!(
            rpc.call(
                "isBlockhashValid",
                json!([message.recent_blockhash.to_string(),{"commitment":"processed"}])
            )
            .await?["value"]
                == true,
            "blockhash expired before replay check"
        );
        let repeated=rpc.call("sendTransaction",json!([STANDARD.encode(bincode::serialize(&repeated_tx)?),{"encoding":"base64","preflightCommitment":"processed"}])).await;
        ensure!(
            repeated
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string().contains("AlreadyProcessed")),
            "duplicate was not rejected as AlreadyProcessed: {repeated:?}"
        );
        confirmed(&rpc, signature).await?;
        ensure!(
            balance(&rpc, recipient).await? == 5_000_000,
            "duplicate executed"
        );
        println!(
            "{}",
            json!({"event":"native_transfer", "authorization":if cpi {"program"}else{"account"},"recipient_balance":5_000_000,"repeat_message_rejected":true})
        );
        let mut altered = request.clone();
        altered.message[0] ^= 1;
        ensure!(
            relay.sign(altered).await.is_err(),
            "altered request accepted"
        );
        let freeze = pairkey_sdk::freeze(controller, &reg, true);
        send(
            &rpc,
            &payer,
            vec![if cpi {
                pairkey_sdk::through_controller(payer.pubkey(), freeze)
            } else {
                freeze
            }],
        )
        .await?;
        ensure!(
            relay.sign(request.clone()).await.is_err(),
            "frozen namespace signed"
        );
        let resume = pairkey_sdk::freeze(controller, &reg, false);
        send(
            &rpc,
            &payer,
            vec![if cpi {
                pairkey_sdk::through_controller(payer.pubkey(), resume)
            } else {
                resume
            }],
        )
        .await?;
        send(
            &rpc,
            &payer,
            vec![pairkey_sdk::retire(payer.pubkey(), [5; 32], true)],
        )
        .await?;
        ensure!(
            relay.sign(request.clone()).await.is_err(),
            "retired set signed"
        );
        send(
            &rpc,
            &payer,
            vec![pairkey_sdk::retire(payer.pubkey(), [5; 32], false)],
        )
        .await?;
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let client = client.clone();
            let coordinator_url = coordinator_url.clone();
            let request = request.clone();
            jobs.spawn(async move { job(&client, &coordinator_url, &request).await });
        }
        let mut signatures = std::collections::BTreeSet::new();
        while let Some(result) = jobs.join_next().await {
            let result = result??;
            latency.push(result.elapsed_ms);
            ensure!(
                signatures.insert(result.signature),
                "concurrent signatures reused"
            );
        }
        ensure!(signatures.len() == 8, "concurrency result count");
        // Kill either worker with pending nonce state; same provisioned roots preserve addresses.
        for stage in 0..4 {
            for side in 0..2 {
                let peers = relay.peers().await?;
                let mut random_id = [0; 32];
                OsRng.fill_bytes(&mut random_id);
                let attempt = Attempt {
                    commit: commit.clone(),
                    random_id,
                };
                let begins = [
                    Begin {
                        registration: reg.clone(),
                        attempt: attempt.clone(),
                        message: bytes.clone(),
                        peer: peers[1].clone(),
                    },
                    Begin {
                        registration: reg.clone(),
                        attempt: attempt.clone(),
                        message: bytes.clone(),
                        peer: peers[0].clone(),
                    },
                ];
                let mut rounds = None;
                let mut shares = None;
                let mut published = None;
                if stage >= 1 {
                    let (a, b) = tokio::join!(
                        relay.post::<_, pairkey_channel::Envelope>(0, "/begin", &begins[0]),
                        relay.post::<_, pairkey_channel::Envelope>(1, "/begin", &begins[1])
                    );
                    rounds = Some([a?, b?]);
                }
                if stage >= 2 {
                    let finishes = [
                        Finish {
                            begin: begins[0].clone(),
                            rounds: rounds.clone().unwrap(),
                        },
                        Finish {
                            begin: begins[1].clone(),
                            rounds: rounds.clone().unwrap(),
                        },
                    ];
                    let (a, b) = tokio::join!(
                        relay.post::<_, pairkey_channel::Envelope>(0, "/finish", &finishes[0]),
                        relay.post::<_, pairkey_channel::Envelope>(1, "/finish", &finishes[1])
                    );
                    shares = Some([a?, b?]);
                }
                if stage >= 3 {
                    let q = ResultRequest {
                        finish: Finish {
                            begin: begins[side].clone(),
                            rounds: rounds.clone().unwrap(),
                        },
                        shares: shares.clone().unwrap(),
                    };
                    published = Some(relay.post::<_, ResultResponse>(side, "/result", &q).await?);
                }
                let mut killed = processes.0[side + 1].take().unwrap();
                let killed_result = killed.kill();
                let waited_result = killed.wait();
                killed_result?;
                waited_result?;
                processes.0[side + 1] = Some(spawn(
                    &worker_bin,
                    &[configs[side].to_string_lossy().into()],
                    &run.join(format!("worker-{side}-restart.log")),
                )?);
                wait_worker(&relay, side).await?;
                let rejected = if stage == 0 {
                    relay
                        .post::<_, pairkey_channel::Envelope>(side, "/begin", &begins[side])
                        .await
                        .is_err()
                } else if stage == 1 {
                    relay
                        .post::<_, pairkey_channel::Envelope>(
                            side,
                            "/finish",
                            &Finish {
                                begin: begins[side].clone(),
                                rounds: rounds.clone().unwrap(),
                            },
                        )
                        .await
                        .is_err()
                } else {
                    relay
                        .post::<_, ResultResponse>(
                            side,
                            "/result",
                            &ResultRequest {
                                finish: Finish {
                                    begin: begins[side].clone(),
                                    rounds: rounds.clone().unwrap(),
                                },
                                shares: shares.unwrap(),
                            },
                        )
                        .await
                        .is_err()
                };
                ensure!(
                    rejected,
                    "restarted process accepted old boot/nonce context"
                );
                if let Some(response) = published {
                    pairkey_sdk::service::verify_receipt(
                        &reg,
                        &attempt,
                        &bytes,
                        &response,
                        identity_public[side],
                        if side == 0 { Role::A } else { Role::B },
                        true,
                    )?;
                }
                let _ = client
                    .post(format!("{}/abort", endpoints[1 - side]))
                    .json(&attempt)
                    .send()
                    .await?;
                let fresh = job(&client, &coordinator_url, &request).await?;
                ensure!(
                    fresh.signature != first.signature,
                    "restart signature reused"
                );
                latency.push(fresh.elapsed_ms);
                ensure!(
                    pairkey_sdk::derived_address(&reg, &commit.account)? == derived,
                    "address changed"
                );
            }
        }
        // A changed blockhash never inherits the previous exact-byte approval.
        let mut changed_message = message.clone();
        changed_message.recent_blockhash = blockhash(&rpc).await?;
        ensure!(
            commit
                .authorize(&reg, &changed_message.serialize())
                .is_err(),
            "new blockhash inherited approval"
        );
        if !cpi {
            // Expired recent blockhash: approval can still sign bytes, destination refuses execution.
            let expired_recipient = Pubkey::new_unique();
            let expired_message = Message::new_with_blockhash(
                &[system_instruction::transfer(
                    &derived,
                    &expired_recipient,
                    5_000_000,
                )],
                Some(&derived),
                &blockhash(&rpc).await?,
            );
            let expired_bytes = expired_message.serialize();
            let expired_commit =
                Commit::new(&reg, [41; 32], commit.account.clone(), &expired_bytes)?;
            send(
                &rpc,
                &payer,
                vec![pairkey_sdk::commit(
                    payer.pubkey(),
                    controller,
                    &reg,
                    expired_commit.clone(),
                )],
            )
            .await?;
            let expired_request = SignRequest {
                registration: reg.clone(),
                commit: expired_commit,
                message: expired_bytes,
            };
            let signed = job(&client, &coordinator_url, &expired_request).await?;
            let deadline = Instant::now() + Duration::from_secs(100);
            loop {
                if rpc.call("isBlockhashValid",json!([expired_message.recent_blockhash.to_string(),{"commitment":"finalized"}])).await?["value"]==false {break;}
                ensure!(Instant::now() < deadline, "blockhash expiry timeout");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let tx = Transaction {
                signatures: vec![Signature::from(<[u8; 64]>::try_from(
                    signed.signature.as_slice(),
                )?)],
                message: expired_message,
            };
            let rejected = rpc.send_bytes(&bincode::serialize(&tx)?).await;
            ensure!(
                rejected
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.to_string().contains("Blockhash not found")),
                "expired blockhash did not fail for expected reason: {rejected:?}"
            );
            ensure!(
                balance(&rpc, expired_recipient).await? == 0,
                "expired transfer executed"
            );
            // Durable nonce: exact-byte repeated signing executes once until the nonce advances.
            let nonce = Keypair::new();
            let rent = rpc
                .call("getMinimumBalanceForRentExemption", json!([80]))
                .await?
                .as_u64()
                .context("nonce rent")?;
            let tx = Transaction::new_signed_with_payer(
                &system_instruction::create_nonce_account(
                    &payer.pubkey(),
                    &nonce.pubkey(),
                    &derived,
                    rent,
                ),
                Some(&payer.pubkey()),
                &[&payer, &nonce],
                blockhash(&rpc).await?,
            );
            let sig = rpc.send_bytes(&bincode::serialize(&tx)?).await?;
            confirmed(&rpc, sig).await?;
            let read_nonce = async {
                let account=rpc.call("getAccountInfo",json!([nonce.pubkey().to_string(),{"encoding":"base64","commitment":"finalized"}])).await?;
                let raw = STANDARD.decode(
                    account["value"]["data"][0]
                        .as_str()
                        .context("nonce bytes")?,
                )?;
                let state: solana_sdk::nonce::state::Versions = bincode::deserialize(&raw)?;
                if let solana_sdk::nonce::state::State::Initialized(data) = state.state() {
                    Ok::<_, anyhow::Error>(data.blockhash())
                } else {
                    anyhow::bail!("nonce uninitialized")
                }
            };
            let nonce_hash = read_nonce.await?;
            let recipient = Pubkey::new_unique();
            let nonce_message = Message::new_with_blockhash(
                &[
                    system_instruction::advance_nonce_account(&nonce.pubkey(), &derived),
                    system_instruction::transfer(&derived, &recipient, 5_000_000),
                ],
                Some(&derived),
                &nonce_hash,
            );
            let nonce_bytes = nonce_message.serialize();
            let nonce_commit = Commit::new(&reg, [42; 32], commit.account.clone(), &nonce_bytes)?;
            send(
                &rpc,
                &payer,
                vec![pairkey_sdk::commit(
                    payer.pubkey(),
                    controller,
                    &reg,
                    nonce_commit.clone(),
                )],
            )
            .await?;
            let req = SignRequest {
                registration: reg.clone(),
                commit: nonce_commit.clone(),
                message: nonce_bytes,
            };
            let a = job(&client, &coordinator_url, &req).await?;
            let b = job(&client, &coordinator_url, &req).await?;
            ensure!(
                a.signature != b.signature,
                "durable nonce signatures reused"
            );
            let tx = Transaction {
                signatures: vec![Signature::from(<[u8; 64]>::try_from(
                    a.signature.as_slice(),
                )?)],
                message: nonce_message.clone(),
            };
            let sig = rpc.send_bytes(&bincode::serialize(&tx)?).await?;
            confirmed(&rpc, sig).await?;
            let tx = Transaction {
                signatures: vec![Signature::from(<[u8; 64]>::try_from(
                    b.signature.as_slice(),
                )?)],
                message: nonce_message,
            };
            ensure!(
                rpc.send_bytes(&bincode::serialize(&tx)?).await.is_err(),
                "consumed durable nonce replayed"
            );
            ensure!(
                balance(&rpc, recipient).await? == 5_000_000,
                "durable nonce executed twice"
            );
            println!(
                "{}",
                json!({"event":"expiry_and_durable_nonce_passed","expired_execution_count":0,"durable_nonce_execution_count":1})
            );
        }
        transfer_results.push(json!({"namespace":id,"cpi":cpi,"derived_account":derived.to_string(),"recipient":recipient.to_string(),"execution_count":1}));
    }
    latency.sort();
    let evidence = json!({"hardware_backed":false,"validator":"Agave 3.0.15","native_transfers":transfer_results,"signing_latency_ms":latency,"artifacts":run});
    std::fs::write(
        run.join("evidence.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!(
        "{}",
        json!({"event":"local_demo_passed","evidence":run.join("evidence.json"),"hardware_backed":false})
    );
    Ok(())
}
