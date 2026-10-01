#[path = "evm_sessions.rs"]
mod evm_sessions;
#[path = "job_lifecycle.rs"]
mod job_lifecycle;
use super::*;
use pairkey_sdk::multi::{self, Intent, KeyRequest, Payload, Suite};
use pairkey_signing::hex;
use serde_json::Value;
async fn approve(
    rpc: &Rpc,
    payer: &Keypair,
    controller: Pubkey,
    cpi: bool,
    reg: &pairkey_types::Registration,
    commit: Commit,
) -> anyhow::Result<()> {
    let ix = pairkey_sdk::commit(payer.pubkey(), controller, reg, commit);
    send(
        rpc,
        payer,
        vec![if cpi {
            pairkey_sdk::through_controller(payer.pubkey(), ix)
        } else {
            ix
        }],
    )
    .await
}
// Bypass both SDK and coordinator validation: neither worker may release a
// signing contribution for a changed intent under the original COMMIT.
async fn workers_refuse(
    configs: &[PathBuf],
    relay: &Relay,
    q: &multi::SignRequest,
) -> anyhow::Result<()> {
    let expected = q
        .validate()
        .expect_err("test intent must be invalid")
        .to_string();
    let peers = relay.peers().await?;
    let http = reqwest::Client::new();
    for (i, config) in configs.iter().enumerate().take(2) {
        let cfg: Value = serde_json::from_slice(&std::fs::read(config)?)?;
        let auth = multi::Authorized {
            request: q.clone(),
            peer: peers[1 - i].clone(),
        };
        let (route, body) = match q.intent.key.suite {
            Suite::Dkls23Secp256k1 => (
                "/multi/d/start",
                serde_json::to_value(multi::DStart {
                    id: q.attempt.digest(),
                    operation: multi::DOperation::Sign {
                        authorized: Box::new(auth),
                        generation: [0; 32],
                    },
                })?,
            ),
            Suite::FrostRedPallas => (
                "/multi/r/begin",
                serde_json::to_value(multi::RBegin { authorized: auth })?,
            ),
        };
        let response = http
            .post(format!(
                "http://{}{}",
                cfg["bind"].as_str().context("worker bind")?,
                route
            ))
            .json(&body)
            .timeout(Duration::from_secs(10))
            .send()
            .await?;
        ensure!(
            response.status() == reqwest::StatusCode::BAD_REQUEST,
            "worker accepted changed intent"
        );
        let error = pairkey_sdk::http::bounded_body(response, 16384).await?;
        let error: Value = serde_json::from_slice(&error)?;
        ensure!(
            error["error"] == expected,
            "unexpected worker refusal: {error}"
        );
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub async fn run(
    root: &Path,
    run: &Path,
    processes: &mut Processes,
    configs: &[PathBuf],
    rpc: &Rpc,
    payer: &Keypair,
    coordinator: &str,
    relay: &Relay,
    network: [u8; 32],
    identities: [[u8; 32]; 2],
) -> anyhow::Result<()> {
    let p = port()?;
    let anvil = Command::new("anvil")
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &p.to_string(),
            "--chain-id",
            "31337",
            "--silent",
        ])
        .stdout(Stdio::from(std::fs::File::create(run.join("anvil.log"))?))
        .stderr(Stdio::inherit())
        .spawn()?;
    processes.0.push(Some(anvil));
    let evm = Rpc::new(format!("http://127.0.0.1:{p}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while evm.call("eth_chainId", json!([])).await.is_err() {
        ensure!(Instant::now() < deadline, "Anvil startup");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let sdk = pairkey_sdk::service::Client::new(coordinator.into())?;
    let mut evidence = vec![];
    let mut session_evidence = vec![];
    let mut job_evidence = Value::Null;
    let controllers: &[bool] = if std::env::var_os("PAIRKEY_DEMO_PROGRAM_ONLY").is_some() {
        &[true]
    } else {
        &[false, true]
    };
    for &cpi in controllers {
        let controller = if cpi {
            example_controller::authority(&example_controller::id(), &payer.pubkey()).0
        } else {
            payer.pubkey()
        };
        let ns = Namespace {
            version: 1,
            scheme: Scheme::FrostEd25519,
            network,
            registry: pair_registry::id().to_bytes(),
            derivation_authority: controller.to_bytes(),
            namespace_id: [if cpi { 72 } else { 71 }; 32],
            enclave_set: [5; 32],
        };
        let proposal = sdk.namespace(ns, controller.to_bytes(), identities).await?;
        let reg = proposal.registration;
        let manifest = pair_registry::registration_message(&reg, &controller);
        let mut ixs = vec![];
        for (i, key) in identities.iter().enumerate() {
            ixs.push(pairkey_sdk::ed25519_instruction(
                *key,
                proposal.identity_signatures[i].as_slice().try_into()?,
                &manifest,
            ));
        }
        let ix = pairkey_sdk::register(payer.pubkey(), controller, reg.clone());
        ixs.push(if cpi {
            pairkey_sdk::through_controller(payer.pubkey(), ix)
        } else {
            ix
        });
        send(rpc, payer, ixs).await?;
        let mut authorized_requests = vec![];
        for suite in [Suite::Dkls23Secp256k1, Suite::FrostRedPallas] {
            let account = AccountPath {
                destination: if suite == Suite::Dkls23Secp256k1 {
                    multi::evm::destination(31337)
                } else {
                    [82; 32]
                },
                path: vec![7, 3],
            };
            let key_request = KeyRequest {
                registration: reg.clone(),
                account: account.clone(),
                suite,
            };
            let key = sdk.signing_key(&key_request, identities).await?;
            let tx = multi::evm::Transfer {
                chain_id: 31337,
                nonce: 0,
                gas_price: 2_000_000_000,
                gas_limit: 21000,
                to: [if cpi { 0x92 } else { 0x91 }; 20],
                value: 1_234_567,
            };
            if suite == Suite::Dkls23Secp256k1 {
                let address = multi::evm::address(&key.key.public_key)?;
                evm.call(
                    "anvil_setBalance",
                    json!([format!("0x{}", hex(&address)), "0xde0b6b3a7640000"]),
                )
                .await?;
            }
            let intent = Intent {
                version: 1,
                key: key.key.clone(),
                payload: match suite {
                    Suite::Dkls23Secp256k1 => Payload::EvmTransfer(tx.clone()),
                    Suite::FrostRedPallas => Payload::RedPallas {
                        message: b"PairKey Solana-authorized RedPallas".to_vec(),
                    },
                },
            };
            let mut id = [0; 32];
            OsRng.fill_bytes(&mut id);
            let commit = Commit::new(&reg, id, account, &intent.bytes()?)?;
            let mut request = multi::SignRequest {
                protocol: pairkey_signing::wire::PROTOCOL_VERSION,
                registration: reg.clone(),
                attempt: Attempt {
                    commit: commit.clone(),
                    random_id: id,
                    authorization: Default::default(),
                },
                intent,
                certificate: key.certificate.clone(),
            };
            ensure!(
                sdk.sign_intent(&request, identities).await.is_err(),
                "unapproved signing succeeded"
            );
            approve(rpc, payer, controller, cpi, &reg, commit).await?;
            OsRng.fill_bytes(&mut request.attempt.random_id);
            let result = sdk.sign_intent(&request, identities).await?;
            multi::verify_result(&request, &result, identities)?;
            let mut old_version = request.clone();
            old_version.protocol = 1;
            workers_refuse(configs, relay, &old_version).await?;
            let mut damaged = result.clone();
            damaged.receipts[0].identity_signature[0] ^= 1;
            ensure!(
                multi::verify_result(&request, &damaged, identities).is_err(),
                "tampered receipt accepted"
            );
            let mut wrong = request.clone();
            match &mut wrong.intent.payload {
                Payload::EvmTransfer(t) => t.value += 1,
                Payload::RedPallas { message } => message.push(0),
            };
            ensure!(
                sdk.sign_intent(&wrong, identities).await.is_err(),
                "changed payload accepted"
            );
            workers_refuse(configs, relay, &wrong).await?;
            let mut wrong = request.clone();
            wrong.intent.key.account.destination[0] ^= 1;
            ensure!(
                sdk.sign_intent(&wrong, identities).await.is_err(),
                "changed destination accepted"
            );
            workers_refuse(configs, relay, &wrong).await?;
            let mut execution = Value::Null;
            if suite == Suite::Dkls23Secp256k1 {
                let raw = tx.signed_bytes(&key.key.public_key, &result.signature)?;
                let raw = format!("0x{}", hex(&raw));
                let hash = evm.call("eth_sendRawTransaction", json!([raw])).await?;
                let deadline = Instant::now() + Duration::from_secs(10);
                let receipt = loop {
                    let value = evm.call("eth_getTransactionReceipt", json!([hash])).await?;
                    if !value.is_null() {
                        break value;
                    }
                    ensure!(Instant::now() < deadline, "EVM mining timeout");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                };
                ensure!(
                    receipt["status"] == "0x1",
                    "EVM execution failed: {receipt}"
                );
                ensure!(
                    evm.call("eth_sendRawTransaction", json!([raw]))
                        .await
                        .is_err(),
                    "EVM replay accepted"
                );
                let bal = evm
                    .call(
                        "eth_getBalance",
                        json!([format!("0x{}", hex(&tx.to)), "latest"]),
                    )
                    .await?;
                ensure!(
                    bal == format!("0x{:x}", tx.value),
                    "unexpected recipient balance"
                );
                let mut wrong_chain = tx.clone();
                wrong_chain.chain_id = 31338;
                ensure!(
                    multi::evm::verify(&key.key.public_key, &wrong_chain, &result.signature)
                        .is_err(),
                    "cross-chain signature accepted"
                );
                execution = json!({"transaction_hash":hash,"status":receipt["status"],"recipient_balance":bal,"replay_refused":true,"wrong_chain_refused":true});
            }
            // Both workers restart with the same provisioning; registration/key must survive.
            relay.multi_reset().await;
            for (i, config) in configs.iter().enumerate().take(2) {
                let mut child = processes.0[1 + i].take().context("worker process")?;
                child.kill()?;
                child.wait()?;
                processes.0[1 + i] = Some(spawn(
                    &root.join("target/debug/pairkey-worker"),
                    &[config.to_string_lossy().into()],
                    &run.join(format!("worker-{i}-multi-restart.log")),
                )?);
            }
            wait_worker(relay, 0).await?;
            wait_worker(relay, 1).await?;
            let restored = sdk.signing_key(&key_request, identities).await?;
            ensure!(restored.key == key.key, "restart changed key");
            let mut retry = request.clone();
            OsRng.fill_bytes(&mut retry.attempt.random_id);
            retry.certificate = restored.certificate;
            let after = sdk.sign_intent(&retry, identities).await?;
            multi::verify_result(&retry, &after, identities)?;
            ensure!(
                after.signature != result.signature,
                "fresh signing repeated nonce/signature"
            );
            authorized_requests.push(retry);
            evidence.push(json!({"authorization":if cpi{"program_cpi"}else{"account"},"suite":suite,"key":key.key,"signature":result.signature,"restart_signature":after.signature,"missing_approval_refused":true,"payload_substitution_refused":true,"destination_substitution_refused":true,"workers_refused_substitutions":true,"tampered_receipt_refused":true,"restart_preserved_key":true,"mixed_version_refused":true,"evm_executed":suite==Suite::Dkls23Secp256k1,"evm_execution":execution}));
            println!(
                "{}",
                json!({"event":"multi_suite_passed","cpi":cpi,"suite":suite})
            );
        }
        if cpi && std::env::var_os("PAIRKEY_DEMO_JOB_LIFECYCLE").is_some() {
            job_evidence = job_lifecycle::run(
                root,
                run,
                processes,
                configs,
                relay,
                rpc,
                payer,
                controller,
                identities,
                &authorized_requests,
            )
            .await?;
        }
        session_evidence.push(
            evm_sessions::run(
                rpc,
                &evm,
                payer,
                controller,
                cpi,
                &sdk,
                relay,
                configs,
                identities,
                &authorized_requests[0],
            )
            .await?,
        );
        for request in &mut authorized_requests {
            request.attempt.authorization.policy_version = 3;
        }
        let freeze = pairkey_sdk::freeze(controller, &reg, true);
        send(
            rpc,
            payer,
            vec![if cpi {
                pairkey_sdk::through_controller(payer.pubkey(), freeze)
            } else {
                freeze
            }],
        )
        .await?;
        for mut q in authorized_requests {
            OsRng.fill_bytes(&mut q.attempt.random_id);
            ensure!(
                sdk.sign_intent(&q, identities).await.is_err(),
                "frozen namespace signed"
            );
        }
        for flow in &mut evidence {
            if flow["authorization"] == if cpi { "program_cpi" } else { "account" } {
                flow["freeze_refused"] = json!(true);
            }
        }
        println!("{}", json!({"event":"multi_freeze_refused","cpi":cpi}));
    }
    std::fs::write(
        run.join("multi-evidence.json"),
        serde_json::to_vec_pretty(
            &json!({"hardware_backed":false,"development":true,"evm_chain_id":31337,"flows":evidence,"job_lifecycle":job_evidence,"evm_sessions":session_evidence}),
        )?,
    )?;
    println!(
        "{}",
        json!({"event":"multi_demo_complete","evidence":run.join("multi-evidence.json")})
    );
    Ok(())
}
