use super::*;
use ed25519_dalek::SigningKey;
use pairkey_types::policy::{Authorization, Credential, EvmSessionGrant, Policy};
fn sign_request(
    template: &multi::SignRequest,
    grant: &EvmSessionGrant,
    delegate: &SigningKey,
) -> anyhow::Result<multi::SignRequest> {
    let mut q = template.clone();
    let mut id = [0; 32];
    OsRng.fill_bytes(&mut id);
    q.attempt = Attempt {
        commit: Commit::new(
            &q.registration,
            id,
            q.intent.key.account.clone(),
            &q.intent.bytes()?,
        )?,
        random_id: id,
        authorization: Authorization {
            policy_version: grant.policy_version,
            session_id: Some(grant.session_id),
            ..Default::default()
        },
    };
    q.attempt.authorization.session_proof = Some(pairkey_sdk::policy::service_proof(
        delegate,
        pairkey_sdk::policy::evm_session_challenge(
            &q.attempt.authorization,
            &q.attempt.commit,
            grant,
        ),
    ));
    q.validate()?;
    Ok(q)
}
async fn refuse_workers(
    configs: &[PathBuf],
    relay: &Relay,
    q: &multi::SignRequest,
) -> anyhow::Result<()> {
    // Valid wire/certificate and delegate proof. The independent policy checks must refuse.
    q.validate()?;
    let peers = relay.peers().await?;
    for (i, config) in configs.iter().enumerate().take(2) {
        let cfg: Value = serde_json::from_slice(&std::fs::read(config)?)?;
        let body = multi::DStart {
            id: q.attempt.digest(),
            operation: multi::DOperation::Sign {
                authorized: Box::new(multi::Authorized {
                    request: q.clone(),
                    peer: peers[1 - i].clone(),
                }),
                generation: [0; 32],
            },
        };
        let response = reqwest::Client::new()
            .post(format!(
                "http://{}/multi/d/start",
                cfg["bind"].as_str().context("bind")?
            ))
            .json(&body)
            .timeout(Duration::from_secs(10))
            .send()
            .await?;
        ensure!(
            response.status() == reqwest::StatusCode::BAD_REQUEST,
            "worker accepted out-of-scope session"
        );
        let error: Value =
            serde_json::from_slice(&pairkey_sdk::http::bounded_body(response, 16384).await?)?;
        // The rejection must originate in authorization, not a missing dummy donor.
        let reason = error["error"].as_str().context("refusal reason")?;
        ensure!(
            reason == "incorrect account owner, PDA, record, or payload"
                || reason == "untrusted, nonfinalized, or stale observation"
                || reason.contains("finalized view rejected")
                || reason.contains("inactive namespace")
                || reason.contains("policy version"),
            "unexpected session refusal: {reason}"
        );
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    rpc: &Rpc,
    evm: &Rpc,
    payer: &Keypair,
    controller: Pubkey,
    cpi: bool,
    sdk: &pairkey_sdk::service::Client,
    relay: &Relay,
    configs: &[PathBuf],
    identities: [[u8; 32]; 2],
    template: &multi::SignRequest,
) -> anyhow::Result<Value> {
    let reg = &template.registration;
    let wrap = |ix| {
        if cpi {
            pairkey_sdk::through_controller(payer.pubkey(), ix)
        } else {
            ix
        }
    };
    let policy = Policy {
        version: 1,
        allow_session: true,
        require_commit: false,
        require_session: true,
        access: None,
        simulation: None,
    };
    send(
        rpc,
        payer,
        vec![wrap(pairkey_sdk::set_policy(
            payer.pubkey(),
            controller,
            reg,
            policy.clone(),
        ))],
    )
    .await?;
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    let delegate = SigningKey::from_bytes(&seed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let mut id = [0; 32];
    OsRng.fill_bytes(&mut id);
    let Payload::EvmTransfer(original) = &template.intent.payload else {
        anyhow::bail!("EVM template")
    };
    let grant = EvmSessionGrant {
        session_id: id,
        policy_version: 1,
        account: template.intent.key.account.clone(),
        key_digest: template.intent.key.digest(),
        credential: Credential::Service {
            public_key: delegate.verifying_key().to_bytes(),
        },
        not_before: now - 30,
        expires_at: now + 600,
        chain_id: original.chain_id,
        recipient: original.to,
        max_value_wei: 1000,
        max_gas_price_wei: 3_000_000_000,
        max_fee_wei: 42_000_000_000_000,
        cumulative_budget: None,
    };
    send(
        rpc,
        payer,
        vec![wrap(pairkey_sdk::grant_evm_session(
            payer.pubkey(),
            controller,
            reg,
            grant.clone(),
        ))],
    )
    .await?;
    let mut operation = template.clone();
    let Payload::EvmTransfer(tx) = &mut operation.intent.payload else {
        unreachable!()
    };
    tx.nonce = 1;
    tx.value = 1000;
    let q = sign_request(&operation, &grant, &delegate)?;
    let ns = pair_registry::namespace_address(&pair_registry::id(), reg).0;
    let request =
        pair_registry::request_address(&pair_registry::id(), &ns, &q.attempt.commit.request_id).0;
    let missing = rpc
        .call(
            "getAccountInfo",
            json!([request.to_string(),{"commitment":"finalized"}]),
        )
        .await?;
    ensure!(
        missing["value"].is_null(),
        "session fixture unexpectedly has COMMIT"
    );
    let result = sdk.sign_intent(&q, identities).await?;
    let Payload::EvmTransfer(tx) = &q.intent.payload else {
        unreachable!()
    };
    let raw = format!(
        "0x{}",
        hex(&tx.signed_bytes(&q.intent.key.public_key, &result.signature)?)
    );
    let hash = evm.call("eth_sendRawTransaction", json!([raw])).await?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let receipt = evm.call("eth_getTransactionReceipt", json!([hash])).await?;
        if !receipt.is_null() {
            ensure!(receipt["status"] == "0x1", "EVM session execution failed");
            break;
        }
        ensure!(Instant::now() < deadline, "EVM mining timeout");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ensure!(
        evm.call("eth_sendRawTransaction", json!([raw]))
            .await
            .is_err(),
        "session transaction replay executed"
    );
    for case in 0..3 {
        let mut altered = operation.clone();
        let Payload::EvmTransfer(tx) = &mut altered.intent.payload else {
            unreachable!()
        };
        match case {
            0 => tx.value = 1001,
            1 => tx.to = [99; 20],
            2 => tx.gas_price = 2_500_000_000,
            _ => unreachable!(),
        }
        let request = sign_request(&altered, &grant, &delegate)?;
        refuse_workers(configs, relay, &request).await?;
    }
    // Require COMMIT+SESSION through a policy update and a new versioned grant.
    let combined = Policy {
        version: 2,
        require_commit: true,
        ..policy
    };
    send(
        rpc,
        payer,
        vec![wrap(pairkey_sdk::set_policy(
            payer.pubkey(),
            controller,
            reg,
            combined,
        ))],
    )
    .await?;
    refuse_workers(configs, relay, &q).await?;
    let mut next = grant.clone();
    OsRng.fill_bytes(&mut next.session_id);
    next.policy_version = 2;
    send(
        rpc,
        payer,
        vec![wrap(pairkey_sdk::grant_evm_session(
            payer.pubkey(),
            controller,
            reg,
            next.clone(),
        ))],
    )
    .await?;
    let q = sign_request(&operation, &next, &delegate)?;
    refuse_workers(configs, relay, &q).await?;
    approve(rpc, payer, controller, cpi, reg, q.attempt.commit.clone()).await?;
    sdk.sign_intent(&q, identities).await?;
    send(
        rpc,
        payer,
        vec![wrap(pairkey_sdk::revoke_evm_session(
            controller,
            reg,
            next.session_id,
        ))],
    )
    .await?;
    refuse_workers(configs, relay, &q).await?;
    let mut revoked_attempt = q.clone();
    OsRng.fill_bytes(&mut revoked_attempt.attempt.random_id);
    ensure!(
        sdk.sign_intent(&revoked_attempt, identities).await.is_err(),
        "revoked EVM grant signed"
    );
    // Restore COMMIT policy for the multi-suite freeze checks that follow.
    send(
        rpc,
        payer,
        vec![wrap(pairkey_sdk::set_policy(
            payer.pubkey(),
            controller,
            reg,
            Policy {
                version: 3,
                ..Default::default()
            },
        ))],
    )
    .await?;
    println!(
        "{}",
        json!({"event":"evm_session_passed","cpi":cpi,"executed_without_commit":true})
    );
    Ok(
        json!({"authorization":if cpi{"program_cpi"}else{"account"},"executed_without_commit":true,"transaction_hash":hash,"limits_refused":true,"revocation_refused":true,"policy_version_refused":true,"required_commit_enforced":true,"commit_plus_session_signed":true,"transaction_replay_refused":true}),
    )
}
