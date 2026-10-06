use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use pairkey_sdk::multi::{self, evm, Intent, KeyRequest, Payload, Suite};
use pairkey_types::{
    policy::{Authorization, Credential, EvmSessionGrant, Policy},
    AccountPath, Attempt, Commit, Namespace, Scheme,
};
use sha3::{Digest, Keccak256};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction, instruction::Instruction, transaction::Transaction,
};

pub fn now() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
fn oracle_call(method: &str, argument: u64) -> String {
    let selector = Keccak256::digest(method.as_bytes());
    format!("0x{}{:064x}", hex(&selector[..4]), argument)
}
fn base_reservation(value: u64, execution: u64, l1: u64, operator: u64) -> Result<u64> {
    let estimate = l1
        .checked_add(operator)
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(execution))
        .context("fee estimate overflow")?;
    ensure!(
        estimate <= MAX_FEE,
        "Base network fee estimate exceeds the demo reserve"
    );
    // This is a local reservation, not a signed ceiling on future network-imposed fees.
    value.checked_add(MAX_FEE).context("cost overflow")
}
fn included_receipt(receipt: &Value, block: &Value) -> bool {
    receipt["blockHash"].as_str().is_some_and(|hash| {
        hash.len() == 66
            && hash.starts_with("0x")
            && hash[2..].bytes().all(|b| b.is_ascii_hexdigit())
            && hash[2..].bytes().any(|b| b != b'0')
            && block["hash"] == hash
            && quantity(&receipt["blockNumber"]).is_ok()
            && block["number"] == receipt["blockNumber"]
    })
}
impl App {
    async fn oracle_fee(&self, method: &str, argument: u64) -> Result<u64> {
        let result = self
            .evm
            .call(
                "eth_call",
                json!([{
            "to":"0x420000000000000000000000000000000000000F",
            "data":oracle_call(method, argument)
        },"latest"]),
            )
            .await?;
        let encoded = result.as_str().context("fee oracle response")?;
        ensure!(
            encoded.starts_with("0x") && encoded.len() == 66,
            "invalid fee oracle ABI result"
        );
        quantity(&result)
    }
    pub async fn networks(&self) -> Result<()> {
        ensure!(
            self.sol.call("getGenesisHash", json!([])).await? == GENESIS,
            "Solana must be devnet"
        );
        ensure!(
            quantity(&self.evm.call("eth_chainId", json!([])).await?)? == CHAIN,
            "EVM must be Base Sepolia"
        );
        Ok(())
    }
    pub(crate) async fn account<T: borsh::BorshDeserialize>(
        &self,
        address: Pubkey,
    ) -> Result<Option<T>> {
        let v = self
            .sol
            .call(
                "getAccountInfo",
                json!([address.to_string(),{"encoding":"base64","commitment":"finalized"}]),
            )
            .await?;
        if v["value"].is_null() {
            return Ok(None);
        }
        ensure!(
            v["value"]["owner"] == pair_registry::id().to_string(),
            "unexpected account owner"
        );
        Ok(Some(borsh::from_slice(&STANDARD.decode(
            v["value"]["data"][0].as_str().context("account bytes")?,
        )?)?))
    }
    async fn finalized(&self, sig: &str) -> Result<()> {
        let end = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let v = self
                .sol
                .call(
                    "getSignatureStatuses",
                    json!([[sig],{"searchTransactionHistory":true}]),
                )
                .await?;
            let s = &v["value"][0];
            if !s.is_null() {
                ensure!(
                    s["err"].is_null(),
                    "Solana transaction failed: {}",
                    s["err"]
                );
                if s["confirmationStatus"] == "finalized" {
                    return Ok(());
                }
            }
            ensure!(
                tokio::time::Instant::now() < end,
                "Solana finalization timeout; reconcile saved signature"
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    pub(crate) async fn send(&self, op: Option<&str>, mut ix: Vec<Instruction>) -> Result<String> {
        ix.insert(
            0,
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        );
        let b = self
            .sol
            .call("getLatestBlockhash", json!([{"commitment":"finalized"}]))
            .await?;
        let tx = Transaction::new_signed_with_payer(
            &ix,
            Some(&self.payer.pubkey()),
            &[&self.payer],
            b["value"]["blockhash"]
                .as_str()
                .context("blockhash")?
                .parse()?,
        );
        let sig = tx.signatures[0].to_string();
        if let Some(id) = op {
            self.journal.op(id, |o| {
                o.solana_tx = Some(sig.clone());
                o.uncertain = true;
            })?;
        } else {
            self.journal.update(|s| {
                s.setup_pending = Some(sig.clone());
                Ok(())
            })?;
        }
        ensure!(
            self.sol
                .send_bytes(&bincode::serialize(&tx)?)
                .await?
                .to_string()
                == sig,
            "Solana signature mismatch"
        );
        self.finalized(&sig).await?;
        if op.is_none() {
            self.journal.update(|s| {
                s.setup_pending = None;
                Ok(())
            })?;
        }
        Ok(sig)
    }
    fn wrap(&self, ix: Instruction) -> Instruction {
        pairkey_sdk::through_controller(self.payer.pubkey(), ix)
    }
    pub async fn bootstrap(&self) -> Result<()> {
        self.stage("Checking Solana devnet and Base Sepolia");
        self.networks().await?;
        for id in [pair_registry::id(), example_controller::id()] {
            let v=self.sol.call("getAccountInfo",json!([id.to_string(),{"commitment":"finalized","dataSlice":{"offset":0,"length":0}}])).await?;
            ensure!(v["value"]["executable"]==true,"program {id} is not deployed; fund the owner and run scripts/demo-testnet.sh deploy");
        }
        if let Some(sig) = self.journal.read().setup_pending {
            self.finalized(&sig).await?;
            self.journal.update(|s| {
                s.setup_pending = None;
                Ok(())
            })?;
        }
        let s = self.journal.read();
        self.stage("Registering the development signer set on Solana");
        let set_addr = pair_registry::set_address(&pair_registry::id(), &s.set_id).0;
        if let Some(set) = self.account::<pair_registry::EnclaveSet>(set_addr).await? {
            ensure!(
                set.set_id == s.set_id
                    && set.governor == self.payer.pubkey().to_bytes()
                    && set.identities == self.identities
                    && set.development
                    && !set.retired,
                "signer set mismatch"
            );
        } else {
            self.send(
                None,
                vec![pairkey_sdk::create_set(
                    self.payer.pubkey(),
                    s.set_id,
                    self.identities,
                    true,
                )],
            )
            .await?;
        }
        self.stage("Starting two development signer processes");
        self.start_workers().await?;
        self.stage("Enrolling the Solana-program-controlled namespace");
        let reg = if let Some(r) = s.registration {
            r
        } else {
            let ns = Namespace {
                version: 1,
                scheme: Scheme::FrostEd25519,
                network: GENESIS.parse::<Pubkey>()?.to_bytes(),
                registry: pair_registry::id().to_bytes(),
                derivation_authority: self.controller.to_bytes(),
                namespace_id: s.namespace_id,
                enclave_set: s.set_id,
            };
            let proposal = self
                .sdk
                .namespace(ns, self.controller.to_bytes(), self.identities)
                .await?;
            let reg = proposal.registration;
            // Persist the deterministic enrollment before the chain write.
            self.journal.update(|s| {
                s.registration = Some(reg.clone());
                Ok(())
            })?;
            reg
        };
        let ns_addr = pair_registry::namespace_address(&pair_registry::id(), &reg).0;
        if let Some(record) = self
            .account::<pair_registry::NamespaceRecord>(ns_addr)
            .await?
        {
            ensure!(
                record.registration == reg
                    && record.controller == self.controller.to_bytes()
                    && !record.frozen,
                "namespace mismatch"
            );
        } else {
            let proposal = self
                .sdk
                .namespace(
                    reg.namespace.clone(),
                    self.controller.to_bytes(),
                    self.identities,
                )
                .await?;
            ensure!(
                proposal.registration == reg,
                "registration changed on restart"
            );
            let manifest = pair_registry::registration_message(&reg, &self.controller);
            let mut ix = vec![];
            for (i, key) in self.identities.iter().enumerate() {
                ix.push(pairkey_sdk::ed25519_instruction(
                    *key,
                    proposal.identity_signatures[i].as_slice().try_into()?,
                    &manifest,
                ));
            }
            ix.push(self.wrap(pairkey_sdk::register(
                self.payer.pubkey(),
                self.controller,
                reg.clone(),
            )));
            self.send(None, ix).await?;
        }
        let policy = Policy {
            version: 1,
            allow_session: true,
            require_commit: false,
            require_session: true,
            access: None,
            simulation: None,
        };
        if let Some(p) = self
            .account::<pair_registry::PolicyRecord>(
                pair_registry::policy_address(&pair_registry::id(), &ns_addr).0,
            )
            .await?
        {
            ensure!(
                borsh::to_vec(&p.policy)? == borsh::to_vec(&policy)?
                    && p.namespace_address == ns_addr.to_bytes(),
                "unexpected demo policy"
            );
        } else {
            self.send(
                None,
                vec![self.wrap(pairkey_sdk::set_policy(
                    self.payer.pubkey(),
                    self.controller,
                    &reg,
                    policy,
                ))],
            )
            .await?;
        }
        self.stage("Enrolling the DKLS23 Base signing key");
        let request = KeyRequest {
            registration: reg,
            account: AccountPath {
                destination: evm::destination(CHAIN),
                path: vec![7, 3],
            },
            suite: Suite::Dkls23Secp256k1,
        };
        let key = if let Some(k) = self.journal.read().key {
            multi::verify_key(&request, &k, self.identities)?;
            k
        } else {
            self.sdk.signing_key(&request, self.identities).await?
        };
        self.journal.update(|s| {
            s.recipients[0] = evm::address(&key.key.public_key)?;
            s.key = Some(key);
            Ok(())
        })?;
        self.bootstrap_messages().await?;
        *self.stage.lock().unwrap() = json!({"ready":true,"message":"Ready. Choose an authority and chain, then approve and sign a message."});
        Ok(())
    }
    pub async fn execute(&self, command: Command) -> Result<()> {
        self.networks().await?;
        let id = command.id().to_string();
        let s = self.journal.read();
        let reg = s.registration.context("namespace not ready")?;
        let key = s.key.context("key not ready")?;
        match command {
            Command::SignMessage {
                authority,
                chain,
                message,
                ..
            } => {
                self.sign_message(&id, authority, chain, &message).await?;
            }
            Command::Retry { original_id, .. } => {
                let old = s
                    .operations
                    .iter()
                    .find(|o| o.command.id() == original_id)
                    .context("original operation missing")?;
                ensure!(
                    old.uncertain
                        && old.status != "working"
                        && old.raw_transaction.is_none()
                        && old.transaction_hash.is_none(),
                    "retry requires a failed signing operation without a stored transaction"
                );
                let original = old
                    .signing_request
                    .as_ref()
                    .context("original signing request missing")?;
                ensure!(
                    original.registration == reg && original.intent.key == key.key,
                    "original key context changed"
                );
                ensure!(
                    s.operations.iter().filter(|o| o.uncertain).all(|o| o
                        .raw_transaction
                        .is_none()
                        && o.transaction_hash.is_none()
                        && o.signing_request
                            .as_ref()
                            .is_some_and(|q| q.intent == original.intent)),
                    "unrelated uncertain operation requires reconciliation"
                );
                ensure!(
                    matches!(
                        self.sdk.poll_intent(original, self.identities).await?,
                        multi::IntentJob::Failed { .. }
                    ),
                    "original signing job is not terminal-failed"
                );
                let Payload::EvmTransfer(tx) = &original.intent.payload else {
                    anyhow::bail!("expected EVM transfer")
                };
                let address = format!("0x{}", hex(&evm::address(&key.key.public_key)?));
                let nonce = quantity(
                    &self
                        .evm
                        .call("eth_getTransactionCount", json!([address, "pending"]))
                        .await?,
                )?;
                ensure!(
                    nonce == tx.nonce,
                    "original nonce already used or pending; reconcile destination first"
                );
                let grant = s.session.context("current grant missing")?;
                ensure!(!s.revoked && now()? < grant.expires_at,"current session revoked or expired; grant a new scoped session before retrying");
                evm::authorize_session(&reg, &grant, &original.intent.bytes()?)?;
                let mut q = multi::fresh_attempt(original, fresh())?;
                q.attempt.authorization = Authorization {
                    policy_version: grant.policy_version,
                    session_id: Some(grant.session_id),
                    ..Default::default()
                };
                q.attempt.authorization.session_proof = Some(pairkey_sdk::policy::service_proof(
                    &self.delegate,
                    pairkey_sdk::policy::evm_session_challenge(
                        &q.attempt.authorization,
                        &q.attempt.commit,
                        &grant,
                    ),
                ));
                q.validate()?;
                ensure!(q.intent == original.intent, "retry changed signed intent");
                self.journal.op(&id, |o| {
                    o.signing_request = Some(q.clone());
                    o.uncertain = true;
                })?;
                self.journal.event(&id,"Explicit retry: same chain, nonce, recipient, value, gas and signing bytes; a fresh MPC attempt cannot execute alongside the original nonce")?;
                self.deliver(&id, &q, tx).await?;
            }
            Command::Grant {
                max_value_wei,
                recipient,
                duration_seconds,
                ..
            } => {
                ensure!(
                    s.session.is_none()
                        || s.revoked
                        || s.session
                            .as_ref()
                            .is_some_and(|g| g.expires_at <= now().unwrap_or(0)),
                    "revoke the current session before creating another"
                );
                let grant = EvmSessionGrant {
                    session_id: fresh(),
                    policy_version: 1,
                    account: key.key.account.clone(),
                    key_digest: key.key.digest(),
                    credential: Credential::Service {
                        public_key: self.delegate.verifying_key().to_bytes(),
                    },
                    not_before: now()? - 30,
                    expires_at: now()? + duration_seconds as i64,
                    chain_id: CHAIN,
                    recipient: s.recipients[recipient],
                    max_value_wei: amount(&max_value_wei)?,
                    max_gas_price_wei: 3_000_000_000,
                    max_fee_wei: MAX_FEE,
                    cumulative_budget: None,
                };
                self.journal.event(
                    &id,
                    "Submitting session grant through the Solana controller program",
                )?;
                let sig = self
                    .send(
                        Some(&id),
                        vec![self.wrap(pairkey_sdk::grant_evm_session(
                            self.payer.pubkey(),
                            self.controller,
                            &reg,
                            grant.clone(),
                        ))],
                    )
                    .await?;
                self.journal.update(|s| {
                    s.session = Some(grant.clone());
                    s.revoked = false;
                    let o = s
                        .operations
                        .iter_mut()
                        .find(|o| o.command.id() == id)
                        .context("operation")?;
                    o.uncertain = false;
                    o.result = json!({"grant":grant,"solana_tx":sig});
                    Ok(())
                })?;
                self.journal
                    .event(&id, "Session grant finalized on Solana devnet")?;
            }
            Command::Revoke { .. } => {
                let grant = s.session.context("create a session first")?;
                ensure!(!s.revoked, "session already revoked");
                self.journal.event(
                    &id,
                    "Submitting session revocation through the Solana controller program",
                )?;
                self.send(
                    Some(&id),
                    vec![self.wrap(pairkey_sdk::revoke_evm_session(
                        self.controller,
                        &reg,
                        grant.session_id,
                    ))],
                )
                .await?;
                self.journal.update(|s| {
                    s.revoked = true;
                    let o = s
                        .operations
                        .iter_mut()
                        .find(|o| o.command.id() == id)
                        .context("operation")?;
                    o.uncertain = false;
                    o.result = json!({"revoked":true});
                    Ok(())
                })?;
                self.journal.event(
                    &id,
                    "Revocation finalized on Solana devnet; future requests are blocked",
                )?;
            }
            Command::Transfer {
                value_wei,
                recipient,
                ..
            } => {
                let grant = s.session.context("create a session first")?;
                ensure!(
                    !s.revoked && now()? < grant.expires_at,
                    "session revoked or expired (backend preflight)"
                );
                let from = format!("0x{}", hex(&evm::address(&key.key.public_key)?));
                let to = format!("0x{}", hex(&s.recipients[recipient]));
                let value = amount(&value_wei)?;
                ensure!(
                    s.recipients[recipient] == grant.recipient && value <= grant.max_value_wei,
                    "request outside session scope (backend preflight)"
                );
                ensure!(
                    self.evm.call("eth_getCode", json!([to, "latest"])).await? == "0x",
                    "demo recipients must have no contract code"
                );
                let nonce = quantity(
                    &self
                        .evm
                        .call("eth_getTransactionCount", json!([from, "pending"]))
                        .await?,
                )?;
                let price = quantity(&self.evm.call("eth_gasPrice", json!([])).await?)?;
                let estimate=quantity(&self.evm.call("eth_estimateGas",json!([{"from":from,"to":to,"value":format!("0x{value:x}"),"gasPrice":format!("0x{price:x}")}])).await?)?;
                // Empty-calldata EOA transfers on Base use 21,000 execution gas.
                // L1 data and operator fees are additional charges, not execution gas.
                ensure!(
                    estimate <= 21_000,
                    "Base estimate exceeds the native-transfer gas bound"
                );
                let gas = 21_000;
                let tx = evm::Transfer {
                    chain_id: CHAIN,
                    nonce,
                    gas_price: price,
                    gas_limit: gas,
                    to: s.recipients[recipient],
                    value,
                };
                let intent = Intent {
                    version: 1,
                    key: key.key.clone(),
                    payload: Payload::EvmTransfer(tx.clone()),
                };
                evm::authorize_session(&reg, &grant, &intent.bytes()?)?;
                let l1 = self
                    .oracle_fee(
                        "getL1FeeUpperBound(uint256)",
                        tx.signing_bytes()?.len() as u64,
                    )
                    .await?;
                let operator = self.oracle_fee("getOperatorFee(uint256)", gas).await?;
                let cost = base_reservation(
                    value,
                    gas.checked_mul(price).context("fee overflow")?,
                    l1,
                    operator,
                )?;
                self.journal.event(&id, &format!("Base fees estimated: L1 {l1} wei, operator {operator} wei; reserving {MAX_FEE} wei for fees"))?;
                let balance = quantity(
                    &self
                        .evm
                        .call("eth_getBalance", json!([from, "pending"]))
                        .await?,
                )?;
                ensure!(
                    balance >= cost,
                    "fund the PairKey address with Base Sepolia test ETH"
                );
                let random_id = fresh();
                let mut q = multi::SignRequest {
                    protocol: pairkey_signing::wire::PROTOCOL_VERSION,
                    registration: reg.clone(),
                    attempt: Attempt {
                        commit: Commit::new(
                            &reg,
                            random_id,
                            key.key.account.clone(),
                            &intent.bytes()?,
                        )?,
                        random_id,
                        authorization: Authorization {
                            policy_version: grant.policy_version,
                            session_id: Some(grant.session_id),
                            ..Default::default()
                        },
                    },
                    intent,
                    certificate: key.certificate,
                };
                q.attempt.authorization.session_proof = Some(pairkey_sdk::policy::service_proof(
                    &self.delegate,
                    pairkey_sdk::policy::evm_session_challenge(
                        &q.attempt.authorization,
                        &q.attempt.commit,
                        &grant,
                    ),
                ));
                q.validate()?;
                self.journal.update(|s| {
                    s.reserved_budget = s
                        .reserved_budget
                        .checked_add(cost)
                        .context("budget overflow")?;
                    ensure!(
                        s.reserved_budget <= TOTAL_BUDGET,
                        "demo lifetime budget exhausted"
                    );
                    let o = s
                        .operations
                        .iter_mut()
                        .find(|o| o.command.id() == id)
                        .context("operation")?;
                    o.signing_request = Some(q.clone());
                    o.uncertain = true;
                    Ok(())
                })?;
                self.deliver(&id, &q, &tx).await?;
            }
        }
        Ok(())
    }
    async fn deliver(&self, id: &str, q: &multi::SignRequest, tx: &evm::Transfer) -> Result<()> {
        self.journal.event(
            id,
            "Both signers independently check the finalized Solana session and run DKLS23",
        )?;
        self.sdk.submit_intent(q).await?;
        let signed = self
            .sdk
            .wait_intent(q, self.identities, Duration::from_secs(180))
            .await?;
        self.journal
            .event(id, "Signature and both signed receipts verified by the SDK")?;
        let bytes = tx.signed_bytes(&q.intent.key.public_key, &signed.signature)?;
        let raw = format!("0x{}", hex(&bytes));
        let hash = format!("0x{}", hex(&Keccak256::digest(&bytes)));
        self.journal.op(id,|o|{o.raw_transaction=Some(raw.clone());o.transaction_hash=Some(hash.clone());o.result=json!({"signature_verified":true,"signature_hex":format!("0x{}",hex(&signed.signature)),"receipts_verified":2,"hardware_backed":false,"receipts":signed.receipts,"transaction":tx});})?;
        self.journal
            .event(id, "Broadcasting the signed transaction to Base Sepolia")?;
        ensure!(
            self.evm
                .call("eth_sendRawTransaction", json!([raw]))
                .await?
                == hash,
            "transaction hash mismatch"
        );
        self.journal
            .op(id, |o| o.result["broadcast_accepted"] = json!(true))?;
        self.journal.event(
            id,
            "Base RPC accepted the signed transaction; waiting for canonical L2 inclusion",
        )?;
        let end = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let receipt = self
                .evm
                .call("eth_getTransactionReceipt", json!([hash]))
                .await?;
            if !receipt.is_null() {
                ensure!(receipt["transactionHash"] == hash, "receipt hash mismatch");
                // Preconfirmation receipts can have a zero block hash. Wait for
                // inclusion in the canonical L2 block before consuming the nonce.
                let block = if receipt["blockNumber"].is_string() {
                    self.evm
                        .call(
                            "eth_getBlockByNumber",
                            json!([receipt["blockNumber"], false]),
                        )
                        .await?
                } else {
                    Value::Null
                };
                if included_receipt(&receipt, &block) {
                    let success = receipt["status"] == "0x1";
                    self.journal.update(|s| {
                            for o in &mut s.operations {
                                if o.command.id()==id {o.uncertain=false;o.result["receipt"]=receipt.clone();}
                                else if o.uncertain && o.signing_request.as_ref().is_some_and(|old|old.intent==q.intent) {
                                    o.uncertain=false;o.status="resolved_same_nonce".into();
                                    o.events.push(format!("Resolved by Base receipt {hash}: the identical transaction nonce has been consumed"));
                                }
                            }
                            Ok(())
                        })?;
                    ensure!(success, "Base transaction reverted");
                    break;
                }
            }
            ensure!(
                tokio::time::Instant::now() < end,
                "receipt timeout; reconcile the saved transaction hash"
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        self.journal.event(
            id,
            "Base Sepolia L2 receipt confirmed (not Ethereum L1 finality)",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod base_tests {
    use super::*;
    #[test]
    fn receipt_requires_nonzero_canonical_block_hash_and_number() {
        let hash = format!("0x{:064x}", 42);
        let receipt = json!({"blockHash":hash,"blockNumber":"0x123"});
        let block = json!({"hash":hash,"number":"0x123"});
        assert!(included_receipt(&receipt, &block));
        assert!(!included_receipt(&receipt, &Value::Null));
        assert!(!included_receipt(
            &receipt,
            &json!({"hash":hash,"number":"0x124"})
        ));
        assert!(!included_receipt(
            &receipt,
            &json!({"hash":format!("0x{:064x}",43),"number":"0x123"})
        ));
        let zero = format!("0x{:064x}", 0);
        assert!(!included_receipt(
            &json!({"blockHash":zero,"blockNumber":"0x123"}),
            &json!({"hash":zero,"number":"0x123"})
        ));
        assert!(!included_receipt(
            &json!({"blockHash":hash}),
            &json!({"hash":hash})
        ));
    }
    #[test]
    fn reserves_extra_fees_and_rejects_overflow_or_over_budget() {
        assert_eq!(base_reservation(5, 1, 1, 1).unwrap(), MAX_FEE + 5);
        assert!(base_reservation(5, MAX_FEE, 1, 0).is_err());
        assert!(base_reservation(5, 1, u64::MAX, 1).is_err());
        assert!(base_reservation(u64::MAX, 1, 1, 1).is_err());
    }
    #[test]
    fn abi_zero_padding_is_accepted_without_truncating_large_fees() {
        assert_eq!(quantity(&json!(format!("0x{:064x}", 123))).unwrap(), 123);
        assert!(quantity(&json!(format!("0x1{:016x}", 0))).is_err());
        assert_eq!(oracle_call("getL1FeeUpperBound(uint256)", 256).len(), 74);
    }
}
