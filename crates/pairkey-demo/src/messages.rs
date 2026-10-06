//! Message-only demo: dedicated COMMIT namespaces, no destination broadcast.
use super::*;
use pairkey_sdk::multi::{self, Intent, KeyRequest, Payload, Suite};
use pairkey_types::{
    policy::{Authorization, Policy},
    AccountPath, Attempt, Commit, Namespace, Registration, Role, Scheme,
};
use serde::{Deserialize, Serialize};
use solana_sdk::instruction::Instruction;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    Program,
    Account,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Chain {
    Solana,
    Evm,
    Zcash,
    Near,
}
impl Chain {
    pub fn label(self) -> &'static str {
        match self {
            Self::Solana => "Solana",
            Self::Evm => "EVM / Base Sepolia 84532",
            Self::Zcash => "Zcash / RedPallas",
            Self::Near => "NEAR",
        }
    }
    fn destination(self) -> [u8; 32] {
        match self {
            Self::Evm => multi::evm::destination(CHAIN),
            _ => pairkey_types::digest(b"pairkey/demo-message-destination/v1", &self.label()),
        }
    }
    pub fn scheme(self) -> &'static str {
        match self {
            Self::Evm => "DKLS23 · secp256k1 / EIP-191",
            Self::Zcash => "FROST · RedPallas",
            _ => "FROST · Ed25519",
        }
    }
    fn path(self) -> AccountPath {
        AccountPath {
            destination: self.destination(),
            path: vec![7, 4],
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageKey {
    pub chain: Chain,
    pub public_key: Vec<u8>,
    pub multi: Option<multi::KeyResponse>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageNamespace {
    pub authority: Authority,
    pub registration: Registration,
    pub keys: Vec<MessageKey>,
}
pub fn display_key(chain: Chain, bytes: &[u8]) -> Result<String> {
    Ok(match chain {
        Chain::Solana | Chain::Near => {
            let key =
                Pubkey::new_from_array(bytes.try_into().context("Ed25519 public key length")?)
                    .to_string();
            if chain == Chain::Near {
                format!("ed25519:{key}")
            } else {
                key
            }
        }
        _ => format!("0x{}", hex(bytes)),
    })
}
pub fn public_keys(s: &Snapshot) -> Vec<Value> {
    s.message_namespaces.iter().flat_map(|ns|ns.keys.iter().map(move |key|json!({
        "authority":ns.authority,"chain":key.chain,"scheme":key.chain.scheme(),
        "controller":Pubkey::new_from_array(ns.registration.namespace.derivation_authority).to_string(),
        "public_key":display_key(key.chain,&key.public_key).unwrap_or_default(),
        "public_key_hex":format!("0x{}",hex(&key.public_key)),
        "address":if key.chain==Chain::Evm {multi::evm::address(&key.public_key).ok().map(|a|format!("0x{}",hex(&a)))} else {None},
        "path":"7 / 4","format":match key.chain {Chain::Evm=>"EIP-191 personal_sign over the displayed UTF-8 envelope",Chain::Zcash=>"Raw RedPallas message signature; not an Orchard transaction",_=>"Ed25519 over the displayed UTF-8 envelope; not a chain transaction"}
    }))).collect()
}
pub fn envelope(
    chain: Chain,
    authority: Authority,
    controller: Pubkey,
    id: &str,
    message: &str,
) -> Result<String> {
    ensure!(
        !message.trim().is_empty() && message.len() <= 256,
        "message bounds"
    );
    let text=format!("PairKey message signing v1\nDestination: {}\nAuthority: {}\nController: {}\nRequest: {}\n\n{}",chain.label(),if authority==Authority::Program {"Solana program"} else {"Solana account"},controller,id,message);
    ensure!(text.len() <= 512, "signing envelope too large");
    Ok(text)
}
impl App {
    fn message_controller(&self, authority: Authority) -> Pubkey {
        if authority == Authority::Program {
            self.controller
        } else {
            self.payer.pubkey()
        }
    }
    fn message_ix(&self, authority: Authority, ix: Instruction) -> Instruction {
        if authority == Authority::Program {
            pairkey_sdk::through_controller(self.payer.pubkey(), ix)
        } else {
            ix
        }
    }
    pub async fn bootstrap_messages(&self) -> Result<()> {
        for authority in [Authority::Program, Authority::Account] {
            self.stage(&format!(
                "Enrolling {authority:?} message-signing authority"
            ));
            let controller = self.message_controller(authority);
            let s = self.journal.read();
            let ns = Namespace {
                version: 1,
                scheme: Scheme::FrostEd25519,
                network: GENESIS.parse::<Pubkey>()?.to_bytes(),
                registry: pair_registry::id().to_bytes(),
                derivation_authority: controller.to_bytes(),
                namespace_id: pairkey_types::digest(
                    b"pairkey/demo-messages/v1",
                    &(s.namespace_id, controller.to_bytes()),
                ),
                enclave_set: s.set_id,
            };
            let registration = if let Some(existing) = s
                .message_namespaces
                .iter()
                .find(|n| n.authority == authority)
            {
                ensure!(
                    existing.registration.namespace == ns,
                    "message namespace mismatch"
                );
                existing.registration.clone()
            } else {
                let proposal = self
                    .sdk
                    .namespace(ns, controller.to_bytes(), self.identities)
                    .await?;
                self.journal.update(|s| {
                    s.message_namespaces.push(MessageNamespace {
                        authority,
                        registration: proposal.registration.clone(),
                        keys: vec![],
                    });
                    Ok(())
                })?;
                proposal.registration
            };
            let address = pair_registry::namespace_address(&pair_registry::id(), &registration).0;
            if let Some(record) = self
                .account::<pair_registry::NamespaceRecord>(address)
                .await?
            {
                ensure!(
                    record.registration == registration
                        && record.controller == controller.to_bytes()
                        && !record.frozen,
                    "message registration mismatch"
                );
            } else {
                let proposal = self
                    .sdk
                    .namespace(
                        registration.namespace.clone(),
                        controller.to_bytes(),
                        self.identities,
                    )
                    .await?;
                ensure!(
                    proposal.registration == registration,
                    "message registration changed"
                );
                let manifest = pair_registry::registration_message(&registration, &controller);
                let mut ix = vec![];
                for (i, identity) in self.identities.iter().enumerate() {
                    ix.push(pairkey_sdk::ed25519_instruction(
                        *identity,
                        proposal.identity_signatures[i].as_slice().try_into()?,
                        &manifest,
                    ));
                }
                ix.push(self.message_ix(
                    authority,
                    pairkey_sdk::register(self.payer.pubkey(), controller, registration.clone()),
                ));
                self.send(None, ix).await?;
            }
            let policy = Policy {
                version: 1,
                ..Default::default()
            };
            if let Some(record) = self
                .account::<pair_registry::PolicyRecord>(
                    pair_registry::policy_address(&pair_registry::id(), &address).0,
                )
                .await?
            {
                ensure!(
                    record.policy == policy && record.namespace_address == address.to_bytes(),
                    "message policy mismatch"
                );
            } else {
                self.send(
                    None,
                    vec![self.message_ix(
                        authority,
                        pairkey_sdk::set_policy(
                            self.payer.pubkey(),
                            controller,
                            &registration,
                            policy,
                        ),
                    )],
                )
                .await?;
            }
            for chain in [Chain::Solana, Chain::Evm, Chain::Zcash, Chain::Near] {
                if self
                    .journal
                    .read()
                    .message_namespaces
                    .iter()
                    .find(|n| n.authority == authority)
                    .unwrap()
                    .keys
                    .iter()
                    .any(|k| k.chain == chain)
                {
                    continue;
                }
                self.stage(&format!(
                    "Deriving {} message key for {authority:?}",
                    chain.label()
                ));
                let key = match chain {
                    Chain::Solana | Chain::Near => MessageKey {
                        chain,
                        public_key: pairkey_sdk::derive_public(&registration, &chain.path())?
                            .to_vec(),
                        multi: None,
                    },
                    _ => {
                        let key = self
                            .sdk
                            .signing_key(
                                &KeyRequest {
                                    registration: registration.clone(),
                                    account: chain.path(),
                                    suite: if chain == Chain::Evm {
                                        Suite::Dkls23Secp256k1
                                    } else {
                                        Suite::FrostRedPallas
                                    },
                                },
                                self.identities,
                            )
                            .await?;
                        MessageKey {
                            chain,
                            public_key: key.key.public_key.clone(),
                            multi: Some(key),
                        }
                    }
                };
                self.journal.update(|s| {
                    s.message_namespaces
                        .iter_mut()
                        .find(|n| n.authority == authority)
                        .unwrap()
                        .keys
                        .push(key);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
    pub async fn sign_message(
        &self,
        id: &str,
        authority: Authority,
        chain: Chain,
        message: &str,
    ) -> Result<()> {
        let s = self.journal.read();
        let ns = s
            .message_namespaces
            .iter()
            .find(|n| n.authority == authority)
            .context("message namespace not ready")?;
        let key = ns
            .keys
            .iter()
            .find(|k| k.chain == chain)
            .context("message key not ready")?;
        let reg = &ns.registration;
        let controller = self.message_controller(authority);
        let text = envelope(chain, authority, controller, id, message)?;
        let intent = key.multi.as_ref().map(|key| Intent {
            version: 1,
            key: key.key.clone(),
            payload: if chain == Chain::Evm {
                Payload::EvmMessage(pairkey_signing::evm_message::Message {
                    chain_id: CHAIN,
                    message: text.as_bytes().to_vec(),
                })
            } else {
                Payload::RedPallas {
                    message: text.as_bytes().to_vec(),
                }
            },
        });
        let approved = if let Some(intent) = &intent {
            intent.validate(reg)?;
            intent.bytes()?
        } else {
            text.as_bytes().to_vec()
        };
        let commit = Commit::new(reg, fresh(), chain.path(), &approved)?;
        self.journal.op(id,|o|o.result=json!({"chain":chain,"authority":authority,"controller":controller.to_string(),"scheme":chain.scheme(),"message":message,"signed_message":text,"public_key":display_key(chain,&key.public_key).unwrap_or_default(),"public_key_hex":format!("0x{}",hex(&key.public_key)),"approval":"per_message","hardware_backed":false}))?;
        self.journal.event(
            id,
            "Submitting exact-message approval to Solana; no session is used",
        )?;
        self.send(
            Some(id),
            vec![self.message_ix(
                authority,
                pairkey_sdk::commit(self.payer.pubkey(), controller, reg, commit.clone()),
            )],
        )
        .await?;
        self.journal.op(id, |o| {
            o.uncertain = false;
            o.result["approval_finalized"] = json!(true);
        })?;
        self.journal
            .event(id, "Exact-message approval finalized on Solana devnet")?;
        let authorization = Authorization {
            policy_version: 1,
            ..Default::default()
        };
        let (signature, receipts, summaries) = if let Some(intent) = intent {
            let q = multi::SignRequest {
                protocol: multi::PROTOCOL_VERSION,
                registration: reg.clone(),
                attempt: Attempt {
                    commit,
                    random_id: fresh(),
                    authorization,
                },
                intent,
                certificate: key.multi.as_ref().unwrap().certificate.clone(),
            };
            q.validate()?;
            self.journal.op(id, |o| {
                o.signing_request = Some(q.clone());
                o.uncertain = true;
                o.result["signing_started"] = json!(true);
            })?;
            self.journal.event(
                id,
                "Both signers independently check the approval and run threshold signing",
            )?;
            self.sdk.submit_intent(&q).await?;
            let signed = self
                .sdk
                .wait_intent(&q, self.identities, Duration::from_secs(180))
                .await?;
            let summaries = signed
                .receipts
                .iter()
                .map(|r| json!({"role":r.role,"finalized_slot":r.finalized_slot}))
                .collect::<Vec<_>>();
            (
                signed.signature,
                serde_json::to_value(signed.receipts)?,
                summaries,
            )
        } else {
            self.journal.op(id,|o|{o.ed_request=Some(json!({"registration":reg,"commit":commit,"message":text.as_bytes(),"authorization":authorization}));o.uncertain=true;o.result["signing_started"]=json!(true);})?;
            self.journal.event(
                id,
                "Both signers independently check the approval and run FROST Ed25519",
            )?;
            let job = self
                .sdk
                .submit_authorized(reg, &commit, text.as_bytes(), &authorization)
                .await?;
            self.journal.op(id, |o| o.result["job_id"] = json!(job))?;
            let end = tokio::time::Instant::now() + Duration::from_secs(180);
            let signed = loop {
                let status: pairkey_coordinator::Job =
                    serde_json::from_value(self.sdk.poll(&job).await?)?;
                match status {
                    pairkey_coordinator::Job::Complete { result } => break result,
                    pairkey_coordinator::Job::Failed { error } => {
                        anyhow::bail!("Ed25519 signing failed; reconcile job: {error}")
                    }
                    _ => {}
                }
                ensure!(
                    tokio::time::Instant::now() < end,
                    "Ed25519 signing timeout; reconcile saved job"
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
            };
            ensure!(
                signed.attempt.commit == commit && signed.attempt.authorization == authorization,
                "Ed25519 result context mismatch"
            );
            for (i, role) in [Role::A, Role::B].into_iter().enumerate() {
                pairkey_sdk::service::verify_receipt(
                    reg,
                    &signed.attempt,
                    text.as_bytes(),
                    &signed.receipts[i],
                    self.identities[i],
                    role,
                    true,
                )?;
                ensure!(
                    signed.receipts[i].receipt.signature == signed.signature,
                    "Ed25519 receipt signature mismatch"
                );
            }
            let summaries = signed
                .receipts
                .iter()
                .map(|r| json!({"role":r.receipt.role,"finalized_slot":r.receipt.finalized_slot}))
                .collect::<Vec<_>>();
            (
                signed.signature,
                serde_json::to_value(signed.receipts)?,
                summaries,
            )
        };
        let verification = Verification {
            chain,
            public_key_hex: format!("0x{}", hex(&key.public_key)),
            signed_message: text.clone(),
            signature_hex: format!("0x{}", hex(&signature)),
        };
        ensure!(
            verification.check()?,
            "final message signature verification failed"
        );
        self.journal.op(id, |o| {
            o.uncertain = false;
            o.result["signature_verified"] = json!(true);
            o.result["receipts_verified"] = json!(2);
            o.result["signature_hex"] = json!(verification.signature_hex);
            o.result["receipts"] = receipts;
            o.result["signers"] = json!(summaries);
        })?;
        self.journal.event(id,"Signature and both identity-signed receipts verified; no destination transaction was broadcast")?;
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub chain: Chain,
    pub public_key_hex: String,
    pub signed_message: String,
    pub signature_hex: String,
}
fn decode(value: &str, limit: usize) -> Result<Vec<u8>> {
    let value = value
        .strip_prefix("0x")
        .context("hex value must start with 0x")?;
    ensure!(
        value.len() <= limit * 2
            && value.len() % 2 == 0
            && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid hex encoding"
    );
    (0..value.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&value[i..i + 2], 16)?))
        .collect()
}
impl Verification {
    pub fn check(&self) -> Result<bool> {
        ensure!(
            !self.signed_message.is_empty() && self.signed_message.len() <= 512,
            "verification message bounds"
        );
        let public = decode(&self.public_key_hex, 65)?;
        let sig = decode(&self.signature_hex, 65)?;
        let valid = match self.chain {
            Chain::Solana | Chain::Near => {
                let key: [u8; 32] = public.as_slice().try_into().context("Ed25519 key length")?;
                let signature = ed25519_dalek::Signature::from_slice(&sig)?;
                ed25519_dalek::VerifyingKey::from_bytes(&key)?
                    .verify_strict(self.signed_message.as_bytes(), &signature)
                    .is_ok()
            }
            Chain::Evm => pairkey_signing::evm_message::Message {
                chain_id: CHAIN,
                message: self.signed_message.as_bytes().to_vec(),
            }
            .verify(&public, &sig)
            .is_ok(),
            Chain::Zcash => {
                pairkey_signing::redpallas::verify(&public, self.signed_message.as_bytes(), &sig)
                    .is_ok()
            }
        };
        Ok(valid)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelope_binds_authority_destination_and_request() {
        let a = envelope(
            Chain::Solana,
            Authority::Account,
            Pubkey::new_from_array([1; 32]),
            &"a".repeat(32),
            "hello",
        )
        .unwrap();
        assert_ne!(
            a,
            envelope(
                Chain::Near,
                Authority::Account,
                Pubkey::new_from_array([1; 32]),
                &"a".repeat(32),
                "hello"
            )
            .unwrap()
        );
        assert_ne!(
            a,
            envelope(
                Chain::Solana,
                Authority::Program,
                Pubkey::new_from_array([1; 32]),
                &"a".repeat(32),
                "hello"
            )
            .unwrap()
        );
        assert!(envelope(
            Chain::Solana,
            Authority::Account,
            Pubkey::new_unique(),
            "id",
            &"a".repeat(257)
        )
        .is_err());
    }
    #[test]
    fn verification_recomputes_signature_and_rejects_changed_message() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let message = "PairKey verification test";
        use ed25519_dalek::Signer;
        let mut q = Verification {
            chain: Chain::Solana,
            public_key_hex: format!("0x{}", hex(key.verifying_key().as_bytes())),
            signed_message: message.into(),
            signature_hex: format!("0x{}", hex(&key.sign(message.as_bytes()).to_bytes())),
        };
        assert!(q.check().unwrap());
        q.signed_message.push('!');
        assert!(!q.check().unwrap());
        q.signature_hex = "0xz0".into();
        assert!(q.check().is_err());
    }
}
