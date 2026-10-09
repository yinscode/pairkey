//! Private per-request authentication ingress; public protocol messages carry commitments.
use super::*;
use pairkey_core::{
    approval_store::{ApprovalStore, Claim, Status},
    oidc::TrustedIssuer,
};
use pairkey_types::approval::{Approval, Identity, Submission};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
}
struct CachedIssuer {
    issuer: Arc<TrustedIssuer>,
    fetched: Instant,
}
pub(super) struct Offchain {
    pub store: Mutex<ApprovalStore>,
    proofs: Mutex<BTreeMap<[u8; 32], Approval>>,
    configs: Vec<IssuerConfig>,
    issuers: tokio::sync::Mutex<BTreeMap<(String, String), CachedIssuer>>,
    http: reqwest::Client,
}
pub(super) struct Evidence {
    pub approval: Approval,
    pub issuer: Option<Arc<TrustedIssuer>>,
}
impl Offchain {
    pub fn new(
        path: &str,
        trust: &Trust,
        role: Role,
        configs: Vec<IssuerConfig>,
    ) -> anyhow::Result<Self> {
        ensure!(configs.len() <= 16, "OIDC configuration bound");
        let mut seen = std::collections::BTreeSet::new();
        for c in &configs {
            for text in [&c.issuer, &c.jwks_url] {
                let url = reqwest::Url::parse(text)?;
                ensure!(
                    url.scheme() == "https"
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.fragment().is_none(),
                    "OIDC requires configured HTTPS endpoints"
                );
            }
            ensure!(
                !c.audience.is_empty()
                    && c.audience.len() <= 256
                    && c.issuer.len() <= 256
                    && seen.insert((c.issuer.clone(), c.audience.clone())),
                "invalid or duplicate OIDC issuer/audience"
            );
        }
        let context = pairkey_types::digest(
            b"pairkey/worker-approval-store/v1",
            &(
                trust.network,
                trust.registry.to_bytes(),
                trust.enclave_set.to_bytes(),
                trust.identity_keys,
                role,
            ),
        );
        Ok(Self {
            store: Mutex::new(ApprovalStore::open(path, context)?),
            proofs: Default::default(),
            configs,
            issuers: Default::default(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(6))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }
    fn cache_key(auth: &pairkey_types::policy::Authorization) -> [u8; 32] {
        pairkey_types::digest(b"pairkey/private-approval/v1", auth)
    }
    pub fn proof(&self, auth: &pairkey_types::policy::Authorization) -> anyhow::Result<Approval> {
        self.proofs
            .lock()
            .unwrap()
            .get(&Self::cache_key(auth))
            .cloned()
            .context("authenticate this exact request at each signer first")
    }
    fn remember(&self, approval: Approval) -> anyhow::Result<()> {
        let mut proofs = self.proofs.lock().unwrap();
        proofs.retain(|_, a| a.request.expires_at > now());
        let key = Self::cache_key(&pairkey_types::policy::Authorization::offchain(&approval));
        if !proofs.contains_key(&key) {
            ensure!(proofs.len() < 1024, "private approval capacity reached");
        }
        proofs.insert(key, approval);
        Ok(())
    }
    pub async fn issuer(&self, identity: &Identity) -> anyhow::Result<Option<Arc<TrustedIssuer>>> {
        let Identity::Oidc {
            issuer, audience, ..
        } = identity
        else {
            return Ok(None);
        };
        let config = self
            .configs
            .iter()
            .find(|c| &c.issuer == issuer && &c.audience == audience)
            .context("OIDC issuer/audience not configured")?;
        let key = (issuer.clone(), audience.clone());
        let mut cache = self.issuers.lock().await;
        if let Some(c) = cache.get(&key) {
            if c.issuer.is_fresh(now())
                && c.fetched.elapsed()
                    < Duration::from_secs(pairkey_core::oidc::MAX_JWKS_AGE as u64)
            {
                return Ok(Some(Arc::clone(&c.issuer)));
            }
        }
        let fetched = Instant::now();
        let fetched_at = now();
        let response = self
            .http
            .get(&config.jwks_url)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        ensure!(response.status().is_success(), "OIDC JWKS fetch refused");
        let bytes =
            pairkey_sdk::http::bounded_body(response, pairkey_core::oidc::MAX_JWKS_BYTES).await?;
        let trusted = Arc::new(TrustedIssuer::from_jwks(
            issuer.clone(),
            audience.clone(),
            &bytes,
            fetched_at,
        )?);
        cache.insert(
            key,
            CachedIssuer {
                issuer: Arc::clone(&trusted),
                fetched,
            },
        );
        Ok(Some(trusted))
    }
}

pub(super) fn claim(reg: &pairkey_types::Registration, attempt: &Attempt) -> Option<Claim> {
    attempt
        .authorization
        .offchain_request()
        .map(|request| Claim {
            namespace_digest: reg.namespace.digest(),
            request_id: attempt.commit.request_id,
            approval_digest: request.digest(),
            attempt_digest: attempt.digest(),
            expires_at: request.expires_at,
        })
}

impl Worker {
    pub(super) fn record_rules(
        &self,
        o: &Observation,
        reg: &pairkey_types::Registration,
        minimum_slot: u64,
    ) -> anyhow::Result<()> {
        let (rules, inactive) =
            pairkey_core::approval::observe_rules(&self.trust, o, reg, now(), minimum_slot)?;
        let mut release = self.release.lock().unwrap();
        let mut store = self.offchain.store.lock().unwrap();
        // An unauthenticated caller cannot fill durable storage with arbitrary
        // absent/default namespaces. Existing or explicitly stored policies are
        // fenced immediately; first defaults are saved after authentication.
        if o.rules.is_some() || store.knows_policy(reg.namespace.digest())? {
            store.observe_policy(
                reg.namespace.digest(),
                rules.revision,
                rules.digest(),
                o.slot,
                now(),
            )?;
        }
        if inactive {
            release.controls.observe_inactive(o.slot)?;
            store.observe_inactive(o.slot, now())?;
        }
        release.highest_slot = release.highest_slot.max(o.slot);
        Ok(())
    }
    pub(super) async fn offchain_view(
        &self,
        reg: &pairkey_types::Registration,
        attempt: &Attempt,
        message: &[u8],
        approval: Approval,
    ) -> anyhow::Result<AuthorizedView> {
        self.active()?;
        let own = self.signer.proof(&reg.namespace, &mut OsRng)?;
        ensure!(
            reg.public_shares[own.role.index()] == own.public_share,
            "namespace root mismatch"
        );
        let issuer = self.offchain.issuer(&approval.request.identity).await?;
        let minimum_slot = {
            let release = self.release.lock().unwrap();
            release
                .highest_slot
                .max(release.controls.minimum_slot())
                .max(self.offchain.store.lock().unwrap().minimum_slot()?)
        };
        let registry = self.trust.registry;
        let namespace = pair_registry::namespace_address(&registry, reg).0;
        let addresses = [
            self.trust.enclave_set,
            namespace,
            pair_registry::policy_address(&registry, &namespace).0,
            pair_registry::approval::rules_address(&registry, &reg.namespace.digest()).0,
        ];
        let response=self.rpc.call("getMultipleAccounts",json!([addresses.map(|a|a.to_string()),{"encoding":"base64","commitment":"finalized","minContextSlot":minimum_slot}])).await?;
        let slot = response["context"]["slot"]
            .as_u64()
            .context("missing slot")?;
        let observed_at = now();
        let accounts = response["value"]
            .as_array()
            .context("missing account response")?;
        ensure!(accounts.len() == addresses.len(), "missing accounts");
        let decode = |i: usize| -> anyhow::Result<ObservedAccount> {
            let a = &accounts[i];
            ensure!(a["data"][1] == "base64", "account encoding");
            Ok(ObservedAccount {
                address: addresses[i],
                owner: a["owner"].as_str().context("account owner")?.parse()?,
                data: STANDARD.decode(a["data"][0].as_str().context("account data")?)?,
            })
        };
        let block_time = self
            .rpc
            .call("getBlockTime", json!([slot]))
            .await?
            .as_i64()
            .context("missing block time")?;
        let observation = Observation {
            rules: if accounts[3].is_null() {
                None
            } else {
                Some(decode(3)?)
            },
            policy: if accounts[2].is_null() {
                None
            } else {
                Some(decode(2)?)
            },
            session: None,
            simulation: None,
            network: self.trust.network,
            finalized: true,
            slot,
            block_time,
            observed_at,
            provider_domain: self.trust.provider_domain.clone(),
            set: decode(0)?,
            namespace: if accounts[1].is_null() {
                ObservedAccount {
                    address: namespace,
                    owner: solana_sdk::system_program::id(),
                    data: vec![],
                }
            } else {
                decode(1)?
            },
            request: ObservedAccount {
                address: pair_registry::request_address(
                    &registry,
                    &namespace,
                    &attempt.commit.request_id,
                )
                .0,
                owner: solana_sdk::system_program::id(),
                data: vec![],
            },
        };
        self.record_rules(&observation, reg, minimum_slot)?;
        let decision = pairkey_core::approval::authorize(
            &self.trust,
            &observation,
            reg,
            attempt,
            message,
            &approval.proof,
            issuer.as_deref(),
            now(),
            minimum_slot,
        );
        if let Err(error) = decision {
            if matches!(error, pairkey_core::Error::Inactive) {
                self.observe_inactive(slot)?;
            }
            return Err(error.into());
        }
        self.freshness.check(
            slot,
            block_time,
            self.started.elapsed().as_millis() as u64,
            self.trust.max_observation_age_secs as u64 * 1000,
        )?;
        let mut release = self.release.lock().unwrap();
        release.controls.check_active(slot)?;
        let rules = pairkey_core::approval::rules(&self.trust, &observation, reg)?;
        self.offchain.store.lock().unwrap().observe_policy(
            reg.namespace.digest(),
            rules.revision,
            rules.digest(),
            slot,
            now(),
        )?;
        release.highest_slot = release.highest_slot.max(slot);
        Ok(AuthorizedView {
            observation,
            minimum_slot,
            offchain: Some(Evidence { approval, issuer }),
        })
    }
    /// Called with the issuance lock held, before allocating any signing nonce.
    pub(super) fn reserve_approval(&self, begin: &Begin) -> anyhow::Result<()> {
        if let Some(claim) = claim(&begin.registration, &begin.attempt) {
            ensure!(
                self.offchain.store.lock().unwrap().reserve(claim, now())?,
                "request already claimed; recover its result instead of starting again"
            );
        }
        Ok(())
    }
    pub(super) fn check_approval(&self, begin: &Begin) -> anyhow::Result<()> {
        if let Some(claim) = claim(&begin.registration, &begin.attempt) {
            self.offchain
                .store
                .lock()
                .unwrap()
                .check_started(&claim, now())?;
        }
        Ok(())
    }
    pub(super) fn complete_approval(
        &self,
        begin: &Begin,
        result: &impl serde::Serialize,
    ) -> anyhow::Result<()> {
        if let Some(claim) = claim(&begin.registration, &begin.attempt) {
            self.offchain.store.lock().unwrap().complete(
                &claim,
                serde_json::to_vec(result)?,
                now(),
            )?;
        }
        Ok(())
    }
}

pub(super) async fn approve(
    State(w): State<W>,
    Json(q): Json<Submission>,
) -> Result<Json<pairkey_types::policy::Authorization>, Failure> {
    let auth = pairkey_types::policy::Authorization::offchain(&q.approval);
    let attempt = Attempt {
        authorization: auth.clone(),
        commit: q.approval.request.commit.clone(),
        random_id: [0; 32],
    };
    w.offchain_view(&q.registration, &attempt, &q.payload, q.approval.clone())
        .await
        .map_err(failure)?;
    w.offchain.remember(q.approval).map_err(failure)?;
    Ok(Json(auth))
}

pub(super) async fn check(
    State(w): State<W>,
    Json(q): Json<ApprovalCheck>,
) -> Result<Json<bool>, Failure> {
    let proof = w
        .offchain
        .proof(&q.attempt.authorization)
        .map_err(failure)?;
    w.offchain_view(&q.registration, &q.attempt, &q.payload, proof)
        .await
        .map_err(failure)?;
    Ok(Json(true))
}

pub(super) async fn lookup(
    State(w): State<W>,
    Json(q): Json<ApprovalLookup>,
) -> Result<Json<Option<Status>>, Failure> {
    w.offchain
        .store
        .lock()
        .unwrap()
        .lookup(q.namespace_digest, q.request_id, q.approval_digest)
        .map(Json)
        .map_err(failure)
}
