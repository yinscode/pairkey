//! Read current policy and construct owner-signed updates; never spends hosted funds.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use pairkey_sdk::hosted::offchain::management::*;
use pairkey_types::approval::{PolicyProof, PolicyUpdate};
use pairkey_types::program_approval::Mode;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction, instruction::Instruction, transaction::Transaction,
};

pub(super) fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v2/policies", post(read_rules))
        .route("/api/v2/policies/prepare", post(prepare_policy))
        .route("/api/v2/policies/instructions", post(policy_instructions))
        .route("/api/v2/programs/example", post(source))
        .route("/api/v2/programs/example/policy", post(example_policy))
        .route(
            "/api/v2/programs/example/policy/read",
            post(read_example_policy),
        )
        .route("/api/v2/programs/example/commit", post(example_commit))
}
async fn app_policy(
    app: &App,
    program: Pubkey,
    owner: Pubkey,
) -> Result<Option<example_controller::approval::AppPolicy>> {
    let address = example_controller::approval::policy_address(&program, &owner).0;
    let response = app
        .sol
        .call(
            "getAccountInfo",
            json!([address.to_string(),{"encoding":"base64","commitment":"finalized"}]),
        )
        .await?;
    let value = &response["value"];
    if value.is_null() {
        return Ok(None);
    }
    ensure!(
        value["owner"] == program.to_string() && value["data"][1] == "base64",
        "unexpected application policy owner or encoding"
    );
    let policy: example_controller::approval::AppPolicy =
        borsh::from_slice(&STANDARD.decode(value["data"][0].as_str().context("policy bytes")?)?)?;
    ensure!(
        policy.owner == owner.to_bytes() && policy.revision > 0,
        "application policy context changed"
    );
    Ok(Some(policy))
}
async fn read_example_policy(
    State(app): State<Arc<App>>,
    Json(q): Json<ExamplePolicyReadRequest>,
) -> ApiResult<Option<ExamplePolicyState>> {
    async {
        app_policy(&app, q.program.parse()?, q.owner.parse()?)
            .await
            .map(|p| p.map(Into::into))
    }
    .await
    .map(Json)
    .map_err(fail)
}
fn namespace_context(app: &App, ns: &Namespace) -> Result<()> {
    ns.validate()?;
    ensure!(
        ns.network == GENESIS.parse::<Pubkey>()?.to_bytes()
            && ns.registry == pair_registry::id().to_bytes()
            && ns.enclave_set == app.journal.read().set_id,
        "policy belongs to another deployment"
    );
    Ok(())
}
async fn read_rules(
    State(app): State<Arc<App>>,
    Json(q): Json<RulesRequest>,
) -> ApiResult<RulesResponse> {
    async {
        context(&app, &q.registration)?;
        Ok::<_, anyhow::Error>(RulesResponse {
            rules: rules(&app, &q.registration).await?,
            policy_address: pair_registry::approval::rules_address(
                &pair_registry::id(),
                &q.registration.namespace.digest(),
            )
            .0
            .to_string(),
        })
    }
    .await
    .map(Json)
    .map_err(fail)
}
async fn check_revision(app: &App, update: &PolicyUpdate) -> Result<()> {
    namespace_context(app, &update.namespace)?;
    let record = app
        .account::<pair_registry::approval::RulesRecord>(
            pair_registry::approval::rules_address(
                &pair_registry::id(),
                &update.namespace.digest(),
            )
            .0,
        )
        .await?;
    let current = if let Some(record) = record {
        ensure!(
            record.namespace_digest == update.namespace.digest() && record.rules.revision > 0,
            "invalid policy context"
        );
        record.rules.validate()?;
        record.rules.revision
    } else {
        0
    };
    ensure!(
        current.checked_add(1) == Some(update.rules.revision),
        "policy revision changed; reload the rules before editing"
    );
    Ok(())
}
async fn prepare_policy(
    State(app): State<Arc<App>>,
    Json(q): Json<PolicyRequest>,
) -> ApiResult<PolicyPrepared> {
    async {
        context(&app, &q.registration)?;
        identity(&q.identity)?;
        let now = crate::chain::now()?;
        let update = PolicyUpdate {
            namespace: q.registration.namespace,
            identity: q.identity,
            rules: q.rules,
            issued_at: now,
            expires_at: now + pairkey_types::approval::MAX_APPROVAL_LIFETIME,
        };
        update.validate(now)?;
        check_revision(&app, &update).await?;
        Ok::<_, anyhow::Error>(PolicyPrepared {
            challenge: update.challenge(),
            signing_message: update.signing_message(),
            update,
        })
    }
    .await
    .map(Json)
    .map_err(fail)
}
fn instructions(payer: Pubkey, list: Vec<Instruction>) -> Result<Instructions> {
    ensure!(payer.is_on_curve(), "transaction payer must be a wallet");
    // Include the same budget prefix as the browser client. Do not return an
    // instruction bundle that cannot fit in the wallet transaction.
    let mut all = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ComputeBudgetInstruction::set_compute_unit_price(1000),
    ];
    all.extend(list.clone());
    let tx = Transaction::new_with_payer(&all, Some(&payer));
    ensure!(bincode::serialized_size(&tx)?<=1232,"instruction bundle exceeds Solana transaction size; shorten the message, identity fields or policy");
    Ok(Instructions {
        instructions: list.into_iter().map(Into::into).collect(),
    })
}
async fn policy_instructions(
    State(app): State<Arc<App>>,
    Json(q): Json<PolicyInstructionsRequest>,
) -> ApiResult<Instructions> {
    async {
        let payer: Pubkey = q.payer.parse()?;
        ensure!(
            payer != app.payer.pubkey(),
            "hosted payer cannot authorize user policy changes"
        );
        q.update.validate(crate::chain::now()?)?;
        check_revision(&app, &q.update).await?;
        let list = match (&q.update.identity, q.authentication) {
            (Identity::Account { .. }, PolicyAuthentication::Wallet) => {
                vec![pairkey_sdk::approval::set_rules(
                    payer,
                    q.update,
                    PolicyProof::Wallet,
                )]
            }
            (Identity::Program(_), PolicyAuthentication::ProgramCpi) => {
                vec![pairkey_sdk::approval::set_rules(
                    payer,
                    q.update,
                    PolicyProof::ProgramCpi,
                )]
            }
            (Identity::Passkey { .. }, PolicyAuthentication::Passkey(assertion)) => {
                pairkey_sdk::approval::passkey_rules(payer, q.update, assertion)?
            }
            (
                Identity::Oidc { .. },
                PolicyAuthentication::Oidc {
                    binding,
                    id_token,
                    signature,
                },
            ) => {
                let approved = pairkey_types::approval::OidcPolicyApproval {
                    update: q.update,
                    binding,
                    id_token,
                    signature,
                };
                let signatures = app
                    .sdk
                    .approve_oidc_policy(&approved, app.identities)
                    .await?;
                pairkey_sdk::approval::oidc_rules(
                    payer,
                    approved.update,
                    signatures,
                    app.identities,
                )?
            }
            _ => anyhow::bail!("policy identity and authentication do not match"),
        };
        instructions(payer, list)
    }
    .await
    .map(Json)
    .map_err(fail)
}
async fn source(
    State(app): State<Arc<App>>,
    Json(q): Json<ExampleSourceRequest>,
) -> ApiResult<ExampleSourceResponse> {
    async {
        let program: Pubkey = q.program.parse()?;
        let code_hash = if q.mode == Mode::Offchain {
            app.sol.executable(program, 0).await?.hash()?
        } else {
            [0; 32]
        };
        example_source(program, q.owner.parse()?, q.mode, code_hash)
    }
    .await
    .map(Json)
    .map_err(fail)
}
async fn example_policy(
    State(app): State<Arc<App>>,
    Json(q): Json<ExamplePolicyRequest>,
) -> ApiResult<Instructions> {
    async {
        let program: Pubkey = q.program.parse()?;
        let owner: Pubkey = q.owner.parse()?;
        ensure!(
            owner != app.payer.pubkey(),
            "hosted wallet cannot manage user program policy"
        );
        let policy = q.policy(app.journal.read().set_id)?;
        let revision = app_policy(&app, program, owner)
            .await?
            .map(|p| p.revision)
            .unwrap_or(0);
        ensure!(
            revision.checked_add(1) == Some(policy.revision),
            "application policy revision changed; reload before editing"
        );
        instructions(
            owner,
            vec![pairkey_sdk::program_approval::example_policy(
                program, policy,
            )],
        )
    }
    .await
    .map(Json)
    .map_err(fail)
}
async fn example_commit(
    State(app): State<Arc<App>>,
    Json(q): Json<ExampleCommitRequest>,
) -> ApiResult<Instructions> {
    async {
        let owner: Pubkey = q.owner.parse()?;
        ensure!(
            owner != app.payer.pubkey(),
            "hosted wallet cannot approve user requests"
        );
        let prepared = q.prepared;
        let key = cached(&app, &prepared.signing_request.key)?;
        prepared.verify(
            &wire::PrepareRequest {
                signing_request: prepared.signing_request.clone(),
                identity: prepared.request.identity.clone(),
            },
            &key,
            app.identities,
            crate::chain::now()?,
        )?;
        context(&app, &prepared.signing_request.key.registration)?;
        instructions(
            owner,
            vec![pairkey_sdk::program_approval::example_commit(
                owner,
                prepared.signing_request.key.registration.namespace,
                prepared.request,
                prepared.payload,
            )?],
        )
    }
    .await
    .map(Json)
    .map_err(fail)
}
