//! Hosted helpers construct unsigned instructions. The owner chooses when to send them.
use super::*;
use pairkey_types::approval::{Assertion, Binding, PolicyUpdate};
use pairkey_types::program_approval::{Mode, Source};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesRequest {
    pub registration: Registration,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesResponse {
    pub rules: Rules,
    pub policy_address: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRequest {
    pub registration: Registration,
    pub identity: Identity,
    /// Explicit next revision. The server never changes caller-supplied rules.
    pub rules: Rules,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPrepared {
    pub update: PolicyUpdate,
    pub challenge: [u8; 32],
    pub signing_message: Vec<u8>,
}
impl PolicyPrepared {
    pub fn verify(&self, expected: &PolicyRequest, now: i64) -> Result<()> {
        self.update.validate(now)?;
        ensure!(
            self.update.namespace == expected.registration.namespace
                && self.update.identity == expected.identity
                && self.update.rules == expected.rules
                && self.challenge == self.update.challenge()
                && self.signing_message == self.update.signing_message(),
            "policy update changed"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PolicyAuthentication {
    Wallet,
    ProgramCpi,
    Passkey(Assertion),
    Oidc {
        binding: Binding,
        id_token: String,
        signature: Vec<u8>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInstructionsRequest {
    pub payer: String,
    pub update: PolicyUpdate,
    pub authentication: PolicyAuthentication,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instructions {
    pub instructions: Vec<InstructionData>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExampleSourceRequest {
    pub program: String,
    pub owner: String,
    pub mode: Mode,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExampleSourceResponse {
    pub identity: Identity,
    pub policy_address: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExamplePolicyReadRequest {
    pub program: String,
    pub owner: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExamplePolicyState {
    pub owner: [u8; 32],
    pub enclave_set: [u8; 32],
    pub revision: u64,
    pub enabled: bool,
    pub destination: [u8; 32],
    pub path_prefix: Vec<u32>,
    pub max_payload_bytes: u16,
    pub require_commit: bool,
    pub remaining_approvals: u64,
}
impl From<example_controller::approval::AppPolicy> for ExamplePolicyState {
    fn from(p: example_controller::approval::AppPolicy) -> Self {
        Self {
            owner: p.owner,
            enclave_set: p.enclave_set,
            revision: p.revision,
            enabled: p.enabled,
            destination: p.destination,
            path_prefix: p.path_prefix,
            max_payload_bytes: p.max_payload_bytes,
            require_commit: p.require_commit,
            remaining_approvals: p.remaining_approvals,
        }
    }
}
/// Derivation uses the original controller PDA. Changing approval mode or policy
/// does not silently move an existing user's keys.
pub fn example_source(
    program: Pubkey,
    owner: Pubkey,
    mode: Mode,
    code_hash: [u8; 32],
) -> Result<ExampleSourceResponse> {
    ensure!(owner.is_on_curve(), "program caller must be a wallet key");
    let authority = example_controller::authority(&program, &owner).0;
    let policy = example_controller::approval::policy_address(&program, &owner).0;
    let source = Source {
        program: program.to_bytes(),
        authority: authority.to_bytes(),
        seeds: vec![b"controller".to_vec(), owner.to_bytes().to_vec()],
        code_hash,
        accounts: vec![policy.to_bytes()],
        mode,
    };
    pair_registry::program_approval::validate_source(&source)?;
    Ok(ExampleSourceResponse {
        identity: Identity::Program(Box::new(source)),
        policy_address: policy.to_string(),
    })
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExamplePolicyRequest {
    pub program: String,
    pub owner: String,
    pub revision: u64,
    pub enabled: bool,
    pub chain: Chain,
    pub path_prefix: Vec<u32>,
    pub max_payload_bytes: u16,
    pub require_commit: bool,
    pub remaining_approvals: u64,
}
impl ExamplePolicyRequest {
    pub fn policy(&self, enclave_set: [u8; 32]) -> Result<example_controller::approval::AppPolicy> {
        let owner: Pubkey = self.owner.parse()?;
        ensure!(
            owner.is_on_curve()
                && self.revision > 0
                && self.max_payload_bytes > 0
                && self.max_payload_bytes as usize <= pairkey_types::MAX_MESSAGE,
            "invalid example policy"
        );
        let account = self.chain.account(self.path_prefix.clone())?;
        Ok(example_controller::approval::AppPolicy {
            owner: owner.to_bytes(),
            enclave_set,
            revision: self.revision,
            enabled: self.enabled,
            destination: account.destination,
            path_prefix: self.path_prefix.clone(),
            max_payload_bytes: self.max_payload_bytes,
            require_commit: self.require_commit,
            remaining_approvals: self.remaining_approvals,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExampleCommitRequest {
    pub owner: String,
    pub prepared: Prepared,
}
