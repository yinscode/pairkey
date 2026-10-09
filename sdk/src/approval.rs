//! Persistent rules do not require a namespace-registration transaction.
use anyhow::{ensure, Result};
use pairkey_types::approval::{Assertion, Identity, PolicyProof, PolicyUpdate};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

impl crate::service::Client {
    /// Both signers authenticate privately. Use the returned public commitment
    /// with existing submit_authorized/submit_intent APIs; do not put proofs in jobs.
    pub async fn approve_offchain(
        &self,
        q: &pairkey_types::approval::Submission,
    ) -> Result<pairkey_types::policy::Authorization> {
        q.approval
            .request
            .commit
            .authorize(&q.registration, &q.payload)?;
        let expected = pairkey_types::policy::Authorization::offchain(&q.approval);
        let response = self
            .http
            .post(format!("{}/approvals/offchain", self.endpoint))
            .json(q)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let auth: pairkey_types::policy::Authorization =
            crate::http::bounded_json(response, crate::http::MAX_SERVICE_RESPONSE).await?;
        ensure!(auth == expected, "approval commitment changed");
        Ok(auth)
    }
}

pub fn set_rules(payer: Pubkey, update: PolicyUpdate, proof: PolicyProof) -> Instruction {
    let registry = Pubkey::new_from_array(update.namespace.registry);
    let owner = match &update.identity {
        Identity::Account { public_key } => {
            AccountMeta::new_readonly(Pubkey::new_from_array(*public_key), true)
        }
        _ => AccountMeta::new_readonly(payer, false),
    };
    pair_registry::instruction(
        registry,
        vec![
            AccountMeta::new(payer, true),
            owner,
            AccountMeta::new_readonly(
                pair_registry::set_address(&registry, &update.namespace.enclave_set).0,
                false,
            ),
            AccountMeta::new(
                pair_registry::approval::rules_address(&registry, &update.namespace.digest()).0,
                false,
            ),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
        ],
        pair_registry::RegistryInstruction::SetRules { update, proof },
    )
}

/// Self-contained native verification; low-S normalization preserves WebAuthn validity.
pub fn p256_instruction(key: &[u8], signature_der: &[u8], message: &[u8]) -> Result<Instruction> {
    ensure!(
        key.len() == 33 && message.len() <= u16::MAX as usize,
        "invalid native P-256 input"
    );
    p256::ecdsa::VerifyingKey::from_sec1_bytes(key)?;
    let signature = p256::ecdsa::Signature::from_der(signature_der)?;
    let signature = signature.normalize_s().unwrap_or(signature).to_bytes();
    let mut data = vec![1, 0];
    for value in [
        49u16,
        u16::MAX,
        16,
        u16::MAX,
        113,
        message.len() as u16,
        u16::MAX,
    ] {
        data.extend_from_slice(&value.to_le_bytes());
    }
    data.extend_from_slice(key);
    data.extend_from_slice(&signature);
    data.extend_from_slice(message);
    Ok(Instruction {
        program_id: pair_registry::approval::P256_PROGRAM,
        accounts: vec![],
        data,
    })
}

pub fn passkey_rules(
    payer: Pubkey,
    update: PolicyUpdate,
    assertion: Assertion,
) -> Result<Vec<Instruction>> {
    let Identity::Passkey { public_key, .. } = &update.identity else {
        anyhow::bail!("passkey identity required");
    };
    let message = pair_registry::approval::passkey_message(
        &update,
        &assertion.authenticator_data,
        &assertion.client_data_json,
    )?;
    let verify = p256_instruction(public_key, &assertion.signature_der, &message)?;
    Ok(vec![
        verify,
        set_rules(
            payer,
            update,
            PolicyProof::Passkey {
                authenticator_data: assertion.authenticator_data,
                client_data_json: assertion.client_data_json,
            },
        ),
    ])
}
