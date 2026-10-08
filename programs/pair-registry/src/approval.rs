//! Optional policy storage independent of namespace registration.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pairkey_types::approval::{Identity, PolicyProof, PolicyUpdate, Rules};

pub const P256_PROGRAM: Pubkey =
    solana_program::pubkey!("Secp256r1SigVerify1111111111111111111111111");

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct RulesRecord {
    pub namespace_digest: [u8; 32],
    pub rules: Rules,
}

pub fn rules_address(program: &Pubkey, namespace_digest: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"rules", namespace_digest], program)
}

/// Checks native, already executed P-256 verification over the exact key/message.
/// Cross-instruction data references and multi-signature layouts are not accepted.
pub fn p256_verified(sysvar: &AccountInfo, key: &[u8], message: &[u8]) -> ProgramResult {
    if key.len() != 33 {
        return Err(bad());
    }
    let current = load_current_index_checked(sysvar)?;
    for index in 0..current {
        let ix = load_instruction_at_checked(index as usize, sysvar)?;
        if ix.program_id != P256_PROGRAM || !ix.accounts.is_empty() {
            continue;
        }
        let d = &ix.data;
        if d.get(..2) != Some(&[1, 0])
            || word(d, 4) != Some(65535)
            || word(d, 8) != Some(65535)
            || word(d, 14) != Some(65535)
        {
            continue;
        }
        let (Some(s), Some(k), Some(m), Some(n)) =
            (word(d, 2), word(d, 6), word(d, 10), word(d, 12))
        else {
            continue;
        };
        if s < 16
            || k < 16
            || m < 16
            || d.get(s..s + 64).is_none()
            || d.get(k..k + 33) != Some(key)
            || n != message.len()
            || d.get(m..m + n) != Some(message)
        {
            continue;
        }
        return Ok(());
    }
    Err(ProgramError::MissingRequiredSignature)
}

/// The precompile verifies the signature; the gateway must still verify WebAuthn's
/// RP, origin, challenge, ceremony type and user-presence/user-verification flags.
pub fn passkey_message(
    update: &PolicyUpdate,
    auth: &[u8],
    json: &[u8],
) -> Result<Vec<u8>, ProgramError> {
    let Identity::Passkey { rp_id, origin, .. } = &update.identity else {
        return Err(bad());
    };
    if auth.len() != 37 || json.len() > 2048 {
        return Err(bad());
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ClientData {
        #[serde(rename = "type")]
        kind: String,
        challenge: String,
        origin: String,
        #[serde(default)]
        cross_origin: bool,
        top_origin: Option<String>,
    }
    let client: ClientData = serde_json::from_slice(json).map_err(|_| bad())?;
    let flags = auth[32];
    if client.kind != "webauthn.get"
        || client.origin != *origin
        || client.cross_origin
        || client.top_origin.is_some()
        || client.challenge != URL_SAFE_NO_PAD.encode(update.challenge())
        || auth[..32] != solana_program::hash::hash(rp_id.as_bytes()).to_bytes()
        || flags & 5 != 5
        || flags & 0xe2 != 0
        || (flags & 0x10 != 0 && flags & 8 == 0)
    {
        return Err(bad());
    }
    let mut message = auth.to_vec();
    message.extend_from_slice(solana_program::hash::hash(json).as_ref());
    Ok(message)
}

pub(super) fn set_rules(
    program: &Pubkey,
    accounts: &[AccountInfo],
    update: PolicyUpdate,
    proof: PolicyProof,
) -> ProgramResult {
    let mut iter = accounts.iter();
    let payer = next_account_info(&mut iter)?;
    let owner = next_account_info(&mut iter)?;
    let set_info = next_account_info(&mut iter)?;
    let target = next_account_info(&mut iter)?;
    let system = next_account_info(&mut iter)?;
    let instructions = next_account_info(&mut iter)?;
    if iter.next().is_some() {
        return Err(bad());
    }
    signer(payer)?;
    update
        .validate(solana_program::clock::Clock::get()?.unix_timestamp)
        .map_err(|_| bad())?;
    if update.namespace.registry != program.to_bytes() {
        return Err(bad());
    }
    address(system, solana_program::system_program::id())?;
    address(instructions, solana_program::sysvar::instructions::id())?;
    address(
        set_info,
        set_address(program, &update.namespace.enclave_set).0,
    )?;
    let set: EnclaveSet = read(set_info, program)?;
    if set.version != VERSION
        || set.set_id != update.namespace.enclave_set
        || set.retired
        || set.identities[0] == set.identities[1]
    {
        return Err(bad());
    }
    match (&update.identity, proof) {
        (Identity::Account { public_key }, PolicyProof::Wallet) => {
            address(owner, Pubkey::new_from_array(*public_key))?;
            signer(owner)?;
        }
        (
            Identity::Passkey { public_key, .. },
            PolicyProof::Passkey {
                authenticator_data,
                client_data_json,
            },
        ) => {
            let message = passkey_message(&update, &authenticator_data, &client_data_json)?;
            p256_verified(instructions, public_key, &message)?;
        }
        (Identity::Oidc { .. }, PolicyProof::OidcAttested) => {
            for identity in set.identities {
                ed_verified(instructions, &identity, &update.attestation_message(), None)?;
            }
        }
        _ => return Err(bad()),
    }
    let namespace_digest = update.namespace.digest();
    let (pda, bump) = rules_address(program, &namespace_digest);
    address(target, pda)?;
    let record = RulesRecord {
        namespace_digest,
        rules: update.rules,
    };
    if target.owner == program {
        let old: RulesRecord = read(target, program)?;
        if old.namespace_digest != record.namespace_digest
            || record.rules.revision != old.rules.revision.checked_add(1).ok_or_else(bad)?
        {
            return Err(bad());
        }
        let bytes = borsh::to_vec(&record).map_err(|_| bad())?;
        let rent = Rent::get()?.minimum_balance(bytes.len());
        if target.lamports() < rent {
            solana_program::program::invoke(
                &system_instruction::transfer(payer.key, target.key, rent - target.lamports()),
                &[payer.clone(), target.clone(), system.clone()],
            )?;
        }
        target.realloc(bytes.len(), false)?;
        write(target, &record)
    } else {
        if record.rules.revision != 1 {
            return Err(bad());
        }
        create(
            payer,
            target,
            system,
            program,
            &[b"rules", &namespace_digest, &[bump]],
            &record,
        )
    }
}
