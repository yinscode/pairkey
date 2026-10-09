//! Identity authentication for the new approval format. Chain observations and durable
//! request claims must still be checked by each worker before any signing round.
pub mod program;
use crate::{access, Error};
use crate::{decode, validate_freshness, validate_set, Observation, Trust};
use pair_registry::{EnclaveSet, NamespaceRecord, PolicyRecord};
use pairkey_types::{
    approval::{Approval, Identity, Proof, Rules},
    policy::{AccessProof, Credential},
    Registration,
};

pub fn verify(
    registration: &Registration,
    payload: &[u8],
    rules: &Rules,
    approval: &Approval,
    now: i64,
) -> Result<(), Error> {
    verify_with_oidc(registration, payload, rules, approval, now, None)
}

pub fn verify_with_oidc(
    registration: &Registration,
    payload: &[u8],
    rules: &Rules,
    approval: &Approval,
    now: i64,
    issuer: Option<&crate::oidc::TrustedIssuer>,
) -> Result<(), Error> {
    let request = &approval.request;
    request
        .validate(registration, payload, rules, now)
        .map_err(|_| Error::Authorization)?;
    let message = request.signing_message();
    match (&request.identity, &approval.proof) {
        (Identity::Program(_), Proof::Program { .. }) => {
            program::source_and_caller(approval).map(|_| ())
        }
        (Identity::Account { public_key }, Proof::Account { signature }) => {
            ed25519(public_key, signature, &message)
        }
        (
            Identity::Passkey {
                public_key,
                rp_id,
                origin,
            },
            Proof::Passkey {
                binding,
                assertion,
                signature,
            },
        ) => {
            binding
                .validate(registration, request, now)
                .map_err(|_| Error::Authorization)?;
            access::verify(
                &Credential::Passkey {
                    public_key: p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                        .map_err(|_| Error::Authorization)?
                        .to_encoded_point(false)
                        .as_bytes()
                        .to_vec(),
                    rp_id: rp_id.clone(),
                    origin: origin.clone(),
                },
                &AccessProof::Passkey {
                    authenticator_data: assertion.authenticator_data.clone(),
                    client_data_json: assertion.client_data_json.clone(),
                    signature_der: assertion.signature_der.clone(),
                },
                binding.challenge(),
            )?;
            ed25519(&binding.public_key, signature, &message)
        }
        (
            Identity::Oidc { .. },
            Proof::Oidc {
                binding,
                id_token,
                signature,
            },
        ) => {
            binding
                .validate(registration, request, now)
                .map_err(|_| Error::Authorization)?;
            issuer.ok_or(Error::Authorization)?.verify(
                &request.identity,
                binding,
                id_token,
                request.expires_at,
                now,
            )?;
            ed25519(&binding.public_key, signature, &message)
        }
        _ => Err(Error::Authorization),
    }
}

fn ed25519(public_key: &[u8; 32], signature: &[u8], message: &[u8]) -> Result<(), Error> {
    ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .and_then(|key| {
            key.verify_strict(message, &ed25519_dalek::Signature::from_slice(signature)?)
        })
        .map_err(|_| Error::Authorization)
}

/// Attests owner intent only. The gateway separately enforces the current set,
/// expiry and next policy revision when applying this update atomically.
pub fn verify_oidc_policy_update(
    q: &pairkey_types::approval::OidcPolicyApproval,
    issuer: &crate::oidc::TrustedIssuer,
    now: i64,
) -> Result<(), Error> {
    q.update.validate(now).map_err(|_| Error::Authorization)?;
    q.binding
        .validate_policy_update(&q.update, now)
        .map_err(|_| Error::Authorization)?;
    issuer.verify(
        &q.update.identity,
        &q.binding,
        &q.id_token,
        q.update.expires_at,
        now,
    )?;
    ed25519(
        &q.binding.public_key,
        &q.signature,
        &q.update.signing_message(),
    )
}

pub fn rules(trust: &Trust, observation: &Observation, reg: &Registration) -> Result<Rules, Error> {
    match &observation.rules {
        None => Ok(Rules::default()),
        Some(info) => {
            let record: pair_registry::approval::RulesRecord = decode(info, &trust.registry)?;
            if info.address
                != pair_registry::approval::rules_address(&trust.registry, &reg.namespace.digest())
                    .0
                || record.namespace_digest != reg.namespace.digest()
                || record.rules.revision == 0
            {
                return Err(Error::Authorization);
            }
            record.rules.validate().map_err(|_| Error::Authorization)?;
            Ok(record.rules)
        }
    }
}

/// Validate registry context before recording a fence, including when new rules
/// deny the request. Older prepared views must not survive a known restriction.
pub fn observe_rules(
    trust: &Trust,
    o: &Observation,
    reg: &Registration,
    now: i64,
    minimum_slot: u64,
) -> Result<(Rules, bool), Error> {
    validate_freshness(trust, o, now, minimum_slot)?;
    reg.validate().map_err(|_| Error::Authorization)?;
    let set: EnclaveSet = decode(&o.set, &trust.registry)?;
    validate_set(trust, o, reg, &set)?;
    if reg.namespace.registry != trust.registry.to_bytes()
        || reg.namespace.network != trust.network
        || o.namespace.address != pair_registry::namespace_address(&trust.registry, reg).0
    {
        return Err(Error::Authorization);
    }
    let frozen = if o.namespace.owner == solana_program::system_program::id()
        && o.namespace.data.is_empty()
    {
        false
    } else {
        let ns: NamespaceRecord = decode(&o.namespace, &trust.registry)?;
        if ns.registration != *reg {
            return Err(Error::Authorization);
        }
        ns.frozen
    };
    Ok((rules(trust, o, reg)?, set.retired || frozen))
}

/// Independent chain authorization without a registration/COMMIT transaction.
/// A missing namespace is represented by an empty system-owned account at its PDA.
/// The adapter must distinguish an RPC error from an actual null account result.
#[allow(clippy::too_many_arguments)]
pub fn authorize(
    trust: &Trust,
    observation: &Observation,
    registration: &Registration,
    attempt: &pairkey_types::Attempt,
    payload: &[u8],
    proof: &pairkey_types::approval::Proof,
    issuer: Option<&crate::oidc::TrustedIssuer>,
    now: i64,
    minimum_slot: u64,
) -> Result<(), Error> {
    authorize_with_program(
        trust,
        observation,
        registration,
        attempt,
        payload,
        proof,
        issuer,
        None,
        now,
        minimum_slot,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn authorize_with_program(
    trust: &Trust,
    observation: &Observation,
    registration: &Registration,
    attempt: &pairkey_types::Attempt,
    payload: &[u8],
    proof: &pairkey_types::approval::Proof,
    issuer: Option<&crate::oidc::TrustedIssuer>,
    program: Option<&program::ProgramObservation>,
    now: i64,
    minimum_slot: u64,
) -> Result<(), Error> {
    validate_freshness(trust, observation, now, minimum_slot)?;
    let set: EnclaveSet = decode(&observation.set, &trust.registry)?;
    validate_set(trust, observation, registration, &set)?;
    let expected = pair_registry::namespace_address(&trust.registry, registration).0;
    if registration.namespace.registry != trust.registry.to_bytes()
        || registration.namespace.network != trust.network
        || observation.namespace.address != expected
        || observation.session.is_some()
        || observation.simulation.is_some()
    {
        return Err(Error::Authorization);
    }
    let frozen = if observation.namespace.owner == solana_program::system_program::id()
        && observation.namespace.data.is_empty()
    {
        false
    } else {
        let record: NamespaceRecord = decode(&observation.namespace, &trust.registry)?;
        if record.registration != *registration
            || record.controller != registration.namespace.derivation_authority
        {
            return Err(Error::Authorization);
        }
        record.frozen
    };
    if let Some(info) = &observation.policy {
        let record: PolicyRecord = decode(info, &trust.registry)?;
        if info.address != pair_registry::policy_address(&trust.registry, &expected).0
            || record.namespace_address != expected.to_bytes()
            || observation.rules.is_none()
        {
            return Err(Error::Authorization);
        }
        record.policy.validate().map_err(|_| Error::Authorization)?;
        // Only an explicit owner-authored new rules record opts into the new flow.
        // Existing custom policy is never silently replaced by an absent default.
    }
    let approval = attempt
        .authorization
        .with_offchain_proof(proof)
        .map_err(|_| Error::Authorization)?;
    if approval.request.commit != attempt.commit {
        return Err(Error::Authorization);
    }
    verify_with_oidc(
        registration,
        payload,
        &rules(trust, observation, registration)?,
        &approval,
        now,
        issuer,
    )?;
    if set.retired || frozen {
        return Err(Error::Inactive);
    }
    if matches!(approval.request.identity, Identity::Program(_)) {
        if !program::decision(
            trust,
            observation,
            registration,
            &approval,
            payload,
            program.ok_or(Error::Authorization)?,
        )? {
            return Err(Error::Authorization);
        }
    } else if program.is_some() {
        return Err(Error::Authorization);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
