//! Program decisions are evidence from the signer's own finalized RPC view, never client output.
use super::*;
use crate::ExecutableObservation;
use pairkey_types::program_approval::{AccountState, Input, Mode, Output, Source};
#[derive(Clone)]
pub enum ProgramObservation {
    Evaluated {
        slot: u64,
        code: Box<ExecutableObservation>,
        states: Vec<AccountState>,
        input: Box<Input>,
        output: Output,
    },
    Committed(ObservedAccount),
}
use crate::ObservedAccount;
pub fn source_and_caller(approval: &Approval) -> Result<(&Source, [u8; 32]), Error> {
    let (Identity::Program(source), Proof::Program { caller, signature }) =
        (&approval.request.identity, &approval.proof)
    else {
        return Err(Error::Authorization);
    };
    pair_registry::program_approval::validate_source(source).map_err(|_| Error::Authorization)?;
    if *caller == [0; 32] {
        return Err(Error::Authorization);
    }
    ed25519(caller, signature, &approval.request.signing_message())?;
    Ok((source, *caller))
}
pub fn input(
    registration: &Registration,
    approval: &Approval,
    payload: &[u8],
    states: &[AccountState],
) -> Result<Input, Error> {
    let (source, caller) = source_and_caller(approval)?;
    if source.mode != Mode::Offchain
        || states.len() != 1 + source.accounts.len()
        || states.iter().map(|s| s.data.len()).sum::<usize>() > 128 * 1024
        || states[1..]
            .iter()
            .zip(&source.accounts)
            .any(|(s, a)| s.address != *a)
    {
        return Err(Error::Authorization);
    }
    Ok(Input {
        version: 1,
        namespace_digest: registration.namespace.digest(),
        request_digest: approval.request.digest(),
        authority: source.authority,
        caller,
        account: approval.request.commit.account.clone(),
        request_id: approval.request.commit.request_id,
        payload: payload.to_vec(),
        expires_at: approval.request.expires_at,
        state_digest: pairkey_types::program_approval::state_digest(states),
    })
}
/// Validates the entire decision context even if the program denied the request.
/// A verified denial can therefore fence older prepared views without trusting a caller's claim.
pub fn decision(
    trust: &Trust,
    observation: &Observation,
    reg: &Registration,
    approval: &Approval,
    payload: &[u8],
    program: &ProgramObservation,
) -> Result<bool, Error> {
    let (source, _) = source_and_caller(approval)?;
    match (source.mode, program) {
        (
            Mode::Offchain,
            ProgramObservation::Evaluated {
                slot,
                code,
                states,
                input: actual,
                output,
            },
        ) => {
            let expected = input(reg, approval, payload, states)?;
            if *slot < observation.slot
                || code.program.to_bytes() != source.program
                || code.hash()? != source.code_hash
                || states[0].address != observation.set.address.to_bytes()
                || states[0].owner != observation.set.owner.to_bytes()
                || states[0].data != observation.set.data
                || **actual != expected
                || output.input_digest != expected.digest()
            {
                return Err(Error::Authorization);
            }
            Ok(output.allowed)
        }
        (Mode::Onchain, ProgramObservation::Committed(info)) => {
            let record: pair_registry::program_approval::ProgramApprovalRecord =
                decode(info, &trust.registry)?;
            if info.address
                != pair_registry::program_approval::approval_address(
                    &trust.registry,
                    &reg.namespace.digest(),
                    &approval.request.commit.request_id,
                )
                .0
                || record.namespace_digest != reg.namespace.digest()
                || record.request_digest != approval.request.digest()
                || record.expires_at != approval.request.expires_at
            {
                return Err(Error::Authorization);
            }
            Ok(true)
        }
        _ => Err(Error::Authorization),
    }
}
/// One state fence per program/application-account list, independent of caller and mode.
pub fn fence_key(reg: &Registration, source: &Source) -> [u8; 32] {
    pairkey_types::digest(
        b"pairkey/program-state-fence/v1",
        &(reg.namespace.digest(), source.program, &source.accounts),
    )
}
