//! Append-only exact-message approval registry. All funds are local test funds.
#![allow(unexpected_cfgs)]
use borsh::{BorshDeserialize, BorshSerialize};
use pairkey_types::{derive_public, Commit, Registration, MAX_MESSAGE, VERSION};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::Instruction,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::{
        instructions::{load_current_index_checked, load_instruction_at_checked},
        Sysvar,
    },
};

solana_program::declare_id!("Fg6PaFpoGXkYsidMpWxTWqkZ6W2BeZ7FEfcYkgMQHGDL");
#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct EnclaveSet {
    pub version: u16,
    pub set_id: [u8; 32],
    pub governor: [u8; 32],
    pub identities: [[u8; 32]; 2],
    pub retired: bool,
    pub development: bool,
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct NamespaceRecord {
    pub registration: Registration,
    pub controller: [u8; 32],
    pub frozen: bool,
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct RequestRecord {
    pub namespace_address: [u8; 32],
    pub commit: Commit,
    pub derived_key: [u8; 32],
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ResponseRecord {
    pub request_address: [u8; 32],
    pub signature: [u8; 64],
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum RegistryInstruction {
    CreateSet {
        set_id: [u8; 32],
        identities: [[u8; 32]; 2],
        development: bool,
    },
    Register {
        registration: Registration,
    },
    Commit {
        commit: Commit,
    },
    Respond {
        message: Vec<u8>,
        signature: [u8; 64],
    },
    Freeze {
        frozen: bool,
    },
    Retire {
        retired: bool,
    },
}
pub fn set_address(program: &Pubkey, id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"set", id], program)
}
pub fn namespace_address(program: &Pubkey, reg: &Registration) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"namespace", &reg.namespace.digest()], program)
}
pub fn request_address(program: &Pubkey, ns: &Pubkey, id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"request", ns.as_ref(), id], program)
}
pub fn response_address(program: &Pubkey, request: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"response", request.as_ref()], program)
}
pub fn registration_message(reg: &Registration, controller: &Pubkey) -> Vec<u8> {
    let mut out = Vec::from(b"pairkey/enrolled-registration/v1".as_slice());
    out.extend_from_slice(&reg.digest());
    out.extend_from_slice(controller.as_ref());
    out
}
fn bad() -> ProgramError {
    ProgramError::InvalidArgument
}
pub fn read<T: BorshDeserialize>(info: &AccountInfo, program: &Pubkey) -> Result<T, ProgramError> {
    if info.owner != program {
        return Err(ProgramError::IllegalOwner);
    }
    T::try_from_slice(&info.try_borrow_data()?).map_err(|_| ProgramError::InvalidAccountData)
}
fn write<T: BorshSerialize>(info: &AccountInfo, data: &T) -> ProgramResult {
    let bytes = borsh::to_vec(data).map_err(|_| ProgramError::InvalidAccountData)?;
    if bytes.len() != info.data_len() {
        return Err(ProgramError::InvalidAccountData);
    }
    info.try_borrow_mut_data()?.copy_from_slice(&bytes);
    Ok(())
}
fn signer(info: &AccountInfo) -> ProgramResult {
    if info.is_signer {
        Ok(())
    } else {
        Err(ProgramError::MissingRequiredSignature)
    }
}
fn address(info: &AccountInfo, expected: Pubkey) -> ProgramResult {
    if *info.key == expected {
        Ok(())
    } else {
        Err(bad())
    }
}
fn create<'a, T: BorshSerialize>(
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    program: &Pubkey,
    seeds: &[&[u8]],
    value: &T,
) -> ProgramResult {
    signer(payer)?;
    if *system.key != solana_program::system_program::id()
        || target.owner != &solana_program::system_program::id()
        || !target.data_is_empty()
    {
        return Err(bad());
    }
    let bytes = borsh::to_vec(value).map_err(|_| bad())?;
    let rent = Rent::get()?.minimum_balance(bytes.len());
    // Supports externally pre-funded PDAs without allowing their contents to be replaced.
    if target.lamports() == 0 {
        invoke_signed(
            &system_instruction::create_account(
                payer.key,
                target.key,
                rent,
                bytes.len() as u64,
                program,
            ),
            &[payer.clone(), target.clone(), system.clone()],
            &[seeds],
        )?;
    } else {
        if target.lamports() < rent {
            solana_program::program::invoke(
                &system_instruction::transfer(payer.key, target.key, rent - target.lamports()),
                &[payer.clone(), target.clone(), system.clone()],
            )?;
        }
        invoke_signed(
            &system_instruction::allocate(target.key, bytes.len() as u64),
            &[target.clone(), system.clone()],
            &[seeds],
        )?;
        invoke_signed(
            &system_instruction::assign(target.key, program),
            &[target.clone(), system.clone()],
            &[seeds],
        )?;
    }
    write(target, value)
}
fn word(data: &[u8], offset: usize) -> Option<usize> {
    Some(u16::from_le_bytes(data.get(offset..offset + 2)?.try_into().ok()?) as usize)
}
/// Only exact, already executed, self-contained native Ed25519 instructions count.
fn ed_verified(
    sysvar: &AccountInfo,
    key: &[u8; 32],
    message: &[u8],
    signature: Option<&[u8; 64]>,
) -> ProgramResult {
    let current = load_current_index_checked(sysvar)?;
    for index in 0..current {
        let ix = load_instruction_at_checked(index as usize, sysvar)?;
        if ix.program_id != solana_program::ed25519_program::id() || !ix.accounts.is_empty() {
            continue;
        }
        let d = &ix.data;
        if d.get(0..2) != Some(&[1, 0]) || d.len() < 16 {
            continue;
        }
        if word(d, 4) != Some(65535) || word(d, 8) != Some(65535) || word(d, 14) != Some(65535) {
            continue;
        }
        let (Some(s), Some(k), Some(m), Some(n)) =
            (word(d, 2), word(d, 6), word(d, 10), word(d, 12))
        else {
            continue;
        };
        if n != message.len()
            || d.get(k..k + 32) != Some(key.as_slice())
            || d.get(m..m + n) != Some(message)
        {
            continue;
        }
        if let Some(sig) = signature {
            if d.get(s..s + 64) != Some(sig.as_slice()) {
                continue;
            }
        }
        return Ok(());
    }
    Err(ProgramError::MissingRequiredSignature)
}
pub fn process_instruction(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() > 1600 {
        return Err(bad());
    }
    let ix = RegistryInstruction::try_from_slice(data).map_err(|_| bad())?;
    let mut iter = accounts.iter();
    match ix {
        RegistryInstruction::CreateSet {
            set_id,
            identities,
            development,
        } => {
            let payer = next_account_info(&mut iter)?;
            let target = next_account_info(&mut iter)?;
            let system = next_account_info(&mut iter)?;
            signer(payer)?;
            if identities[0] == identities[1] {
                return Err(bad());
            }
            let (pda, bump) = set_address(program, &set_id);
            address(target, pda)?;
            // Creation governance is this signer; consumers must pin the enclave-set PDA.
            let set = EnclaveSet {
                version: VERSION,
                set_id,
                governor: payer.key.to_bytes(),
                identities,
                retired: false,
                development,
            };
            create(
                payer,
                target,
                system,
                program,
                &[b"set", &set_id, &[bump]],
                &set,
            )
        }
        RegistryInstruction::Register { registration } => {
            let payer = next_account_info(&mut iter)?;
            let controller = next_account_info(&mut iter)?;
            let set_info = next_account_info(&mut iter)?;
            let target = next_account_info(&mut iter)?;
            let instructions = next_account_info(&mut iter)?;
            let system = next_account_info(&mut iter)?;
            signer(controller)?;
            registration.validate().map_err(|_| bad())?;
            if registration.namespace.registry != program.to_bytes()
                || registration.namespace.derivation_authority != controller.key.to_bytes()
            {
                return Err(bad());
            }
            address(
                set_info,
                set_address(program, &registration.namespace.enclave_set).0,
            )?;
            let set: EnclaveSet = read(set_info, program)?;
            if set.retired || set.version != VERSION {
                return Err(bad());
            }
            let message = registration_message(&registration, controller.key);
            for key in &set.identities {
                ed_verified(instructions, key, &message, None)?;
            }
            let hash = registration.namespace.digest();
            let (pda, bump) = namespace_address(program, &registration);
            address(target, pda)?;
            let record = NamespaceRecord {
                registration,
                controller: controller.key.to_bytes(),
                frozen: false,
            };
            create(
                payer,
                target,
                system,
                program,
                &[b"namespace", &hash, &[bump]],
                &record,
            )
        }
        RegistryInstruction::Commit { commit } => {
            let payer = next_account_info(&mut iter)?;
            let controller = next_account_info(&mut iter)?;
            let ns_info = next_account_info(&mut iter)?;
            let set_info = next_account_info(&mut iter)?;
            let target = next_account_info(&mut iter)?;
            let system = next_account_info(&mut iter)?;
            signer(controller)?;
            let ns: NamespaceRecord = read(ns_info, program)?;
            address(ns_info, namespace_address(program, &ns.registration).0)?;
            address(
                set_info,
                set_address(program, &ns.registration.namespace.enclave_set).0,
            )?;
            let set: EnclaveSet = read(set_info, program)?;
            if ns.frozen
                || set.retired
                || ns.controller != controller.key.to_bytes()
                || commit.registration_digest != ns.registration.digest()
                || commit.message_len == 0
                || commit.message_len as usize > MAX_MESSAGE
            {
                return Err(bad());
            }
            let key = derive_public(&ns.registration, &commit.account).map_err(|_| bad())?;
            let (pda, bump) = request_address(program, ns_info.key, &commit.request_id);
            address(target, pda)?;
            let id = commit.request_id;
            let record = RequestRecord {
                namespace_address: ns_info.key.to_bytes(),
                commit,
                derived_key: key,
            };
            create(
                payer,
                target,
                system,
                program,
                &[b"request", ns_info.key.as_ref(), &id, &[bump]],
                &record,
            )
        }
        RegistryInstruction::Respond { message, signature } => {
            let payer = next_account_info(&mut iter)?;
            let ns_info = next_account_info(&mut iter)?;
            let req_info = next_account_info(&mut iter)?;
            let target = next_account_info(&mut iter)?;
            let instructions = next_account_info(&mut iter)?;
            let system = next_account_info(&mut iter)?;
            let ns: NamespaceRecord = read(ns_info, program)?;
            address(ns_info, namespace_address(program, &ns.registration).0)?;
            let req: RequestRecord = read(req_info, program)?;
            address(
                req_info,
                request_address(program, ns_info.key, &req.commit.request_id).0,
            )?;
            if req.namespace_address != ns_info.key.to_bytes() {
                return Err(bad());
            }
            req.commit
                .authorize(&ns.registration, &message)
                .map_err(|_| bad())?;
            ed_verified(instructions, &req.derived_key, &message, Some(&signature))?;
            let (pda, bump) = response_address(program, req_info.key);
            address(target, pda)?;
            let response = ResponseRecord {
                request_address: req_info.key.to_bytes(),
                signature,
            };
            create(
                payer,
                target,
                system,
                program,
                &[b"response", req_info.key.as_ref(), &[bump]],
                &response,
            )
        }
        RegistryInstruction::Freeze { frozen } => {
            let controller = next_account_info(&mut iter)?;
            let ns_info = next_account_info(&mut iter)?;
            signer(controller)?;
            let mut ns: NamespaceRecord = read(ns_info, program)?;
            address(ns_info, namespace_address(program, &ns.registration).0)?;
            if ns.controller != controller.key.to_bytes() {
                return Err(bad());
            }
            ns.frozen = frozen;
            write(ns_info, &ns)
        }
        RegistryInstruction::Retire { retired } => {
            let governor = next_account_info(&mut iter)?;
            let set_info = next_account_info(&mut iter)?;
            signer(governor)?;
            let mut set: EnclaveSet = read(set_info, program)?;
            address(set_info, set_address(program, &set.set_id).0)?;
            if set.governor != governor.key.to_bytes() {
                return Err(bad());
            }
            set.retired = retired;
            write(set_info, &set)
        }
    }
}
pub fn instruction(
    program: Pubkey,
    accounts: Vec<solana_program::instruction::AccountMeta>,
    data: RegistryInstruction,
) -> Instruction {
    Instruction {
        program_id: program,
        accounts,
        data: borsh::to_vec(&data).unwrap(),
    }
}
