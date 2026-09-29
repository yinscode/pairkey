//! Destination adapter v1: canonical legacy Solana messages with one native transfer.
//! Refuses lookup tables, extra instructions, additional signers, fees, and durable nonce flows.
use crate::Error;
use pairkey_types::{AccountPath, Registration};
use solana_sdk::{message::Message, pubkey::Pubkey};

pub fn destination(network: [u8; 32]) -> [u8; 32] {
    pairkey_types::policy::solana_destination(network)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub recipient: [u8; 32],
    pub lamports: u64,
}
pub fn parse(reg: &Registration, account: &AccountPath, message: &[u8]) -> Result<Transfer, Error> {
    if account.destination != destination(reg.namespace.network) {
        return Err(Error::Authorization);
    }
    let key = pairkey_types::derive_public(reg, account).map_err(|_| Error::Authorization)?;
    let tx: Message = bincode::deserialize(message).map_err(|_| Error::Authorization)?;
    if tx.serialize() != message
        || tx.header.num_required_signatures != 1
        || tx.header.num_readonly_signed_accounts != 0
        || tx.header.num_readonly_unsigned_accounts != 1
        || tx.account_keys.len() != 3
        || tx.account_keys[0] != Pubkey::new_from_array(key)
        || tx.instructions.len() != 1
        || tx.recent_blockhash == solana_sdk::hash::Hash::default()
    {
        return Err(Error::Authorization);
    }
    let ix = &tx.instructions[0];
    if ix.accounts != [0, 1]
        || ix.program_id_index != 2
        || tx.account_keys[2] != solana_sdk::system_program::id()
        || tx.account_keys[1] == tx.account_keys[0]
        || tx.account_keys[1] == tx.account_keys[2]
        || ix.data.len() != 12
        || ix.data[..4] != 2u32.to_le_bytes()
    {
        return Err(Error::Authorization);
    }
    let lamports = u64::from_le_bytes(
        ix.data[4..12]
            .try_into()
            .map_err(|_| Error::Authorization)?,
    );
    if lamports == 0 {
        return Err(Error::Authorization);
    }
    Ok(Transfer {
        recipient: tx.account_keys[1].to_bytes(),
        lamports,
    })
}
