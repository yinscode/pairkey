//! Restricted BIP-174/BIP-371 single-input Taproot key-path PSBT adapter.
//! The complete PSBT and exact outputs are approved; workers compute BIP-341
//! sighashes independently. The previous transaction is required to prevent a
//! caller-supplied witness UTXO from understating the true fee.
use anyhow::{ensure, Context, Result};
use bitcoin as btc;
use borsh::{BorshDeserialize, BorshSerialize};
use btc::{
    consensus,
    hashes::Hash,
    psbt::Psbt,
    sighash::{Prevouts, SighashCache, TapSighashType},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub value_sats: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct Spend {
    pub network: crate::bitcoin::Network,
    pub psbt: Vec<u8>,
    pub outputs: Vec<Output>,
    pub max_fee_sats: u64,
    pub max_fee_rate_sat_vb: u64,
}

impl Spend {
    fn parsed(&self, public: &[u8]) -> Result<(Psbt, btc::TxOut)> {
        ensure!(public.len() == 32, "x-only Taproot key required");
        ensure!(
            !self.psbt.is_empty() && self.psbt.len() <= 1024,
            "PSBT size"
        );
        ensure!((1..=2).contains(&self.outputs.len()), "output count");
        ensure!(
            self.max_fee_sats > 0 && self.max_fee_rate_sat_vb > 0,
            "fee limits required"
        );
        let psbt = Psbt::deserialize(&self.psbt).context("invalid PSBT")?;
        ensure!(
            psbt.version == 0 && psbt.serialize() == self.psbt,
            "noncanonical PSBT v0"
        );
        ensure!(
            psbt.unsigned_tx.input.len() == 1 && psbt.inputs.len() == 1,
            "one input required"
        );
        ensure!(
            psbt.unsigned_tx.output.len() == self.outputs.len(),
            "output count mismatch"
        );
        ensure!(
            psbt.outputs.iter().all(|o| *o == Default::default()),
            "PSBT output metadata unsupported"
        );
        ensure!(
            psbt.xpub.is_empty() && psbt.proprietary.is_empty() && psbt.unknown.is_empty(),
            "PSBT global metadata unsupported"
        );
        let txin = &psbt.unsigned_tx.input[0];
        ensure!(
            txin.script_sig.is_empty() && txin.witness.is_empty(),
            "unsigned input expected"
        );
        ensure!(
            !txin.previous_output.is_null(),
            "coinbase outpoint unsupported"
        );
        let input = &psbt.inputs[0];
        ensure!(
            input
                .sighash_type
                .is_none_or(|s| s.taproot_hash_ty().ok() == Some(TapSighashType::Default)),
            "only SIGHASH_DEFAULT supported"
        );
        ensure!(
            input.tap_merkle_root.is_none()
                && input.tap_scripts.is_empty()
                && input.tap_script_sigs.is_empty(),
            "script-path spending unsupported"
        );
        ensure!(
            input.tap_internal_key.is_none() && input.tap_key_origins.is_empty(),
            "Taproot derivation metadata unsupported"
        );
        ensure!(
            input.tap_key_sig.is_none()
                && input.final_script_witness.is_none()
                && input.final_script_sig.is_none(),
            "already signed PSBT"
        );
        ensure!(
            input.partial_sigs.is_empty()
                && input.redeem_script.is_none()
                && input.witness_script.is_none(),
            "legacy signing data unsupported"
        );
        ensure!(
            input.bip32_derivation.is_empty()
                && input.ripemd160_preimages.is_empty()
                && input.sha256_preimages.is_empty()
                && input.hash160_preimages.is_empty()
                && input.hash256_preimages.is_empty(),
            "extraneous PSBT input data"
        );
        ensure!(
            input.proprietary.is_empty() && input.unknown.is_empty(),
            "PSBT input metadata unsupported"
        );
        let previous = input
            .non_witness_utxo
            .as_ref()
            .context("previous transaction required")?;
        ensure!(
            previous.compute_txid() == txin.previous_output.txid,
            "previous transaction ID mismatch"
        );
        let prevout = previous
            .output
            .get(txin.previous_output.vout as usize)
            .context("previous output index")?
            .clone();
        ensure!(
            input.witness_utxo.as_ref() == Some(&prevout),
            "witness UTXO mismatch"
        );
        let mut expected_script = vec![0x51, 0x20];
        expected_script.extend_from_slice(public);
        ensure!(
            prevout.script_pubkey.as_bytes() == expected_script,
            "Taproot output key mismatch"
        );
        let mut sum = 0u64;
        for (actual, expected) in psbt.unsigned_tx.output.iter().zip(&self.outputs) {
            ensure!(
                actual.value.to_sat() == expected.value_sats
                    && actual.script_pubkey.as_bytes() == expected.script_pubkey,
                "unexpected recipient or change output"
            );
            ensure!(
                !actual.script_pubkey.is_empty() && actual.value.to_sat() > 0,
                "invalid output"
            );
            sum = sum
                .checked_add(actual.value.to_sat())
                .context("output overflow")?;
        }
        let fee = prevout
            .value
            .to_sat()
            .checked_sub(sum)
            .context("outputs exceed input")?;
        ensure!(fee <= self.max_fee_sats, "absolute fee limit");
        let estimated_vbytes = (psbt.unsigned_tx.weight().to_wu() + 68).div_ceil(4);
        ensure!(
            fee <= self.max_fee_rate_sat_vb.saturating_mul(estimated_vbytes),
            "fee-rate limit"
        );
        Ok((psbt, prevout))
    }

    pub fn sighash(&self, public: &[u8]) -> Result<[u8; 32]> {
        let (psbt, prevout) = self.parsed(public)?;
        let prevouts = [prevout];
        let digest = SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        )?;
        Ok(digest.to_byte_array())
    }

    pub fn verify(&self, public: &[u8], signature: &[u8]) -> Result<()> {
        crate::bitcoin::verify(public, &self.sighash(public)?, signature)
    }

    pub fn signed(&self, public: &[u8], signature: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        self.verify(public, signature)?;
        let (mut psbt, _) = self.parsed(public)?;
        let signature = btc::taproot::Signature {
            signature: btc::secp256k1::schnorr::Signature::from_slice(signature)?,
            sighash_type: TapSighashType::Default,
        };
        psbt.inputs[0].tap_key_sig = Some(signature);
        psbt.inputs[0].final_script_witness = Some(btc::Witness::p2tr_key_spend(&signature));
        let signed_psbt = psbt.serialize();
        let raw_tx = consensus::serialize(&psbt.extract_tx_unchecked_fee_rate());
        Ok((signed_psbt, raw_tx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };

    fn fixture() -> (Spend, [u8; 32], btc::secp256k1::Keypair) {
        let secp = btc::secp256k1::Secp256k1::new();
        let secret = btc::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
        let keypair = btc::secp256k1::Keypair::from_secret_key(&secp, &secret);
        let public = keypair.x_only_public_key().0.serialize();
        let mut owner_script = vec![0x51, 0x20];
        owner_script.extend_from_slice(&public);
        let previous_output = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(owner_script),
        };
        let previous = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![previous_output.clone()],
        };
        let recipient = Output {
            value_sats: 99_000,
            script_pubkey: vec![0x51, 0x20].into_iter().chain([9; 32]).collect(),
        };
        let unsigned = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: previous.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(recipient.value_sats),
                script_pubkey: ScriptBuf::from_bytes(recipient.script_pubkey.clone()),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(previous);
        psbt.inputs[0].witness_utxo = Some(previous_output);
        (
            Spend {
                network: crate::bitcoin::Network::Testnet,
                psbt: psbt.serialize(),
                outputs: vec![recipient],
                max_fee_sats: 1_000,
                max_fee_rate_sat_vb: 10,
            },
            public,
            keypair,
        )
    }

    #[test]
    fn signs_only_exact_owned_psbt_and_enforces_fee() {
        let (spend, public, keypair) = fixture();
        let digest = spend.sighash(&public).unwrap();
        let secp = btc::secp256k1::Secp256k1::new();
        let sig =
            secp.sign_schnorr_no_aux_rand(&btc::secp256k1::Message::from_digest(digest), &keypair);
        let (signed_psbt, raw_tx) = spend.signed(&public, sig.as_ref()).unwrap();
        let parsed = Psbt::deserialize(&signed_psbt).unwrap();
        assert!(parsed.inputs[0].tap_key_sig.is_some());
        let transaction: Transaction = consensus::deserialize(&raw_tx).unwrap();
        assert_eq!(transaction.input[0].witness.len(), 1);

        let mut changed = spend.clone();
        changed.outputs[0].value_sats -= 1;
        assert!(changed.sighash(&public).is_err());
        let mut changed = spend.clone();
        changed.max_fee_sats = 999;
        assert!(changed.sighash(&public).is_err());
        let mut changed = spend.clone();
        changed.max_fee_rate_sat_vb = 1;
        assert!(changed.sighash(&public).is_err());
        let mut changed = spend.clone();
        let mut psbt = Psbt::deserialize(&changed.psbt).unwrap();
        psbt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(101_000);
        changed.psbt = psbt.serialize();
        assert!(changed.sighash(&public).is_err());
        let mut changed = spend.clone();
        let mut psbt = Psbt::deserialize(&changed.psbt).unwrap();
        psbt.inputs[0].sighash_type = Some(btc::psbt::PsbtSighashType::from_u32(0x81));
        changed.psbt = psbt.serialize();
        assert!(changed.sighash(&public).is_err());
        let mut changed = spend.clone();
        let mut psbt = Psbt::deserialize(&changed.psbt).unwrap();
        psbt.unsigned_tx
            .input
            .push(psbt.unsigned_tx.input[0].clone());
        psbt.inputs.push(psbt.inputs[0].clone());
        changed.psbt = psbt.serialize();
        assert!(changed.sighash(&public).is_err());
        assert!(spend.sighash(&[8; 32]).is_err());
    }
}
