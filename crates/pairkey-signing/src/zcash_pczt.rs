//! Version-6 Ironwood PCZT validation and signature insertion.
//!
//! This module is deliberately separate from the hosted signing protocol. A
//! caller may not sign its returned digest until the PCZT attachment, viewing
//! key, output policy, and enrollment have all been approved by both workers.
use anyhow::{anyhow, ensure, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use group14::ff::PrimeField;
use orchard::{keys::FullViewingKey, note::NoteVersion, value::Sign};
use pczt::roles::{
    signer::{Signer, SpendAuthSignature},
    verifier::{OrchardError, Verifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_PCZT_BYTES: usize = 256 * 1024;
const IRONWOOD_BRANCH_ID: u32 = 0x37a5_165b;
const V6_VERSION_GROUP_ID: u32 = 0xd884_b698;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 133,
            Self::Testnet => 1,
        }
    }

    pub fn activation_height(self) -> u32 {
        match self {
            Self::Mainnet => 3_428_143,
            Self::Testnet => 4_134_000,
        }
    }
}

/// Fields small enough for an exact Solana COMMIT. The PCZT is an attachment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct Spend {
    pub network: Network,
    pub pczt_hash: [u8; 32],
    pub pczt_len: u32,
    pub fvk: Vec<u8>,
    pub recipient: Vec<u8>,
    pub output_value_zats: u64,
    pub max_fee_zats: u64,
    pub expiry_height: u32,
}

pub fn commitment(pczt_bytes: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        !pczt_bytes.is_empty() && pczt_bytes.len() <= MAX_PCZT_BYTES,
        "PCZT size"
    );
    let mut h = Sha256::new();
    h.update(b"pairkey/zcash/ironwood-pczt/v1\0");
    h.update((pczt_bytes.len() as u32).to_le_bytes());
    h.update(pczt_bytes);
    Ok(h.finalize().into())
}

impl Spend {
    fn pczt(&self, pczt_bytes: &[u8], public: &[u8]) -> Result<(pczt::Pczt, [u8; 32])> {
        ensure!(
            self.network == Network::Testnet,
            "mainnet Ironwood enrollment unavailable"
        );
        ensure!(
            self.pczt_len as usize == pczt_bytes.len(),
            "PCZT length mismatch"
        );
        ensure!(
            self.pczt_hash == commitment(pczt_bytes)?,
            "PCZT commitment mismatch"
        );
        ensure!(
            pczt_bytes.starts_with(b"PCZT\x02\0\0\0"),
            "PCZT v2 required"
        );
        ensure!(public.len() == 32, "RedPallas public key length");
        ensure!(self.output_value_zats > 0, "empty output");
        ensure!(self.max_fee_zats > 0, "fee limit required");
        ensure!(
            self.expiry_height >= self.network.activation_height(),
            "expiry predates Ironwood"
        );
        let fvk_bytes: &[u8; 96] = self
            .fvk
            .as_slice()
            .try_into()
            .context("full viewing key length")?;
        ensure!(self.recipient.len() == 43, "recipient length");
        let fvk = FullViewingKey::from_bytes(fvk_bytes).context("invalid full viewing key")?;
        // Orchard ak has even Y. The registered threshold key may need to be
        // negated as part of the distinct Orchard enrollment/signing flow.
        let expected_ak = crate::redpallas::orchard_ak(public)?;
        ensure!(
            fvk.to_bytes()[..32] == expected_ak,
            "viewing key does not match PairKey spend key"
        );
        let p = pczt::Pczt::parse(pczt_bytes).context("invalid PCZT")?;
        let g = p.global();
        ensure!(
            *g.tx_version() == 6 && *g.version_group_id() == V6_VERSION_GROUP_ID,
            "transaction version 6 required"
        );
        ensure!(
            *g.consensus_branch_id() == IRONWOOD_BRANCH_ID,
            "NU6.3 consensus branch required"
        );
        ensure!(
            *g.coin_type() == self.network.coin_type(),
            "Zcash network mismatch"
        );
        ensure!(*g.expiry_height() == self.expiry_height, "expiry mismatch");
        ensure!(
            p.transparent().inputs().is_empty() && p.transparent().outputs().is_empty(),
            "transparent bundle unsupported"
        );
        ensure!(
            p.sapling().spends().is_empty() && p.sapling().outputs().is_empty(),
            "Sapling bundle unsupported"
        );
        ensure!(p.orchard().actions().is_empty(), "Orchard pool unsupported");
        ensure!(
            p.ironwood().actions().len() == 1,
            "one Ironwood action required"
        );
        let mut alpha_bytes = None;
        Verifier::new(p.clone())
            .with_ironwood::<anyhow::Error, _>(|bundle| {
                macro_rules! check {
                    ($condition:expr, $message:expr) => {
                        if !$condition {
                            return Err(OrchardError::Custom(anyhow!($message)));
                        }
                    };
                }
                let action = &bundle.actions()[0];
                let spend = action.spend();
                let output = action.output();
                check!(
                    spend.dummy_sk().is_none() && spend.spend_auth_sig().is_none(),
                    "dummy or already signed spend"
                );
                check!(
                    spend.value().is_some_and(|v| v.inner() > 0),
                    "real spend required"
                );
                check!(
                    spend.fvk().as_ref() == Some(&fvk),
                    "PCZT viewing key mismatch"
                );
                spend.verify_nullifier(Some(&fvk))?;
                spend.verify_rk(Some(&fvk))?;
                alpha_bytes = spend.alpha().as_ref().map(|alpha| alpha.to_repr());
                action.verify_cv_net()?;
                output.verify_note_commitment(spend)?;
                bundle.verify_cross_address_restriction()?;
                check!(
                    *output.note_version() == NoteVersion::V3,
                    "Ironwood v3 note format required"
                );
                check!(output.user_address().is_none(), "unverified user address");
                let recipient = output
                    .recipient()
                    .as_ref()
                    .ok_or_else(|| OrchardError::Custom(anyhow!("missing output recipient")))?;
                check!(
                    recipient.to_raw_address_bytes() == self.recipient.as_slice(),
                    "output recipient mismatch"
                );
                check!(
                    output
                        .value()
                        .is_some_and(|v| v.inner() == self.output_value_zats),
                    "output value mismatch"
                );
                let spend_recipient = spend
                    .recipient()
                    .as_ref()
                    .ok_or_else(|| OrchardError::Custom(anyhow!("missing spend recipient")))?;
                let scope = fvk.scope_for_address(spend_recipient).ok_or_else(|| {
                    OrchardError::Custom(anyhow!("spend address not in viewing key"))
                })?;
                let recovered = action
                    .recover_output_with_ovk(&fvk.to_ovk(scope), *bundle.bundle_version())
                    .map_err(|e| {
                        OrchardError::Custom(anyhow!("unsupported note encryption: {e:?}"))
                    })?
                    .ok_or_else(|| {
                        OrchardError::Custom(anyhow!("output ciphertext not recoverable"))
                    })?;
                check!(
                    recovered.0.recipient() == *recipient
                        && recovered.0.value().inner() == self.output_value_zats
                        && output.rseed().as_ref().map(|r| r.as_bytes())
                            == Some(recovered.0.rseed().as_bytes()),
                    "output ciphertext mismatch"
                );
                let input = spend.value().as_ref().unwrap().inner();
                let fee = input
                    .checked_sub(self.output_value_zats)
                    .ok_or_else(|| OrchardError::Custom(anyhow!("output exceeds input")))?;
                check!(fee <= self.max_fee_zats, "fee limit");
                let (balance, sign) = bundle.value_sum().magnitude_sign();
                check!(
                    matches!(sign, Sign::Positive) && balance == fee,
                    "Ironwood balance mismatch"
                );
                Ok(())
            })
            .map_err(|e| anyhow!("Ironwood verification: {e:?}"))?;
        Ok((p, alpha_bytes.context("missing Ironwood spend randomizer")?))
    }

    /// Returns the exact randomized spend key scalar after checking the PCZT.
    pub fn alpha(&self, pczt_bytes: &[u8], public: &[u8]) -> Result<[u8; 32]> {
        Ok(self.pczt(pczt_bytes, public)?.1)
    }

    pub fn sighash(&self, pczt_bytes: &[u8], public: &[u8]) -> Result<[u8; 32]> {
        Ok(Signer::new(self.pczt(pczt_bytes, public)?.0)
            .map_err(|e| anyhow!("PCZT signer: {e:?}"))?
            .shielded_sighash())
    }

    pub fn signed(&self, pczt_bytes: &[u8], public: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        let mut signer = Signer::new(self.pczt(pczt_bytes, public)?.0)
            .map_err(|e| anyhow!("PCZT signer: {e:?}"))?;
        let signature: [u8; 64] = signature.try_into().context("RedPallas signature length")?;
        signer
            .apply_orchard_spend_auth_signature(&SpendAuthSignature::from_parts(
                orchard::ValuePool::Ironwood,
                0,
                signature,
            ))
            .map_err(|e| anyhow!("PCZT signature: {e:?}"))?;
        Ok(signer
            .finish()
            .serialize()
            .map_err(|e| anyhow!("PCZT encoding: {e:?}"))?)
    }
}
