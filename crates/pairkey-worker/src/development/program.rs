//! Each worker constructs and authenticates its own read-only RPC simulation.
use super::*;
use pairkey_core::approval::program::{self, ProgramObservation};
use pairkey_types::{approval::Approval, program_approval::AccountState, Registration};
impl Worker {
    pub(super) async fn evaluate_program(
        &self,
        reg: &Registration,
        approval: &Approval,
        payload: &[u8],
        observation: &Observation,
        states: Vec<AccountState>,
    ) -> anyhow::Result<ProgramObservation> {
        let (source, _) = program::source_and_caller(approval)?;
        let program = Pubkey::new_from_array(source.program);
        let code = self.rpc.executable(program, observation.slot).await?;
        ensure!(
            code.hash()? == source.code_hash,
            "program code does not match caller-approved code"
        );
        let input = program::input(reg, approval, payload, &states)?;
        let signature = {
            let release = self.release.lock().unwrap();
            ensure!(!release.incident, "worker incident");
            release.controls.check_active(observation.slot)?;
            self.channel
                .sign_public(&input.attestation_message())
                .as_slice()
                .try_into()?
        };
        let mut tx = pairkey_sdk::program_approval::simulation_transaction(
            program,
            Pubkey::new_from_array(self.channel.identity()),
            self.trust.enclave_set,
            &source.accounts,
            self.channel.identity(),
            signature,
            &input,
        )?;
        let hash = self
            .rpc
            .call(
                "getLatestBlockhash",
                json!([{"commitment":"finalized","minContextSlot":observation.slot}]),
            )
            .await?;
        tx.message.recent_blockhash = hash["value"]["blockhash"]
            .as_str()
            .context("simulation blockhash")?
            .parse()?;
        tx.signatures[0] = solana_sdk::signature::Signature::from(<[u8; 64]>::try_from(
            self.channel.sign_public(&tx.message.serialize()).as_slice(),
        )?);
        let result=self.rpc.call("simulateTransaction",json!([STANDARD.encode(bincode::serialize(&tx)?),
            {"encoding":"base64","commitment":"finalized","minContextSlot":observation.slot,"replaceRecentBlockhash":false,"sigVerify":true}])).await?;
        ensure!(
            result["value"].get("err") == Some(&Value::Null),
            "program evaluation failed: {}",
            result["value"]["err"]
        );
        let returned = &result["value"]["returnData"];
        ensure!(
            returned["programId"].as_str() == Some(&program.to_string())
                && returned["data"][1] == "base64",
            "program evaluation return context"
        );
        let output = borsh::from_slice(
            &STANDARD.decode(returned["data"][0].as_str().context("program decision")?)?,
        )?;
        Ok(ProgramObservation::Evaluated {
            slot: result["context"]["slot"]
                .as_u64()
                .context("simulation slot")?,
            code: Box::new(code),
            states,
            input: Box::new(input),
            output,
        })
    }
    pub(super) fn record_program(
        &self,
        reg: &Registration,
        approval: &Approval,
        payload: &[u8],
        observation: &Observation,
        program: &ProgramObservation,
    ) -> anyhow::Result<()> {
        let allowed = program::decision(&self.trust, observation, reg, approval, payload, program)?;
        if let ProgramObservation::Evaluated { slot, input, .. } = program {
            let source = program::source_and_caller(approval)?.0;
            let key = program::fence_key(reg, source);
            let _release = self.release.lock().unwrap();
            let mut store = self.offchain.store.lock().unwrap();
            // Rejected callers cannot fill storage with new state fences. A verified
            // denial for a known context still invalidates an older prepared release.
            if allowed || store.program_slot(key)?.is_some() {
                store.observe_program(key, input.state_digest, *slot, now())?;
            }
        }
        Ok(())
    }
}
