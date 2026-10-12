//! EIP-712 typed data. The complete JSON is approved; workers parse and hash it.
use alloy_dyn_abi::TypedData as AlloyTypedData;
use anyhow::{ensure, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

fn check_fields(
    types: &serde_json::Value,
    type_name: &str,
    value: &serde_json::Value,
    depth: usize,
) -> Result<()> {
    ensure!(depth <= 16, "typed-data nesting limit");
    if let Some(open) = type_name.rfind('[') {
        ensure!(type_name.ends_with(']'), "typed-data array type");
        let items = value.as_array().context("typed-data array value")?;
        ensure!(items.len() <= 256, "typed-data array bound");
        for item in items {
            check_fields(types, &type_name[..open], item, depth + 1)?;
        }
        return Ok(());
    }
    let Some(definitions) = types.get(type_name) else {
        return Ok(()); // Solidity atomic type; Alloy validates it below.
    };
    let definitions = definitions
        .as_array()
        .context("typed-data type definition")?;
    let object = value.as_object().context("typed-data struct value")?;
    ensure!(
        object.len() == definitions.len(),
        "typed-data struct fields"
    );
    for definition in definitions {
        let name = definition
            .get("name")
            .and_then(|x| x.as_str())
            .context("typed-data field name")?;
        let kind = definition
            .get("type")
            .and_then(|x| x.as_str())
            .context("typed-data field type")?;
        let field = object.get(name).context("typed-data field missing")?;
        check_fields(types, kind, field, depth + 1)?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedData {
    pub chain_id: u64,
    pub json: Vec<u8>,
}

impl TypedData {
    fn parsed(&self) -> Result<AlloyTypedData> {
        ensure!(
            self.chain_id > 0 && self.chain_id <= (u64::MAX - 36) / 2,
            "EVM chain ID bounds"
        );
        ensure!(
            !self.json.is_empty() && self.json.len() <= 1000,
            "typed-data bounds"
        );
        let value: serde_json::Value = serde_json::from_slice(&self.json)?;
        ensure!(value.is_object(), "typed data must be an object");
        ensure!(
            serde_json::to_vec(&value)? == self.json,
            "typed data must use canonical JSON"
        );
        ensure!(
            value.as_object().is_some_and(|map| {
                map.len() == 4
                    && ["types", "primaryType", "domain", "message"]
                        .iter()
                        .all(|key| map.contains_key(*key))
            }),
            "typed-data fields"
        );
        let domain = value.get("domain").context("typed-data domain missing")?;
        let domain = domain
            .as_object()
            .context("typed-data domain must be an object")?;
        let schema = value
            .get("types")
            .and_then(|v| v.get("EIP712Domain"))
            .and_then(|v| v.as_array())
            .context("EIP712Domain type missing")?;
        let expected_domain = [
            ("name", "string"),
            ("version", "string"),
            ("chainId", "uint256"),
            ("verifyingContract", "address"),
            ("salt", "bytes32"),
        ]
        .into_iter()
        .filter(|(name, _)| domain.contains_key(*name))
        .map(|(name, ty)| serde_json::json!({"name":name,"type":ty}))
        .collect::<Vec<_>>();
        ensure!(*schema == expected_domain, "EIP712Domain schema mismatch");
        ensure!(
            domain.len() == expected_domain.len(),
            "unsupported EIP712Domain field"
        );
        let supplied = domain
            .get("chainId")
            .context("typed-data chainId missing")?;
        let supplied = supplied
            .as_u64()
            .or_else(|| supplied.as_str()?.parse().ok());
        ensure!(
            supplied == Some(self.chain_id),
            "typed-data chainId mismatch"
        );
        ensure!(
            value
                .get("primaryType")
                .and_then(|x| x.as_str())
                .is_some_and(|x| x != "EIP712Domain"),
            "typed-data primary type"
        );
        ensure!(
            value.get("message").is_some_and(|x| x.is_object()),
            "typed-data message"
        );
        check_fields(
            &value["types"],
            value["primaryType"].as_str().unwrap(),
            &value["message"],
            0,
        )?;
        let parsed: AlloyTypedData = serde_json::from_value(value)?;
        ensure!(
            parsed.domain.chain_id.is_some_and(|id| id == self.chain_id),
            "typed-data domain chain mismatch"
        );
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<()> {
        self.prehash()?;
        Ok(())
    }

    pub fn prehash(&self) -> Result<[u8; 32]> {
        Ok(self.parsed()?.eip712_signing_hash()?.into())
    }

    pub fn verify(&self, public: &[u8], signature: &[u8]) -> Result<()> {
        crate::evm::verify_prehash(public, self.prehash()?, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use serde_json::json;

    fn example() -> TypedData {
        TypedData {
            chain_id: 1,
            json: serde_json::to_vec(&json!({
                "types": {
                    "EIP712Domain": [
                        {"name":"name","type":"string"},
                        {"name":"chainId","type":"uint256"},
                        {"name":"verifyingContract","type":"address"}
                    ],
                    "Vote": [{"name":"proposalId","type":"uint256"},{"name":"support","type":"bool"}]
                },
                "primaryType":"Vote",
                "domain":{"name":"Council","chainId":1,"verifyingContract":"0x1111111111111111111111111111111111111111"},
                "message":{"proposalId":"42","support":true}
            })).unwrap(),
        }
    }

    #[test]
    fn signed_data_binds_domain_chain_and_exact_values() {
        let data = example();
        let hash = data.prehash().unwrap();
        let key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let (sig, recovery) = key.sign_prehash_recoverable(&hash).unwrap();
        let mut signature = sig.to_bytes().to_vec();
        signature.push(recovery.to_byte());
        let public = key.verifying_key().to_encoded_point(true);
        data.verify(public.as_bytes(), &signature).unwrap();

        let mut wrong_chain = data.clone();
        wrong_chain.chain_id = 84532;
        assert!(wrong_chain.validate().is_err());
        let mut noncanonical = data.clone();
        noncanonical.json.insert(0, b' ');
        assert!(noncanonical.validate().is_err());
        let mut wrong_schema = data.clone();
        let mut value: serde_json::Value = serde_json::from_slice(&wrong_schema.json).unwrap();
        value["types"]["EIP712Domain"][2]["type"] = json!("bytes32");
        wrong_schema.json = serde_json::to_vec(&value).unwrap();
        assert!(wrong_schema.validate().is_err());
        value = serde_json::from_slice(&data.json).unwrap();
        value["message"]["unexpected"] = json!(true);
        wrong_schema.json = serde_json::to_vec(&value).unwrap();
        assert!(wrong_schema.validate().is_err());
        let mut changed = data.clone();
        let mut value: serde_json::Value = serde_json::from_slice(&changed.json).unwrap();
        value["message"]["proposalId"] = json!(43);
        changed.json = serde_json::to_vec(&value).unwrap();
        assert_ne!(hash, changed.prehash().unwrap());
        assert!(changed.verify(public.as_bytes(), &signature).is_err());
        value["domain"]["verifyingContract"] = json!("0x2222222222222222222222222222222222222222");
        changed.json = serde_json::to_vec(&value).unwrap();
        assert!(changed.verify(public.as_bytes(), &signature).is_err());
    }
}
