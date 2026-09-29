mod support;
use ed25519_dalek::SigningKey;
use pair_registry::{NamespaceRecord, PolicyRecord, SessionRecord};
use pairkey_core::{
    authorize, operation, prepare, Error, Freshness, Observation, ObservedAccount, Trust,
};
use pairkey_types::{policy::*, Attempt, Commit};
use solana_sdk::{hash::Hash, message::Message, pubkey::Pubkey, system_instruction};

fn session_fixture() -> (
    Trust,
    Observation,
    Attempt,
    Vec<u8>,
    SessionGrant,
    SigningKey,
) {
    let (trust, mut o, mut at, _) = support::fixture();
    let ns: NamespaceRecord = borsh::from_slice(&o.namespace.data).unwrap();
    let mut path = at.commit.account.clone();
    path.destination = operation::destination(trust.network);
    let derived = pairkey_sdk::derived_address(&ns.registration, &path).unwrap();
    let recipient = Pubkey::new_unique();
    let bytes = Message::new_with_blockhash(
        &[system_instruction::transfer(&derived, &recipient, 10)],
        Some(&derived),
        &Hash::new_unique(),
    )
    .serialize();
    at.commit = Commit::new(&ns.registration, [7; 32], path.clone(), &bytes).unwrap();
    let key = SigningKey::from_bytes(&[43; 32]);
    let grant = SessionGrant {
        session_id: [61; 32],
        policy_version: 1,
        account: path,
        credential: Credential::Service {
            public_key: key.verifying_key().to_bytes(),
        },
        not_before: 990,
        expires_at: 1020,
        recipient: recipient.to_bytes(),
        max_lamports_per_operation: 10,
        cumulative_budget: None,
    };
    let policy = Policy {
        version: 1,
        allow_session: true,
        require_commit: false,
        require_session: true,
        access: None,
        simulation: None,
    };
    o.policy = Some(ObservedAccount {
        address: pair_registry::policy_address(&trust.registry, &o.namespace.address).0,
        owner: trust.registry,
        data: borsh::to_vec(&PolicyRecord {
            namespace_address: o.namespace.address.to_bytes(),
            policy,
        })
        .unwrap(),
    });
    o.session = Some(ObservedAccount {
        address: pair_registry::session_address(
            &trust.registry,
            &o.namespace.address,
            &grant.session_id,
        )
        .0,
        owner: trust.registry,
        data: borsh::to_vec(&SessionRecord {
            namespace_address: o.namespace.address.to_bytes(),
            grant: grant.clone(),
            revoked: false,
        })
        .unwrap(),
    });
    at.authorization = Authorization {
        policy_version: 1,
        session_id: Some(grant.session_id),
        ..Default::default()
    };
    at.authorization.session_proof = Some(pairkey_sdk::policy::service_proof(
        &key,
        pairkey_sdk::policy::session_challenge(&at.authorization, &at.commit, &grant),
    ));
    // No on-chain per-operation COMMIT exists for the SESSION flow.
    o.request.data.clear();
    (trust, o, at, bytes, grant, key)
}
fn update_policy(o: &mut Observation, change: impl FnOnce(&mut Policy)) {
    let info = o.policy.as_mut().unwrap();
    let mut record: PolicyRecord = borsh::from_slice(&info.data).unwrap();
    change(&mut record.policy);
    info.data = borsh::to_vec(&record).unwrap();
}
#[test]
fn session_authorizes_native_operation_without_commit_but_refuses_payload_and_scope_changes() {
    let (t, o, at, bytes, grant, key) = session_fixture();
    authorize(&t, &o, &at, &bytes, 1000, 100).unwrap();
    assert!(authorize(&t, &o, &at, b"arbitrary digest", 1000, 100).is_err());
    let ns: NamespaceRecord = borsh::from_slice(&o.namespace.data).unwrap();
    let derived = pairkey_sdk::derived_address(&ns.registration, &at.commit.account).unwrap();
    for (recipient, lamports, extra) in [
        (Pubkey::new_unique(), 10, false),
        (
            Pubkey::new_from_array(
                o.session
                    .as_ref()
                    .map(|x| {
                        borsh::from_slice::<SessionRecord>(&x.data)
                            .unwrap()
                            .grant
                            .recipient
                    })
                    .unwrap(),
            ),
            11,
            false,
        ),
        (Pubkey::new_unique(), 1, true),
    ] {
        let mut instructions = vec![system_instruction::transfer(&derived, &recipient, lamports)];
        if extra {
            instructions.push(system_instruction::transfer(&derived, &recipient, 1));
        }
        let changed =
            Message::new_with_blockhash(&instructions, Some(&derived), &Hash::new_unique())
                .serialize();
        let mut attempt = at.clone();
        attempt.commit = Commit::new(
            &ns.registration,
            [7; 32],
            at.commit.account.clone(),
            &changed,
        )
        .unwrap();
        attempt.authorization.session_proof = Some(pairkey_sdk::policy::service_proof(
            &key,
            pairkey_sdk::policy::session_challenge(&attempt.authorization, &attempt.commit, &grant),
        ));
        assert!(authorize(&t, &o, &attempt, &changed, 1000, 100).is_err());
    }
    let mut forged = at.clone();
    forged.authorization.session_proof = Some(AccessProof::Service {
        signature: vec![0; 64],
    });
    assert!(authorize(&t, &o, &forged, &bytes, 1000, 100).is_err());
    assert_ne!(at.digest(), forged.digest());
}
#[test]
fn revoked_expired_future_wrong_version_wrong_account_sessions_fail_closed() {
    let (t, mut o, mut at, bytes, _, _) = session_fixture();
    assert!(authorize(&t, &o, &at, &bytes, 1020, 100).is_err());
    assert!(authorize(&t, &o, &at, &bytes, 989, 100).is_err());
    at.authorization.policy_version = 0;
    assert!(authorize(&t, &o, &at, &bytes, 1000, 100).is_err());
    at.authorization.policy_version = 1;
    let original = o.session.clone();
    o.session.as_mut().unwrap().owner = Pubkey::new_unique();
    assert!(authorize(&t, &o, &at, &bytes, 1000, 100).is_err());
    o.session = original;
    let info = o.session.as_mut().unwrap();
    let mut record: SessionRecord = borsh::from_slice(&info.data).unwrap();
    record.revoked = true;
    info.data = borsh::to_vec(&record).unwrap();
    assert!(matches!(
        authorize(&t, &o, &at, &bytes, 1000, 100),
        Err(Error::Inactive)
    ));
}
#[test]
fn registered_policy_prevents_commit_session_or_access_downgrades() {
    let (t, mut o, at, bytes, _, _) = session_fixture();
    update_policy(&mut o, |p| p.require_commit = true);
    assert!(authorize(&t, &o, &at, &bytes, 1000, 100).is_err());
    let ns: NamespaceRecord = borsh::from_slice(&o.namespace.data).unwrap();
    o.request.data = borsh::to_vec(&pair_registry::RequestRecord {
        namespace_address: o.namespace.address.to_bytes(),
        commit: at.commit.clone(),
        derived_key: pairkey_sdk::derive_public(&ns.registration, &at.commit.account).unwrap(),
    })
    .unwrap();
    authorize(&t, &o, &at, &bytes, 1000, 100).unwrap();
    let mut downgraded = at.clone();
    downgraded.authorization.session_id = None;
    downgraded.authorization.session_proof = None;
    assert!(authorize(&t, &o, &downgraded, &bytes, 1000, 100).is_err());
    update_policy(&mut o, |p| p.version = 2);
    assert!(authorize(&t, &o, &at, &bytes, 1000, 100).is_err());
}
#[test]
fn access_credential_is_separate_from_delegate_and_controller_authority() {
    let (t, mut o, mut at, bytes, _, delegate) = session_fixture();
    let access = SigningKey::from_bytes(&[51; 32]);
    update_policy(&mut o, |p| {
        p.access = Some(Credential::Service {
            public_key: access.verifying_key().to_bytes(),
        })
    });
    assert!(authorize(&t, &o, &at, &bytes, 1000, 100).is_err());
    at.authorization.access_proof = Some(pairkey_sdk::policy::service_proof(
        &delegate,
        pairkey_sdk::policy::access_challenge(&at.authorization, &at.commit),
    ));
    assert!(authorize(&t, &o, &at, &bytes, 1000, 100).is_err());
    at.authorization.access_proof = Some(pairkey_sdk::policy::service_proof(
        &access,
        pairkey_sdk::policy::access_challenge(&at.authorization, &at.commit),
    ));
    authorize(&t, &o, &at, &bytes, 1000, 100).unwrap();
    at.commit.request_id[0] ^= 1;
    assert!(authorize(&t, &o, &at, &bytes, 1000, 100).is_err());
}
#[test]
fn passkey_requires_exact_challenge_rp_origin_up_uv_and_cryptographic_signature() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::signature::Signer;
    use sha2::{Digest, Sha256};
    let key = p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let credential = Credential::Passkey {
        public_key: key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        rp_id: "pairkey.example".into(),
        origin: "https://pairkey.example".into(),
    };
    let challenge = [17; 32];
    let client=serde_json::to_vec(&serde_json::json!({"type":"webauthn.get","challenge":URL_SAFE_NO_PAD.encode(challenge),"origin":"https://pairkey.example","crossOrigin":false})).unwrap();
    let mut authenticator = Sha256::digest(b"pairkey.example").to_vec();
    authenticator.push(5);
    authenticator.extend_from_slice(&0u32.to_be_bytes());
    let mut signed = authenticator.clone();
    signed.extend_from_slice(&Sha256::digest(&client));
    let sig: p256::ecdsa::Signature = key.sign(&signed);
    let proof = AccessProof::Passkey {
        authenticator_data: authenticator,
        client_data_json: client,
        signature_der: sig.to_der().as_bytes().to_vec(),
    };
    pairkey_core::access::verify(&credential, &proof, challenge).unwrap();
    assert!(pairkey_core::access::verify(&credential, &proof, [18; 32]).is_err());
    for flag in [1, 4, 0, 0x85, 0x45, 0x15] {
        let mut changed = proof.clone();
        if let AccessProof::Passkey {
            authenticator_data, ..
        } = &mut changed
        {
            authenticator_data[32] = flag;
        }
        assert!(pairkey_core::access::verify(&credential, &changed, challenge).is_err());
    }
    let other = Credential::Passkey {
        public_key: key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        rp_id: "evil.example".into(),
        origin: "https://evil.example".into(),
    };
    assert!(pairkey_core::access::verify(&other, &proof, challenge).is_err());
}
#[test]
fn simulation_is_mandatory_and_binds_exact_input_code_state_and_return_program() {
    let (t, mut o, at, bytes, _, _) = session_fixture();
    let code = vec![1, 2, 3];
    let program = Pubkey::new_unique();
    update_policy(&mut o, |p| {
        p.simulation = Some(SimulationConfig {
            program: program.to_bytes(),
            code_hash: pairkey_core::code_hash(&code),
            max_lamports: 10,
        })
    });
    prepare(&t, &o, &at, &bytes, 1000, 100).unwrap();
    assert!(authorize(&t, &o, &at, &bytes, 1000, 100).is_err());
    let input = pairkey_core::simulation_input(&o, &at, &bytes)
        .unwrap()
        .unwrap();
    o.simulation = Some(pairkey_core::SimulationObservation {
        slot: o.slot,
        program: pairkey_core::ExecutableObservation {
            program,
            owner: solana_sdk::bpf_loader::id(),
            executable: true,
            code,
            program_data: None,
        },
        output: SimulationOutput {
            input_digest: input.digest(),
            allowed: true,
        },
    });
    authorize(&t, &o, &at, &bytes, 1000, 100).unwrap();
    o.simulation.as_mut().unwrap().program.owner = solana_sdk::bpf_loader_upgradeable::id();
    assert!(authorize(&t, &o, &at, &bytes, 1000, 100).is_err());
    o.simulation.as_mut().unwrap().program.owner = solana_sdk::bpf_loader::id();
    o.simulation.as_mut().unwrap().output.input_digest[0] ^= 1;
    assert!(authorize(&t, &o, &at, &bytes, 1000, 100).is_err());
}
#[test]
fn stalled_slot_cannot_renew_freshness_and_budget_promises_are_rejected() {
    let freshness = Freshness::default();
    freshness.check(100, 999, 0, 3000).unwrap();
    freshness.check(100, 999, 2999, 3000).unwrap();
    freshness.check(99, 998, 2999, 3000).unwrap();
    assert!(freshness.check(100, 999, 3000, 3000).is_err());
    assert!(freshness.check(100, 1000, 2999, 3000).is_err());
    assert!(freshness.check(99, 999, 3001, 3000).is_err());
    freshness.check(101, 1000, 3001, 3000).unwrap();
    let (_, _, _, _, mut grant, _) = session_fixture();
    grant.cumulative_budget = Some(100);
    assert!(grant.validate().is_err());
}

#[test]
fn immutable_programdata_resolution_rejects_upgrade_authority_wrong_pda_and_pointer_only_pins() {
    use solana_sdk::bpf_loader_upgradeable::{self, UpgradeableLoaderState};
    let program = Pubkey::new_unique();
    let address =
        Pubkey::find_program_address(&[program.as_ref()], &bpf_loader_upgradeable::id()).0;
    let pointer = bincode::serialize(&UpgradeableLoaderState::Program {
        programdata_address: address,
    })
    .unwrap();
    let mut bytes = bincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 1,
        upgrade_authority_address: None,
    })
    .unwrap();
    bytes.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
    bytes.extend_from_slice(&[1, 2, 3]);
    let mut executable = pairkey_core::ExecutableObservation {
        program,
        owner: bpf_loader_upgradeable::id(),
        executable: true,
        code: pointer.clone(),
        program_data: Some(ObservedAccount {
            address,
            owner: bpf_loader_upgradeable::id(),
            data: bytes.clone(),
        }),
    };
    assert_eq!(executable.hash().unwrap(), pairkey_core::code_hash(&bytes));
    assert_ne!(
        executable.hash().unwrap(),
        pairkey_core::code_hash(&pointer)
    );
    executable.program_data.as_mut().unwrap().address = Pubkey::new_unique();
    assert!(executable.hash().is_err());
    executable.program_data.as_mut().unwrap().address = address;
    let mut mutable = bincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 1,
        upgrade_authority_address: Some(Pubkey::new_unique()),
    })
    .unwrap();
    mutable.extend_from_slice(&[1, 2, 3]);
    executable.program_data.as_mut().unwrap().data = mutable;
    assert!(executable.hash().is_err());
    executable.program_data = None;
    assert!(executable.hash().is_err());
}
