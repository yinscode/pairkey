use pairkey_signing::{evm, hex, redpallas, Intent, Payload, Suite};
use pairkey_types::{AccountPath, Attempt, Commit, Namespace, Role, Scheme};
fn reg() -> pairkey_types::Registration {
    let ns = Namespace {
        version: 1,
        scheme: Scheme::FrostEd25519,
        network: [1; 32],
        registry: [2; 32],
        derivation_authority: [3; 32],
        namespace_id: [4; 32],
        enclave_set: [5; 32],
    };
    let a = pairkey_frost::prove(
        &pairkey_frost::Root::new([7; 32]),
        &ns,
        Role::A,
        &mut rand_core::OsRng,
    )
    .unwrap();
    let b = pairkey_frost::prove(
        &pairkey_frost::Root::new([8; 32]),
        &ns,
        Role::B,
        &mut rand_core::OsRng,
    )
    .unwrap();
    pairkey_frost::register(ns, &a, &b).unwrap()
}
#[test]
fn canonical_eip155_vector_and_network_separation() {
    let mut tx = evm::Transfer {
        chain_id: 1,
        nonce: 9,
        gas_price: 20_000_000_000,
        gas_limit: 21000,
        to: [0x35; 20],
        value: 1_000_000_000_000_000_000,
    };
    assert_eq!(hex(&tx.signing_bytes().unwrap()),"ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080");
    assert_eq!(
        hex(&tx.prehash().unwrap()),
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    );
    let key = k256::ecdsa::SigningKey::from_bytes(&[0x46; 32].into()).unwrap();
    let (s, r) = key
        .sign_prehash_recoverable(&tx.prehash().unwrap())
        .unwrap();
    let mut sig = s.to_bytes().to_vec();
    sig.push(r.to_byte());
    let public = key.verifying_key().to_encoded_point(true);
    assert_eq!(hex(&tx.signed_bytes(public.as_bytes(),&sig).unwrap()),"f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83");
    tx.chain_id = 2;
    assert!(evm::verify(public.as_bytes(), &tx, &sig).is_err());
}
#[test]
fn redpallas_two_party_signature_verifies_with_native_reddsa_and_binds_approval() {
    let reg = reg();
    let path = AccountPath {
        destination: [9; 32],
        path: vec![7, 3],
    };
    let public = redpallas::Public {
        proofs: [
            redpallas::proof(&[11; 32], &reg, &path, Role::A).unwrap(),
            redpallas::proof(&[12; 32], &reg, &path, Role::B).unwrap(),
        ],
    };
    let key = public.key(&reg, &path).unwrap();
    let message = b"PairKey RedPallas";
    let (a, pa) =
        redpallas::Pending::begin(&[11; 32], &reg, &path, &public, Role::A, message).unwrap();
    let (b, pb) =
        redpallas::Pending::begin(&[12; 32], &reg, &path, &public, Role::B, message).unwrap();
    let rounds = [a, b];
    let shares = [pa.finish(&rounds).unwrap(), pb.finish(&rounds).unwrap()];
    let sig = redpallas::aggregate(&reg, &path, &public, message, &rounds, &shares).unwrap();
    redpallas::verify(&key.public_key, message, &sig).unwrap();
    assert!(redpallas::verify(&key.public_key, b"changed", &sig).is_err());
    let intent = Intent {
        version: 1,
        key,
        payload: Payload::RedPallas {
            message: message.to_vec(),
        },
    };
    let commit = Commit::new(&reg, [17; 32], path.clone(), &intent.bytes().unwrap()).unwrap();
    let request = pairkey_signing::wire::SignRequest {
        protocol: pairkey_signing::wire::PROTOCOL_VERSION,
        registration: reg.clone(),
        attempt: Attempt {
            commit,
            random_id: [18; 32],
            authorization: Default::default(),
        },
        intent,
        certificate: pairkey_signing::wire::Certificate::RedPallas(public.clone()),
    };
    request.validate().unwrap();
    let mut old = request.clone();
    old.protocol = 1;
    assert!(old.validate().is_err());
    let mut missing = serde_json::to_value(&request).unwrap();
    missing.as_object_mut().unwrap().remove("protocol");
    assert!(serde_json::from_value::<pairkey_signing::wire::SignRequest>(missing).is_err());
    let mut wrong = request.clone();
    wrong.intent.key.suite = Suite::Dkls23Secp256k1;
    assert!(wrong.validate().is_err());
    let mut wrong = request.clone();
    wrong.intent.key.account.path.push(1);
    assert!(wrong.validate().is_err());
    let changed = redpallas::Public {
        proofs: [
            redpallas::proof(&[11; 32], &reg, &path, Role::A).unwrap(),
            redpallas::proof(&[12; 32], &reg, &path, Role::B).unwrap(),
        ],
    };
    assert_eq!(
        changed.key(&reg, &path).unwrap(),
        public.key(&reg, &path).unwrap()
    );
    assert!(redpallas::Pending::begin(&[99; 32], &reg, &path, &public, Role::A, message).is_err());
    let mut bad = public.clone();
    bad.proofs[0].response[0] ^= 1;
    assert!(bad.key(&reg, &path).is_err());
}

#[test]
fn arbitrum_estimated_gas_signature_binds_network_nonce_and_fee() {
    let tx = evm::Transfer {
        chain_id: 421_614,
        nonce: 8,
        gas_price: 10_000_000,
        gas_limit: 120_000,
        to: [3; 20],
        value: 500,
    };
    let key = k256::ecdsa::SigningKey::from_bytes(&[0x47; 32].into()).unwrap();
    let (sig, recovery) = key
        .sign_prehash_recoverable(&tx.prehash().unwrap())
        .unwrap();
    let mut bytes = sig.to_bytes().to_vec();
    bytes.push(recovery.to_byte());
    let public = key.verifying_key().to_encoded_point(true);
    let encoded = tx.signed_bytes(public.as_bytes(), &bytes).unwrap();
    let rlp = rlp::Rlp::new(&encoded);
    assert_eq!(rlp.val_at::<u64>(2).unwrap(), 120_000);
    assert_eq!(
        rlp.val_at::<u64>(6).unwrap(),
        421_614 * 2 + 35 + recovery.to_byte() as u64
    );
    for field in 0..3 {
        let mut changed = tx.clone();
        match field {
            0 => changed.gas_limit += 1,
            1 => changed.nonce += 1,
            _ => changed.gas_price += 1,
        }
        assert!(changed.signed_bytes(public.as_bytes(), &bytes).is_err());
    }
}

#[test]
fn base_sepolia_native_transfer_cannot_replay_on_arbitrum_or_base_mainnet() {
    let mut tx = evm::Transfer {
        chain_id: 84_532,
        nonce: 0,
        gas_price: 10_000_000,
        gas_limit: 21_000,
        to: [4; 20],
        value: 5_000_000_000_000,
    };
    let key = k256::ecdsa::SigningKey::from_bytes(&[0x48; 32].into()).unwrap();
    let (s, r) = key
        .sign_prehash_recoverable(&tx.prehash().unwrap())
        .unwrap();
    let mut sig = s.to_bytes().to_vec();
    sig.push(r.to_byte());
    let public = key.verifying_key().to_encoded_point(true);
    assert!(tx.signed_bytes(public.as_bytes(), &sig).is_ok());
    for other in [421_614, 8453] {
        tx.chain_id = other;
        assert!(tx.signed_bytes(public.as_bytes(), &sig).is_err());
        assert_ne!(evm::destination(84_532), evm::destination(other));
    }
    tx.chain_id = 84_532;
    tx.gas_limit = 25_200;
    assert!(tx.validate().is_err());
}

#[test]
fn evm_message_intent_binds_destination_and_exact_approval() {
    let reg = reg();
    let account = AccountPath {
        destination: evm::destination(84532),
        path: vec![7, 4],
    };
    let secret = k256::ecdsa::SigningKey::from_bytes(&[0x46; 32].into()).unwrap();
    let mut intent = Intent {
        version: 1,
        key: pairkey_signing::Key {
            version: 1,
            suite: Suite::Dkls23Secp256k1,
            namespace: reg.digest(),
            account: account.clone(),
            public_key: secret
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            registration: [0; 32],
        },
        payload: Payload::EvmMessage(pairkey_signing::evm_message::Message {
            chain_id: 84532,
            message: b"approved message".to_vec(),
        }),
    };
    intent.validate(&reg).unwrap();
    let approved = intent.bytes().unwrap();
    let commit = Commit::new(&reg, [17; 32], account, &approved).unwrap();
    assert_eq!(Intent::from_bytes(&approved).unwrap(), intent);
    if let Payload::EvmMessage(m) = &mut intent.payload {
        m.message.push(b'!');
    }
    assert_ne!(
        Commit::new(
            &reg,
            [17; 32],
            intent.key.account.clone(),
            &intent.bytes().unwrap()
        )
        .unwrap(),
        commit
    );
    if let Payload::EvmMessage(m) = &mut intent.payload {
        m.chain_id = 1;
    }
    assert!(intent.validate(&reg).is_err());
}
