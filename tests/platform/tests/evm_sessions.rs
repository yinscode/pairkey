mod support;
use ed25519_dalek::SigningKey;
use pair_registry::{EvmSessionRecord, NamespaceRecord, PolicyRecord};
use pairkey_core::{authorize, Error, Observation, ObservedAccount, Trust};
use pairkey_signing::{evm, Intent, Key, Payload, Suite};
use pairkey_types::{policy::*, AccountPath, Attempt, Commit, Registration};
use solana_sdk::pubkey::Pubkey;
struct Fixture {
    trust: Trust,
    observation: Observation,
    reg: Registration,
    at: Attempt,
    intent: Intent,
    grant: EvmSessionGrant,
    delegate: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let (trust, mut observation, mut at, _) = support::fixture();
        let reg = borsh::from_slice::<NamespaceRecord>(&observation.namespace.data)
            .unwrap()
            .registration;
        let account = AccountPath {
            destination: evm::destination(31337),
            path: vec![7, 3],
        };
        // A valid public secp256k1 point; these tests isolate policy, not MPC enrollment.
        let public_key = vec![
            2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155,
            252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
        ];
        let key = Key {
            version: 1,
            suite: Suite::Dkls23Secp256k1,
            namespace: reg.digest(),
            account: account.clone(),
            public_key,
            registration: [11; 32],
        };
        let delegate = SigningKey::from_bytes(&[43; 32]);
        let grant = EvmSessionGrant {
            session_id: [61; 32],
            policy_version: 1,
            account,
            key_digest: key.digest(),
            credential: Credential::Service {
                public_key: delegate.verifying_key().to_bytes(),
            },
            not_before: 990,
            expires_at: 1020,
            chain_id: 31337,
            recipient: [42; 20],
            max_value_wei: 100,
            max_gas_price_wei: 10,
            max_fee_wei: 189_000,
            cumulative_budget: None,
        };
        let intent = Intent {
            version: 1,
            key,
            payload: Payload::EvmTransfer(evm::Transfer {
                chain_id: 31337,
                nonce: 0,
                gas_price: 9,
                gas_limit: 21000,
                to: [42; 20],
                value: 100,
            }),
        };
        observation.policy = Some(ObservedAccount {
            address: pair_registry::policy_address(&trust.registry, &observation.namespace.address)
                .0,
            owner: trust.registry,
            data: borsh::to_vec(&PolicyRecord {
                namespace_address: observation.namespace.address.to_bytes(),
                policy: Policy {
                    version: 1,
                    allow_session: true,
                    require_commit: false,
                    require_session: true,
                    access: None,
                    simulation: None,
                },
            })
            .unwrap(),
        });
        observation.request.data.clear();
        at.authorization = Authorization {
            policy_version: 1,
            session_id: Some(grant.session_id),
            ..Default::default()
        };
        let mut f = Self {
            trust,
            observation,
            reg,
            at,
            intent,
            grant,
            delegate,
        };
        f.install();
        f.sign();
        f
    }
    fn install(&mut self) {
        self.observation.session = Some(ObservedAccount {
            address: pair_registry::evm_session_address(
                &self.trust.registry,
                &self.observation.namespace.address,
                &self.grant.session_id,
            )
            .0,
            owner: self.trust.registry,
            data: borsh::to_vec(&EvmSessionRecord {
                namespace_address: self.observation.namespace.address.to_bytes(),
                grant: self.grant.clone(),
                revoked: false,
            })
            .unwrap(),
        });
    }
    fn sign(&mut self) {
        self.at.commit = Commit::new(
            &self.reg,
            [7; 32],
            self.intent.key.account.clone(),
            &self.intent.bytes().unwrap(),
        )
        .unwrap();
        self.at.authorization.session_proof = Some(pairkey_sdk::policy::service_proof(
            &self.delegate,
            evm_session_challenge(&self.at.authorization, &self.at.commit, &self.grant),
        ));
    }
    fn check(&self, now: i64) -> Result<Registration, Error> {
        authorize(
            &self.trust,
            &self.observation,
            &self.at,
            &self.intent.bytes().unwrap(),
            now,
            100,
        )
    }
    fn policy(&mut self, change: impl FnOnce(&mut Policy)) {
        let info = self.observation.policy.as_mut().unwrap();
        let mut p: PolicyRecord = borsh::from_slice(&info.data).unwrap();
        change(&mut p.policy);
        info.data = borsh::to_vec(&p).unwrap();
    }
}
#[test]
fn evm_session_scopes_are_checked_even_with_a_valid_delegate_signature() {
    Fixture::new().check(1000).unwrap();
    for case in 0..10 {
        let mut f = Fixture::new();
        let Payload::EvmTransfer(tx) = &mut f.intent.payload else {
            panic!()
        };
        match case {
            0 => tx.value = 101,
            1 => tx.to = [43; 20],
            2 => tx.gas_price = 11,
            3 => tx.gas_price = 10, // Below price cap, but above total fee cap.
            4 => tx.gas_limit = 21001,
            5 => {
                tx.chain_id = 31338;
                f.intent.key.account.destination = evm::destination(31338);
            }
            6 => f.intent.key.account.path.push(1),
            7 => f.intent.key.registration[0] ^= 1,
            8 => f.intent.key.public_key[0] = 3,
            9 => {
                tx.gas_price = u64::MAX;
                f.grant.max_gas_price_wei = u64::MAX;
                f.grant.max_fee_wei = u64::MAX;
                f.install();
            }
            _ => unreachable!(),
        }
        f.sign();
        assert!(f.check(1000).is_err(), "case {case}");
    }
}
#[test]
fn evm_sessions_refuse_revocation_expiry_wrong_pda_credentials_and_policy_downgrades() {
    let f = Fixture::new();
    assert!(f.check(989).is_err());
    assert!(f.check(1020).is_err());
    for case in 0..10 {
        let mut f = Fixture::new();
        match case {
            0 => {
                let info = f.observation.session.as_mut().unwrap();
                let mut r: EvmSessionRecord = borsh::from_slice(&info.data).unwrap();
                r.revoked = true;
                info.data = borsh::to_vec(&r).unwrap();
            }
            1 => f.observation.session.as_mut().unwrap().owner = Pubkey::new_unique(),
            2 => {
                f.observation.session.as_mut().unwrap().address = pair_registry::session_address(
                    &f.trust.registry,
                    &f.observation.namespace.address,
                    &f.grant.session_id,
                )
                .0
            }
            3 => f.policy(|p| p.version = 2),
            4 => f.policy(|p| p.require_commit = true),
            5 => f.policy(|p| p.allow_session = false),
            6 => {
                f.at.authorization.session_id = None;
                f.at.authorization.session_proof = None;
            }
            7 => {
                f.delegate = SigningKey::from_bytes(&[99; 32]);
                f.sign();
            }
            8 => f.observation.block_time = 1020,
            9 => f.observation.block_time = 989,
            _ => unreachable!(),
        }
        assert!(f.check(1000).is_err(), "case {case}");
    }
}
#[test]
fn evm_sessions_compose_with_commit_and_access_but_reject_solana_simulation_and_redpallas() {
    let mut f = Fixture::new();
    f.policy(|p| p.require_commit = true);
    f.observation.request.data = borsh::to_vec(&pair_registry::RequestRecord {
        namespace_address: f.observation.namespace.address.to_bytes(),
        commit: f.at.commit.clone(),
        derived_key: pairkey_types::derive_public(&f.reg, &f.at.commit.account).unwrap(),
    })
    .unwrap();
    f.check(1000).unwrap();
    let access = SigningKey::from_bytes(&[51; 32]);
    f.policy(|p| {
        p.access = Some(Credential::Service {
            public_key: access.verifying_key().to_bytes(),
        })
    });
    assert!(f.check(1000).is_err());
    f.at.authorization.access_proof = Some(pairkey_sdk::policy::service_proof(
        &access,
        pairkey_sdk::policy::access_challenge(&f.at.authorization, &f.at.commit),
    ));
    f.check(1000).unwrap();
    f.policy(|p| {
        p.simulation = Some(SimulationConfig {
            program: [12; 32],
            code_hash: [13; 32],
            max_lamports: 100,
        })
    });
    assert!(f.check(1000).is_err());
    let mut f = Fixture::new();
    f.intent.key.suite = Suite::FrostRedPallas;
    f.intent.payload = Payload::RedPallas {
        message: b"wrong suite".to_vec(),
    };
    f.sign();
    assert!(f.check(1000).is_err());
    let mut f = Fixture::new();
    f.grant.cumulative_budget = Some(100);
    assert!(f.grant.validate().is_err());
}
#[test]
fn evm_intents_require_exact_canonical_encoding_and_proofs_bind_nonce_and_grant() {
    let mut f = Fixture::new();
    let bytes = f.intent.bytes().unwrap();
    assert_eq!(Intent::from_bytes(&bytes).unwrap(), f.intent);
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Intent::from_bytes(&trailing).is_err());
    let Payload::EvmTransfer(tx) = &mut f.intent.payload else {
        panic!()
    };
    tx.nonce += 1;
    f.at.commit = Commit::new(
        &f.reg,
        [7; 32],
        f.intent.key.account.clone(),
        &f.intent.bytes().unwrap(),
    )
    .unwrap();
    assert!(f.check(1000).is_err());
    f.sign();
    f.check(1000).unwrap();
    f.grant.max_value_wei += 1;
    f.install();
    assert!(f.check(1000).is_err());
}

#[test]
fn transfer_session_cannot_authorize_message_signing() {
    let mut f = Fixture::new();
    f.intent.payload = Payload::EvmMessage(pairkey_signing::evm_message::Message {
        chain_id: 31337,
        message: b"hello".to_vec(),
    });
    f.sign();
    assert!(f.check(1000).is_err());
}
