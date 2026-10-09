mod support;
use ed25519_dalek::{Signer, SigningKey};
use pairkey_core::{
    approval::{
        self,
        program::{self, ProgramObservation},
    },
    ExecutableObservation, Observation, ObservedAccount, Trust,
};
use pairkey_types::{
    approval::{Approval, Identity, Proof, Request, Rules},
    policy::Authorization,
    program_approval::{AccountState, Mode, Output, Source},
    Attempt, Commit, Registration,
};
use solana_sdk::pubkey::Pubkey;
struct Fixture {
    t: Trust,
    o: Observation,
    r: Registration,
    a: Attempt,
    approval: Approval,
    m: Vec<u8>,
    p: ProgramObservation,
}
impl Fixture {
    fn new(mode: Mode) -> Self {
        let (t, mut o, old, m) = support::fixture();
        let ns: pair_registry::NamespaceRecord = borsh::from_slice(&o.namespace.data).unwrap();
        let mut r = ns.registration;
        let key = SigningKey::from_bytes(&[42; 32]);
        let program = Pubkey::new_unique();
        let seeds = vec![b"pairkey".to_vec()];
        let authority = Pubkey::find_program_address(&[b"pairkey"], &program).0;
        let code = ExecutableObservation {
            program,
            owner: solana_sdk::bpf_loader::id(),
            executable: true,
            code: vec![1, 2, 3],
            program_data: None,
        };
        r.namespace.derivation_authority = authority.to_bytes();
        o.namespace = ObservedAccount {
            address: pair_registry::namespace_address(&t.registry, &r).0,
            owner: solana_sdk::system_program::id(),
            data: vec![],
        };
        let account = Pubkey::new_unique();
        let source = Source {
            program: program.to_bytes(),
            authority: authority.to_bytes(),
            seeds,
            code_hash: if mode == Mode::Offchain {
                code.hash().unwrap()
            } else {
                [0; 32]
            },
            accounts: vec![account.to_bytes()],
            mode,
        };
        let commit = Commit::new(&r, old.commit.request_id, old.commit.account, &m).unwrap();
        let request = Request {
            version: 1,
            identity: Identity::Program(Box::new(source)),
            commit: commit.clone(),
            policy_revision: 0,
            policy_digest: Rules::default().digest(),
            issued_at: 1000,
            expires_at: 1100,
        };
        let proof = Proof::Program {
            caller: key.verifying_key().to_bytes(),
            signature: key.sign(&request.signing_message()).to_bytes().to_vec(),
        };
        let approval = Approval { request, proof };
        let a = Attempt {
            authorization: Authorization::offchain(&approval),
            commit,
            random_id: [6; 32],
        };
        let p = if mode == Mode::Offchain {
            let states = vec![
                AccountState {
                    address: o.set.address.to_bytes(),
                    owner: o.set.owner.to_bytes(),
                    lamports: 1,
                    executable: false,
                    data: o.set.data.clone(),
                },
                AccountState {
                    address: account.to_bytes(),
                    owner: program.to_bytes(),
                    lamports: 1,
                    executable: false,
                    data: vec![1],
                },
            ];
            let input = program::input(&r, &approval, &m, &states).unwrap();
            let output = Output {
                input_digest: input.digest(),
                allowed: true,
            };
            ProgramObservation::Evaluated {
                slot: o.slot,
                code: Box::new(code),
                states,
                input: Box::new(input),
                output,
            }
        } else {
            ProgramObservation::Committed(ObservedAccount {
                address: pair_registry::program_approval::approval_address(
                    &t.registry,
                    &r.namespace.digest(),
                    &a.commit.request_id,
                )
                .0,
                owner: t.registry,
                data: borsh::to_vec(&pair_registry::program_approval::ProgramApprovalRecord {
                    namespace_digest: r.namespace.digest(),
                    request_digest: approval.request.digest(),
                    expires_at: 1100,
                })
                .unwrap(),
            })
        };
        Self {
            t,
            o,
            r,
            a,
            approval,
            m,
            p,
        }
    }
    fn check(&self, p: Option<&ProgramObservation>) -> Result<(), pairkey_core::Error> {
        approval::authorize_with_program(
            &self.t,
            &self.o,
            &self.r,
            &self.a,
            &self.m,
            &self.approval.proof,
            None,
            p,
            1000,
            100,
        )
    }
}
#[test]
fn program_decision_requires_authenticated_caller_code_state_and_exact_output() {
    let f = Fixture::new(Mode::Offchain);
    f.check(Some(&f.p)).unwrap();
    assert!(f.check(None).is_err());
    let mutations: [fn(&mut ProgramObservation); 7] = [
        |p| {
            if let ProgramObservation::Evaluated { code, .. } = p {
                code.code[0] ^= 1
            }
        },
        |p| {
            if let ProgramObservation::Evaluated { code, .. } = p {
                code.executable = false
            }
        },
        |p| {
            if let ProgramObservation::Evaluated { states, .. } = p {
                states[1].address[0] ^= 1
            }
        },
        |p| {
            if let ProgramObservation::Evaluated { states, .. } = p {
                states[0].data[0] ^= 1
            }
        },
        |p| {
            if let ProgramObservation::Evaluated { input, .. } = p {
                input.caller[0] ^= 1
            }
        },
        |p| {
            if let ProgramObservation::Evaluated { output, .. } = p {
                output.input_digest[0] ^= 1
            }
        },
        |p| {
            if let ProgramObservation::Evaluated { slot, .. } = p {
                *slot = 99
            }
        },
    ];
    for mutate in mutations {
        let mut p = f.p.clone();
        mutate(&mut p);
        assert!(f.check(Some(&p)).is_err());
    }
    let mut p = f.p.clone();
    if let ProgramObservation::Evaluated { output, .. } = &mut p {
        output.allowed = false
    }
    assert!(f.check(Some(&p)).is_err());
    assert!(!program::decision(&f.t, &f.o, &f.r, &f.approval, &f.m, &p).unwrap());
    let mut f = f;
    if let Proof::Program { signature, .. } = &mut f.approval.proof {
        signature[0] ^= 1
    }
    f.a.authorization = Authorization::offchain(&f.approval);
    assert!(f.check(Some(&f.p)).is_err());
}
#[test]
fn committed_program_approval_requires_exact_gateway_record_and_cannot_be_simulated() {
    let mut f = Fixture::new(Mode::Onchain);
    f.check(Some(&f.p)).unwrap();
    assert!(f.check(None).is_err());
    let off = Fixture::new(Mode::Offchain);
    assert!(f.check(Some(&off.p)).is_err());
    let mutations: [fn(&mut ProgramObservation); 4] = [
        |p| {
            if let ProgramObservation::Committed(a) = p {
                a.owner = Pubkey::new_unique()
            }
        },
        |p| {
            if let ProgramObservation::Committed(a) = p {
                a.address = Pubkey::new_unique()
            }
        },
        |p| {
            if let ProgramObservation::Committed(a) = p {
                a.data[32] ^= 1
            }
        },
        |p| {
            if let ProgramObservation::Committed(a) = p {
                a.data[64] ^= 1
            }
        },
    ];
    for mutate in mutations {
        let mut p = f.p.clone();
        mutate(&mut p);
        assert!(f.check(Some(&p)).is_err());
    }
    f.o.finalized = false;
    assert!(f.check(Some(&f.p)).is_err());
}
