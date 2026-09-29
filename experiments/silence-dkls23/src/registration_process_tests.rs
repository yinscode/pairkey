//! SIGKILL and checkpoint-error schedules through the actual WalletStore APIs.
//! These do not simulate a storage device failing or machine power loss.
use super::*;
use crate::{fresh, public};
use k256::elliptic_curve::group::GroupEncoding;
use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
const STEPS: [WriteStep; 8] = [
    WriteStep::BeforeCreate,
    WriteStep::Created,
    WriteStep::PartiallyWritten,
    WriteStep::Written,
    WriteStep::BeforeFileSync,
    WriteStep::FileSynced,
    WriteStep::BeforeDirectorySync,
    WriteStep::DirectorySynced,
];
fn wait(dir: &Path, name: &str) {
    let end = Instant::now() + Duration::from_secs(10);
    while !dir.join(name).exists() {
        assert!(Instant::now() < end, "missing registration event {name}");
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn record(dir: &Path) -> WalletRecord {
    let roots = [
        Root::load(&dir.join("a")).unwrap(),
        Root::load(&dir.join("b")).unwrap(),
    ];
    let key = [7; 32];
    let contributions = [
        public(&roots[0].derive(0, key).unwrap()),
        public(&roots[1].derive(1, key).unwrap()),
    ];
    let q = (point(&contributions[0]).unwrap() + point(&contributions[1]).unwrap())
        .to_bytes()
        .to_vec();
    WalletRecord::new(Manifest {
        version: 1,
        key_id: key,
        identities: [
            roots[0].identity(0).verifying_key().to_bytes(),
            roots[1].identity(1).verifying_key().to_bytes(),
        ],
        additive_public: contributions,
        public_key: q.clone(),
        chain_code: digest(b"pairkey/dkls-research/public-chain-code/v1", &(key, q)),
    })
    .unwrap()
}
#[test]
#[ignore = "explicit registration subprocess fixture"]
fn registration_process_child() {
    let dir = PathBuf::from(std::env::var_os("PAIRKEY_REGISTRATION_DIR").expect("parent fixture"));
    let operation = std::env::var("PAIRKEY_REGISTRATION_OPERATION").unwrap();
    let target: usize = std::env::var("PAIRKEY_REGISTRATION_STEP")
        .unwrap()
        .parse()
        .unwrap();
    let mode = std::env::var("PAIRKEY_REGISTRATION_MODE").unwrap();
    let root = Root::load(&dir.join("a")).unwrap();
    let r: WalletRecord =
        serde_json::from_slice(&fs::read(dir.join("record.json")).unwrap()).unwrap();
    let store = WalletStore::new(dir.join("wallets"));
    let checkpoint = |step| {
        if step == STEPS[target] {
            fs::write(dir.join("paused"), []).unwrap();
            wait(&dir, "resume");
            if mode == "error" {
                anyhow::bail!("injected registration write/sync checkpoint error");
            }
        }
        Ok(())
    };
    let ok = if operation == "prepare" {
        store.endorse_checkpoint(&r, &root, 0, checkpoint).is_ok()
    } else {
        let wallet: RegisteredWallet =
            serde_json::from_slice(&fs::read(dir.join("wallet.json")).unwrap()).unwrap();
        store
            .commit_checkpoint(&wallet, &root, 0, checkpoint)
            .is_ok()
    };
    let outcome = if ok {
        b"ok".as_slice()
    } else {
        b"error".as_slice()
    };
    if std::env::var_os("PAIRKEY_REGISTRATION_PAUSE_RETURNED").is_some() {
        // Deterministically expose the same creation-before-write window Astra
        // reproduced. The parent must wait for process completion, not existence.
        let mut file = fs::File::create(dir.join("returned")).unwrap();
        fs::write(dir.join("returned.created"), []).unwrap();
        wait(&dir, "returned.resume");
        file.write_all(outcome).unwrap();
    } else {
        fs::write(dir.join("returned"), outcome).unwrap();
    }
}
struct Actor(Child);
impl Drop for Actor {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Actor {
    fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "registration fixture failed: {status}");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "registration fixture did not finish"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
fn schedules(mode: &str) {
    for operation in ["prepare", "commit"] {
        for (index, step) in STEPS.iter().enumerate() {
            let dir = std::env::temp_dir().join(format!("dkls-registration-process-{:?}", fresh()));
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("a"), [11; 32]).unwrap();
            fs::write(dir.join("b"), [22; 32]).unwrap();
            let r = record(&dir);
            fs::write(dir.join("record.json"), serde_json::to_vec(&r).unwrap()).unwrap();
            let roots = [
                Root::load(&dir.join("a")).unwrap(),
                Root::load(&dir.join("b")).unwrap(),
            ];
            let store = WalletStore::new(dir.join("wallets"));
            let w = if operation == "commit" {
                let w = RegisteredWallet {
                    record: r.clone(),
                    endorsements: [
                        store.endorse(&r, &roots[0], 0).unwrap(),
                        store.endorse(&r, &roots[1], 1).unwrap(),
                    ],
                };
                fs::write(dir.join("wallet.json"), serde_json::to_vec(&w).unwrap()).unwrap();
                Some(w)
            } else {
                None
            };
            let mut child = Actor(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "registration::process_tests::registration_process_child",
                        "--quiet",
                    ])
                    .env("PAIRKEY_REGISTRATION_DIR", &dir)
                    .env("PAIRKEY_REGISTRATION_OPERATION", operation)
                    .env("PAIRKEY_REGISTRATION_STEP", index.to_string())
                    .env("PAIRKEY_REGISTRATION_MODE", mode)
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            wait(&dir, "paused");
            let path = if operation == "prepare" {
                store.prepared_path([7; 32], 0)
            } else {
                store.record_path([7; 32])
            };
            let original = fs::read(&path).ok();
            // Inspect bytes independently before killing/resuming; completeness
            // determines recovery, not whether a sync checkpoint was reached.
            let complete = original.as_ref().is_some_and(|bytes| {
                if operation == "prepare" {
                    serde_json::from_slice::<Prepared>(bytes).is_ok()
                } else {
                    serde_json::from_slice::<RegisteredWallet>(bytes).is_ok()
                }
            });
            assert_eq!(
                complete,
                !matches!(
                    step,
                    WriteStep::BeforeCreate | WriteStep::Created | WriteStep::PartiallyWritten
                )
            );
            if mode == "death" {
                child.0.kill().unwrap();
                child.0.wait().unwrap();
                assert!(!dir.join("returned").exists());
            } else {
                fs::write(dir.join("resume"), []).unwrap();
                // Existence does not imply the child finished writing the file.
                child.finish();
                assert_eq!(fs::read(dir.join("returned")).unwrap(), b"error");
            }
            let retry = if operation == "prepare" {
                let recovered = store.endorse(&r, &roots[0], 0);
                if complete {
                    let expected: Prepared =
                        serde_json::from_slice(original.as_ref().unwrap()).unwrap();
                    assert_eq!(recovered.as_ref().unwrap(), &expected.endorsement);
                }
                recovered.is_ok()
            } else {
                let recovered = store.commit(w.as_ref().unwrap(), &roots[0], 0);
                if complete {
                    assert_eq!(store.load([7; 32]).unwrap(), *w.as_ref().unwrap());
                }
                recovered.is_ok()
            };
            let should_recover = complete || *step == WriteStep::BeforeCreate;
            assert_eq!(retry, should_recover, "{mode} {operation} {step:?}");
            if let Some(original) = original {
                assert_eq!(
                    fs::read(&path).unwrap(),
                    original,
                    "existing bytes rewritten"
                );
            }
            if !should_recover {
                assert!(store.endorse(&r, &roots[0], 0).is_err());
                assert!(store.load([7; 32]).is_err());
            }
            // A valid same-key fork must not replace complete or partial artifacts.
            let mut fork = r.clone();
            fork.manifest.additive_public[1] = public(&roots[1].derive(1, [8; 32]).unwrap());
            fork.manifest.public_key = (point(&fork.manifest.additive_public[0]).unwrap()
                + point(&fork.manifest.additive_public[1]).unwrap())
            .to_bytes()
            .to_vec();
            fork.manifest.chain_code = digest(
                b"pairkey/dkls-research/public-chain-code/v1",
                &(fork.manifest.key_id, fork.manifest.public_key.clone()),
            );
            fork.validate().unwrap();
            assert!(store.endorse(&fork, &roots[0], 0).is_err());
            if let Some(output) = std::env::var_os("PAIRKEY_ASSURANCE_EVIDENCE_DIR") {
                let output = PathBuf::from(output);
                fs::create_dir_all(&output).unwrap();
                fs::write(output.join(format!("registration-{mode}-{operation}-{index}.json")),serde_json::to_vec_pretty(&serde_json::json!({"operation":operation,"mode":mode,"checkpoint":format!("{step:?}"),"complete_before_interruption":complete,"retry_succeeded":retry,"existing_bytes_unchanged":true,"conflicting_record_refused":true,"passed":true})).unwrap()).unwrap();
            }
            drop(child);
            fs::remove_dir_all(dir).unwrap();
        }
    }
}
#[test]
fn registration_process_death_recovers_exact_records_or_refuses_incomplete_records() {
    schedules("death");
}
#[test]
fn registration_checkpoint_errors_recover_exact_records_or_refuse_incomplete_records() {
    schedules("error");
}

#[test]
fn completion_reader_waits_for_child_exit_even_when_returned_file_already_exists() {
    let dir = std::env::temp_dir().join(format!("dkls-registration-completion-{:?}", fresh()));
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("a"), [11; 32]).unwrap();
    fs::write(dir.join("b"), [22; 32]).unwrap();
    fs::write(
        dir.join("record.json"),
        serde_json::to_vec(&record(&dir)).unwrap(),
    )
    .unwrap();
    let child = Actor(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "registration::process_tests::registration_process_child",
                "--quiet",
            ])
            .env("PAIRKEY_REGISTRATION_DIR", &dir)
            .env("PAIRKEY_REGISTRATION_OPERATION", "prepare")
            .env("PAIRKEY_REGISTRATION_STEP", "1")
            .env("PAIRKEY_REGISTRATION_MODE", "error")
            .env("PAIRKEY_REGISTRATION_PAUSE_RETURNED", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    wait(&dir, "paused");
    fs::write(dir.join("resume"), []).unwrap();
    wait(&dir, "returned.created");
    assert!(fs::read(dir.join("returned")).unwrap().is_empty());
    let (tx, rx) = std::sync::mpsc::channel();
    let reader_dir = dir.clone();
    let reader = std::thread::spawn(move || {
        let mut child = child;
        child.finish();
        tx.send(fs::read(reader_dir.join("returned")).unwrap())
            .unwrap();
    });
    let blocked = rx.recv_timeout(Duration::from_millis(20)).is_err();
    // Always release the child before asserting, including the bypass outcome.
    fs::write(dir.join("returned.resume"), []).unwrap();
    reader.join().unwrap();
    assert!(
        blocked,
        "completion reader accepted a file still being written"
    );
    assert_eq!(rx.recv().unwrap(), b"error");
    fs::remove_dir_all(dir).unwrap();
}
