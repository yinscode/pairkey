use super::*;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static ID: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "pairkey-approvals-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            ID.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn file(&self) -> PathBuf {
        self.0.join("approvals.json")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn claim() -> Claim {
    Claim {
        namespace_digest: [1; 32],
        request_id: [2; 32],
        approval_digest: [3; 32],
        attempt_digest: [4; 32],
        expires_at: 1200,
    }
}

#[test]
fn only_one_concurrent_claim_can_generate_a_signing_nonce() {
    let temp = Temp::new();
    let store = Arc::new(Mutex::new(
        ApprovalStore::open(temp.file(), [9; 32]).unwrap(),
    ));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || store.lock().unwrap().reserve(claim(), 1000).unwrap())
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|t| t.join().unwrap() as usize)
            .sum::<usize>(),
        1
    );
    let mut changed = claim();
    changed.approval_digest[0] ^= 1;
    assert!(store.lock().unwrap().reserve(changed, 1000).is_err());
    let mut changed = claim();
    changed.attempt_digest[0] ^= 1;
    assert!(store.lock().unwrap().reserve(changed, 1000).is_err());
}
#[test]
fn restart_makes_inflight_uncertain_and_preserves_completed_results() {
    let temp = Temp::new();
    let mut store = ApprovalStore::open(temp.file(), [9; 32]).unwrap();
    let first = claim();
    store.reserve(first.clone(), 1000).unwrap();
    let mut second = first.clone();
    second.request_id = [7; 32];
    store.reserve(second.clone(), 1000).unwrap();
    store.complete(&second, vec![42; 64], 1001).unwrap();
    drop(store);
    let mut store = ApprovalStore::open(temp.file(), [9; 32]).unwrap();
    assert_eq!(
        store
            .lookup(
                first.namespace_digest,
                first.request_id,
                first.approval_digest
            )
            .unwrap(),
        Some(Status::Uncertain)
    );
    assert!(!store.reserve(first.clone(), 1002).unwrap());
    assert!(store.check_started(&first, 1002).is_err());
    assert!(store.complete(&first, vec![42; 64], 1002).is_err());
    assert_eq!(
        store
            .lookup(
                second.namespace_digest,
                second.request_id,
                second.approval_digest
            )
            .unwrap(),
        Some(Status::Complete(vec![42; 64]))
    );
    store.complete(&second, vec![42; 64], 2000).unwrap();
    assert!(store.complete(&second, vec![43; 64], 2000).is_err());
}
#[test]
fn policy_clock_and_negative_control_fences_survive_restart() {
    let temp = Temp::new();
    let mut store = ApprovalStore::open(temp.file(), [9; 32]).unwrap();
    store
        .observe_policy([1; 32], 2, [5; 32], 100, 1000)
        .unwrap();
    assert!(store
        .observe_policy([1; 32], 1, [4; 32], 101, 1000)
        .is_err());
    assert!(store
        .observe_policy([1; 32], 2, [4; 32], 101, 1000)
        .is_err());
    assert!(store.observe_policy([1; 32], 2, [5; 32], 99, 1000).is_err());
    store.observe_inactive(101, 1001).unwrap();
    drop(store);
    let mut store = ApprovalStore::open(temp.file(), [9; 32]).unwrap();
    assert_eq!(store.minimum_slot().unwrap(), 102);
    assert!(store.check_policy([1; 32], 2, [5; 32], 101).is_err());
    assert!(store
        .observe_policy([1; 32], 2, [5; 32], 102, 1000)
        .is_err());
    store
        .observe_policy([1; 32], 2, [5; 32], 102, 1002)
        .unwrap();
    store.check_policy([1; 32], 2, [5; 32], 102).unwrap();
    assert!(store.observe_inactive(u64::MAX, 1003).is_err());
    assert!(store.reserve(claim(), 1001).is_err());
}
#[test]
fn persistence_errors_poison_issuance_and_context_cannot_be_replaced() {
    let temp = Temp::new();
    let mut store = ApprovalStore::open(temp.file(), [9; 32]).unwrap();
    assert!(ApprovalStore::open(temp.file(), [9; 32]).is_err());
    std::fs::create_dir(temp.0.join("approvals.json.next")).unwrap();
    assert!(store.reserve(claim(), 1000).is_err());
    assert!(store.check_started(&claim(), 1000).is_err());
    assert!(store.reserve(claim(), 1000).is_err());
    drop(store);
    std::fs::remove_dir(temp.0.join("approvals.json.next")).unwrap();
    assert!(ApprovalStore::open(temp.file(), [8; 32]).is_err());
    let mut store = ApprovalStore::open(temp.file(), [9; 32]).unwrap();
    // The failed pre-issuance write exposed no nonce and left the durable file empty.
    assert!(store.reserve(claim(), 1000).unwrap());
}

#[test]
fn program_state_fences_survive_restart_and_load_pre_program_snapshots() {
    let temp = Temp::new();
    let mut store = ApprovalStore::open(temp.file(), [9; 32]).unwrap();
    store.observe_program([1; 32], [2; 32], 100, 1000).unwrap();
    store.check_program([1; 32], [2; 32], 100).unwrap();
    store.observe_program([1; 32], [3; 32], 101, 1001).unwrap();
    assert!(store.check_program([1; 32], [2; 32], 100).is_err());
    assert!(store.observe_program([1; 32], [2; 32], 100, 1001).is_err());
    assert!(store.observe_program([1; 32], [2; 32], 101, 1001).is_err());
    drop(store);
    let store = ApprovalStore::open(temp.file(), [9; 32]).unwrap();
    assert_eq!(store.program_slot([1; 32]).unwrap(), Some(101));
    store.check_program([1; 32], [3; 32], 101).unwrap();
    assert!(store.check_program([1; 32], [2; 32], 102).is_err());
    drop(store);
    // Additive snapshot field: an old journal can be opened without resetting claims.
    let old = Temp::new();
    let mut store = ApprovalStore::open(old.file(), [9; 32]).unwrap();
    store.reserve(claim(), 1000).unwrap();
    drop(store);
    let mut snapshot: serde_json::Value =
        serde_json::from_slice(&std::fs::read(old.file()).unwrap()).unwrap();
    snapshot.as_object_mut().unwrap().remove("program_states");
    std::fs::write(old.file(), serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let store = ApprovalStore::open(old.file(), [9; 32]).unwrap();
    assert_eq!(
        store.lookup([1; 32], [2; 32], [3; 32]).unwrap(),
        Some(Status::Uncertain)
    );
}
