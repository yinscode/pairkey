//! Review harness: real root KDF, public registration, exact research constructor,
//! unchanged native signing. No aggregate private scalar is reconstructed.
use derivation_path::DerivationPath;
use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey},
    elliptic_curve::group::GroupEncoding,
    ProjectivePoint, Scalar,
};
use pairkey_dkls23_research::{
    digest, fresh, point, public,
    registration::{RegisteredWallet, WalletRecord, WalletStore},
    Manifest, Root,
};
use sl_dkls23::{
    keygen::{self, Keyshare},
    sign,
};
use sl_mpc_mate::coord::SimpleMessageRelay;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

type Shares = Vec<Arc<Keyshare>>;
struct Fixture {
    dir: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let suffix: String = fresh().iter().map(|x| format!("{x:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("derived-wallet-fixtures-{suffix}"));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        for i in 0..3 {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join(format!("root-{i}")))
                .unwrap();
            f.write_all(&*Zeroizing::new(fresh())).unwrap();
        }
        Self { dir }
    }
    fn root(&self, p: usize) -> Root {
        Root::load(&self.root_path(p)).unwrap()
    }
    fn root_path(&self, p: usize) -> PathBuf {
        self.dir.join(format!("root-{p}"))
    }
    fn store(&self, p: usize) -> WalletStore {
        WalletStore::new(self.dir.join(format!("public-{p}")))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn manifest(a: &Root, b: &Root, id: [u8; 32]) -> Manifest {
    let points = [
        public(&a.derive(0, id).unwrap()),
        public(&b.derive(1, id).unwrap()),
    ];
    let q = (point(&points[0]).unwrap() + point(&points[1]).unwrap())
        .to_bytes()
        .to_vec();
    Manifest {
        version: 1,
        key_id: id,
        identities: [
            a.identity(0).verifying_key().to_bytes(),
            b.identity(1).verifying_key().to_bytes(),
        ],
        additive_public: points,
        public_key: q.clone(),
        chain_code: digest(b"pairkey/dkls-research/public-chain-code/v1", &(id, q)),
    }
}
fn register(f: &Fixture, id: [u8; 32]) -> RegisteredWallet {
    let roots = [f.root(0), f.root(1)];
    let record = WalletRecord::new(manifest(&roots[0], &roots[1], id)).unwrap();
    let endorsements = [
        f.store(0).endorse(&record, &roots[0], 0).unwrap(),
        f.store(1).endorse(&record, &roots[1], 1).unwrap(),
    ];
    let w = RegisteredWallet {
        record,
        endorsements,
    };
    for p in 0..2 {
        f.store(p).commit(&w, &roots[p], p as u8).unwrap();
    }
    w
}
async fn native_setup() -> Shares {
    let relay = SimpleMessageRelay::new();
    let mut jobs = JoinSet::new();
    for (setup, _) in keygen::utils::setup_keygen(None, 2, 2, None) {
        jobs.spawn(keygen::run(setup, fresh(), relay.connect()));
    }
    let mut out = vec![];
    while let Some(r) = jobs.join_next().await {
        out.push(Arc::new(r.unwrap().unwrap()));
    }
    out.sort_by_key(|s| s.party_id);
    out
}
fn package(root_path: &Path, role: u8, w: &RegisteredWallet, donor: &Keyshare) -> Keyshare {
    w.validate().unwrap();
    let root = Root::load(root_path).unwrap();
    let contribution = w.record.manifest.check_local(&root, role).unwrap();
    let share = Zeroizing::new(if role == 0 {
        *contribution * Scalar::from(2u64).invert().unwrap()
    } else {
        -*contribution
    });
    let (s, r, z) = donor.direct_review_material();
    let setup_id = digest(
        b"pairkey/direct-review/package/v1",
        &(w.record.digest(), donor.final_session_id),
    );
    let p = Keyshare::pairkey_research_two_party(
        role,
        *share,
        w.record.manifest.stored_public().unwrap(),
        point(&w.record.manifest.public_key).unwrap(),
        w.record.manifest.key_id,
        w.record.manifest.chain_code,
        setup_id,
        &z,
        &s,
        &r,
        &w.record.digest(),
    )
    .unwrap();
    assert_eq!(
        p.public_key(),
        point(&w.record.manifest.public_key).unwrap()
    );
    assert_eq!(p.rank_list(), vec![0, 0]);
    assert_eq!(p.threshold, 2);
    assert_eq!(p.root_chain_code(), w.record.manifest.chain_code);
    p
}
async fn sign(shares: Shares, path: &str, msg: [u8; 32], success: bool) {
    let expected = shares[0]
        .derive_with_offset(&DerivationPath::from_str(path).unwrap())
        .unwrap()
        .1;
    let vk = VerifyingKey::from_affine(expected.to_affine()).unwrap();
    let relay = SimpleMessageRelay::new();
    let mut jobs = JoinSet::new();
    for (setup, _) in sign::setup_dsg(None, &shares, path) {
        jobs.spawn(sign::run(setup.with_hash(msg), fresh(), relay.connect()));
    }
    let out = tokio::time::timeout(Duration::from_secs(30), async {
        let mut out = vec![];
        while let Some(r) = jobs.join_next().await {
            out.push(r.unwrap());
        }
        out
    })
    .await
    .expect("signing timeout");
    assert_eq!(out.len(), 2);
    if success {
        for r in &out {
            let (s, recovery) = r.as_ref().expect("sign failed");
            vk.verify_prehash(&msg, s).unwrap();
            assert_eq!(
                VerifyingKey::recover_from_prehash(&msg, s, *recovery).unwrap(),
                vk
            );
        }
        assert_eq!(out[0].as_ref().unwrap(), out[1].as_ref().unwrap());
    } else {
        assert!(out.iter().all(|x| x.is_err()));
        println!("  expected rejection: {out:?}");
    }
}
fn build(f: &Fixture, w: &RegisteredWallet, donor: &Shares) -> Shares {
    (0..2)
        .map(|p| Arc::new(package(&f.root_path(p), p as u8, w, &donor[p])))
        .collect()
}

fn boundary_tests(f: &Fixture, w: &RegisteredWallet, donor: &Shares) {
    let roots = [f.root(0), f.root(1)];
    let id = w.record.manifest.key_id;
    assert_eq!(
        *roots[0].derive(0, id).unwrap(),
        *f.root(0).derive(0, id).unwrap()
    );
    assert_ne!(
        *roots[0].derive(0, id).unwrap(),
        *roots[0].derive(1, id).unwrap()
    );
    assert_ne!(
        *roots[0].derive(0, id).unwrap(),
        *roots[0].derive(0, fresh()).unwrap()
    );
    assert!(w.record.manifest.check_local(&f.root(2), 0).is_err());
    assert!(w.record.manifest.check_local(&roots[0], 1).is_err());
    let other_peer = manifest(&roots[0], &f.root(2), id);
    assert_eq!(
        other_peer.additive_public[0],
        w.record.manifest.additive_public[0]
    );
    assert_ne!(other_peer.identities[1], w.record.manifest.identities[1]);
    println!("PASS KDF determinism/role/wallet separation and wrong-root rejection; FINDING: same root/role/key-ID repeats a contribution across different peer pairs");
    let a = w.record.manifest.check_local(&roots[0], 0).unwrap();
    let good = *a * Scalar::from(2u64).invert().unwrap();
    let (s, r, z) = donor[0].direct_review_material();
    let points = w.record.manifest.stored_public().unwrap();
    let q = point(&w.record.manifest.public_key).unwrap();
    let accepts = |role, secret, ps, pubkey| {
        Keyshare::pairkey_research_two_party(
            role,
            secret,
            ps,
            pubkey,
            id,
            w.record.manifest.chain_code,
            fresh(),
            &z,
            &s,
            &r,
            &[],
        )
        .is_some()
    };
    assert!(accepts(0, good, points, q));
    assert!(!accepts(2, good, points, q));
    assert!(!accepts(0, Scalar::ZERO, points, q));
    assert!(!accepts(0, good + Scalar::ONE, points, q));
    assert!(!accepts(0, good, points, q + ProjectivePoint::GENERATOR));
    assert!(!accepts(0, good, [ProjectivePoint::IDENTITY, points[1]], q));
    assert!(!accepts(0, good, [points[0], points[0]], points[0]));
    assert!(!accepts(0, good, [points[1], points[0]], q));
    println!("PASS constructor: valid input accepted; seven malformed/degenerate inputs rejected");
    let mut bad = w.clone();
    bad.record.manifest.chain_code[0] ^= 1;
    assert!(bad.validate().is_err());
    let mut bad = w.clone();
    bad.record.coordinates.swap(0, 1);
    assert!(bad.validate().is_err());
    let mut bad = w.clone();
    bad.endorsements.swap(0, 1);
    assert!(bad.validate().is_err());
    let mut bad = w.clone();
    bad.endorsements[0].signature[0] ^= 1;
    assert!(bad.validate().is_err());
    println!("PASS registration: chain-code, coordinates, endorsement-role and signature mutations rejected");
}

async fn run() {
    let f = Fixture::new();
    let mut records = vec![];
    let mut donors = vec![];
    for _ in 0..20 {
        let w = register(&f, fresh());
        donors.push(native_setup().await);
        records.push(w);
    }
    boundary_tests(&f, &records[0], &donors[0]);
    // Discard in-memory registration records and reload the public store.
    // Roots remain on disk; setup donors remain in memory for this experiment.
    let ids: Vec<_> = records.iter().map(|w| w.record.manifest.key_id).collect();
    let public_digests: Vec<_> = records.iter().map(|w| w.record.digest()).collect();
    drop(records);
    for p in 0..2 {
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(
                f.store(p).load(*id).unwrap().record.digest(),
                public_digests[i]
            );
        }
        let d = f.dir.join(format!("public-{p}"));
        for entry in fs::read_dir(d).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|x| x == "wallet") {
                let v: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                let obj = v.as_object().unwrap();
                assert_eq!(obj.len(), 2);
                assert!(obj.contains_key("record") && obj.contains_key("endorsements"));
            }
        }
    }
    println!("PASS: discarded records reload from both public stores; wallet file schema contains record + endorsements only");
    let shared = native_setup().await;
    for stage in 0..2 {
        let mut count = 0;
        for batch in 0..125 {
            let mut jobs = JoinSet::new();
            for lane in 0..4 {
                let index = if batch % 2 == 0 {
                    batch % 20
                } else {
                    (batch + lane) % 20
                };
                let w = f.store(0).load(ids[index]).unwrap();
                assert_eq!(w, f.store(1).load(ids[index]).unwrap());
                let donor = if stage == 0 { &donors[index] } else { &shared };
                let shares = build(&f, &w, donor);
                // Every attempt reloads roots and rederives shares; packages are
                // discarded by the signing task, never serialized to storage.
                let path = if batch % 2 == 0 { "m" } else { "m/0/7" };
                let msg = if batch % 3 == 0 { [1; 32] } else { fresh() };
                jobs.spawn(sign(shares, path, msg, true));
            }
            while let Some(r) = jobs.join_next().await {
                r.unwrap();
                count += 1;
            }
            if count % 100 == 0 {
                println!("Stage {} verified signatures: {count}", stage + 1);
            }
        }
        assert_eq!(count, 500);
    }
    let w = f.store(0).load(ids[0]).unwrap();
    let w2 = f.store(0).load(ids[1]).unwrap();
    let first = build(&f, &w, &shared);
    let second = build(&f, &w2, &shared);
    sign(
        vec![first[0].clone(), second[1].clone()],
        "m",
        fresh(),
        false,
    )
    .await;
    let mismatched = vec![
        first[0].clone(),
        Arc::new(package(&f.root_path(1), 1, &w, &donors[0][1])),
    ];
    sign(mismatched, "m", fresh(), false).await;
    println!("PASS: mixed wallets and setup generations rejected");
    let regenerated = build(&f, &w, &shared);
    for p in 0..2 {
        assert_eq!(first[p].as_slice(), regenerated[p].as_slice());
    }
    println!("PASS: same roots + public record + same global setup deterministically reconstruct identical packages; signing randomness remains fresh");
    println!("RESULT: 500 derived-share signatures with per-wallet setup + 500 with shared OT AND masking state across 20 wallets");
    println!("LIMITS: no aggregate scalar reconstructed; local no-auth signing relay; native donors supply setup state; no proof of malicious registration/composition, distributed quarantine, rollback resistance or physical erasure");
}
#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    tokio::time::timeout(Duration::from_secs(300), run())
        .await
        .expect("suite timeout");
}
