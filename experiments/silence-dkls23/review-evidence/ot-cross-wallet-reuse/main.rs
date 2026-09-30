//! Disposable local fixtures; no key recovery or production-network tests.
use derivation_path::DerivationPath;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sl_dkls23::{
    keygen::{self, Keyshare},
    sign::{self, SignError},
};
use sl_mpc_mate::coord::SimpleMessageRelay;
use sl_oblivious::{endemic_ot::*, soft_spoken::*};
use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;

fn fresh() -> [u8; 32] {
    let mut x = [0; 32];
    OsRng.fill_bytes(&mut x);
    x
}
type Wallet = Vec<Arc<Keyshare>>;

async fn wallet() -> Wallet {
    let relay = SimpleMessageRelay::new();
    let mut tasks = JoinSet::new();
    for (setup, _) in keygen::utils::setup_keygen(None, 2, 2, None) {
        tasks.spawn(keygen::run(setup, fresh(), relay.connect()));
    }
    let mut out = vec![];
    while let Some(r) = tasks.join_next().await {
        out.push(Arc::new(r.unwrap().unwrap()));
    }
    out.sort_by_key(|s| s.party_id);
    out
}

async fn attempt(shares: Wallet, path: &str, message: [u8; 32], should_pass: bool) -> f64 {
    let begun = Instant::now();
    let expected = shares[0]
        .derive_with_offset(&DerivationPath::from_str(path).unwrap())
        .unwrap()
        .1;
    let verify = VerifyingKey::from_affine(expected.to_affine()).unwrap();
    let relay = SimpleMessageRelay::new();
    let mut tasks = JoinSet::new();
    for (setup, _) in sign::setup_dsg(None, &shares, path) {
        tasks.spawn(sign::run(
            setup.with_hash(message),
            fresh(),
            relay.connect(),
        ));
    }
    let gather = async {
        let mut out = vec![];
        while let Some(r) = tasks.join_next().await {
            out.push(r.unwrap());
        }
        out
    };
    let results = tokio::time::timeout(Duration::from_secs(30), gather)
        .await
        .expect("protocol timeout");
    assert_eq!(results.len(), 2);
    if should_pass {
        for result in &results {
            let (sig, rec) = result.as_ref().expect("honest signing failed");
            verify.verify_prehash(&message, sig).unwrap();
            assert_eq!(
                VerifyingKey::recover_from_prehash(&message, sig, *rec).unwrap(),
                verify
            );
        }
        assert_eq!(results[0].as_ref().unwrap(), results[1].as_ref().unwrap());
    } else {
        assert!(
            results.iter().all(|r| r.is_err()),
            "unexpected signing success"
        );
        let typed = results.iter().any(|r| {
            matches!(
                r,
                Err(SignError::AbortProtocolAndBanParty(_))
                    | Err(SignError::InvalidFinalSessionID)
                    | Err(SignError::FailedCheck(_))
            )
        });
        assert!(typed, "unexpected errors: {results:?}");
        println!("  rejection: {results:?}");
    }
    begun.elapsed().as_secs_f64() * 1000.0
}

fn make_base_ot() -> (SenderOTSeed, ReceiverOTSeed) {
    let sid = fresh();
    let psid = fresh();
    let mut msg1 = EndemicOTMsg1::default();
    let receiver = EndemicOTReceiver::new(&sid, &mut msg1, &mut OsRng);
    let mut msg2 = EndemicOTMsg2::default();
    let sender = EndemicOTSender::process(&sid, &msg1, &mut msg2, &mut OsRng).unwrap();
    let recv = receiver.process(&msg2).unwrap();
    let mut s = SenderOTSeed::default();
    let mut r = ReceiverOTSeed::default();
    let mut proof = PPRFOutput::default();
    build_pprf(&psid, &sender, &mut s, &mut proof);
    eval_pprf(&psid, &recv, &proof, &mut r).unwrap();
    (s, r)
}

fn extension(sid: [u8; 32], seed: &SenderOTSeed, byte: u8) -> Round1Output {
    let mut ext: Box<ReceiverExtendedOutput> = bytemuck::allocation::zeroed_box();
    ext.choices.fill(byte);
    let mut message = Round1Output::default();
    SoftSpokenOTReceiver::process(&sid, seed, &mut message, &mut ext, &mut OsRng);
    message
}

fn extension_tests() {
    let (s, r) = make_base_ot();
    let sid = fresh();
    // Fixed repr(C): the first field of Round1Output is matrix u. Its first row
    // starts with the masked choices. Inspect only the first 32 choice bytes.
    let a = extension(sid, &s, 0x35);
    let b = extension(sid, &s, 0xa7);
    assert!(SoftSpokenOTSender::process(&sid, &r, &a).is_ok());
    assert!(SoftSpokenOTSender::process(&sid, &r, &b).is_ok());
    let ab = bytemuck::bytes_of(&a);
    let bb = bytemuck::bytes_of(&b);
    assert!((0..32).all(|i| ab[i] ^ bb[i] == 0x35 ^ 0xa7));
    println!("PASS negative control: SAME seed + SAME extension SID exposes choice-vector XOR; both individual checks accept");
    let fresh_sid = fresh();
    let c = extension(fresh_sid, &s, 0xa7);
    assert!(SoftSpokenOTSender::process(&fresh_sid, &r, &c).is_ok());
    assert!((0..32).any(|i| ab[i] ^ bytemuck::bytes_of(&c)[i] != 0x35 ^ 0xa7));
    assert!(SoftSpokenOTSender::process(&fresh_sid, &r, &a).is_err());
    let mut tampered = c;
    bytemuck::bytes_of_mut(&mut tampered)[0] ^= 1;
    assert!(SoftSpokenOTSender::process(&fresh_sid, &r, &tampered).is_err());
    println!("PASS: fresh SID removes that cancellation; wrong SID and altered extension message are rejected");
}

fn selective_abort_tests() {
    let mut accept = 0;
    let mut reject = 0;
    for _ in 0..32 {
        let sid = fresh();
        let psid = fresh();
        let mut m1 = EndemicOTMsg1::default();
        let receiver = EndemicOTReceiver::new(&sid, &mut m1, &mut OsRng);
        let mut m2 = EndemicOTMsg2::default();
        let output = EndemicOTSender::process(&sid, &m1, &mut m2, &mut OsRng).unwrap();
        let mut sender = SenderOTSeed::default();
        let mut proof = PPRFOutput::default();
        build_pprf(&psid, &output, &mut sender, &mut proof);
        // One intentionally invalid branch in a disposable local fixture.
        bytemuck::bytes_of_mut(&mut m2)[..33].fill(0xff);
        match receiver.process(&m2) {
            Err("Decode error") => reject += 1,
            Err(e) => panic!("unexpected error {e}"),
            Ok(o) => {
                let mut seed = ReceiverOTSeed::default();
                eval_pprf(&psid, &o, &proof, &mut seed).unwrap();
                assert_eq!(seed.random_choices[0] & 8, 0);
                accept += 1;
            }
        }
    }
    assert!(accept > 0 && reject > 0);
    println!("PASS selective-abort reproduction: {accept}/32 accepted, all select the unmodified branch; {reject}/32 decode rejection. No wallet-key recovery tested.");
}

async fn run() {
    extension_tests();
    selective_abort_tests();
    let donor = wallet().await;
    let mut wallets = vec![];
    let mut baseline = vec![];
    for _ in 0..20 {
        let native = wallet().await;
        baseline.push(attempt(native.clone(), "m", [1; 32], true).await);
        let spliced: Wallet = (0..2)
            .map(|p| Arc::new(native[p].reuse_probe_splice(&donor[p])))
            .collect();
        for p in 0..2 {
            assert_eq!(
                spliced[p].reuse_probe_ot_bytes(),
                donor[p].reuse_probe_ot_bytes()
            );
        }
        wallets.push(spliced);
    }
    println!(
        "PASS: 20 native wallet controls; only OT regions replaced by the same matched donor setup"
    );
    let mut timings = vec![];
    for round in 0..25 {
        for w in &wallets {
            let path = if round % 2 == 0 { "m" } else { "m/0/7" };
            let message = if round % 3 == 0 { [1; 32] } else { fresh() };
            timings.push(attempt(w.clone(), path, message, true).await);
        }
        if round % 5 == 4 {
            println!("Sequential cross-wallet signatures: {}", (round + 1) * 20);
        }
    }
    let mut done = 0;
    for batch in 0..125 {
        let mut tasks = JoinSet::new();
        for lane in 0..4 {
            // Alternate shared-wallet and different-wallet concurrency.
            let index = if batch % 2 == 0 {
                batch % 20
            } else {
                (batch + lane) % 20
            };
            tasks.spawn(attempt(wallets[index].clone(), "m", fresh(), true));
        }
        while let Some(r) = tasks.join_next().await {
            timings.push(r.unwrap());
            done += 1;
        }
        if done % 100 == 0 {
            println!("Concurrent cross-wallet/same-wallet signatures: {done}");
        }
    }
    for w in &wallets {
        for p in 0..2 {
            assert_eq!(w[p].reuse_probe_ot_bytes(), donor[p].reuse_probe_ot_bytes());
        }
    }
    println!("PASS: 1000 signatures verified under intended wallet/path; both outputs and recovery IDs agree; OT state unchanged");
    let a = wallet().await;
    let independent = wallet().await;
    let mismatch = vec![
        Arc::new(a[0].reuse_probe_splice(&donor[0])),
        Arc::new(a[1].reuse_probe_splice(&independent[1])),
    ];
    attempt(mismatch, "m", fresh(), false).await;
    println!("PASS: mismatched OT states rejected");
    let cross = vec![wallets[0][0].clone(), wallets[1][1].clone()];
    attempt(cross, "m", fresh(), false).await;
    println!("PASS: mixed-wallet packages with the same OT state rejected");
    baseline.sort_by(f64::total_cmp);
    timings.sort_by(f64::total_cmp);
    println!("Local release timing: native control median {:.3} ms (n=20); reuse median {:.3} ms (n=1000, mixed concurrency; NOT a performance comparison)",baseline[10],timings[500]);
    println!("LIMITS: local in-process no-auth test relay; no production replay/rollback/quarantine enforcement tested; successful signatures do not prove secrecy or multi-wallet composition security.");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    tokio::time::timeout(Duration::from_secs(300), run())
        .await
        .expect("suite timeout");
}
