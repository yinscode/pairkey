//! Leaky-donor amplification probe. Isolated, honest sl-oblivious endpoint, no
//! native or honest-library edit. Measures how well the honest SoftSpokenOT
//! sender consistency check detects a receiver that injects one inconsistency
//! after learning all but j bits of the per-setup correlation secret nabla.
//! Confirms: detection probability 1 - 2^-j, every miss is the typed ban error,
//! and the leak does not compound across a setup. No signature or key is formed.
use bytemuck::bytes_of_mut;
use rand_core::{OsRng, RngCore};
use sl_oblivious::{endemic_ot::*, soft_spoken::*};

const S_BYTES: usize = 16; // one 128-bit column
const U_LEN: usize = 64 * 80; // u: [[u8; L_PRIME_BYTES=80]; 64]
const X_OFF: usize = U_LEN; // x: [u8; 16]
const T_OFF: usize = U_LEN + S_BYTES; // t: [[u8; 16]; 256]
const ROWS: usize = 256; // LAMBDA_C consistency rows

fn fresh() -> [u8; 32] {
    let mut x = [0; 32];
    OsRng.fill_bytes(&mut x);
    x
}

// Honest base OT + PPRF: unmodified library calls on both sides.
fn make_base_ot() -> (SenderOTSeed, ReceiverOTSeed) {
    let sid = fresh();
    let psid = fresh();
    let mut m1 = EndemicOTMsg1::default();
    let receiver = EndemicOTReceiver::new(&sid, &mut m1, &mut OsRng);
    let mut m2 = EndemicOTMsg2::default();
    let sender = EndemicOTSender::process(&sid, &m1, &mut m2, &mut OsRng).unwrap();
    let recv = receiver.process(&m2).unwrap();
    let mut s = SenderOTSeed::default();
    let mut r = ReceiverOTSeed::default();
    let mut proof = PPRFOutput::default();
    build_pprf(&psid, &sender, &mut s, &mut proof);
    eval_pprf(&psid, &recv, &proof, &mut r).unwrap();
    (s, r)
}

// One honest extension message the honest sender accepts as-is.
fn honest_message(sid: &[u8; 32], s: &SenderOTSeed) -> Round1Output {
    let mut ext: Box<ReceiverExtendedOutput> = bytemuck::allocation::zeroed_box();
    OsRng.fill_bytes(&mut ext.choices);
    let mut msg = Round1Output::default();
    SoftSpokenOTReceiver::process(sid, s, &mut msg, &mut ext, &mut OsRng);
    msg
}

// nabla bit for consistency row `row`, as the sender packs it.
fn nabla_bit(r: &ReceiverOTSeed, row: usize) -> u8 {
    (r.random_choices[row / 4] >> (row % 4)) & 1
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let trials: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(4096);

    // Control 1: honest message is accepted.
    let (s, r) = make_base_ot();
    let sid = fresh();
    let base = honest_message(&sid, &s);
    assert!(SoftSpokenOTSender::process(&sid, &r, &base).is_ok());
    println!("control: honest extension accepted");

    // For each j, inject Delta into x, repair every row from known nabla except
    // j rows where the attacker must guess. Accept iff all j guesses are right.
    println!("trials per cohort: {trials}");
    println!("  j   accepted   rate       predicted 2^-j   every reject = ban error");
    let mut nonban = 0u64;
    for &j in &[0usize, 1, 2, 3, 4, 6, 8] {
        let mut accepted = 0u64;
        for _ in 0..trials {
            // pick j distinct unknown rows
            let mut unknown = [false; ROWS];
            let mut picked = 0;
            while picked < j {
                let row = (OsRng.next_u32() as usize) % ROWS;
                if !unknown[row] {
                    unknown[row] = true;
                    picked += 1;
                }
            }
            let mut msg = base;
            let b = bytes_of_mut(&mut msg);
            b[X_OFF] ^= 1; // one real inconsistency in x, column 0
            for row in 0..ROWS {
                let present = if unknown[row] {
                    (OsRng.next_u32() & 1) as u8 // guess
                } else {
                    nabla_bit(&r, row) // learned from setup leak: repair exactly
                };
                if present == 1 {
                    b[T_OFF + row * S_BYTES] ^= 1; // repair column 0 of this row
                }
            }
            match SoftSpokenOTSender::process(&sid, &r, &msg) {
                Ok(_) => accepted += 1,
                Err(SoftSpokenOTError::AbortProtocolAndBanReceiver) => {}
                Err(_) => nonban += 1,
            }
        }
        let rate = accepted as f64 / trials as f64;
        let pred = 2f64.powi(-(j as i32));
        println!(
            "  {j:<3} {accepted:<10} {rate:<10.6} {pred:<16.6} {}",
            if nonban == 0 { "yes" } else { "NO" }
        );
    }
    assert_eq!(nonban, 0, "a reject used an untyped or non-ban error");

    // Control 2: compounding check. Two independent setups; bits learned from
    // one give no advantage against the other's secret.
    let (_s2, r2) = make_base_ot();
    let mut cross_pass = 0u64;
    for _ in 0..trials {
        let mut msg = base;
        let b = bytes_of_mut(&mut msg);
        b[X_OFF] ^= 1;
        for row in 0..ROWS {
            // repair using the WRONG setup's nabla (r2), not r
            if nabla_bit(&r2, row) == 1 {
                b[T_OFF + row * S_BYTES] ^= 1;
            }
        }
        if SoftSpokenOTSender::process(&sid, &r, &msg).is_ok() {
            cross_pass += 1;
        }
    }
    println!(
        "cross-setup repair (knowledge of another donor's secret): {cross_pass}/{trials} accepted"
    );
    println!("DONE");
}
