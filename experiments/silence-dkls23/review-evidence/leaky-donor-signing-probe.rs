//! Leaky-donor amplification at the RVOLE call site that signing uses.
//! `sign/dsg.rs:303` calls RVOLESender::process, whose first step is the
//! SoftSpokenOT consistency check. Honest endpoint = unmodified pinned
//! sl-oblivious RVOLESender; adversary = this harness, which runs the honest
//! RVOLEReceiver then tampers its Round1Output using bits it claims to know.
//! No honest-library edit. No signature or private key is formed: the gate
//! runs before any multiplication share is used, and `a` does not affect it.
use bytemuck::bytes_of_mut;
use k256::Scalar;
use rand_core::{OsRng, RngCore};
use sl_oblivious::{endemic_ot::*, rvole::*, soft_spoken::*};

const S_BYTES: usize = 16;
const U_LEN: usize = 64 * 80;
const X_OFF: usize = U_LEN;
const T_OFF: usize = U_LEN + S_BYTES;
const ROWS: usize = 256;

fn fresh() -> [u8; 32] {
    let mut x = [0; 32];
    OsRng.fill_bytes(&mut x);
    x
}

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

fn nabla_bit(r: &ReceiverOTSeed, row: usize) -> u8 {
    (r.random_choices[row / 4] >> (row % 4)) & 1
}

// Run the honest RVOLE sender gate on a (possibly tampered) round-1 message.
fn gate(sid: &[u8; 32], r: &ReceiverOTSeed, a: &[Scalar; 2], msg: &Round1Output) -> bool {
    let mut out = RVOLEOutput::default();
    match RVOLESender::process(sid, r, a, msg, &mut out, &mut OsRng) {
        Ok(_) => true,
        Err(SoftSpokenOTError::AbortProtocolAndBanReceiver) => false,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let trials: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2048);

    let sid = fresh();
    let (s, r) = make_base_ot();
    // Honest round-1 message the RVOLE sender accepts, plus signing-style `a`.
    let mut honest = Round1Output::default();
    let (_rx, beta) = RVOLEReceiver::new(sid, &s, &mut honest, &mut OsRng);
    let a = [beta, beta + beta];
    assert!(gate(&sid, &r, &a, &honest), "honest RVOLE round-1 rejected");
    println!("control: honest RVOLE round-1 accepted at the sign call site");

    // A. Amplification: inject one inconsistency in x, repair every row from
    // known nabla except j rows the attacker must guess. Accept iff all guesses
    // are right -> 2^-j. Confirms the gate from experiment 1 survives the RVOLE
    // wrapper; the error maps to SignError::AbortProtocolAndBanParty (dsg.rs:303)
    // and then to QuarantinePeer (lifecycle.rs:121-124).
    println!("A. RVOLE-layer amplification, {trials} trials/cohort");
    println!("   j    accepted   rate       2^-j        exp.bits/attempt (j*rate)");
    for &j in &[0usize, 1, 2, 3, 4, 6, 8] {
        let mut accepted = 0u64;
        for _ in 0..trials {
            let mut unknown = [false; ROWS];
            let mut picked = 0;
            while picked < j {
                let row = (OsRng.next_u32() as usize) % ROWS;
                if !unknown[row] {
                    unknown[row] = true;
                    picked += 1;
                }
            }
            let mut msg = honest;
            let b = bytes_of_mut(&mut msg);
            b[X_OFF] ^= 1;
            for row in 0..ROWS {
                let present = if unknown[row] {
                    (OsRng.next_u32() & 1) as u8
                } else {
                    nabla_bit(&r, row)
                };
                if present == 1 {
                    b[T_OFF + row * S_BYTES] ^= 1;
                }
            }
            if gate(&sid, &r, &a, &msg) {
                accepted += 1;
            }
        }
        let rate = accepted as f64 / trials as f64;
        println!(
            "   {j:<4} {accepted:<10} {rate:<10.6} {:<11.6} {:.4}",
            2f64.powi(-(j as i32)),
            j as f64 * rate
        );
    }

    // B. No incremental oracle: an injection the attacker cannot fully account
    // for is detected. "flip x, repair nothing" is the j=256 case (needs every
    // nabla bit = 0). "flip one row only" cancels nothing. Both ~never accept.
    let big = trials * 8;
    let mut xonly = 0u64;
    let mut onerow = 0u64;
    for _ in 0..big {
        let mut m1 = honest;
        bytes_of_mut(&mut m1)[X_OFF] ^= 1;
        if gate(&sid, &r, &a, &m1) {
            xonly += 1;
        }
        let mut m2 = honest;
        let row = (OsRng.next_u32() as usize) % ROWS;
        bytes_of_mut(&mut m2)[T_OFF + row * S_BYTES] ^= 1;
        if gate(&sid, &r, &a, &m2) {
            onerow += 1;
        }
    }
    println!("B. no incremental oracle over {big} trials each:");
    println!("   flip x, repair nothing (j=256): {xonly} accepted");
    println!("   flip one t-row only:            {onerow} accepted");

    // C. No cross-donor accumulation: repairing with a different donor's secret.
    let (_s2, r2) = make_base_ot();
    let mut cross = 0u64;
    for _ in 0..big {
        let mut m = honest;
        let b = bytes_of_mut(&mut m);
        b[X_OFF] ^= 1;
        for row in 0..ROWS {
            if nabla_bit(&r2, row) == 1 {
                b[T_OFF + row * S_BYTES] ^= 1;
            }
        }
        if gate(&sid, &r, &a, &m) {
            cross += 1;
        }
    }
    println!("C. cross-donor repair (another donor's secret) over {big}: {cross} accepted");
    println!("DONE");
}
