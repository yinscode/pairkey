//! Review-only counterexample to unconditional honest-setup distribution.
//! Uses the unchanged public native API; does not demonstrate signing-key recovery.
use pairkey_dkls23_research::{fresh, pool::hash};
use rand_core::OsRng;
use sl_oblivious::{
    endemic_ot::{EndemicOTMsg1, EndemicOTMsg2, EndemicOTReceiver, EndemicOTSender},
    soft_spoken::{build_pprf, eval_pprf, PPRFOutput, ReceiverOTSeed, SenderOTSeed},
};

#[test]
fn malicious_reply_can_filter_an_accepted_base_choice() {
    let mut accepted = 0;
    let mut rejected = 0;
    // Independent local trials, not a live-peer retry strategy. PairKey's
    // quarantine must prevent a peer continuing after an attributable rejection.
    for _ in 0..256 {
        let entry = fresh();
        let base_sid = hash("pairkey/pool/base-ot/v1", &[&entry, &[0], &[1]]);
        let pprf_sid = hash("pairkey/pool/pprf/v1", &[&entry, &[1], &[0]]);
        let mut msg1 = EndemicOTMsg1::default();
        let receiver = EndemicOTReceiver::new(&base_sid, &mut msg1, &mut OsRng);
        let mut msg2 = EndemicOTMsg2::default();
        let sender_output = EndemicOTSender::process(&base_sid, &msg1, &mut msg2, &mut OsRng).unwrap();
        let mut sender = SenderOTSeed::default();
        let mut proof = PPRFOutput::default();
        build_pprf(&pprf_sid, &sender_output, &mut sender, &mut proof);

        // Sender changes only choice-0's point in the first base-OT reply.
        // Fixed repr(C): [[33-byte point; 2]; LAMBDA_C]. Prefix ff is invalid.
        bytemuck::bytes_of_mut(&mut msg2)[..33].fill(0xff);
        match receiver.process(&msg2) {
            Err("Decode error") => rejected += 1,
            Err(other) => panic!("unexpected error: {other}"),
            Ok(output) => {
                let mut seed = ReceiverOTSeed::default();
                eval_pprf(&pprf_sid, &output, &proof, &mut seed).unwrap();
                // y* packs complements of the four base choices, first as MSB.
                // Every accepted setup therefore reveals that first choice was 1.
                assert_eq!(seed.random_choices[0] & 8, 0);
                accepted += 1;
            }
        }
        if accepted > 0 && rejected > 0 {
            break;
        }
    }
    assert!(accepted > 0 && rejected > 0, "did not observe both outcomes in 256 independent trials");
    println!("Observed {accepted} accepted PPRF setup(s), all with first base choice 1; {rejected} typed decode rejection(s). No signing or peer retry performed.");
}
