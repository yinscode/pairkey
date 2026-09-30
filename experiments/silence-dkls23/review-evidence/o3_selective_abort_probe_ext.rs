//! Claude's strengthened variant of Astra's probe: fixed trial count, assertion on every accepted
//! outcome, so a wrong packing assumption would fail with overwhelming probability.
use pairkey_dkls23_research::{fresh, pool::hash};
use rand_core::OsRng;
use sl_oblivious::{
    endemic_ot::{EndemicOTMsg1, EndemicOTMsg2, EndemicOTReceiver, EndemicOTSender},
    soft_spoken::{build_pprf, eval_pprf, PPRFOutput, ReceiverOTSeed, SenderOTSeed},
};

#[test]
fn every_accepted_setup_reveals_first_base_choice() {
    let trials = 64;
    let mut accepted = 0;
    let mut rejected = 0;
    for _ in 0..trials {
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
        bytemuck::bytes_of_mut(&mut msg2)[..33].fill(0xff);
        match receiver.process(&msg2) {
            Err("Decode error") => rejected += 1,
            Err(other) => panic!("unexpected error: {other}"),
            Ok(output) => {
                let mut seed = ReceiverOTSeed::default();
                eval_pprf(&pprf_sid, &output, &proof, &mut seed).expect("proof verifies on accepted branch");
                assert_eq!(seed.random_choices[0] & 8, 0, "accepted setup with first base choice 0");
                accepted += 1;
            }
        }
    }
    println!("{trials} trials: {accepted} accepted (all with first base choice 1), {rejected} decode rejections");
    assert_eq!(accepted + rejected, trials);
    assert!(accepted >= 16 && rejected >= 16, "both outcomes should appear often: {accepted}/{rejected}");
}
