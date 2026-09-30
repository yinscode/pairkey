//! Review-only integration tests, run in a scratch copy of the experiment.
//! Exercises actual EndemicOT/PPRF, not synthetic seed fixtures. This is not a
//! malicious-security proof and does not exercise the worker/channel/journal.
use k256::Scalar;
use pairkey_dkls23_research::{fresh, pool::hash};
use rand_core::OsRng;
use sl_oblivious::{
    endemic_ot::{EndemicOTMsg1, EndemicOTMsg2, EndemicOTReceiver, EndemicOTSender},
    rvole::{RVOLEOutput, RVOLEReceiver, RVOLESender},
    soft_spoken::{
        build_pprf, eval_pprf, PPRFOutput, ReceiverOTSeed, Round1Output,
        SenderOTSeed, SoftSpokenOTError,
    },
};

fn material(corrupt_proof: bool) -> Result<(SenderOTSeed, ReceiverOTSeed), &'static str> {
    let entry = fresh();
    let base_sid = hash("pairkey/pool/base-ot/v1", &[&entry, &[0], &[1]]);
    let pprf_sid = hash("pairkey/pool/pprf/v1", &[&entry, &[1], &[0]]);
    let mut msg1 = EndemicOTMsg1::default();
    let receiver = EndemicOTReceiver::new(&base_sid, &mut msg1, &mut OsRng);
    let mut msg2 = EndemicOTMsg2::default();
    let sender_output = EndemicOTSender::process(&base_sid, &msg1, &mut msg2, &mut OsRng)?;
    let mut sender = SenderOTSeed::default();
    let mut pprf = PPRFOutput::default();
    build_pprf(&pprf_sid, &sender_output, &mut sender, &mut pprf);
    if corrupt_proof {
        // First proof's s_tilda, after (K-1)*2*32 = 192 t bytes.
        bytemuck::bytes_of_mut(&mut pprf)[192] ^= 1;
    }
    let receiver_output = receiver.process(&msg2)?;
    let mut recv = ReceiverOTSeed::default();
    eval_pprf(&pprf_sid, &receiver_output, &pprf, &mut recv)?;
    Ok((sender, recv))
}

#[test]
fn actual_preprocessing_supports_inputs_chosen_later() {
    // Separate material per direction/case; never reuses a consumed pool entry.
    for wallet in 0..3u8 {
        for direction in 0..2u8 {
            let (sender, receiver) = material(false).unwrap();
            // Online context and inputs exist only after preprocessing finishes.
            let sid = hash("pairkey/review/online/v1", &[&fresh(), &[wallet, direction]]);
            let mut msg1 = Round1Output::default();
            let (bob, b) = RVOLEReceiver::new(sid, &sender, &mut msg1, &mut OsRng);
            let a = [Scalar::generate_biased(&mut OsRng), Scalar::generate_biased(&mut OsRng)];
            let mut msg2 = RVOLEOutput::default();
            let c = RVOLESender::process(&sid, &receiver, &a, &msg1, &mut msg2, &mut OsRng).unwrap();
            let d = bob.process(&msg2).unwrap();
            for i in 0..2 {
                assert_eq!(c[i] + d[i], a[i] * b);
            }
        }
    }
}

#[test]
fn corrupted_pprf_proof_is_rejected_at_setup() {
    assert!(matches!(material(true), Err("Invalid proof")));
}

#[test]
fn mismatched_online_sid_is_rejected_by_softspoken() {
    let (sender, receiver) = material(false).unwrap();
    let sid = fresh();
    let mut other_sid = sid;
    other_sid[0] ^= 1;
    let mut msg1 = Round1Output::default();
    let (_bob, _b) = RVOLEReceiver::new(sid, &sender, &mut msg1, &mut OsRng);
    let mut msg2 = RVOLEOutput::default();
    assert!(matches!(
        RVOLESender::process(&other_sid, &receiver, &[Scalar::ONE; 2], &msg1, &mut msg2, &mut OsRng),
        Err(SoftSpokenOTError::AbortProtocolAndBanReceiver)
    ));
}

#[test]
fn cross_entry_material_is_rejected_by_softspoken() {
    let (sender, _) = material(false).unwrap();
    let (_, unrelated_receiver) = material(false).unwrap();
    let sid = fresh();
    let mut msg1 = Round1Output::default();
    let (_bob, _b) = RVOLEReceiver::new(sid, &sender, &mut msg1, &mut OsRng);
    let mut msg2 = RVOLEOutput::default();
    assert!(matches!(
        RVOLESender::process(&sid, &unrelated_receiver, &[Scalar::ONE; 2], &msg1, &mut msg2, &mut OsRng),
        Err(SoftSpokenOTError::AbortProtocolAndBanReceiver)
    ));
}
