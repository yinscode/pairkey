//! Disposable primitive probes. Passing controls do not validate donor composition.
use pairkey_dkls23_research::fresh;
use rand_core::OsRng;
use sl_oblivious::{endemic_ot::*, soft_spoken::*};
#[test]
fn reused_base_and_extension_sid_expose_choice_xor_but_fresh_sid_breaks_it() {
    let sid = fresh();
    let psid = fresh();
    let mut m1 = EndemicOTMsg1::default();
    let recv = EndemicOTReceiver::new(&sid, &mut m1, &mut OsRng);
    let mut m2 = EndemicOTMsg2::default();
    let send = EndemicOTSender::process(&sid, &m1, &mut m2, &mut OsRng).unwrap();
    let recv = recv.process(&m2).unwrap();
    let mut s = SenderOTSeed::default();
    let mut r = ReceiverOTSeed::default();
    let mut proof = PPRFOutput::default();
    build_pprf(&psid, &send, &mut s, &mut proof);
    eval_pprf(&psid, &recv, &proof, &mut r).unwrap();
    let extension = |id: [u8; 32], value: u8| {
        let mut output: Box<ReceiverExtendedOutput> = bytemuck::allocation::zeroed_box();
        output.choices.fill(value);
        let mut message = Round1Output::default();
        SoftSpokenOTReceiver::process(&id, &s, &mut message, &mut output, &mut OsRng);
        message
    };
    let id = fresh();
    let a = extension(id, 0x35);
    let b = extension(id, 0xa7);
    assert!(SoftSpokenOTSender::process(&id, &r, &a).is_ok());
    assert!(SoftSpokenOTSender::process(&id, &r, &b).is_ok());
    let ab = bytemuck::bytes_of(&a);
    let bb = bytemuck::bytes_of(&b);
    assert!((0..32).all(|i| ab[i] ^ bb[i] == 0x35 ^ 0xa7));
    let other = fresh();
    let c = extension(other, 0xa7);
    assert!(SoftSpokenOTSender::process(&other, &r, &c).is_ok());
    assert!((0..32).any(|i| ab[i] ^ bytemuck::bytes_of(&c)[i] != 0x35 ^ 0xa7));
    assert!(SoftSpokenOTSender::process(&other, &r, &a).is_err());
    let mut bad = c;
    bytemuck::bytes_of_mut(&mut bad)[0] ^= 1;
    assert!(SoftSpokenOTSender::process(&other, &r, &bad).is_err());
}
#[test]
fn selective_abort_each_accepted_setup_reveals_same_base_choice() {
    let mut accepted = 0;
    let mut rejected = 0;
    for _ in 0..64 {
        let sid = fresh();
        let psid = fresh();
        let mut m1 = EndemicOTMsg1::default();
        let recv = EndemicOTReceiver::new(&sid, &mut m1, &mut OsRng);
        let mut m2 = EndemicOTMsg2::default();
        let send = EndemicOTSender::process(&sid, &m1, &mut m2, &mut OsRng).unwrap();
        let mut s = SenderOTSeed::default();
        let mut proof = PPRFOutput::default();
        build_pprf(&psid, &send, &mut s, &mut proof);
        bytemuck::bytes_of_mut(&mut m2)[..33].fill(0xff);
        match recv.process(&m2) {
            Err("Decode error") => rejected += 1,
            Err(e) => panic!("unexpected {e}"),
            Ok(output) => {
                let mut seed = ReceiverOTSeed::default();
                eval_pprf(&psid, &output, &proof, &mut seed).unwrap();
                assert_eq!(seed.random_choices[0] & 8, 0);
                accepted += 1;
            }
        }
    }
    assert_eq!(accepted + rejected, 64);
    assert!(accepted > 0 && rejected > 0);
    eprintln!("selective-abort probe: {accepted} accepted, {rejected} rejected; every accepted branch matches leaked base choice");
}
