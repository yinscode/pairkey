//! Public deterministic test fixtures, not a malicious-security proof or donor DKG.
//! Run only from the isolated copied crate; never used by any worker.
use k256::Scalar;
use rand_core::{CryptoRng, Error, RngCore};
use sha2::{Digest, Sha256};
use sl_oblivious::{
    params::consts::*,
    rvole::{RVOLEOutput, RVOLEReceiver, RVOLESender},
    soft_spoken::{
        generate_all_but_one_seed_ot, ReceiverExtendedOutput, Round1Output, SoftSpokenOTReceiver,
        SoftSpokenOTSender,
    },
};

// Public deterministic fixtures. The marker is required by the primitive API;
// this source intentionally supplies no production entropy or security claim.
struct FixtureRng {
    label: u64,
    counter: u64,
    block: [u8; 32],
    offset: usize,
}
impl FixtureRng {
    fn new(label: u64) -> Self {
        Self {
            label,
            counter: 0,
            block: [0; 32],
            offset: 32,
        }
    }
}
impl RngCore for FixtureRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            if self.offset == 32 {
                let mut h = Sha256::new();
                h.update(b"pairkey/output-fixing/public-test-fixture");
                h.update(self.label.to_be_bytes());
                h.update(self.counter.to_be_bytes());
                self.block = h.finalize().into();
                self.counter += 1;
                self.offset = 0;
            }
            *byte = self.block[self.offset];
            self.offset += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for FixtureRng {}

fn main() {
    let mut paired_rows = 0;
    let mut complement_rows = 0;
    let mut replayed_rows = 0;
    let mut distinct_sid_rows = 0;
    let mut correctness_checks = 0;
    let mut check_field_refusals = 0;
    let mut x_field_refusals = 0;
    let mut correction_refusals = 0;
    let u_len = LAMBDA_C_DIV_SOFT_SPOKEN_K * L_PRIME_BYTES;
    assert_eq!(u_len, 5120);
    assert_eq!(
        std::mem::size_of::<Round1Output>(),
        u_len + S_BYTES + LAMBDA_C * S_BYTES
    );

    for generation in 0..4u64 {
        // Direct honest correlated-seed helper, not the native DKG/setup protocol.
        let (all_leaves, punctured_leaves) =
            generate_all_but_one_seed_ot(&mut FixtureRng::new(100 + generation));
        let mut prior_pairs: Option<Box<sl_oblivious::soft_spoken::SenderExtendedOutput>> = None;
        for session in 0..4u64 {
            let sid: [u8; 32] =
                Sha256::digest([generation.to_be_bytes(), session.to_be_bytes()].concat()).into();
            let mut round1 = Round1Output::default();
            let mut recv: Box<ReceiverExtendedOutput> = bytemuck::allocation::zeroed_box();
            FixtureRng::new(200 + session).fill_bytes(&mut recv.choices);
            SoftSpokenOTReceiver::process(
                &sid,
                &all_leaves,
                &mut round1,
                &mut recv,
                &mut FixtureRng::new(300 + session),
            );
            let pairs = SoftSpokenOTSender::process(&sid, &punctured_leaves, &round1).unwrap();
            let repeated = SoftSpokenOTSender::process(&sid, &punctured_leaves, &round1).unwrap();
            assert_eq!(
                bytemuck::bytes_of(pairs.as_ref()),
                bytemuck::bytes_of(repeated.as_ref())
            );
            replayed_rows += L;

            for j in 0..L {
                let bit = (recv.choices[j / 8] >> (j % 8)) & 1;
                let selected = if bit == 0 {
                    &pairs.v_0[j]
                } else {
                    &pairs.v_1[j]
                };
                assert_eq!(selected, &recv.v_x[j]);
                paired_rows += 1;
                if let Some(previous) = prior_pairs.as_ref() {
                    // Observed difference; not a mathematical independence test.
                    assert!((pairs.v_0[j], pairs.v_1[j]) != (previous.v_0[j], previous.v_1[j]));
                    distinct_sid_rows += 1;
                }
            }

            // Same SID and leaves, complementary choices: pairs swap order while
            // the honest receiver's selected pads do not change.
            let mut inverse_round1 = Round1Output::default();
            let mut inverse_recv: Box<ReceiverExtendedOutput> = bytemuck::allocation::zeroed_box();
            inverse_recv.choices = recv.choices.map(|byte| !byte);
            SoftSpokenOTReceiver::process(
                &sid,
                &all_leaves,
                &mut inverse_round1,
                &mut inverse_recv,
                &mut FixtureRng::new(300 + session),
            );
            let inverse_pairs =
                SoftSpokenOTSender::process(&sid, &punctured_leaves, &inverse_round1).unwrap();
            assert_eq!(recv.v_x, inverse_recv.v_x);
            for j in 0..L {
                assert_eq!(pairs.v_0[j], inverse_pairs.v_1[j]);
                assert_eq!(pairs.v_1[j], inverse_pairs.v_0[j]);
                complement_rows += 1;
            }

            // x,t are omitted from the matrix-challenge input, but checked by
            // the native sender. Mutating t leaves the entire U prefix intact.
            let mut changed = round1;
            bytemuck::bytes_of_mut(&mut changed)[u_len + S_BYTES] ^= 1;
            assert_eq!(
                &bytemuck::bytes_of(&changed)[..u_len],
                &bytemuck::bytes_of(&round1)[..u_len],
            );
            assert!(SoftSpokenOTSender::process(&sid, &punctured_leaves, &changed).is_err());
            check_field_refusals += 1;
            let mut changed_x = round1;
            bytemuck::bytes_of_mut(&mut changed_x)[u_len] ^= 1;
            assert_eq!(
                &bytemuck::bytes_of(&changed_x)[..u_len],
                &bytemuck::bytes_of(&round1)[..u_len],
            );
            assert!(punctured_leaves
                .random_choices
                .iter()
                .any(|delta| *delta != 0));
            assert!(SoftSpokenOTSender::process(&sid, &punctured_leaves, &changed_x).is_err());
            x_field_refusals += 1;

            let mut vole_round1 = Round1Output::default();
            let (honest_receiver, b) = RVOLEReceiver::new(
                sid,
                &all_leaves,
                &mut vole_round1,
                &mut FixtureRng::new(400 + session),
            );
            let a = [Scalar::from(7u64), Scalar::from(13u64)];
            let mut response = RVOLEOutput::default();
            let c = RVOLESender::process(
                &sid,
                &punctured_leaves,
                &a,
                &vole_round1,
                &mut response,
                &mut FixtureRng::new(500 + session),
            )
            .unwrap();
            let d = honest_receiver.process(&response).unwrap();
            for i in 0..L_BATCH {
                assert_eq!(c[i] + d[i], a[i] * b);
                correctness_checks += 1;
            }
            let mut repeated_response = RVOLEOutput::default();
            let repeated_c = RVOLESender::process(
                &sid,
                &punctured_leaves,
                &a,
                &vole_round1,
                &mut repeated_response,
                &mut FixtureRng::new(500 + session),
            )
            .unwrap();
            assert_eq!(c, repeated_c);
            assert_eq!(
                bytemuck::bytes_of(&response),
                bytemuck::bytes_of(&repeated_response)
            );

            // A simple correction mutation, not an optimized malicious attack.
            let mut changed_response = response;
            bytemuck::bytes_of_mut(&mut changed_response)[KAPPA_BYTES - 1] ^= 1;
            assert!(honest_receiver.process(&changed_response).is_err());
            assert_eq!(honest_receiver.process(&response).unwrap(), d);
            correction_refusals += 1;
            prior_pairs = Some(pairs);
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "public_fixture_generations":4,"sessions_per_generation":4,
            "selected_pad_matches":paired_rows,"same_context_replayed_rows":replayed_rows,
            "complementary_choice_swapped_rows":complement_rows,
            "observed_different_sid_rows":distinct_sid_rows,
            "rvole_product_identities":correctness_checks,
            "unhashed_t_mutations_refused":check_field_refusals,
        "unhashed_x_mutations_refused":x_field_refusals,
            "simple_correction_mutations_refused":correction_refusals,
            "scope":"honest correlated-seed helper; fixed-input algebra/correspondence only",
            "not_claimed":"native donor DKG, malicious setup/extraction, independence, reuse security"
        })
    );
}
