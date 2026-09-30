// PairKey review evidence, 2026-10-11 (scratch copy only, not part of the pinned source).
#[cfg(test)]
mod pairkey_research_tests {
    use super::*;
    use crate::keygen::utils::gen_keyshares;
    use crate::sign::{run as run_dsg, setup_dsg};
    use k256::elliptic_curve::ops::MulByGenerator;
    use k256::{NonZeroScalar, ProjectivePoint, Scalar};
    use sl_mpc_mate::coord::SimpleMessageRelay;
    use std::sync::Arc;
    use tokio::task::JoinSet;

    const INFO: usize = Keyshare::INFO;
    const EACH: usize = Keyshare::EACH;
    const OTHER: usize = Keyshare::OTHER;

    fn lagrange_at_zero(x: &[NonZeroScalar]) -> [Scalar; 2] {
        let x0: Scalar = *x[0];
        let x1: Scalar = *x[1];
        let l0 = x1 * (x1 - x0).invert().unwrap();
        let l1 = x0 * (x0 - x1).invert().unwrap();
        [l0, l1]
    }

    async fn sign_collect(shares: &[Arc<Keyshare>]) -> Vec<Result<(), String>> {
        let coord = SimpleMessageRelay::new();
        let mut parties = JoinSet::new();
        for (setup, seed) in setup_dsg(None, shares, "m") {
            parties.spawn(run_dsg(setup, seed, coord.connect()));
        }
        let mut out = vec![];
        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();
            out.push(fini.map(|_| ()).map_err(|e| format!("{e:?}")));
        }
        out
    }

    struct Fixed {
        shares: [Scalar; 2],
        big_s: [ProjectivePoint; 2],
        pk: ProjectivePoint,
    }

    // Re-share the native key at coordinates 1 and 2, keeping party 0's share.
    fn reshare_at_one_two(native: &[Arc<Keyshare>]) -> Fixed {
        let x = native[0].x_i_list();
        let lam = lagrange_at_zero(&x);
        let sk = lam[0] * native[0].s_i() + lam[1] * native[1].s_i();
        let pk = native[0].public_key();
        assert_eq!(ProjectivePoint::mul_by_generator(&sk), pk, "lagrange reconstruction");
        let s0 = native[0].s_i();
        let s1 = Scalar::from(2u64) * s0 - sk;
        Fixed {
            shares: [s0, s1],
            big_s: [
                ProjectivePoint::mul_by_generator(&s0),
                ProjectivePoint::mul_by_generator(&s1),
            ],
            pk,
        }
    }

    fn build(
        p: usize,
        fixed: &Fixed,
        meta: &Keyshare,
        zeta: &[u8; 32],
        seeds: &details::OtherParty,
    ) -> Keyshare {
        let info = meta.info();
        Keyshare::pairkey_research_two_party(
            p as u8,
            fixed.shares[p],
            fixed.big_s,
            fixed.pk,
            info.key_id,
            info.root_chain_code,
            info.final_session_id,
            zeta,
            &seeds.send_ot_seed,
            &seeds.recv_ot_seed,
            meta.extra_data(),
        )
        .expect("constructor accepts native-derived inputs")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn constructor_layout_matches_native_and_rebuilt_shares_sign() {
        let native = gen_keyshares(2, 2, None).await;
        assert_eq!(native.len(), 2);
        let fixed = reshare_at_one_two(&native);

        let mut rebuilt = vec![];
        for p in 0..2usize {
            let nat = &native[p];
            let r = build(p, &fixed, nat, &nat.each(0).zeta_seed, nat.other(1 - p as u8));
            let a = nat.as_slice();
            let b = r.as_slice();
            assert_eq!(a.len(), b.len(), "buffer size");
            // Header: everything except the 32-byte s_i tail is identical; party 0 keeps its share.
            assert_eq!(&a[..INFO - 32], &b[..INFO - 32], "header bytes");
            if p == 0 {
                assert_eq!(&a[INFO - 32..INFO], &b[INFO - 32..INFO], "party 0 share bytes");
            }
            // EachParty: rank byte and zeta slot identical; x_i and big_s differ by design.
            for i in 0..2usize {
                let off = INFO + i * EACH;
                assert_eq!(a[off], b[off], "rank byte of entry {i}");
                let z = off + 1 + 33 + 32;
                assert_eq!(&a[z..off + EACH], &b[z..off + EACH], "zeta slot of entry {i}");
            }
            // OtherParty: the whole 65,600-byte OT seed region identical.
            let o = INFO + 2 * EACH;
            assert_eq!(&a[o..o + OTHER], &b[o..o + OTHER], "OT seed region");
            assert_eq!(&a[o + OTHER..], &b[o + OTHER..], "extra data");
            assert!(Keyshare::from_bytes(b).is_some(), "native validity check");
            println!("party {p}: native and rebuilt layouts agree outside x_i/big_s/s_i");
            rebuilt.push(Arc::new(r));
        }

        let ok = sign_collect(&rebuilt).await;
        assert!(ok.iter().all(|r| r.is_ok()), "signing with rebuilt keyshares failed: {ok:?}");
        println!("signing with rebuilt keyshares succeeded");

        // Mismatched OT material: party 1 takes its seeds from an independent DKG run.
        let other_run = gen_keyshares(2, 2, None).await;
        let mixed = vec![
            Arc::new(build(0, &fixed, &native[0], &native[0].each(0).zeta_seed, native[0].other(1))),
            Arc::new(build(1, &fixed, &native[1], &native[1].each(0).zeta_seed, other_run[1].other(0))),
        ];
        let res = sign_collect(&mixed).await;
        println!("mixed OT material results: {res:?}");
        assert!(res.iter().any(|r| r.is_err()), "mismatched OT material must not sign");

        // Mismatched zero seed: party 1 uses a random seed.
        let random_zeta: [u8; 32] = rand::random();
        let zeta_mismatch = vec![
            Arc::new(build(0, &fixed, &native[0], &native[0].each(0).zeta_seed, native[0].other(1))),
            Arc::new(build(1, &fixed, &native[1], &random_zeta, native[1].other(0))),
        ];
        let res = sign_collect(&zeta_mismatch).await;
        println!("zero seed mismatch results: {res:?}");
        assert!(res.iter().any(|r| r.is_err()), "mismatched zero seed must not sign");
    }
}
