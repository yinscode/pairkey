// PairKey review evidence v2, 2026-10-11 (scratch copy only, not part of the pinned source).
#[cfg(test)]
mod pairkey_research_tests {
    use super::*;
    use crate::keygen::utils::gen_keyshares;
    use crate::sign::{run as run_dsg, setup_dsg, SignError};
    use derivation_path::DerivationPath;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use k256::elliptic_curve::ops::MulByGenerator;
    use k256::{NonZeroScalar, ProjectivePoint, Scalar};
    use sl_mpc_mate::coord::SimpleMessageRelay;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::task::JoinSet;

    const INFO: usize = Keyshare::INFO;
    const EACH: usize = Keyshare::EACH;
    const OTHER: usize = Keyshare::OTHER;
    /// setup_dsg signs the fixed prehash [1; 32] under chain path "m".
    const PREHASH: [u8; 32] = [1; 32];
    const BOUND: Duration = Duration::from_secs(60);

    type Outcome = Result<(Signature, RecoveryId), SignError>;

    fn lagrange_at_zero(x: &[NonZeroScalar]) -> [Scalar; 2] {
        let x0: Scalar = *x[0];
        let x1: Scalar = *x[1];
        let l0 = x1 * (x1 - x0).invert().unwrap();
        let l1 = x0 * (x0 - x1).invert().unwrap();
        [l0, l1]
    }

    /// Runs native signing for exactly two parties within a time bound.
    async fn sign_bounded(shares: &[Arc<Keyshare>]) -> Vec<Outcome> {
        assert_eq!(shares.len(), 2);
        let coord = SimpleMessageRelay::new();
        let mut parties = JoinSet::new();
        for (setup, seed) in setup_dsg(None, shares, "m") {
            parties.spawn(run_dsg(setup, seed, coord.connect()));
        }
        let collect = async {
            let mut out = vec![];
            while let Some(fini) = parties.join_next().await {
                out.push(fini.expect("signing task panicked"));
            }
            out
        };
        let out = tokio::time::timeout(BOUND, collect)
            .await
            .expect("signing did not complete within the bound");
        assert_eq!(out.len(), 2, "exactly two completed results");
        out
    }

    /// Every result is a signature that verifies under the derived key with the right recovery id.
    fn verify_all(shares: &[Arc<Keyshare>], results: &[Outcome]) {
        let path = DerivationPath::from_str("m").unwrap();
        let (_, derived) = shares[0].derive_with_offset(&path).unwrap();
        let key = VerifyingKey::from_affine(derived.to_affine()).unwrap();
        assert_eq!(results.len(), 2);
        for r in results {
            let (sig, rec) = r.as_ref().expect("signing failed");
            key.verify_prehash(&PREHASH, sig).expect("signature does not verify");
            assert_eq!(
                VerifyingKey::recover_from_prehash(&PREHASH, sig, *rec).unwrap(),
                key,
                "recovery id"
            );
        }
    }

    /// No signature accepted; at least one party reports the typed error, the other either the
    /// same typed error or the abort it received from the detecting party.
    fn assert_rejected(results: &[Outcome], typed: impl Fn(&SignError) -> bool, what: &str) {
        assert_eq!(results.len(), 2);
        assert!(
            results.iter().all(|r| r.is_err()),
            "{what}: a signature was accepted: {results:?}"
        );
        let n_typed = results.iter().filter(|r| matches!(r, Err(e) if typed(e))).count();
        let n_abort = results
            .iter()
            .filter(|r| matches!(r, Err(SignError::AbortProtocol(_))))
            .count();
        assert!(
            n_typed >= 1 && n_typed + n_abort == 2,
            "{what}: unexpected error classes: {results:?}"
        );
    }

    struct Fixed {
        shares: [Scalar; 2],
        big_s: [ProjectivePoint; 2],
        pk: ProjectivePoint,
    }

    /// Re-share the native key at coordinates 1 and 2, keeping party 0's share.
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
        // Case 1: layout equivalence against a native keyshare, then positive signing.
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
            assert_eq!(&a[..INFO - 32], &b[..INFO - 32], "header bytes");
            if p == 0 {
                assert_eq!(&a[INFO - 32..INFO], &b[INFO - 32..INFO], "party 0 share bytes");
            }
            for i in 0..2usize {
                let off = INFO + i * EACH;
                assert_eq!(a[off], b[off], "rank byte of entry {i}");
                let z = off + 1 + 33 + 32;
                assert_eq!(&a[z..off + EACH], &b[z..off + EACH], "zeta slot of entry {i}");
            }
            let o = INFO + 2 * EACH;
            assert_eq!(&a[o..o + OTHER], &b[o..o + OTHER], "OT seed region");
            assert_eq!(&a[o + OTHER..], &b[o + OTHER..], "extra data");
            assert!(Keyshare::from_bytes(b).is_some(), "native validity check");
            rebuilt.push(Arc::new(r));
        }
        let ok = sign_bounded(&rebuilt).await;
        verify_all(&rebuilt, &ok);
        println!("case 1: layouts agree outside x_i/big_s/s_i; 2 verified signatures from rebuilt keyshares");

        // Case 2: mixed OT material. Party 1 takes its seeds from an independent run.
        let a = gen_keyshares(2, 2, None).await;
        let b = gen_keyshares(2, 2, None).await;
        let fa = reshare_at_one_two(&a);
        let mixed = vec![
            Arc::new(build(0, &fa, &a[0], &a[0].each(0).zeta_seed, a[0].other(1))),
            Arc::new(build(1, &fa, &a[1], &a[1].each(0).zeta_seed, b[1].other(0))),
        ];
        let res = sign_bounded(&mixed).await;
        println!("case 2 (mixed OT material): {res:?}");
        assert_rejected(&res, |e| matches!(e, SignError::AbortProtocolAndBanParty(_)), "mixed OT material");

        // Case 3: mismatched zero seed on a fresh run.
        let c = gen_keyshares(2, 2, None).await;
        let fc = reshare_at_one_two(&c);
        let random_zeta: [u8; 32] = rand::random();
        assert_ne!(random_zeta, c[1].each(0).zeta_seed);
        let zm = vec![
            Arc::new(build(0, &fc, &c[0], &c[0].each(0).zeta_seed, c[0].other(1))),
            Arc::new(build(1, &fc, &c[1], &random_zeta, c[1].other(0))),
        ];
        let res = sign_bounded(&zm).await;
        println!("case 3 (zero seed mismatch): {res:?}");
        assert_rejected(&res, |e| matches!(e, SignError::FailedCheck(_)), "zero seed mismatch");

        // Case 4: identity splice preserving native coordinates and shares. Run D's keyshares
        // receive run E's OT seed regions on both sides; everything else stays native.
        let d = gen_keyshares(2, 2, None).await;
        let e = gen_keyshares(2, 2, None).await;
        let o = INFO + 2 * EACH;
        let mut spliced = vec![];
        for p in 0..2usize {
            let mut bytes = d[p].as_slice().to_vec();
            bytes[o..o + OTHER].copy_from_slice(&e[p].as_slice()[o..o + OTHER]);
            let k = Keyshare::from_vec(bytes).ok().expect("spliced buffer passes native validity check");
            spliced.push(Arc::new(k));
        }
        let ok = sign_bounded(&spliced).await;
        verify_all(&spliced, &ok);
        println!("case 4 (identity splice, consistent seeds both sides): 2 verified signatures");

        // Case 4b: the same splice on one side only must be rejected.
        let mut half = vec![];
        for p in 0..2usize {
            let mut bytes = d[p].as_slice().to_vec();
            if p == 0 {
                bytes[o..o + OTHER].copy_from_slice(&e[0].as_slice()[o..o + OTHER]);
            }
            half.push(Arc::new(Keyshare::from_vec(bytes).ok().unwrap()));
        }
        let res = sign_bounded(&half).await;
        println!("case 4b (one-sided splice): {res:?}");
        assert_rejected(&res, |e| matches!(e, SignError::AbortProtocolAndBanParty(_)), "one-sided OT splice");
        // Case 5: two valid sharings of the same key at coordinates 1 and 2, mixed across the
        // parties. Models peers holding packages from different refresh generations.
        let f = gen_keyshares(2, 2, None).await;
        let ff = reshare_at_one_two(&f);
        let delta = Scalar::from(7u64);
        let alt_shares = [ff.shares[0] + delta, ff.shares[1] + delta + delta];
        let alt = Fixed {
            shares: alt_shares,
            big_s: [
                ProjectivePoint::mul_by_generator(&alt_shares[0]),
                ProjectivePoint::mul_by_generator(&alt_shares[1]),
            ],
            pk: ff.pk,
        };
        assert_eq!(
            ProjectivePoint::mul_by_generator(&(Scalar::from(2u64) * alt_shares[0] - alt_shares[1])),
            ff.pk,
            "alternate sharing reconstructs the same key"
        );
        let gen_mismatch = vec![
            Arc::new(build(0, &ff, &f[0], &f[0].each(0).zeta_seed, f[0].other(1))),
            Arc::new(build(1, &alt, &f[1], &f[1].each(0).zeta_seed, f[1].other(0))),
        ];
        let res = sign_bounded(&gen_mismatch).await;
        println!("case 5 (mismatched share generations): {res:?}");
        assert!(res.iter().all(|r| r.is_err()), "mismatched generations must not sign: {res:?}");
    }
}
