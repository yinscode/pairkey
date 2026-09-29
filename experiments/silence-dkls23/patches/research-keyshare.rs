// PairKey research modification, 2026-10-10. No involvement by Silence Labs.
// Included inside the pinned upstream keyshare module. Signing math is unchanged.
// This local constructor does NOT certify remote OT correlations or setup security.
impl Keyshare {
    /// Restricted two-party research construction; not a production import API.
    #[allow(clippy::too_many_arguments)]
    pub fn pairkey_research_two_party(
        party: u8,
        secret: Scalar,
        public_shares: [ProjectivePoint; 2],
        public_key: ProjectivePoint,
        key_id: [u8; 32],
        chain_code: [u8; 32],
        setup_id: [u8; 32],
        zero_seed: &[u8; 32],
        sender: &SenderOTSeed,
        receiver: &ReceiverOTSeed,
        extra: &[u8],
    ) -> Option<Self> {
        if party > 1 || secret == Scalar::ZERO
            || public_key == ProjectivePoint::IDENTITY
            || public_shares.contains(&ProjectivePoint::IDENTITY)
            || public_shares[0] == public_shares[1]
            || public_shares[0] * Scalar::from(2u64) - public_shares[1] != public_key
            || ProjectivePoint::GENERATOR * secret != public_shares[party as usize]
        {
            return None;
        }
        let mut package = Keyshare::new(2, 2, party, extra);
        let info = package.info_mut();
        info.s_i = encode_scalar(&secret);
        info.public_key = encode_point(&public_key);
        info.key_id = key_id;
        info.root_chain_code = chain_code;
        info.final_session_id = setup_id;
        for (id, point) in public_shares.iter().enumerate() {
            let each = package.each_mut(id as u8);
            each.rank = 0;
            each.x_i = encode_scalar(&Scalar::from(id as u64 + 1));
            each.big_s = encode_point(point);
        }
        // get_zeta_i stores the pair seed in EachParty[0] for both 0 and 1.
        package.each_mut(0).zeta_seed = *zero_seed;
        let other = package.other_mut(1 - party);
        other.send_ot_seed = *sender;
        other.recv_ot_seed = *receiver;
        Some(package)
    }
}
