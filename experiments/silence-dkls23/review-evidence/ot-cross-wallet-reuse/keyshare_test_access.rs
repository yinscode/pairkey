// Test-only accessors appended to an extracted pristine source copy by run.py.
// No protocol arithmetic changes. Never reconstructs the aggregate private key.
impl Keyshare {
    /// Copy only the peer OT region for a disposable cross-wallet test.
    pub fn reuse_probe_splice(&self, donor: &Self) -> Self {
        assert_eq!(self.party_id, donor.party_id);
        assert_eq!(self.total_parties, 2);
        let mut out = self.clone();
        let peer = 1 - self.party_id;
        out.other_mut(peer).send_ot_seed = donor.other(peer).send_ot_seed;
        out.other_mut(peer).recv_ot_seed = donor.other(peer).recv_ot_seed;
        let start = Self::INFO + 2 * Self::EACH;
        assert_eq!(&out.as_slice()[..start], &self.as_slice()[..start]);
        assert_eq!(
            &out.as_slice()[start + Self::OTHER..],
            &self.as_slice()[start + Self::OTHER..]
        );
        out
    }
    /// Borrow the secret OT bytes for equality assertions; never print them.
    pub fn reuse_probe_ot_bytes(&self) -> &[u8] {
        let start = Self::INFO + 2 * Self::EACH;
        &self.as_slice()[start..start + Self::OTHER]
    }
}
