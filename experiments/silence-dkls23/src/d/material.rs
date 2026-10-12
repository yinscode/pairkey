//! Extract only correlated donor material from the exact pinned binary layout.
//! No donor Keyshare or signing scalar is cached; no seeds are serialized.
use super::*;
use anyhow::Context;
use sl_dkls23::keygen::Keyshare;
use sl_oblivious::soft_spoken::{ReceiverOTSeed, SenderOTSeed};
use std::time::{Duration, Instant};
use zeroize::Zeroize;
struct Clearing<T: bytemuck::AnyBitPattern + bytemuck::NoUninit>(Box<T>);
impl<T: bytemuck::AnyBitPattern + bytemuck::NoUninit> Drop for Clearing<T> {
    fn drop(&mut self) {
        bytemuck::bytes_of_mut(self.0.as_mut()).zeroize();
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Limits {
    pub uses: u64,
    pub age_secs: u64,
    pub abort_window_secs: u64,
    pub abort_limit: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            uses: 100,
            age_secs: 600,
            abort_window_secs: 60,
            abort_limit: 3,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=100).contains(&self.uses)
                && (self.age_secs == 0 || (1..=600).contains(&self.age_secs))
                && self.abort_limit > 0
                && self.abort_window_secs > 0,
            "invalid D donor hygiene bounds"
        );
        Ok(())
    }
}
pub struct Donor {
    sender: Clearing<SenderOTSeed>,
    receiver: Clearing<ReceiverOTSeed>,
    zero: Zeroizing<Hash>,
    pub generation: Hash,
    pub unused_public_key: Vec<u8>,
    pub role: u8,
    pub identities: [Hash; 2],
    created: Instant,
    pub uses: u64,
    limits: Limits,
}
impl Donor {
    pub fn extract(
        package: Keyshare,
        identities: [Hash; 2],
        role: u8,
        limits: Limits,
    ) -> Result<Self> {
        limits.validate()?;
        ensure!(
            package.party_id == role
                && role < 2
                && package.total_parties == 2
                && package.threshold == 2
                && package.zero_ranks(),
            "invalid donor metadata"
        );
        // Header (172), two EachParty (98 each), one OtherParty (sender,receiver).
        // Alignment=1 at this exact upstream pin. Runtime size checks fail closed.
        const INFO: usize = 172;
        const EACH: usize = 98;
        const OTHER: usize = INFO + 2 * EACH;
        let b = package.as_slice();
        let sender_len = std::mem::size_of::<SenderOTSeed>();
        let receiver_len = std::mem::size_of::<ReceiverOTSeed>();
        ensure!(
            sender_len == 32768
                && receiver_len == 32832
                && b.len() == OTHER + sender_len + receiver_len + package.extra_data().len(),
            "donor pinned layout mismatch"
        );
        let sender = Clearing(Box::new(
            bytemuck::try_pod_read_unaligned(&b[OTHER..OTHER + sender_len])
                .map_err(|_| anyhow::anyhow!("donor sender layout"))?,
        ));
        let receiver = Clearing(Box::new(
            bytemuck::try_pod_read_unaligned(
                &b[OTHER + sender_len..OTHER + sender_len + receiver_len],
            )
            .map_err(|_| anyhow::anyhow!("donor receiver layout"))?,
        ));
        let zero = Zeroizing::new(b[INFO + 66..INFO + 98].try_into().unwrap());
        let generation = package.final_session_id;
        let unused_public_key = package.public_key().to_bytes().to_vec();
        // package drops here and native ZeroizeOnDrop clears the donor share.
        Ok(Self {
            sender,
            receiver,
            zero,
            generation,
            unused_public_key,
            role,
            identities,
            created: Instant::now(),
            uses: 0,
            limits,
        })
    }
    pub fn remaining_age(&self) -> Option<Duration> {
        (self.limits.age_secs != 0).then(|| {
            Duration::from_secs(self.limits.age_secs).saturating_sub(self.created.elapsed())
        })
    }
    pub fn usable(&self) -> bool {
        within_bounds(self.uses, self.created.elapsed(), &self.limits)
    }
    pub fn reserve(&mut self) -> Result<()> {
        ensure!(self.usable(), "D donor bound reached");
        self.uses += 1;
        Ok(())
    }
    pub fn package(&self, root: &Root, record: &Record, instance: Hash) -> Result<Keyshare> {
        ensure!(
            record.public_key != self.unused_public_key,
            "D donor key must never sign"
        );
        ensure!(
            self.identities == record.wallet.identities,
            "D donor pairing mismatch"
        );
        let x = record.local(root, self.role)?;
        let weighted = Zeroizing::new(if self.role == 0 {
            *x * Scalar::from(2u64).invert().unwrap()
        } else {
            -*x
        });
        let points = [
            point(&record.openings[0].point)? * Scalar::from(2u64).invert().unwrap(),
            -point(&record.openings[1].point)?,
        ];
        let sid = digest(
            b"pairkey/d/transient-package/v2",
            &(record.digest(), self.generation, instance),
        );
        Keyshare::pairkey_research_two_party(
            self.role,
            *weighted,
            points,
            point(&record.public_key)?,
            record.wallet.key_id,
            record.chain_code,
            sid,
            &self.zero,
            &self.sender.0,
            &self.receiver.0,
            &instance,
        )
        .context("D transient constructor refused")
    }
    #[cfg(test)]
    pub(crate) fn fingerprint(&self) -> Hash {
        pool::hash(
            "test-only/d/donor-material",
            &[
                bytemuck::bytes_of(self.sender.0.as_ref()),
                bytemuck::bytes_of(self.receiver.0.as_ref()),
                &*self.zero,
            ],
        )
    }
}

fn within_bounds(uses: u64, age: Duration, limits: &Limits) -> bool {
    uses < limits.uses && (limits.age_secs == 0 || age < Duration::from_secs(limits.age_secs))
}
#[cfg(test)]
mod hygiene_tests {
    use super::*;
    #[test]
    fn default_hygiene_is_100_attempts_or_600_seconds_with_strict_edges() {
        let limits = Limits::default();
        assert_eq!(limits.uses, 100);
        assert_eq!(limits.age_secs, 600);
        assert!(within_bounds(99, Duration::from_secs(599), &limits));
        assert!(!within_bounds(100, Duration::ZERO, &limits));
        assert!(within_bounds(
            0,
            Duration::from_secs(600) - Duration::from_nanos(1),
            &limits
        ));
        assert!(!within_bounds(0, Duration::from_secs(600), &limits));
        assert!(!within_bounds(0, Duration::from_secs(601), &limits));
        assert!(Limits {
            uses: 101,
            ..limits.clone()
        }
        .validate()
        .is_err());
        assert!(Limits {
            age_secs: 601,
            ..limits
        }
        .validate()
        .is_err());
    }
    #[test]
    fn explicit_demo_zero_age_keeps_the_attempt_limit() {
        let limits = Limits {
            age_secs: 0,
            ..Limits::default()
        };
        limits.validate().unwrap();
        assert!(within_bounds(99, Duration::from_secs(86_400), &limits));
        assert!(!within_bounds(100, Duration::ZERO, &limits));
    }
}
