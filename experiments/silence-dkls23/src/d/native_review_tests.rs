//! Native implementation evidence only; no composition/security theorem.
use super::*;
use futures_util::{Sink, Stream};
use sl_dkls23::{
    keygen::{self, Keyshare},
    setup::ProtocolParticipant,
    sign,
};
use sl_mpc_mate::{
    coord::{simple::MessageRelay, MessageSendError, Relay, SimpleMessageRelay},
    message::{InstanceId, MessageTag},
};
use std::{
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
type Outcome =
    std::result::Result<(k256::ecdsa::Signature, k256::ecdsa::RecoveryId), sign::SignError>;
struct GuardedRelay {
    relay: MessageRelay,
    guard: Option<Arc<R1Guard>>,
}
impl Stream for GuardedRelay {
    type Item = Vec<u8>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result = Pin::new(&mut self.relay).poll_next(cx);
        if let Poll::Ready(Some(ref bytes)) = result {
            if let Some(g) = &self.guard {
                if g.observe(bytes, false).is_err() {
                    return Poll::Ready(None);
                }
            }
        }
        result
    }
}
impl Sink<Vec<u8>> for GuardedRelay {
    type Error = MessageSendError;
    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.relay).poll_ready(cx)
    }
    fn start_send(
        mut self: Pin<&mut Self>,
        bytes: Vec<u8>,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(g) = &self.guard {
            g.observe(&bytes, true).map_err(|_| MessageSendError)?;
        }
        Pin::new(&mut self.relay).start_send(bytes)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.relay).poll_flush(cx)
    }
    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.relay).poll_close(cx)
    }
}
impl Relay for GuardedRelay {}
async fn donors(f: &Fixture) -> [Donor; 2] {
    let relay = SimpleMessageRelay::new();
    let id = crate::fresh();
    let identities = f
        .wallet
        .identities
        .map(|b| TestIdentity(VerifyingKey::from_bytes(&b).unwrap()))
        .to_vec();
    let setup = |role: usize| {
        sl_dkls23::setup::keygen::SetupMessage::<_, _, Signature>::new(
            InstanceId::new(id),
            f.roots[role].identity(role as u8),
            role,
            identities.clone(),
            &[0, 0],
            2,
        )
    };
    let (a, b) = tokio::join!(
        keygen::run(setup(0), crate::fresh(), relay.connect()),
        keygen::run(setup(1), crate::fresh(), relay.connect())
    );
    [
        Donor::extract(a.unwrap(), f.wallet.identities, 0, Limits::default()).unwrap(),
        Donor::extract(b.unwrap(), f.wallet.identities, 1, Limits::default()).unwrap(),
    ]
}
async fn run(
    f: &Fixture,
    packages: [Keyshare; 2],
    request: Request,
    observer: bool,
) -> ([Outcome; 2], [Arc<R1Guard>; 2]) {
    let relay = SimpleMessageRelay::new();
    let identities = f
        .wallet
        .identities
        .map(|b| TestIdentity(VerifyingKey::from_bytes(&b).unwrap()))
        .to_vec();
    let path = derivation_path::DerivationPath::from_str(&request.path).unwrap();
    let instance = request.instance();
    let packages = packages.map(Arc::new);
    let setups = std::array::from_fn::<_, 2, _>(|r| {
        sl_dkls23::setup::sign::SetupMessage::<_, _, Signature>::new(
            InstanceId::new(instance),
            f.roots[r].identity(r as u8),
            r,
            identities.clone(),
            packages[r].clone(),
        )
        .with_hash(request.prehash)
        .with_chain_path(path.clone())
        // Match the worker's operation budget. Sixteen concurrent debug-mode
        // executions plus other suite fixtures can exceed a two-second test TTL.
        .with_ttl(Duration::from_secs(30))
    });
    let guards = std::array::from_fn::<_, 2, _>(|r| {
        Arc::new(R1Guard::new(
            std::array::from_fn(|role| {
                setups[r]
                    .msg_id_from(role, None, MessageTag::tag(1))
                    .as_ref()
                    .try_into()
                    .unwrap()
            }),
            packages[r].final_session_id,
            r as u8,
            f.wallet.identities,
            f.dir.join("observed-r1"),
        ))
    });
    let mut setups = setups.into_iter();
    let left = setups.next().unwrap();
    let right = setups.next().unwrap();
    let (a, b) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(
            sign::run(
                left,
                *hedged_seed(&[42; 32], instance, 1, 0, "sign"),
                GuardedRelay {
                    relay: relay.connect(),
                    guard: observer.then(|| guards[0].clone())
                }
            ),
            sign::run(
                right,
                *hedged_seed(&[42; 32], instance, 1, 1, "sign"),
                GuardedRelay {
                    relay: relay.connect(),
                    guard: observer.then(|| guards[1].clone())
                }
            )
        )
    })
    .await
    .expect("bounded native attempt");
    ([a, b], guards)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identical_wallet_path_prehash_concurrent_attempts_have_distinct_observed_sessions() {
    let f = Fixture::new();
    let d = donors(&f).await;
    let before = d.each_ref().map(Donor::fingerprint);
    let record = f.record();
    let mut jobs = vec![];
    for _ in 0..16 {
        let request = Request {
            wallet: f.wallet.clone(),
            record: record.digest(),
            generation: d[0].generation,
            path: "m/7/3".into(),
            prehash: [9; 32],
            attempt: crate::fresh(),
            fault: None,
        };
        let packages = std::array::from_fn(|r| {
            d[r].package(&f.roots[r], &record, request.instance())
                .unwrap()
        });
        jobs.push(run(&f, packages, request, true));
    }
    let mut finals = std::collections::BTreeSet::new();
    let mut rs = std::collections::BTreeSet::new();
    for (outcomes, guards) in futures_util::future::join_all(jobs).await {
        assert!(guards.iter().all(|g| g.failure().is_none()));
        let a = outcomes[0].as_ref().unwrap();
        assert_eq!(a, outcomes[1].as_ref().unwrap());
        let sid = guards[0].final_session().unwrap();
        assert_eq!(sid, guards[1].final_session().unwrap());
        assert!(finals.insert(sid));
        assert!(rs.insert(a.0.to_bytes()[..32].to_vec()));
        let key = point(&record.public_key).unwrap();
        let expected = sl_dkls23::keygen::Keyshare::derive_with_offset(
            &d[0].package(&f.roots[0], &record, crate::fresh()).unwrap(),
            &derivation_path::DerivationPath::from_str("m/7/3").unwrap(),
        )
        .unwrap()
        .1;
        assert_ne!(expected, key);
        use signature::hazmat::PrehashVerifier;
        k256::ecdsa::VerifyingKey::from_affine(expected.to_affine())
            .unwrap()
            .verify_prehash(&[9; 32], &a.0)
            .unwrap();
    }
    assert_eq!(finals.len(), 16);
    assert_eq!(before, d.each_ref().map(Donor::fingerprint));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transient_package_tamper_matrix_records_native_validation_boundary() {
    use crate::lifecycle::{Action, Failure};
    let f = Fixture::new();
    let d = donors(&f).await;
    let record = f.record();
    for case in [
        "public-share",
        "coordinate",
        "aggregate-key",
        "key-id",
        "extra",
        "session",
    ] {
        let request = Request {
            wallet: f.wallet.clone(),
            record: record.digest(),
            generation: d[0].generation,
            path: "m".into(),
            prehash: [9; 32],
            attempt: crate::fresh(),
            fault: None,
        };
        let mut packages = std::array::from_fn(|r| {
            d[r].package(&f.roots[r], &record, request.instance())
                .unwrap()
        });
        let mut bytes = Zeroizing::new(packages[1].as_slice().to_vec());
        match case {
            "public-share" => bytes[173..206].copy_from_slice(&public(&Scalar::ONE)),
            "coordinate" => bytes[206..238].copy_from_slice(&Scalar::from(3u64).to_bytes()),
            "aggregate-key" => bytes[75..108].copy_from_slice(&public(&Scalar::ONE)),
            "key-id" => bytes[108] ^= 1,
            "extra" => {
                let n = bytes.len();
                bytes[n - 1] ^= 1
            }
            "session" => bytes[11] ^= 1,
            _ => unreachable!(),
        };
        packages[1] = Keyshare::from_bytes(&bytes).expect("valid pinned encoding");
        let (outcomes, _) = run(&f, packages, request, false).await;
        let expected = match case {
            "public-share" | "key-id" | "extra" => None,
            "session" => Some(Action::Burn),
            _ => Some(Action::FreezeConfiguration),
        };
        if let Some(action) = expected {
            assert!(
                outcomes.iter().all(std::result::Result::is_err),
                "{case}: {outcomes:?}"
            );
            assert!(
                outcomes
                    .iter()
                    .filter_map(|o| o.as_ref().err())
                    .any(|e| Failure::native_sign(e, f.wallet.identities[1]).action == action),
                "{case}: {outcomes:?}"
            );
        } else {
            let result = outcomes[0].as_ref().unwrap();
            assert_eq!(result, outcomes[1].as_ref().unwrap());
            use signature::hazmat::PrehashVerifier;
            k256::ecdsa::VerifyingKey::from_sec1_bytes(&record.public_key)
                .unwrap()
                .verify_prehash(&[9; 32], &result.0)
                .unwrap();
        }
        eprintln!(
            "package tamper {case}: {}",
            if expected.is_none() {
                "native signs valid original wallet; metadata not checked by signing"
            } else {
                "native refuses"
            }
        );
    }
}
