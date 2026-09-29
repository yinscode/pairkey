use crate::wire::{self, SetupChannel, Wire};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use k256::{elliptic_curve::group::GroupEncoding, Scalar};
use pairkey_dkls23_research::lifecycle::{scope_dir, Failure, FailureKind, Phase, ReleaseGate};
use pairkey_dkls23_research::{
    digest, fresh, point, reserve, Frame, Hello, Outcome, Request, Root, Route,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sl_dkls23::{
    keygen::{migration, Keyshare},
    setup::{keygen, sign},
};
use sl_mpc_mate::message::InstanceId;
use sl_oblivious::{
    endemic_ot::{EndemicOTMsg1, EndemicOTMsg2, EndemicOTReceiver, EndemicOTSender},
    soft_spoken::{build_pprf, eval_pprf, PPRFOutput, ReceiverOTSeed, SenderOTSeed},
};
use std::{
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
struct Identity(VerifyingKey);
impl AsRef<[u8]> for Identity {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl signature::Verifier<Signature> for Identity {
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> std::result::Result<(), signature::Error> {
        self.0.verify_strict(message, signature)
    }
}
struct Clearing<T: bytemuck::AnyBitPattern + bytemuck::NoUninit>(T);
impl<T: bytemuck::AnyBitPattern + bytemuck::NoUninit> Drop for Clearing<T> {
    fn drop(&mut self) {
        bytemuck::bytes_of_mut(&mut self.0).zeroize();
    }
}
#[derive(Serialize, Deserialize)]
struct OtReply {
    msg2: Vec<u8>,
    pprf: Vec<u8>,
}
impl Drop for OtReply {
    fn drop(&mut self) {
        self.msg2.zeroize();
        self.pprf.zeroize();
    }
}

async fn direct(
    root: &Root,
    role: u8,
    request: &Request,
    channel: &SetupChannel,
    wire: &mut Wire,
) -> Result<Keyshare> {
    let setup_failure = |message| {
        Failure::violation(
            Phase::DirectSetup,
            request.manifest.identities[(1 - role) as usize],
            message,
        )
    };
    let contribution = root.derive(role, request.manifest.key_id)?;
    let secret = Zeroizing::new(if role == 0 {
        *contribution * Scalar::from(2u64).invert().unwrap()
    } else {
        -*contribution
    });

    // Joint zero-share coin: commit before either contribution is disclosed.
    let coin = Zeroizing::new(fresh());
    let commitment = digest(
        b"pairkey/dkls-research/zero-coin/v1",
        &(request.context(), role, &*coin),
    );
    let peer_commitment: [u8; 32] = channel.exchange(wire, "zero-commit", &commitment).await?;
    let mut revealed = Zeroizing::new(*coin);
    if request.fault_is("bad-zero-reveal") && role == 1 {
        revealed[0] ^= 1;
    }
    let peer_coin: Zeroizing<[u8; 32]> =
        Zeroizing::new(channel.exchange(wire, "zero-reveal", &*revealed).await?);
    if peer_commitment
        != digest(
            b"pairkey/dkls-research/zero-coin/v1",
            &(request.context(), 1 - role, &*peer_coin),
        )
    {
        return Err(Failure::violation(
            Phase::DirectSetup,
            request.manifest.identities[(1 - role) as usize],
            "zero-share commitment mismatch",
        )
        .into());
    }
    let coins = Zeroizing::new(if role == 0 {
        (*coin, *peer_coin)
    } else {
        (*peer_coin, *coin)
    });
    let zero_seed = Zeroizing::new(digest(
        b"pairkey/dkls-research/zero-seed/v1",
        &(request.context(), &*coins),
    ));

    let receiver_sid = digest(
        b"pairkey/dkls-research/base-ot/v1",
        &(request.context(), role, 1 - role),
    );
    let sender_sid = digest(
        b"pairkey/dkls-research/base-ot/v1",
        &(request.context(), 1 - role, role),
    );
    let mut msg1 = EndemicOTMsg1::default();
    let receiver = EndemicOTReceiver::new(&receiver_sid, &mut msg1, &mut OsRng);
    let peer_msg1: Vec<u8> = channel
        .exchange(wire, "base-ot-1", &bytemuck::bytes_of(&msg1))
        .await?;
    let peer_msg1 = Zeroizing::new(peer_msg1);
    let peer_msg1: EndemicOTMsg1 = bytemuck::try_pod_read_unaligned(peer_msg1.as_slice())
        .map_err(|_| setup_failure("invalid base OT message length"))?;
    let mut msg2 = EndemicOTMsg2::default();
    let sender_output = EndemicOTSender::process(&sender_sid, &peer_msg1, &mut msg2, &mut OsRng)
        .map_err(setup_failure)?;
    let mut sender_seed = Clearing(SenderOTSeed::default());
    let mut receiver_seed = Clearing(ReceiverOTSeed::default());
    let mut pprf = PPRFOutput::default();
    let pprf_send_sid = digest(
        b"pairkey/dkls-research/pprf/v1",
        &(request.context(), role, 1 - role),
    );
    let pprf_recv_sid = digest(
        b"pairkey/dkls-research/pprf/v1",
        &(request.context(), 1 - role, role),
    );
    build_pprf(
        &pprf_send_sid,
        &sender_output,
        &mut sender_seed.0,
        &mut pprf,
    );
    let mut reply = OtReply {
        msg2: bytemuck::bytes_of(&msg2).to_vec(),
        pprf: bytemuck::bytes_of(&pprf).to_vec(),
    };
    if request.fault_is("bad-ot") && role == 1 {
        reply.msg2.fill(0);
    }
    if request.fault_is("truncated-ot") && role == 1 {
        reply.msg2.truncate(1);
    }
    if request.fault_is("truncated-pprf") && role == 1 {
        reply.pprf.truncate(1);
    }
    let peer: OtReply = channel.exchange(wire, "base-ot-2", &reply).await?;
    let peer_msg2: EndemicOTMsg2 = bytemuck::try_pod_read_unaligned(&peer.msg2)
        .map_err(|_| setup_failure("invalid base OT reply length"))?;
    let peer_pprf: PPRFOutput = bytemuck::try_pod_read_unaligned(&peer.pprf)
        .map_err(|_| setup_failure("invalid PPRF length"))?;
    let output = receiver.process(&peer_msg2).map_err(setup_failure)?;
    eval_pprf(&pprf_recv_sid, &output, &peer_pprf, &mut receiver_seed.0).map_err(setup_failure)?;
    if request.fault_is("corrupt-ot") && role == 1 {
        for row in &mut sender_seed.0.otp_enc_keys {
            for leaf in row {
                leaf[0] ^= 1;
            }
        }
    }
    Keyshare::pairkey_research_two_party(
        role,
        *secret,
        request.manifest.stored_public()?,
        point(&request.manifest.public_key)?,
        request.manifest.key_id,
        request.manifest.chain_code,
        request.context(),
        &zero_seed,
        &sender_seed.0,
        &receiver_seed.0,
        &request.manifest.digest(),
    )
    .context("research constructor refused")
}

async fn execute(
    root: &Root,
    role: u8,
    request: &Request,
    dh: &StaticSecret,
    wire: &mut Wire,
    controls: &Path,
    gate: &ReleaseGate,
) -> Result<Outcome> {
    let result = tokio::select! {
        biased;
        _=gate.cancelled()=>Err(Failure::burn(Phase::Control,FailureKind::Quarantined,"active attempt cancelled by incident cutoff").into()),
        result=execute_inner(root,role,request,dh,wire,controls,gate)=>result,
    };
    result.map_err(|error: anyhow::Error| {
        let failure = error.downcast_ref::<Failure>().cloned().unwrap_or_else(|| {
            Failure::burn(Phase::Admission, FailureKind::Local, format!("{error:#}"))
        });
        gate.apply(failure, request.context()).into()
    })
}

async fn execute_inner(
    root: &Root,
    role: u8,
    request: &Request,
    dh: &StaticSecret,
    wire: &mut Wire,
    controls: &Path,
    gate: &ReleaseGate,
) -> Result<Outcome> {
    request.validate()?;
    let contribution = request.manifest.check_local(root, role)?;
    gate.release(|| Ok(()))?;
    wire.gate = Some(gate.clone());
    // Burn before setup: interruptions, malformed data and uncertain peer state
    // cannot release the entry back to availability.
    gate.release(|| {
        reserve(
            &controls.join("entries"),
            role,
            request.entry,
            request.context(),
        )
    })?;
    let channel = SetupChannel::new(dh, request, role)?;
    let peer_context: [u8; 32] = channel
        .exchange(wire, "reservation", &request.context())
        .await?;
    ensure!(
        peer_context == request.context(),
        "reservation disagreement"
    );
    let identities = request
        .manifest
        .identities
        .iter()
        .map(|bytes| Ok(Identity(VerifyingKey::from_bytes(bytes)?)))
        .collect::<Result<Vec<_>>>()?;
    let started = Instant::now();
    let (setup_future, setup_active) = crate::measure::active(async {
        Ok::<_, anyhow::Error>(match request.route {
            Route::Migration => {
                let setup = keygen::SetupMessage::<_, _, Signature>::new(
                    InstanceId::new(request.context()),
                    root.identity(role),
                    role as usize,
                    identities.clone(),
                    &[0, 0],
                    2,
                )
                .with_key_id(Some(request.manifest.key_id))
                .with_ttl(Duration::from_secs(30));
                let abort = wire.watch_abort(&setup, request.fault_is("migration-pprf-abort-send"));
                let seed = Zeroizing::new(fresh());
                migration::run(
                    setup,
                    *seed,
                    &mut *wire,
                    *contribution,
                    point(&request.manifest.public_key)?,
                    request.manifest.chain_code,
                )
                .await
                .map_err(|error| {
                    let mut failure = Failure::native_migration(
                        &error,
                        request.manifest.identities[(1 - role) as usize],
                    );
                    failure.abort_send_failed = abort.load(std::sync::atomic::Ordering::SeqCst);
                    if failure.abort_send_failed {
                        failure
                            .detail
                            .push_str("; abort send failed (original violation preserved)");
                    }
                    failure
                })?
            }
            Route::Direct => direct(root, role, request, &channel, wire).await?,
            Route::Pooled => anyhow::bail!("pooled route requires pool-worker"),
        })
    });
    let mut package = setup_future.await?;
    let setup_ms = started.elapsed().as_secs_f64() * 1000.0;
    ensure!(
        package.party_id == role
            && package.total_parties == 2
            && package.threshold == 2
            && package.zero_ranks()
            && package.public_key().to_bytes().as_slice() == request.manifest.public_key
            && package.root_chain_code() == request.manifest.chain_code
            && package.key_id == request.manifest.key_id,
        "package/manifest mismatch"
    );
    let path = derivation_path::DerivationPath::from_str(&request.path)?;
    let (_, derived) = package.derive_with_offset(&path)?;
    let package_bytes = package.as_slice().len();
    let setup_id = package.final_session_id.to_vec();
    let ready: [u8; 32] = channel.exchange(wire, "ready", &request.context()).await?;
    ensure!(ready == request.context(), "peer readiness mismatch");
    wire.send(Frame::Ready(request.context()))?;
    gate.release(|| Ok(()))?;
    if request.fault_is("duplicate-party") && role == 1 {
        // Authenticated malicious R1 claim. Header byte 10 is party_id in the
        // exact pinned format. This is only a negative fixture, not construction.
        let mut bytes = Zeroizing::new(package.as_slice().to_vec());
        bytes[10] = 0;
        package = Keyshare::from_bytes(&bytes).context("duplicate-party fixture decode")?;
    }
    let setup = sign::SetupMessage::<_, _, Signature>::new(
        InstanceId::new(digest(
            b"pairkey/dkls-research/sign-instance/v1",
            &request.context(),
        )),
        root.identity(role),
        role as usize,
        identities,
        Arc::new(package),
    )
    .with_chain_path(path)
    .with_hash(request.prehash)
    .with_ttl(Duration::from_secs(30));
    #[cfg(all(test, feature = "research-faults"))]
    if let Some(probe) = &mut wire.partial_probe {
        use sl_dkls23::setup::ProtocolParticipant;
        probe.id = setup
            .msg_id(None, sl_mpc_mate::message::MessageTag::tag(4))
            .as_ref()
            .try_into()
            .unwrap();
        probe.trace.r4_ids.lock().unwrap().insert(probe.id);
    }
    let seed = Zeroizing::new(fresh());
    #[cfg(all(test, feature = "research-faults"))]
    if let Some(probe) = &mut wire.process_probe {
        use sl_dkls23::setup::ProtocolParticipant;
        probe.r4 = setup
            .msg_id(None, sl_mpc_mate::message::MessageTag::tag(4))
            .as_ref()
            .try_into()
            .unwrap();
    }
    let started = Instant::now();
    let (sign_future, sign_active) =
        crate::measure::active(sl_dkls23::sign::run(setup, *seed, &mut *wire));
    let result = tokio::select! {
        biased;
        _ = gate.cancelled() => return Err(Failure::burn(Phase::Signing,FailureKind::Quarantined,"active attempt cancelled by incident cutoff").into()),
        result = sign_future => result,
    };
    let (signature, recovery) = match result {
        Ok(result) => result,
        Err(error) => {
            return Err(Failure::native_sign(
                &error,
                request.manifest.identities[(1 - role) as usize],
            )
            .into());
        }
    };
    use signature::hazmat::PrehashVerifier;
    k256::ecdsa::VerifyingKey::from_affine(derived.to_affine())?
        .verify_prehash(&request.prehash, &signature)?;
    ensure!(signature.normalize_s().is_none(), "high-S output");
    Ok(Outcome {
        role,
        route: request.route,
        context: request.context(),
        public_key: derived.to_bytes().to_vec(),
        signature: signature.to_bytes().to_vec(),
        recovery_id: recovery.to_byte(),
        setup_ms,
        signing_ms: started.elapsed().as_secs_f64() * 1000.0,
        setup_active_poll_ms: Some(crate::measure::milliseconds(&setup_active)),
        signing_active_poll_ms: crate::measure::milliseconds(&sign_active),
        package_bytes,
        setup_id,
    })
}

pub async fn run(role: u8, root_path: &Path, key_id: [u8; 32]) -> Result<()> {
    let root = Root::load(root_path)?;
    let dh_seed = Zeroizing::new(fresh());
    let dh = StaticSecret::from(*dh_seed);
    let hello = Hello::new(&root, role, key_id, PublicKey::from(&dh).to_bytes())?;
    let (mut wire, writer, reader) = wire::stdio();
    #[cfg(all(test, feature = "research-faults"))]
    {
        wire.process_probe = crate::process_probe::Probe::from_env(role);
    }
    wire.send(Frame::Hello(hello.clone()))?;

    let result = async {
        let Frame::Start(request) = wire.receive().await? else {
            anyhow::bail!("expected start");
        };
        ensure!(
            request.hellos[role as usize].message() == hello.message(),
            "own boot/hello substituted"
        );
        let controls = root_path
            .parent()
            .context("root directory")?
            .join("controls");
        request.validate()?;
        let gate = ReleaseGate::new(scope_dir(&controls, &request.manifest), role);

        tokio::time::timeout(
            Duration::from_secs(30),
            execute(&root, role, &request, &dh, &mut wire, &controls, &gate),
        )
        .await
        .map_err(|_| Failure::burn(Phase::Control, FailureKind::Timeout, "attempt timeout"))?
    }
    .await;
    match result {
        Ok(out) => wire.send(Frame::Result(out))?,
        Err(error) => {
            let failure = error.downcast_ref::<Failure>().cloned().unwrap_or_else(|| {
                Failure::burn(Phase::Admission, FailureKind::Local, format!("{error:#}"))
            });
            wire.send(Frame::Failure(failure))?;
        }
    }
    drop(wire);
    writer.await??;
    reader.abort();
    Ok(())
}

#[cfg(all(test, feature = "research-faults"))]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use pairkey_dkls23_research::{public, Manifest};
    use sl_mpc_mate::coord::SimpleMessageRelay;
    use std::sync::Barrier;
    use tokio::sync::mpsc;

    async fn r4_case(publish_incident: bool, bypass_gate: bool) -> Arc<wire::QueueTrace> {
        let dir = std::env::temp_dir().join(format!("dkls-multi-{:?}", fresh()));
        std::fs::create_dir(&dir).unwrap();
        for role in 0..2 {
            std::fs::write(dir.join(format!("root-{role}")), [11 + role as u8; 32]).unwrap();
        }
        let roots: Vec<_> = (0..2)
            .map(|role| Arc::new(Root::load(&dir.join(format!("root-{role}"))).unwrap()))
            .collect();
        let key_id = [7; 32];
        let contributions = [
            public(&roots[0].derive(0, key_id).unwrap()),
            public(&roots[1].derive(1, key_id).unwrap()),
        ];
        let q = point(&contributions[0]).unwrap() + point(&contributions[1]).unwrap();
        let manifest = Manifest {
            version: 1,
            key_id,
            identities: [
                roots[0].identity(0).verifying_key().to_bytes(),
                roots[1].identity(1).verifying_key().to_bytes(),
            ],
            additive_public: contributions,
            public_key: q.to_bytes().to_vec(),
            chain_code: [8; 32],
        };
        let gate = ReleaseGate::new(scope_dir(&dir.join("controls"), &manifest), 0);
        let barrier = Arc::new(Barrier::new(3));
        let trace = Arc::new(wire::QueueTrace::default());
        let publisher = {
            let barrier = barrier.clone();
            let gate = gate.clone();
            let trace = trace.clone();
            std::thread::spawn(move || {
                barrier.wait();
                assert_eq!(
                    trace.reached.load(std::sync::atomic::Ordering::SeqCst),
                    2,
                    "both executions must reach native R4 before publication"
                );
                if publish_incident {
                    gate.publish([9; 32]).unwrap();
                    trace
                        .cutoff
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
                barrier.wait();
            })
        };
        let mut tasks = vec![];
        let mut pumps = vec![];
        for _ in 0..2 {
            let dhs = [StaticSecret::from(fresh()), StaticSecret::from(fresh())];
            let request = Arc::new(Request {
                route: Route::Direct,
                manifest: manifest.clone(),
                hellos: [
                    Hello::new(&roots[0], 0, key_id, PublicKey::from(&dhs[0]).to_bytes()).unwrap(),
                    Hello::new(&roots[1], 1, key_id, PublicKey::from(&dhs[1]).to_bytes()).unwrap(),
                ],
                entry: fresh(),
                attempt: fresh(),
                path: "m".into(),
                prehash: [6; 32],
                wallet_record: None,
                fault: None,
            });
            let coordinator = SimpleMessageRelay::new();
            let mut native_inputs = vec![];
            let mut control_inputs = vec![];
            let mut outputs = vec![];
            let mut wires = vec![];
            for role in 0..2 {
                let (tx, out) = mpsc::unbounded_channel();
                let (incoming, rx) = mpsc::unbounded_channel();
                let (controls, control) = mpsc::unbounded_channel();
                native_inputs.push(incoming);
                control_inputs.push(controls);
                outputs.push(out);
                wires.push(Wire {
                    tx,
                    rx,
                    control,
                    gate: None,
                    abort_watch: None,
                    process_probe: None,
                    partial_probe: if role == 0 {
                        Some(wire::PartialProbe {
                            id: [0; 32],
                            barrier: barrier.clone(),
                            trace: trace.clone(),
                            bypass_gate,
                        })
                    } else {
                        None
                    },
                });
            }
            for role in 0..2 {
                let mut relay = coordinator.connect();
                let mut out = outputs.remove(0);
                let peer = control_inputs[1 - role].clone();
                let native = native_inputs[role].clone();
                let observed = trace.clone();
                pumps.push(tokio::spawn(async move {
                    let mut native_open=true;
                    loop {tokio::select! {
                        frame=out.recv()=>match frame {
                            Some(Frame::Setup(bytes))=>{let _=peer.send(Frame::Setup(bytes));},
                            Some(Frame::Relay(bytes))=>{
                                // Observe the actual outgoing queue independently
                                // of Wire::send, its gate and returned cancellation.
                                if role==0 && bytes.get(..32).is_some_and(|id|observed.r4_ids.lock().unwrap().iter().any(|expected|expected.as_slice()==id)) {
                                    observed.r4_handoffs.lock().unwrap().push(observed.cutoff.load(std::sync::atomic::Ordering::SeqCst));
                                }
                                let _=relay.send(bytes).await;
                            },
                            Some(_)=>{},None=>break
                        },
                        bytes=relay.next(),if native_open=>{
                            match bytes {
                                Some(bytes)=>if native.send(bytes).is_err(){native_open=false;},
                                None=>native_open=false,
                            }
                        }
                    }}
                }));
            }
            for (role, (mut wire, dh)) in wires.into_iter().zip(dhs).enumerate() {
                let root = roots[role].clone();
                let request = request.clone();
                let controls = dir.join("controls");
                let gate = if role == 0 {
                    gate.clone()
                } else {
                    ReleaseGate::new(scope_dir(&controls, &manifest), 1)
                };
                tasks.push((
                    role,
                    tokio::spawn(async move {
                        execute(
                            &root, role as u8, &request, &dh, &mut wire, &controls, &gate,
                        )
                        .await
                    }),
                ));
            }
        }
        for (role, task) in tasks {
            if role == 0 || !publish_incident {
                let result = tokio::time::timeout(Duration::from_secs(10), task)
                    .await
                    .unwrap()
                    .unwrap();
                if !publish_incident {
                    assert!(result.is_ok(), "positive control did not sign");
                }
            } else {
                task.abort();
            }
        }
        publisher.join().unwrap();
        assert_eq!(trace.reached.load(std::sync::atomic::Ordering::SeqCst), 2);
        if publish_incident {
            assert!(gate.release(|| Ok(())).is_err());
        }
        // Drain the real output queues through EOF before evaluating the
        // handoff evidence; cancellation must not discard queued R4 frames.
        for pump in pumps {
            tokio::time::timeout(Duration::from_secs(10), pump)
                .await
                .unwrap()
                .unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
        trace
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn two_native_attempts_have_no_r4_handoffs_after_cutoff() {
        let trace = r4_case(true, false).await;
        assert!(
            trace.r4_handoffs.lock().unwrap().is_empty(),
            "R4 reached actual queue after cutoff"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn r4_positive_control_observes_two_actual_handoffs() {
        let trace = r4_case(false, false).await;
        assert_eq!(*trace.r4_handoffs.lock().unwrap(), vec![false, false]);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn r4_observer_detects_deliberate_gate_bypass_despite_cancellation() {
        let trace = r4_case(true, true).await;
        // Mutation control reproduces the old false-pass: regardless of returned
        // cancellation/errors, the observer must detect both late queue handoffs.
        assert_eq!(*trace.r4_handoffs.lock().unwrap(), vec![true, true]);
    }
}
