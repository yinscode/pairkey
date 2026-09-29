//! Sequential command service in each long-lived, separate research process.
use crate::wire::{self, SetupChannel, Wire};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use k256::elliptic_curve::group::GroupEncoding;
use pairkey_dkls23_research::{fresh, reserve, Frame, Hello, Outcome, Root, Route};
use pairkey_dkls23_research::{
    lifecycle::{pair_scope_dir, Failure, FailureKind, Phase, ReleaseGate},
    pool::{
        self, AvailableEntry, Boot, Command, Consumption, Material, RamPool, SetupInput, Status,
        Transcript,
    },
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
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
    fn verify(&self, m: &[u8], s: &Signature) -> std::result::Result<(), signature::Error> {
        self.0.verify_strict(m, s)
    }
}
struct Clearing<T: bytemuck::AnyBitPattern + bytemuck::NoUninit>(T);
impl<T: bytemuck::AnyBitPattern + bytemuck::NoUninit> Drop for Clearing<T> {
    fn drop(&mut self) {
        bytemuck::bytes_of_mut(&mut self.0).zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    msg2: Vec<u8>,
    pprf: Vec<u8>,
}
impl Drop for Reply {
    fn drop(&mut self) {
        self.msg2.zeroize();
        self.pprf.zeroize();
    }
}
fn reply_body(r: &Reply) -> Zeroizing<Vec<u8>> {
    let mut b = Zeroizing::new(Vec::new());
    b.extend((r.msg2.len() as u64).to_be_bytes());
    b.extend(&r.msg2);
    b.extend((r.pprf.len() as u64).to_be_bytes());
    b.extend(&r.pprf);
    b
}
fn fault_is(fault: Option<&str>, label: &str) -> bool {
    cfg!(feature = "research-faults") && fault == Some(label)
}

async fn preprocess(
    role: u8,
    input: &SetupInput,
    channel: &SetupChannel,
    wire: &mut Wire,
    fault: Option<&str>,
) -> Result<(AvailableEntry, Status)> {
    let peer = input.peers[(1 - role) as usize];
    let violation = |m| Failure::violation(Phase::DirectSetup, peer, m);
    let total = Instant::now();
    let mut compute = Duration::ZERO;
    let mut transcript = Transcript::new(input.digest());
    let t = Instant::now();
    let coin = Zeroizing::new(fresh());
    let commitment = pool::hash(
        "pairkey/pool/zero-commit/v1",
        &[&input.digest(), &[role], &*coin],
    );
    compute += t.elapsed();
    let peer_commit: [u8; 32] = channel
        .exchange(wire, "pool-zero-commit", &commitment)
        .await?;
    transcript.record(0, role, &commitment)?;
    transcript.record(0, 1 - role, &peer_commit)?;
    let mut reveal = Zeroizing::new(*coin);
    if fault_is(fault, "bad-zero-reveal") && role == 1 {
        reveal[0] ^= 1;
    }
    let peer_coin = Zeroizing::new(
        channel
            .exchange::<_, [u8; 32]>(wire, "pool-zero-reveal", &*reveal)
            .await?,
    );
    let t = Instant::now();
    ensure!(
        peer_commit
            == pool::hash(
                "pairkey/pool/zero-commit/v1",
                &[&input.digest(), &[1 - role], &*peer_coin]
            ),
        violation("pool zero commitment mismatch")
    );
    transcript.record(1, role, &*reveal)?;
    transcript.record(1, 1 - role, &*peer_coin)?;
    let (c0, c1) = if role == 0 {
        (&*coin, &*peer_coin)
    } else {
        (&*peer_coin, &*coin)
    };
    let zero = Zeroizing::new(pool::hash(
        "pairkey/pool/zero-seed/v1",
        &[&input.digest(), c0, c1],
    ));
    let mut msg1 = Clearing(EndemicOTMsg1::default());
    // Base OT msg1 is emitted by the receiver; directional order is explicit.
    let receiver_sid = input.base_ot_sid(role, 1 - role);
    let sender_sid = input.base_ot_sid(1 - role, role);
    let receiver = EndemicOTReceiver::new(&receiver_sid, &mut msg1.0, &mut OsRng);
    compute += t.elapsed();
    let peer_msg1: Vec<u8> = channel
        .exchange(wire, "pool-base-ot-1", &bytemuck::bytes_of(&msg1.0))
        .await?;
    let peer_msg1 = Zeroizing::new(peer_msg1);
    let t = Instant::now();
    let decoded: EndemicOTMsg1 = bytemuck::try_pod_read_unaligned(&peer_msg1)
        .map_err(|_| violation("invalid pool OT msg1 length"))?;
    let mut msg2 = Clearing(EndemicOTMsg2::default());
    let sender_output = EndemicOTSender::process(&sender_sid, &decoded, &mut msg2.0, &mut OsRng)
        .map_err(violation)?;
    let mut sender = Clearing(SenderOTSeed::default());
    let mut receiver_seed = Clearing(ReceiverOTSeed::default());
    let mut pprf = Clearing(PPRFOutput::default());
    build_pprf(
        &input.pprf_sid(role, 1 - role),
        &sender_output,
        &mut sender.0,
        &mut pprf.0,
    );
    transcript.record(2, role, bytemuck::bytes_of(&msg1.0))?;
    transcript.record(2, 1 - role, &peer_msg1)?;
    let mut reply = Reply {
        msg2: bytemuck::bytes_of(&msg2.0).to_vec(),
        pprf: bytemuck::bytes_of(&pprf.0).to_vec(),
    };
    if fault_is(fault, "truncated-ot") && role == 1 {
        reply.msg2.truncate(1);
    }
    if fault_is(fault, "truncated-pprf") && role == 1 {
        reply.pprf.truncate(1);
    }
    compute += t.elapsed();
    let peer_reply: Reply = channel.exchange(wire, "pool-base-ot-2", &reply).await?;
    let t = Instant::now();
    let msg2: EndemicOTMsg2 = bytemuck::try_pod_read_unaligned(&peer_reply.msg2)
        .map_err(|_| violation("invalid pool OT msg2 length"))?;
    let pprf: PPRFOutput = bytemuck::try_pod_read_unaligned(&peer_reply.pprf)
        .map_err(|_| violation("invalid pool PPRF length"))?;
    let output = receiver.process(&msg2).map_err(violation)?;
    eval_pprf(
        &input.pprf_sid(1 - role, role),
        &output,
        &pprf,
        &mut receiver_seed.0,
    )
    .map_err(violation)?;
    transcript.record(3, role, &reply_body(&reply))?;
    transcript.record(3, 1 - role, &reply_body(&peer_reply))?;
    let completed = transcript.completed()?;
    compute += t.elapsed();
    let mut ack = completed;
    if fault_is(fault, "completed-mismatch") && role == 1 {
        ack[0] ^= 1;
    }
    if fault_is(fault, "setup-timeout") && role == 1 {
        std::future::pending::<()>().await;
    }
    let peer_ack: [u8; 32] = channel.exchange(wire, "pool-completed-ack", &ack).await?;
    // Even the deliberately faulty local role must not publish its own entry.
    ensure!(
        peer_ack == completed,
        violation("pool completed digest disagreement")
    );
    if ack != completed {
        // Fault actor cannot blame the honest peer for its own changed ACK.
        // Wait for parent EOF while the receiver detects the authenticated fault.
        wire.receive().await?;
        anyhow::bail!("injected local completed ACK corruption");
    }
    if fault_is(fault, "corrupt-ot") && role == 1 {
        for row in &mut sender.0.otp_enc_keys {
            for leaf in row {
                leaf[0] ^= 1;
            }
        }
    }
    let entry = AvailableEntry::agreed(
        input.clone(),
        completed,
        Material::new(sender.0, receiver_seed.0, *zero),
        Duration::from_secs(300),
    )?;
    Ok((
        entry,
        Status {
            operation: "refill".into(),
            entry: input.entry,
            input: input.digest(),
            completed,
            available: 0,
            elapsed_ms: total.elapsed().as_secs_f64() * 1000.0,
            compute_ms: compute.as_secs_f64() * 1000.0,
        },
    ))
}

struct Service {
    role: u8,
    root: Root,
    dh: StaticSecret,
    own: Boot,
    boots: [Boot; 2],
    gate: ReleaseGate,
    pool: RamPool,
    controls: std::path::PathBuf,
}
impl Service {
    async fn command(&mut self, command: Command, wire: &mut Wire) -> Result<Frame> {
        self.gate.release(|| Ok(()))?;
        match command {
            Command::Ping(nonce) => Ok(Frame::PoolStatus(Status {
                operation: "pong".into(),
                entry: nonce,
                input: [0; 32],
                completed: [0; 32],
                available: self.pool.available(),
                elapsed_ms: 0.0,
                compute_ms: 0.0,
            })),
            Command::Setup { input, fault } => {
                ensure!(
                    cfg!(feature = "research-faults") || fault.is_none(),
                    "fault injection requires research-faults feature"
                );
                input.validate()?;
                ensure!(self.pool.available() < 2, "pool full");
                ensure!(
                    input.peers == self.boots.clone().map(|b| b.identity)
                        && input.boots == self.boots.clone().map(|b| b.generation),
                    "pool setup enrollment/boot mismatch"
                );
                // Burn setup identity BEFORE any OT exchange. It cannot be refilled again.
                self.gate.release(|| {
                    reserve(
                        &self.controls.join("pool-setups"),
                        self.role,
                        input.entry,
                        input.digest(),
                    )
                })?;
                let channel = SetupChannel::bound(
                    &self.dh,
                    self.boots[(1 - self.role) as usize].ephemeral,
                    input.digest(),
                    self.role,
                    input.peers[(1 - self.role) as usize],
                )?;
                let (entry, mut status) =
                    preprocess(self.role, &input, &channel, wire, fault.as_deref()).await?;
                self.pool.insert(entry)?;
                status.available = self.pool.available();
                Ok(Frame::PoolStatus(status))
            }
            Command::Describe(key) => {
                let hello = Hello::new(&self.root, self.role, key, self.own.ephemeral)?;
                Ok(Frame::Hello(hello))
            }
            Command::Sign {
                request,
                consumption,
            } => self.sign(&request, &consumption, wire).await,
            Command::Incident(context) => {
                self.pool.invalidate();
                let failure = Failure {
                    action: pairkey_dkls23_research::lifecycle::Action::FreezeConfiguration,
                    ..Failure::burn(
                        Phase::Control,
                        FailureKind::Quarantined,
                        "explicit research incident",
                    )
                };
                anyhow::bail!(self.gate.apply(failure, context));
            }
            _ => anyhow::bail!("unexpected pool command"),
        }
    }
    async fn sign(
        &self,
        r: &pairkey_dkls23_research::Request,
        c: &Consumption,
        wire: &mut Wire,
    ) -> Result<Frame> {
        r.validate()?;
        ensure!(
            r.route == Route::Pooled
                && r.manifest.identities == self.boots.clone().map(|b| b.identity),
            "pooled route/peer mismatch"
        );
        ensure!(
            r.hellos[self.role as usize].ephemeral == self.own.ephemeral,
            "own signing DH substituted"
        );
        r.manifest.check_local(&self.root, self.role)?;
        let start = Instant::now();
        let reserved = self.pool.reserve(c)?; // ownership consumed BEFORE request validation/agreement
        if r.fault_is("disconnect") {
            wire.send(Frame::Ready(c.digest()))?;
        }
        c.validate_request(r)?;
        if r.fault_is("cancel-reserved") {
            anyhow::bail!(Failure::burn(
                Phase::Control,
                FailureKind::Cancelled,
                "injected cancellation after pool reservation"
            ));
        }
        let channel = SetupChannel::bound(
            &self.dh,
            self.boots[(1 - self.role) as usize].ephemeral,
            c.digest(),
            self.role,
            r.manifest.identities[(1 - self.role) as usize],
        )?;
        let peer: [u8; 32] = channel
            .exchange(wire, "pool-reservation", &c.digest())
            .await?;
        ensure!(peer == c.digest(), "pool reservation disagreement");
        if r.fault_is("sign-timeout") && self.role == 1 {
            std::future::pending::<()>().await;
        }
        let package = reserved.into_package(r, &self.root, self.role)?;
        let path = derivation_path::DerivationPath::from_str(&r.path)?;
        let (_, derived) = package.derive_with_offset(&path)?;
        ensure!(
            package.extra_data() == c.digest(),
            "pooled package extra mismatch"
        );
        let bytes = package.as_slice().len();
        let sid = package.final_session_id.to_vec();
        let identities = r
            .manifest
            .identities
            .iter()
            .map(|b| Ok(Identity(VerifyingKey::from_bytes(b)?)))
            .collect::<Result<Vec<_>>>()?;
        let setup = sl_dkls23::setup::sign::SetupMessage::<_, _, Signature>::new(
            InstanceId::new(c.digest()),
            self.root.identity(self.role),
            self.role as usize,
            identities,
            Arc::new(package),
        )
        .with_chain_path(path)
        .with_hash(r.prehash)
        .with_ttl(Duration::from_secs(30));
        let online_setup = start.elapsed().as_secs_f64() * 1000.0;
        let seed = Zeroizing::new(fresh());
        let start = Instant::now();
        let (sign_future, sign_active) =
            crate::measure::active(sl_dkls23::sign::run(setup, *seed, &mut *wire));
        let (signature, recovery) = sign_future.await.map_err(|e| {
            Failure::native_sign(&e, r.manifest.identities[(1 - self.role) as usize])
        })?;
        use signature::hazmat::PrehashVerifier;
        let key = k256::ecdsa::VerifyingKey::from_affine(derived.to_affine())?;
        key.verify_prehash(&r.prehash, &signature)?;
        ensure!(signature.normalize_s().is_none(), "pooled high-S output");
        ensure!(
            k256::ecdsa::VerifyingKey::recover_from_prehash(&r.prehash, &signature, recovery)?
                == key,
            "pooled recovery ID mismatch"
        );
        Ok(Frame::Result(Outcome {
            role: self.role,
            route: Route::Pooled,
            context: c.digest(),
            public_key: derived.to_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
            recovery_id: recovery.to_byte(),
            setup_ms: online_setup,
            signing_ms: start.elapsed().as_secs_f64() * 1000.0,
            setup_active_poll_ms: None, // Reported online setup wall includes reservation/agreement.
            signing_active_poll_ms: crate::measure::milliseconds(&sign_active),
            package_bytes: bytes,
            setup_id: sid,
        }))
    }
}
pub async fn run(role: u8, root_path: &Path, peer: [u8; 32]) -> Result<()> {
    ensure!(role < 2, "invalid pool worker role");
    let root = Root::load(root_path)?;
    let dh = StaticSecret::from(fresh());
    let own = Boot::new(&root, role, PublicKey::from(&dh).to_bytes());
    let (mut wire, writer, reader) = wire::stdio();
    wire.send(Frame::PoolHello(own.clone()))?;
    let result:Result<()>=async {
        let Frame::PoolCommand(command)=wire.receive().await? else {anyhow::bail!("expected pool enrollment");};
        let Command::Enroll(boots)=*command else {anyhow::bail!("expected boot pair");};
        for (i,b) in boots.iter().enumerate() {b.validate()?;ensure!(b.role as usize==i,"pool boot order mismatch");}
        ensure!(boots[role as usize].message()==own.message() && boots[(1-role) as usize].identity==peer,"pool boot pin mismatch");
        let controls=root_path.parent().context("root dir")?.join("controls");
        let identities=boots.clone().map(|b|b.identity);
        // Shared A/B/C incident authority: route changes cannot reset quarantine.
        let gate=ReleaseGate::new(pair_scope_dir(&controls,identities,1),role);
        wire.gate=Some(gate.clone());
        let pool=RamPool::new(gate.clone(),controls.join("entries"),role,identities,boots.clone().map(|b|b.generation),2)?;
        let mut service=Service {role,root,dh,own,boots,gate:gate.clone(),pool,controls};
        loop {
            let next=tokio::select! {
                biased;
                _=gate.cancelled()=>{service.pool.invalidate();anyhow::bail!("pool incident cutoff");},
                next=wire.receive()=>next?,
            };
            let Frame::PoolCommand(command)=next else {anyhow::bail!("unexpected pooled control frame");};
            if matches!(*command,Command::Stop) {service.pool.invalidate();break;}
            let context=match &*command {
                Command::Sign {consumption,..}=>consumption.digest(),Command::Setup {input,..}=>input.digest(),_=>[0;32],
            };
            // Test-only shorter deadline for explicit timeout fixtures.
            let fault_timeout=match &*command {
                Command::Setup {fault,..}=>fault_is(fault.as_deref(),"setup-timeout"),
                Command::Sign {request,..}=>request.fault_is("sign-timeout"),_=>false,
            };
            let timeout=if fault_timeout {Duration::from_millis(500)} else {Duration::from_secs(30)};
            let result=tokio::select! {
                biased;
                _=gate.cancelled()=>Err(Failure::burn(Phase::Control,FailureKind::Quarantined,"pool incident cutoff").into()),
                result=tokio::time::timeout(timeout,service.command(*command,&mut wire))=>result.unwrap_or_else(|_|Err(Failure::burn(Phase::Control,FailureKind::Timeout,"pool command timeout").into())),
            };
            match result {
                Ok(frame)=>wire.send(frame)?,
                Err(error)=>{
                    service.pool.invalidate();
                    let failure=error.downcast_ref::<Failure>().cloned().unwrap_or_else(||Failure::burn(Phase::Control,FailureKind::Local,format!("{error:#}")));
                    wire.send(Frame::Failure(gate.apply(failure,context)))?;
                    break; // Any ambiguity destroys this generation and all unused entries.
                }
            }
        } Ok(())
    }.await;
    if let Err(error) = result {
        wire.send(Frame::Failure(
            error.downcast_ref::<Failure>().cloned().unwrap_or_else(|| {
                Failure::burn(
                    Phase::Transport,
                    FailureKind::Transport,
                    format!("{error:#}"),
                )
            }),
        ))?;
    }
    drop(wire);
    writer.await??;
    reader.abort();
    Ok(())
}
