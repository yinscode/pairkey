//! Long-lived donor worker: roots + donor material in RAM, never wallet packages.
use crate::wire::{self, SetupChannel, Wire};
use anyhow::{ensure, Context, Result};
use derivation_path::DerivationPath;
use ed25519_dalek::{Signature, VerifyingKey};
use pairkey_dkls23_research::{
    d::{
        self, Certificate, Command, Counter, Donor, Endorsement, Journal, Limits, Opening, Record,
        Reply, Request, Wallet,
    },
    digest, fresh,
    lifecycle::{pair_scope_dir, Failure, FailureKind, Phase, ReleaseGate},
    pool::Boot,
    public, reserve, Frame, Root,
};
use serde::{Deserialize, Serialize};
use sl_dkls23::{keygen, setup::ProtocolParticipant, sign};
use sl_mpc_mate::message::InstanceId;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
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
fn context(detail: impl Into<String>) -> anyhow::Error {
    Failure::burn(Phase::Control, FailureKind::Context, detail).into()
}
fn checkpoint(stage: &str, role: u8) {
    if !cfg!(feature = "research-faults")
        || std::env::var("PAIRKEY_D_STAGE").ok().as_deref() != Some(stage)
        || std::env::var("PAIRKEY_D_ROLE").ok().as_deref() != Some(&role.to_string())
    {
        return;
    }
    if let Some(dir) = std::env::var_os("PAIRKEY_D_PROBE") {
        let dir = PathBuf::from(dir);
        std::fs::write(dir.join("reached"), []).unwrap();
        let end = Instant::now() + Duration::from_secs(15);
        while !dir.join("resume").exists() {
            assert!(Instant::now() < end, "D checkpoint deadline");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
#[derive(Serialize, Deserialize)]
struct RegStatus {
    record: Option<Record>,
    retired: bool,
}
pub(crate) struct Service {
    role: u8,
    root: Root,
    dh: StaticSecret,
    boots: [Boot; 2],
    gate: ReleaseGate,
    controls: PathBuf,
    counter: Counter,
    donor: Option<Donor>,
    limits: Limits,
}
impl Service {
    fn peers(&self) -> [[u8; 32]; 2] {
        self.boots.clone().map(|b| b.identity)
    }
    fn base(&self) -> PathBuf {
        self.controls
            .join("d")
            .join(crate::hex(&d::pairing(self.peers())))
    }
    fn channel(&self, context: [u8; 32]) -> Result<SetupChannel> {
        SetupChannel::bound(
            &self.dh,
            self.boots[(1 - self.role) as usize].ephemeral,
            context,
            self.role,
            self.peers()[(1 - self.role) as usize],
        )
    }
    fn discard(&mut self) -> Result<()> {
        if let Some(d) = self.donor.take() {
            reserve(
                &self.base().join("retired-generations"),
                self.role,
                d.generation,
                d.generation,
            )?;
            drop(d);
        }
        Ok(())
    }
    async fn register(
        &self,
        wallet: &Wallet,
        attempt: [u8; 32],
        fault: Option<&str>,
        wire: &mut Wire,
    ) -> Result<Reply> {
        wallet.validate()?;
        ensure!(
            wallet.identities == self.peers(),
            "D registration peer mismatch"
        );
        let journal = Journal::new(&self.base().join("wallets"), wallet, self.role)?;
        let prior = if journal.exists("active") {
            Some(journal.active(&self.root)?.record)
        } else if journal.exists("prepared") {
            let (r, e): (Record, Endorsement) = journal.read("prepared")?;
            r.local(&self.root, self.role)?;
            e.validate(&r)?;
            Some(r)
        } else {
            None
        };
        if prior.is_none() && journal.exists("reserved") {
            journal.retire()?;
        }
        let channel = self.channel(digest(
            b"pairkey/d/registration-context/v2",
            &(wallet, attempt),
        ))?;
        let peer: RegStatus = channel
            .exchange(
                wire,
                "d-register-state",
                &RegStatus {
                    record: prior.clone(),
                    retired: journal.retired(),
                },
            )
            .await?;
        ensure!(
            !journal.retired() && !peer.retired,
            context("D wallet retired or incomplete registration")
        );
        let record = if let Some(record) = prior {
            ensure!(
                peer.record.as_ref() == Some(&record),
                context("D prepared registration disagreement")
            );
            record
        } else {
            ensure!(
                peer.record.is_none(),
                context("D asymmetric incomplete registration")
            );
            checkpoint("before-reserved", self.role);
            self.gate.release(|| journal.reserve(wallet, attempt))?;
            checkpoint("reserved", self.role);
            let x = self.root.derive_v2(self.role, wallet)?;
            // Opening remains private in RAM. A crash before PREPARED retires
            // the slot; no salt or point is persisted ahead of reveal.
            let mut opening = Opening {
                point: public(&x),
                salt: fresh(),
            };
            let own = opening.commitment(wallet, self.role);
            checkpoint("before-commit", self.role);
            journal.write("commit", &own)?;
            checkpoint("commit", self.role);
            let peer_commit: [u8; 32] = channel.exchange(wire, "d-register-commit", &own).await?;
            checkpoint("before-peer-commit", self.role);
            journal.write("peer-commit", &peer_commit)?;
            checkpoint("peer-commit", self.role);
            let ack = if self.role == 0 {
                [own, peer_commit]
            } else {
                [peer_commit, own]
            };
            let peer_ack: [[u8; 32]; 2] = channel.exchange(wire, "d-register-ack", &ack).await?;
            ensure!(
                ack == peer_ack,
                context("D registration acknowledgment mismatch")
            );
            checkpoint("before-reveal-release", self.role);
            journal.write("reveal-release", &ack)?;
            checkpoint("reveal-release", self.role);
            if cfg!(feature = "research-faults")
                && fault == Some("reveal-mismatch")
                && self.role == 1
            {
                opening.salt[0] ^= 1;
            }
            let other: Opening = channel
                .exchange(wire, "d-register-reveal", &opening)
                .await?;
            ensure!(
                other.commitment(wallet, 1 - self.role) == peer_commit,
                Failure::violation(
                    Phase::Admission,
                    self.peers()[(1 - self.role) as usize],
                    "D registration reveal mismatch"
                )
            );
            let openings = if self.role == 0 {
                [opening, other]
            } else {
                [other, opening]
            };
            let record = Record::new(wallet.clone(), ack, openings)?;
            checkpoint("before-prepared", self.role);
            let local = journal.prepare(&record, &self.root)?;
            checkpoint("prepared", self.role);
            // Preparation precedes releasing this exact public endorsement.
            let peer: Endorsement = channel.exchange(wire, "d-register-endorse", &local).await?;
            ensure!(peer.role == 1 - self.role, "D peer endorsement role");
            peer.validate(&record)?;
            let endorsements = if self.role == 0 {
                [local, peer]
            } else {
                [peer, local]
            };
            let cert = Certificate {
                record: record.clone(),
                endorsements,
            };
            checkpoint("before-active", self.role);
            journal.commit(&cert, &self.root)?;
            checkpoint("active", self.role);
            let ack: [u8; 32] = channel
                .exchange(wire, "d-register-active", &record.digest())
                .await?;
            ensure!(
                ack == record.digest(),
                context("D active record disagreement")
            );
            return Ok(Reply::Registered(Box::new(cert)));
        };
        let local = journal.prepare(&record, &self.root)?;
        let peer: Endorsement = channel.exchange(wire, "d-register-endorse", &local).await?;
        peer.validate(&record)?;
        let endorsements = if self.role == 0 {
            [local, peer]
        } else {
            [peer, local]
        };
        let cert = Certificate {
            record,
            endorsements,
        };
        journal.commit(&cert, &self.root)?;
        let ack: [u8; 32] = channel
            .exchange(wire, "d-register-active", &cert.record.digest())
            .await?;
        ensure!(
            ack == cert.record.digest(),
            context("D active record disagreement")
        );
        Ok(Reply::Registered(Box::new(cert)))
    }
    async fn prepare(
        &mut self,
        attempt: [u8; 32],
        fault: Option<&str>,
        wire: &mut Wire,
    ) -> Result<Reply> {
        self.discard()?;
        let start = Instant::now();
        let input = digest(
            b"pairkey/d/donor-dkg/v2",
            &(
                self.peers(),
                self.boots.clone().map(|b| b.generation),
                d::configuration(),
                &self.limits,
                attempt,
            ),
        );
        self.gate
            .release(|| reserve(&self.base().join("donor-attempts"), self.role, input, input))?;
        let channel = self.channel(input)?;
        let peer: [u8; 32] = channel.exchange(wire, "d-donor-ready", &input).await?;
        ensure!(peer == input, context("D donor context mismatch"));
        let n = self.counter.issue()?;
        let seed = d::hedged_seed(&fresh(), input, n, self.role, "donor-dkg");
        let identities = self
            .peers()
            .into_iter()
            .map(|b| Ok(Identity(VerifyingKey::from_bytes(&b)?)))
            .collect::<Result<Vec<_>>>()?;
        let setup = sl_dkls23::setup::keygen::SetupMessage::<_, _, Signature>::new(
            InstanceId::new(input),
            self.root.identity(self.role),
            self.role as usize,
            identities,
            &[0, 0],
            2,
        )
        .with_key_id(Some(input))
        .with_ttl(Duration::from_secs(30));
        let abort = wire.watch_abort(
            &setup,
            cfg!(feature = "research-faults") && fault == Some("donor-abort-send"),
        );
        if cfg!(feature = "research-faults")
            && self.role == 1
            && matches!(fault, Some("donor-pprf" | "donor-abort-send"))
        {
            std::env::set_var("PAIRKEY_RESEARCH_BAD_MIGRATION_PPRF", "1");
        }
        let result = keygen::run(setup, *seed, &mut *wire).await;
        std::env::remove_var("PAIRKEY_RESEARCH_BAD_MIGRATION_PPRF");
        let package = result.map_err(|e| {
            let mut failure = Failure::native_migration(&e, self.peers()[(1 - self.role) as usize]);
            failure.abort_send_failed = abort.load(std::sync::atomic::Ordering::SeqCst);
            if failure.abort_send_failed {
                failure
                    .detail
                    .push_str("; abort delivery failed (original native error preserved)");
            }
            failure
        })?;
        let donor = Donor::extract(package, self.peers(), self.role, self.limits.clone())?;
        let peer: ([u8; 32], Vec<u8>) = channel
            .exchange(
                wire,
                "d-donor-generation",
                &(donor.generation, &donor.unused_public_key),
            )
            .await?;
        ensure!(
            peer == (donor.generation, donor.unused_public_key.clone()),
            context("D donor generation disagreement")
        );
        self.gate.release(|| {
            reserve(
                &self.base().join("generations"),
                self.role,
                donor.generation,
                input,
            )
        })?;
        let reply = Reply::Donor {
            role: self.role,
            generation: donor.generation,
            unused_public_key: donor.unused_public_key.clone(),
            elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        };
        self.donor = Some(donor);
        Ok(reply)
    }
    async fn sign(&mut self, r: &Request, wire: &mut Wire) -> Result<Reply> {
        let start = Instant::now();
        r.wallet.validate()?;
        ensure!(
            r.wallet.identities == self.peers(),
            context("D signing peer mismatch")
        );
        let cert =
            Journal::new(&self.base().join("wallets"), &r.wallet, self.role)?.active(&self.root)?;
        ensure!(
            cert.record.digest() == r.record,
            context("D request record mismatch")
        );
        let path = DerivationPath::from_str(&r.path)?;
        let channel = self.channel(r.instance())?;
        if cfg!(feature = "research-faults")
            && self.role == 1
            && r.fault.as_deref() == Some("missing-donor")
        {
            self.discard()?;
        }
        let generation = self
            .donor
            .as_ref()
            .filter(|d| d.usable())
            .map(|d| d.generation);
        let peer: Option<[u8; 32]> = channel
            .exchange(wire, "d-sign-generation", &generation)
            .await?;
        ensure!(
            generation == Some(r.generation) && peer == generation,
            context("D donor generation/bound mismatch")
        );
        let instance = r.instance();
        self.gate.release(|| {
            reserve(
                &self.base().join("own-instances"),
                self.role,
                instance,
                instance,
            )
        })?;
        let peer_instance: [u8; 32] = channel.exchange(wire, "d-sign-instance", &instance).await?;
        ensure!(
            peer_instance == instance,
            context("D instance disagreement")
        );
        self.gate.release(|| {
            reserve(
                &self.base().join("peer-instances"),
                self.role,
                peer_instance,
                instance,
            )
        })?;
        let count = self.counter.issue()?;
        let donor = self.donor.as_mut().context("D donor absent")?;
        donor.reserve()?;
        let mut package = donor.package(&self.root, &cert.record, instance)?;
        if cfg!(feature = "research-faults")
            && self.role == 1
            && r.fault.as_deref() == Some("mismatched-zero")
        {
            let mut bytes = Zeroizing::new(package.as_slice().to_vec());
            bytes[172 + 66] ^= 1;
            package = sl_dkls23::keygen::Keyshare::from_bytes(&bytes)
                .context("D injected package rejected")?;
        }
        let expected = package.derive_with_offset(&path)?.1;
        let package_sid = package.final_session_id;
        let identities = self
            .peers()
            .into_iter()
            .map(|b| Ok(Identity(VerifyingKey::from_bytes(&b)?)))
            .collect::<Result<Vec<_>>>()?;
        let setup = sl_dkls23::setup::sign::SetupMessage::<_, _, Signature>::new(
            InstanceId::new(instance),
            self.root.identity(self.role),
            self.role as usize,
            identities,
            Arc::new(package),
        )
        .with_chain_path(path)
        .with_hash(r.prehash)
        .with_ttl(Duration::from_secs(30));
        let ids = std::array::from_fn(|role| {
            setup
                .msg_id_from(role, None, sl_mpc_mate::message::MessageTag::tag(1))
                .as_ref()
                .try_into()
                .unwrap()
        });
        let guard = Arc::new(d::R1Guard::new(
            ids,
            package_sid,
            self.role,
            self.peers(),
            self.base().join("r1-journal"),
        ));
        #[cfg(feature = "research-faults")]
        if self.role == 1 && r.fault.as_deref() == Some("native-r1-commit") {
            guard.inject_commitment_fault(self.root.identity(self.role));
        }
        #[cfg(all(test, feature = "research-faults"))]
        if let Some(probe) = &mut wire.process_probe {
            probe.r4 = setup
                .msg_id(None, sl_mpc_mate::message::MessageTag::tag(4))
                .as_ref()
                .try_into()
                .unwrap();
        }
        wire.d_guard = Some(guard.clone());
        let entropy =
            if cfg!(feature = "research-faults") && r.fault.as_deref() == Some("repeat-entropy") {
                [42; 32]
            } else {
                fresh()
            };
        let seed = if cfg!(feature = "research-faults")
            && r.fault.as_deref() == Some("repeat-native-seed")
        {
            Zeroizing::new([42; 32])
        } else {
            d::hedged_seed(&entropy, instance, count, self.role, "sign")
        };
        let result = sign::run(setup, *seed, &mut *wire).await;
        wire.d_guard = None;
        if let Some(failure) = guard.failure() {
            return Err(failure.into());
        }
        let (signature, recovery) =
            result.map_err(|e| Failure::native_sign(&e, self.peers()[(1 - self.role) as usize]))?;
        use signature::hazmat::PrehashVerifier;
        let key = k256::ecdsa::VerifyingKey::from_affine(expected.to_affine())?;
        key.verify_prehash(&r.prehash, &signature)?;
        ensure!(signature.normalize_s().is_none(), "D high-S");
        ensure!(
            k256::ecdsa::VerifyingKey::recover_from_prehash(&r.prehash, &signature, recovery)?
                == key,
            "D recovery mismatch"
        );
        Ok(Reply::Signed {
            role: self.role,
            instance,
            generation: r.generation,
            final_session: guard.final_session()?,
            signature: signature.to_bytes().to_vec(),
            public_key: expected.to_bytes().to_vec(),
            recovery_id: recovery.to_byte(),
            uses: self.donor.as_ref().unwrap().uses,
            elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        })
    }
    async fn command(&mut self, command: Command, wire: &mut Wire) -> Result<Reply> {
        match command {
            Command::Register {
                wallet,
                attempt,
                fault,
            } => {
                ensure!(
                    cfg!(feature = "research-faults") || fault.is_none(),
                    "D fault feature disabled"
                );
                self.register(&wallet, attempt, fault.as_deref(), wire)
                    .await
            }
            Command::Prepare { attempt, fault } => {
                ensure!(
                    cfg!(feature = "research-faults") || fault.is_none(),
                    "D fault feature disabled"
                );
                self.prepare(attempt, fault.as_deref(), wire).await
            }
            Command::Sign(r) => {
                ensure!(
                    cfg!(feature = "research-faults") || r.fault.is_none(),
                    "D fault feature disabled"
                );
                self.sign(&r, wire).await
            }
            Command::Discard => {
                self.discard()?;
                Ok(Reply::Discarded)
            }
            Command::Incident(id) => {
                self.gate.publish(id)?;
                Err(Failure::incident_cutoff().into())
            }
            _ => anyhow::bail!("unexpected D command"),
        }
    }
}
use k256::elliptic_curve::group::GroupEncoding;
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.discard();
    }
}
pub async fn run(role: u8, root_path: &Path, peer: [u8; 32], limits: Limits) -> Result<()> {
    ensure!(role < 2, "D role");
    limits.validate()?;
    let root = Root::load(root_path)?;
    let entropy = Zeroizing::new(fresh());
    let dh = StaticSecret::from(*entropy);
    let own = Boot::new(&root, role, PublicKey::from(&dh).to_bytes());
    let (mut wire, writer, reader) = wire::stdio();
    #[cfg(all(test, feature = "research-faults"))]
    {
        wire.process_probe = crate::process_probe::Probe::from_env(role);
    }
    wire.send(Frame::PoolHello(own.clone()))?;
    let result:Result<()>=async {
        let Frame::DCommand(command)=wire.receive().await? else{anyhow::bail!("expected D enrollment")};
        let Command::Enroll(boots)=*command else{anyhow::bail!("expected D boot pair")};
        for (role,b) in boots.iter().enumerate(){b.validate()?;ensure!(b.role as usize==role,"D boot roles");}
        ensure!(boots[role as usize].message()==own.message() && boots[(1-role) as usize].identity==peer,"D enrollment pin");
        let controls=root_path.parent().context("D root directory")?.join("controls");let gate=ReleaseGate::new(pair_scope_dir(&controls,boots.clone().map(|b|b.identity),1),role);wire.gate=Some(gate.clone());
        let base=controls.join("d").join(crate::hex(&d::pairing(boots.clone().map(|b|b.identity))));
        let mut service=Service{role,root,dh,boots,gate:gate.clone(),controls,counter:Counter::new(base.join("counters"),role),donor:None,limits};
        loop {
            let command=tokio::select!{biased; f=gate.cancelled()=>return Err(f.into()),frame=wire.receive()=>frame?};
            let Frame::DCommand(command)=command else{anyhow::bail!("expected D command")};if matches!(*command,Command::Stop){break;}
            let operation_context=digest(b"pairkey/d/operation",&*command);
            let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            service.counter.check_rate(now,service.limits.abort_window_secs,service.limits.abort_limit)?;
            let result=tokio::select!{biased; f=gate.cancelled()=>Err(f.into()),r=tokio::time::timeout(Duration::from_secs(30),service.command(*command,&mut wire))=>r.unwrap_or_else(|_|Err(Failure::burn(Phase::Control,FailureKind::Timeout,"D command timeout").into()))};
            match result {Ok(reply)=>wire.send(Frame::DReply(reply))?,Err(error)=>{let discard=service.discard();let mut failure=error.downcast_ref::<Failure>().cloned().unwrap_or_else(||Failure::burn(Phase::Control,FailureKind::Local,format!("{error:#}")));if let Err(e)=discard{failure.detail.push_str(&format!("; donor retirement failed: {e:#}"));}
                if matches!(failure.kind,FailureKind::Transport|FailureKind::PeerAbort|FailureKind::Timeout){if let Err(e)=service.counter.transport(now,operation_context){failure.detail.push_str(&format!("; transport accounting failed: {e:#}"));}}wire.send(Frame::Failure(gate.apply(failure,operation_context)))?;break;}}
        }Ok(())
    }.await;
    if let Err(error) = result {
        wire.send(Frame::Failure(
            error.downcast_ref::<Failure>().cloned().unwrap_or_else(|| {
                Failure::burn(Phase::Control, FailureKind::Local, format!("{error:#}"))
            }),
        ))?;
    }
    drop(wire);
    writer.await??;
    reader.abort();
    Ok(())
}
