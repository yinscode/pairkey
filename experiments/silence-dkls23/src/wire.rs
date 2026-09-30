use anyhow::{ensure, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit,
};
use futures_util::{Sink, Stream};
use hkdf::Hkdf;
use pairkey_dkls23_research::{
    fresh,
    lifecycle::{Failure, FailureKind, Phase, ReleaseGate},
    Frame, Request, MAX_FRAME,
};
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;
use sl_mpc_mate::coord::{MessageSendError, Relay};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::mpsc,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct AbortWatch {
    id: [u8; 32],
    failed: Arc<AtomicBool>,
    inject: bool,
}
#[cfg(all(test, feature = "research-faults"))]
#[derive(Default)]
pub struct QueueTrace {
    pub reached: std::sync::atomic::AtomicUsize,
    pub cutoff: AtomicBool,
    pub r4_handoffs: std::sync::Mutex<Vec<bool>>,
    pub r4_ids: std::sync::Mutex<std::collections::BTreeSet<[u8; 32]>>,
}
#[cfg(all(test, feature = "research-faults"))]
pub struct PartialProbe {
    pub id: [u8; 32],
    pub barrier: Arc<std::sync::Barrier>,
    pub trace: Arc<QueueTrace>,
    pub bypass_gate: bool,
}
pub struct Wire {
    pub d_guard: Option<Arc<pairkey_dkls23_research::d::R1Guard>>,
    pub abort_watch: Option<AbortWatch>,
    pub gate: Option<ReleaseGate>,
    #[cfg(all(test, feature = "research-faults"))]
    pub partial_probe: Option<PartialProbe>,
    #[cfg(all(test, feature = "research-faults"))]
    pub process_probe: Option<crate::process_probe::Probe>,
    pub tx: mpsc::UnboundedSender<Frame>,
    pub rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub control: mpsc::UnboundedReceiver<Frame>,
}
impl Wire {
    pub async fn receive(&mut self) -> Result<Frame> {
        self.control.recv().await.ok_or_else(|| {
            Failure::burn(
                Phase::Transport,
                FailureKind::Transport,
                "peer disconnected",
            )
            .into()
        })
    }
    pub fn watch_abort(
        &mut self,
        setup: &impl sl_dkls23::setup::ProtocolParticipant,
        inject: bool,
    ) -> Arc<AtomicBool> {
        let failed = Arc::new(AtomicBool::new(false));
        self.abort_watch = Some(AbortWatch {
            id: setup
                .msg_id(None, sl_dkls23::setup::ABORT_MESSAGE_TAG)
                .as_ref()
                .try_into()
                .unwrap(),
            failed: failed.clone(),
            inject,
        });
        failed
    }
    pub fn send(&self, mut frame: Frame) -> Result<()> {
        if let (Some(guard), Frame::Relay(bytes)) = (&self.d_guard, &mut frame) {
            guard.fault_outbound(bytes);
            guard.observe(bytes, true)?;
        }
        #[cfg(all(test, feature = "research-faults"))]
        let process_target = self.process_probe.as_ref().is_some_and(|p| p.pause(&frame));
        let is_abort = matches!((&self.abort_watch,&frame),(Some(watch),Frame::Relay(bytes)) if bytes.get(..32)==Some(watch.id.as_slice()));
        #[cfg(all(test, feature = "research-faults"))]
        let is_r4 = matches!((&self.partial_probe,&frame),(Some(probe),Frame::Relay(bytes)) if bytes.get(..32)==Some(probe.id.as_slice()));
        #[cfg(all(test, feature = "research-faults"))]
        if is_r4 {
            let probe = self.partial_probe.as_ref().unwrap();
            probe.trace.reached.fetch_add(1, Ordering::SeqCst);
            probe.barrier.wait();
            probe.barrier.wait();
        }
        if cfg!(feature = "research-faults")
            && is_abort
            && self.abort_watch.as_ref().unwrap().inject
        {
            self.abort_watch
                .as_ref()
                .unwrap()
                .failed
                .store(true, Ordering::SeqCst);
            anyhow::bail!("injected abort-send failure");
        }
        let gated = matches!(
            frame,
            Frame::DReply(_)
                | Frame::Relay(_)
                | Frame::Setup(_)
                | Frame::Result(_)
                | Frame::WalletEndorsement(_)
                | Frame::WalletRegistered(_)
        );
        #[cfg(all(test, feature = "research-faults"))]
        let gated = gated && !(is_r4 && self.partial_probe.as_ref().unwrap().bypass_gate);
        #[cfg(all(test, feature = "research-faults"))]
        let gated = gated && !(process_target && self.process_probe.as_ref().unwrap().bypass);
        let send = || {
            self.tx
                .send(frame)
                .map_err(|_| anyhow::anyhow!("writer disconnected"))?;
            Ok(())
        };
        let result = if gated {
            if let Some(gate) = &self.gate {
                gate.release(send)
            } else {
                send()
            }
        } else {
            send()
        };
        if is_abort && result.is_err() {
            self.abort_watch
                .as_ref()
                .unwrap()
                .failed
                .store(true, Ordering::SeqCst);
        }
        result
    }
}
impl Stream for Wire {
    type Item = Vec<u8>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Vec<u8>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                if self
                    .d_guard
                    .as_ref()
                    .is_some_and(|guard| guard.observe(&bytes, false).is_err())
                {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(bytes))
                }
            }
            other => other,
        }
    }
}
impl Sink<Vec<u8>> for Wire {
    type Error = MessageSendError;
    fn poll_ready(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn start_send(self: Pin<&mut Self>, bytes: Vec<u8>) -> Result<(), Self::Error> {
        self.send(Frame::Relay(bytes)).map_err(|_| MessageSendError)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
impl Relay for Wire {}
impl Relay for &mut Wire {}

pub fn stdio() -> (
    Wire,
    tokio::task::JoinHandle<Result<()>>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (tx, mut outgoing) = mpsc::unbounded_channel();
    let (incoming, rx) = mpsc::unbounded_channel();
    let (controls, control) = mpsc::unbounded_channel();
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(frame) = outgoing.recv().await {
            #[cfg(all(test, feature = "research-faults"))]
            crate::process_probe::observe(&frame);
            let mut bytes = serde_json::to_vec(&frame)?;
            ensure!(bytes.len() <= MAX_FRAME, "oversized frame");
            bytes.push(b'\n');
            stdout.write_all(&bytes).await?;
            stdout.flush().await?;
        }
        Ok(())
    });
    let reader = tokio::spawn(async move {
        let mut input = BufReader::new(tokio::io::stdin());
        loop {
            let mut line = Vec::new();
            // Bound allocation before deserializing untrusted experimental IPC.
            use tokio::io::AsyncReadExt;
            let n = (&mut input)
                .take(MAX_FRAME as u64 + 1)
                .read_until(b'\n', &mut line)
                .await?;
            if n == 0 {
                break;
            }
            ensure!(
                line.len() <= MAX_FRAME && line.last() == Some(&b'\n'),
                "oversized or truncated frame"
            );
            let frame: Frame = serde_json::from_slice(&line)?;
            match frame {
                Frame::Relay(bytes) => {
                    if incoming.send(bytes).is_err() {
                        break;
                    }
                }
                other => {
                    if controls.send(other).is_err() {
                        break;
                    }
                }
            }
        }
        Ok(())
    });
    (
        Wire {
            d_guard: None,
            gate: None,
            abort_watch: None,
            #[cfg(all(test, feature = "research-faults"))]
            partial_probe: None,
            #[cfg(all(test, feature = "research-faults"))]
            process_probe: None,
            tx,
            rx,
            control,
        },
        writer,
        reader,
    )
}

pub struct SetupChannel {
    cipher: ChaCha20Poly1305,
    context: [u8; 32],
    role: u8,
    peer: [u8; 32],
}
impl SetupChannel {
    pub fn new(secret: &StaticSecret, request: &Request, role: u8) -> Result<Self> {
        Self::bound(
            secret,
            request.hellos[(1 - role) as usize].ephemeral,
            request.context(),
            role,
            request.manifest.identities[(1 - role) as usize],
        )
    }
    pub fn bound(
        secret: &StaticSecret,
        ephemeral: [u8; 32],
        context: [u8; 32],
        role: u8,
        peer: [u8; 32],
    ) -> Result<Self> {
        let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
        ensure!(shared.was_contributory(), "noncontributory peer DH key");
        let hk = Hkdf::<Sha256>::new(
            Some(b"pairkey/dkls-research/setup-channel/v1"),
            shared.as_bytes(),
        );
        let mut key = Zeroizing::new([0; 32]);
        hk.expand(&context, key.as_mut())
            .expect("fixed HKDF length");
        Ok(Self {
            cipher: ChaCha20Poly1305::new(key.as_ref().into()),
            context,
            role,
            peer,
        })
    }
    fn aad(&self, sender: u8, label: &str) -> Vec<u8> {
        serde_json::to_vec(&(self.context, sender, label)).unwrap()
    }
    pub async fn exchange<T: Serialize, U: DeserializeOwned>(
        &self,
        wire: &mut Wire,
        label: &str,
        value: &T,
    ) -> Result<U> {
        let nonce = fresh();
        let plaintext = Zeroizing::new(serde_json::to_vec(value)?);
        let mut encrypted = nonce[..12].to_vec();
        encrypted.extend(
            self.cipher
                .encrypt(
                    (&nonce[..12]).into(),
                    Payload {
                        msg: &plaintext,
                        aad: &self.aad(self.role, label),
                    },
                )
                .map_err(|_| anyhow::anyhow!("setup encryption failed"))?,
        );
        #[cfg(all(test, feature = "research-faults"))]
        if let Some(probe) = &wire.process_probe {
            probe.setup(label);
        }
        wire.send(Frame::Setup(encrypted))?;
        let Frame::Setup(encrypted) = wire.receive().await? else {
            anyhow::bail!("wrong setup frame");
        };
        ensure!(encrypted.len() >= 28, "truncated setup frame");
        let plaintext = Zeroizing::new(
            self.cipher
                .decrypt(
                    (&encrypted[..12]).into(),
                    Payload {
                        msg: &encrypted[12..],
                        aad: &self.aad(1 - self.role, label),
                    },
                )
                .map_err(|_| {
                    Failure::burn(
                        Phase::DirectSetup,
                        FailureKind::Context,
                        "authenticated setup context mismatch",
                    )
                })?,
        );
        serde_json::from_slice(&plaintext).map_err(|error| {
            Failure::violation(
                Phase::DirectSetup,
                self.peer,
                format!("authenticated setup deserialization: {error}"),
            )
            .into()
        })
    }
}
