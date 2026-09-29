use anyhow::{ensure, Context, Result};
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
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::mpsc,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct Wire {
    pub gate: Option<ReleaseGate>,
    #[cfg(all(test, feature = "research-faults"))]
    pub partial_barrier: Option<([u8; 32], std::sync::Arc<std::sync::Barrier>)>,
    pub tx: mpsc::UnboundedSender<Frame>,
    pub rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub control: mpsc::UnboundedReceiver<Frame>,
}
impl Wire {
    pub async fn receive(&mut self) -> Result<Frame> {
        self.control.recv().await.context("peer disconnected")
    }
    pub fn send(&self, frame: Frame) -> Result<()> {
        #[cfg(all(test, feature = "research-faults"))]
        if let (Some((id, barrier)), Frame::Relay(bytes)) = (&self.partial_barrier, &frame) {
            if bytes.get(..32) == Some(id.as_slice()) {
                barrier.wait();
                barrier.wait();
            }
        }
        let gated = matches!(frame, Frame::Relay(_) | Frame::Setup(_) | Frame::Result(_));
        let send = || {
            self.tx
                .send(frame)
                .map_err(|_| anyhow::anyhow!("writer disconnected"))
        };
        if let Some(gate) = &self.gate {
            // All protocol output, including native R4 partials, is fenced.
            if gated {
                return gate.release(send);
            }
        }
        send()
    }
}
impl Stream for Wire {
    type Item = Vec<u8>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Vec<u8>>> {
        self.rx.poll_recv(cx)
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
            gate: None,
            #[cfg(all(test, feature = "research-faults"))]
            partial_barrier: None,
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
        let shared = secret.diffie_hellman(&PublicKey::from(
            request.hellos[(1 - role) as usize].ephemeral,
        ));
        ensure!(shared.was_contributory(), "noncontributory peer DH key");
        let context = request.context();
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
            peer: request.manifest.identities[(1 - role) as usize],
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
