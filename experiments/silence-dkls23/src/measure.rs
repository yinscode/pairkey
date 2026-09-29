//! Active async poll timing excludes suspended awaits, but includes synchronous
//! crypto, serialization, control filesystem calls and OS preemption in each poll.
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Instant,
};
pub struct Active<F> {
    inner: Pin<Box<F>>,
    nanos: Arc<AtomicU64>,
}
impl<F: Future> Future for Active<F> {
    type Output = F::Output;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let t = Instant::now();
        let result = self.inner.as_mut().poll(cx);
        self.nanos
            .fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
        result
    }
}
pub fn active<F: Future>(future: F) -> (Active<F>, Arc<AtomicU64>) {
    let nanos = Arc::new(AtomicU64::new(0));
    (
        Active {
            inner: Box::pin(future),
            nanos: nanos.clone(),
        },
        nanos,
    )
}
pub fn milliseconds(nanos: &AtomicU64) -> f64 {
    nanos.load(Ordering::Relaxed) as f64 / 1e6
}
