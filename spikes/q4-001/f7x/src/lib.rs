//! q4-001 scratch SDK: a mirror of frozen F7 plus three candidate streaming/SSE/WS/detached extensions and a
//! mock host that mints capabilities and drives handlers. Not production code.
#![forbid(unsafe_code)]

pub mod d1;
pub mod d2;
pub mod d3;
pub mod host;
pub mod surface;

pub use surface::*;

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// Runtime-agnostic single yield (keeps d1/d2 free of tokio).
#[derive(Debug, Default)]
pub(crate) struct YieldNow(bool);

impl Future for YieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
