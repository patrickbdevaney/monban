// E7 [d3] Granted sent over a typed channel to a long-lived consumer (static Sender)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
static TX: std::sync::OnceLock<std::sync::Mutex<std::sync::mpsc::Sender<OwnedGranted<SELECT>>>> = std::sync::OnceLock::new();
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        let g = ctx.grant::<SELECT>()?;
        if let Some(t) = TX.get() { if let Ok(t) = t.lock() { let _ = t.send(g); } }
        Ok(())
    }
}

fn main() {}
