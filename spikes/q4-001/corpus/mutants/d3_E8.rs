// E8 [d3] Ctx sent over a channel as Box<dyn Any + Send>
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<Box<dyn std::any::Any + Send>>(); let _ = tx.send(Box::new(ctx));
        Ok(())
    }
}

fn main() {}
