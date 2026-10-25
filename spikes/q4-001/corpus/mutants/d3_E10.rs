// E10 [d3] Box::leak(Granted) to &'static, then tokio::spawn
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        let g: &'static OwnedGranted<SELECT> = Box::leak(Box::new(ctx.grant::<SELECT>()?)); tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; let _ = g; });
        Ok(())
    }
}

fn main() {}
