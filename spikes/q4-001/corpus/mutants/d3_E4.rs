// E4 [d3] Ctx cloned, clone moved into tokio::spawn, original keeps serving
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        let c2 = ctx.clone();
        tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; let _ = c2.grant::<SELECT>(); });
        let _ = ctx.grant::<SELECT>()?;
        Ok(())
    }
}

fn main() {}
