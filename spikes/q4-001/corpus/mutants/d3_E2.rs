// E2 [d3] whole Ctx moved into tokio::spawn
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        tokio::spawn(async move { let c = ctx; tokio::time::sleep(std::time::Duration::from_millis(5)).await; let _ = c.grant::<SELECT>(); });
        Ok(())
    }
}

fn main() {}
