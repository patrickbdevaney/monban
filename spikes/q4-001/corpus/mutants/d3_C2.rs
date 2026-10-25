// C2 [d3] CONTROL: plain data (ids, strings) moved into tokio::spawn
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        let tenant = ctx.principal().tenant(); tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; let _ = tenant; });
        Ok(())
    }
}

fn main() {}
