// E18 [d3] unsafe transmute of Granted<'r> to Granted<'static>, then spawn
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        let c: OwnedCtx = unsafe { core::mem::transmute::<OwnedCtx, OwnedCtx>(ctx) };
        Ok(())
    }
}

fn main() {}
