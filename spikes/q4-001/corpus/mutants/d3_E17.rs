// E17 [d3] handler forges a Granted (struct literal) instead of asking the host
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        let g = OwnedGranted::<INSERT>(PhantomData);
        Ok(())
    }
}

fn main() {}
