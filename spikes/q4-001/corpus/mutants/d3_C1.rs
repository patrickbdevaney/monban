// C1 [d3] CONTROL: std::thread::scope borrowing a Granted (joined before the scope ends)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        let g = ctx.grant::<SELECT>()?; std::thread::scope(|s| { s.spawn(|| { let _ = &g; }); });
        Ok(())
    }
}

fn main() {}
