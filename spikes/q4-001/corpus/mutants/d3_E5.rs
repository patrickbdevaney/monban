// E5 [d3] Granted stored in static OnceLock
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
static CELL: std::sync::OnceLock<OwnedGranted<SELECT>> = std::sync::OnceLock::new();
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        let _ = CELL.set(ctx.grant::<SELECT>()?);
        Ok(())
    }
}

fn main() {}
