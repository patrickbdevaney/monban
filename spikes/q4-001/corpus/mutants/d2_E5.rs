// E5 [d2] Granted stored in static OnceLock
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
static CELL: std::sync::OnceLock<Granted<'static, DataCap<SELECT>>> = std::sync::OnceLock::new();
use f7x::d2::*;
struct H;
struct G { n: u64 }
impl BodyHandler for H {
    type Gen = G;
    fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<G, SdkError> {
        Ok(G { n: 0 })
    }
}
impl StreamGen for G {
    type Item = Chunk;
    fn next<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Chunk>, SdkError> {
        let _ = CELL.set(ctx.grant::<SELECT>()?);
        Ok(Step::Done)
    }
}

fn main() {}
