// E4 [d2] Ctx cloned, clone moved into tokio::spawn, original keeps serving
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
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
        let c2 = ctx.clone();
        tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; let _ = c2.grant::<SELECT>(); });
        let _ = ctx.grant::<SELECT>()?;
        Ok(Step::Done)
    }
}

fn main() {}
