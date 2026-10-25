// E10 [d2] Box::leak(Granted) to &'static, then tokio::spawn
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
        let g: &'static Granted<'_, DataCap<SELECT>> = Box::leak(Box::new(ctx.grant::<SELECT>()?)); tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; let _ = g; });
        Ok(Step::Done)
    }
}

fn main() {}
