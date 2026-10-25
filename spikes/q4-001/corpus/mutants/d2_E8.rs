// E8 [d2] Ctx sent over a channel as Box<dyn Any + Send>
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
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<Box<dyn std::any::Any + Send>>(); let _ = tx.send(Box::new(ctx));
        Ok(Step::Done)
    }
}

fn main() {}
