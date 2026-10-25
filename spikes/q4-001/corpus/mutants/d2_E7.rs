// E7 [d2] Granted sent over a typed channel to a long-lived consumer (static Sender)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
static TX: std::sync::OnceLock<std::sync::Mutex<std::sync::mpsc::Sender<Granted<'static, DataCap<SELECT>>>>> = std::sync::OnceLock::new();
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
        let g = ctx.grant::<SELECT>()?;
        if let Some(t) = TX.get() { if let Ok(t) = t.lock() { let _ = t.send(g); } }
        Ok(Step::Done)
    }
}

fn main() {}
