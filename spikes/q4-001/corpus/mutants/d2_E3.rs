// E3 [d2] SSE producer task: tenant db handle + grant moved into tokio::spawn
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d2::*;
struct H;
struct G { n: u64 }
impl SseHandler for H {
    type Gen = G;
    fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D, last: Option<u64>) -> Result<G, SdkError> {
        Ok(G { n: 0 })
    }
}
impl StreamGen for G {
    type Item = Event;
    fn next<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Event>, SdkError> {
        let g = ctx.grant::<SELECT>()?;
        tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; if let Ok(mut tx) = db.begin() { let _ = db.run(&mut tx, &g, Op::select(0)); } });
        Ok(Step::Done)
    }
}

fn main() {}
