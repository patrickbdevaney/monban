// E3 [d3] SSE producer task: tenant db handle + grant moved into tokio::spawn
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl SseHandler for H {
    fn events(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Event>) -> Result<(), SdkError> {
        let g = ctx.grant::<SELECT>()?;
        tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; if let Ok(mut tx) = db.begin() { let _ = db.run(&mut tx, &g, Op::select(0)); } });
        Ok(())
    }
}

fn main() {}
