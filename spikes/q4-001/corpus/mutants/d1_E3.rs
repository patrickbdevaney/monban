// E3 [d1] SSE producer task: tenant db handle + grant moved into tokio::spawn
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d1::*;
struct H;
impl SseHandler for H {
    fn events<'r, D: Db<'r>>(&'r self, ctx: Ctx<'r>, db: &'r D, mut out: Sink<'r, Event>)
        -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
        async move {
            let g = ctx.grant::<SELECT>()?;
            tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; if let Ok(mut tx) = db.begin() { let _ = db.run(&mut tx, &g, Op::select(0)); } });
            Ok(())
        }
    }
}

fn main() {}
