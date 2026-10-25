// E2 [d1] whole Ctx moved into tokio::spawn
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d1::*;
struct H;
impl BodyHandler for H {
    fn stream<'r, D: Db<'r>>(&'r self, ctx: Ctx<'r>, db: &'r D, mut out: Sink<'r, Chunk>)
        -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
        async move {
            tokio::spawn(async move { let c = ctx; tokio::time::sleep(std::time::Duration::from_millis(5)).await; let _ = c.grant::<SELECT>(); });
            Ok(())
        }
    }
}

fn main() {}
