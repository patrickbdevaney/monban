// C2 [d1] CONTROL: plain data (ids, strings) moved into tokio::spawn
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
            let tenant = ctx.principal().tenant(); tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; let _ = tenant; });
            Ok(())
        }
    }
}

fn main() {}
