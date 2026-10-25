// E9 [d1] Granted wrapped in Arc, Arc clone moved into tokio::spawn
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
            let g = std::sync::Arc::new(ctx.grant::<SELECT>()?); let g2 = g.clone(); tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; drop(g2); });
            Ok(())
        }
    }
}

fn main() {}
