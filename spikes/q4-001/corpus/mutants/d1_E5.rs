// E5 [d1] Granted stored in static OnceLock
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
static CELL: std::sync::OnceLock<Granted<'static, DataCap<SELECT>>> = std::sync::OnceLock::new();
use f7x::d1::*;
struct H;
impl BodyHandler for H {
    fn stream<'r, D: Db<'r>>(&'r self, ctx: Ctx<'r>, db: &'r D, mut out: Sink<'r, Chunk>)
        -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
        async move {
            let _ = CELL.set(ctx.grant::<SELECT>()?);
            Ok(())
        }
    }
}

fn main() {}
