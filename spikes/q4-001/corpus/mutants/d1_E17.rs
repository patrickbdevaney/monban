// E17 [d1] handler forges a Granted (struct literal) instead of asking the host
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
            let g: Granted<'_, DataCap<INSERT>> = Granted { _c: PhantomData, _r: PhantomData };
            Ok(())
        }
    }
}

fn main() {}
