// C1 [d1] CONTROL: std::thread::scope borrowing a Granted (joined before the scope ends)
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
            let g = ctx.grant::<SELECT>()?; std::thread::scope(|s| { s.spawn(|| { let _ = &g; }); });
            Ok(())
        }
    }
}

fn main() {}
