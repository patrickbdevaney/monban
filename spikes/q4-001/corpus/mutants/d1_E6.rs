// E6 [d1] Ctx stashed in thread_local RefCell (no Sync needed)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
thread_local! { static STASH: std::cell::RefCell<Option<Ctx<'static>>> = std::cell::RefCell::new(None); }
use f7x::d1::*;
struct H;
impl BodyHandler for H {
    fn stream<'r, D: Db<'r>>(&'r self, ctx: Ctx<'r>, db: &'r D, mut out: Sink<'r, Chunk>)
        -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
        async move {
            STASH.with(|s| *s.borrow_mut() = Some(ctx));
            Ok(())
        }
    }
}

fn main() {}
