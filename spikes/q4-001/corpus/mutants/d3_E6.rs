// E6 [d3] Ctx stashed in thread_local RefCell (no Sync needed)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
thread_local! { static STASH: std::cell::RefCell<Option<OwnedCtx>> = std::cell::RefCell::new(None); }
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        STASH.with(|s| *s.borrow_mut() = Some(ctx));
        Ok(())
    }
}

fn main() {}
