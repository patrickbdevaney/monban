// E6 [d2] Ctx stashed in thread_local RefCell (no Sync needed)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
thread_local! { static STASH: std::cell::RefCell<Option<Ctx<'static>>> = std::cell::RefCell::new(None); }
use f7x::d2::*;
struct H;
struct G { n: u64 }
impl BodyHandler for H {
    type Gen = G;
    fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<G, SdkError> {
        Ok(G { n: 0 })
    }
}
impl StreamGen for G {
    type Item = Chunk;
    fn next<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Chunk>, SdkError> {
        STASH.with(|s| *s.borrow_mut() = Some(ctx));
        Ok(Step::Done)
    }
}

fn main() {}
