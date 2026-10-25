// E16 [d1] Tx used after commit
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
            let g = ctx.grant::<INSERT>()?;
            let mut tx = db.begin()?;
            db.run(&mut tx, &g, Op::insert(1, "a"))?;
            let done = db.commit(tx)?;
            db.run(&mut tx, &g, Op::insert(2, "dup"))?;
            Ok(())
        }
    }
}

fn main() {}
