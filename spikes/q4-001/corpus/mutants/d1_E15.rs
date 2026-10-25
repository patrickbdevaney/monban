// E15 [d1] open Tx<Open> held across streamed chunks (writes after the response head is committed)
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
            for i in 0..3u64 {
                out.send(i.to_string()).await?;
                db.run(&mut tx, &g, Op::insert(100 + i, "late"))?;
            }
            db.commit(tx)?;
            Ok(())
        }
    }
}

fn main() {}
