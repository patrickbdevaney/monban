// E15 [d3] open Tx<Open> held across streamed chunks (writes after the response head is committed)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        tokio::spawn(async move {
            for i in 0..3u64 {
                if out.send(i.to_string()).await.is_err() { return }
                let _ = db.run(&mut tx, &g, Op::insert(100 + i, "late"));
            }
            let _ = db.commit(tx);
        });
        Ok(())
    }
}

fn main() {}
