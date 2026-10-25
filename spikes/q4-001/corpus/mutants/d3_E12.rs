// E12 [d3] detached job keeps the request's tenant db handle
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;

impl JobHandler for H {
    fn handle(&self, ctx: OwnedCtx, db: OwnedDb) -> Result<(), SdkError> {
        let db2 = db.clone();
        tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; let Ok(g) = ctx.grant::<INSERT>() else { return }; let Ok(mut tx) = db2.begin() else { return }; let _ = db2.run(&mut tx, &g, Op::insert(9, "x")); let _ = db2.commit(tx); });
        Ok(())
    }
}

fn main() {}
