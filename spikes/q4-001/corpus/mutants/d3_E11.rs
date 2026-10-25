// E11 [d3] detached job keeps the request's Granted (instead of re-deriving at run time)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;

impl JobHandler for H {
    fn handle(&self, ctx: OwnedCtx, db: OwnedDb) -> Result<(), SdkError> {
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        db.commit(tx)?;
        tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; let Ok(mut tx) = db.begin() else { return }; let _ = db.run(&mut tx, &g, Op::insert(7, "late")); let _ = db.commit(tx); });
        Ok(())
    }
}

fn main() {}
