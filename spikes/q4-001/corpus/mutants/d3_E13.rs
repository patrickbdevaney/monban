// E13 [d3] detached job enqueued before the transaction commits (effect before commit)
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
        let (c2, d2) = (ctx.clone(), db.clone());
        tokio::spawn(async move { let Ok(g) = c2.grant::<INSERT>() else { return }; let Ok(mut t) = d2.begin() else { return }; let _ = d2.run(&mut t, &g, Op::insert(7, "audited")); let _ = d2.commit(t); });
        db.commit(tx)?;
        Ok(())
    }
}

fn main() {}
