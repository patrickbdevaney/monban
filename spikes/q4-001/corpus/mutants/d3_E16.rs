// E16 [d3] Tx used after commit
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
        db.run(&mut tx, &g, Op::insert(1, "a"))?;
        let done = db.commit(tx)?;
        db.run(&mut tx, &g, Op::insert(2, "dup"))?;
        Ok(())
    }
}

fn main() {}
