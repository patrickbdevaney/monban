// E16 [d2] Tx used after commit
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d2::*;
struct H;
struct AuditJob { key: u64 }
impl Job for AuditJob {
    fn run<'j, D: Db<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { Ok(()) }
}

impl ScopedHandler for H {
    type Response = &'static str;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<&'static str, SdkError> {
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(1, "a"))?;
        let done = db.commit(tx)?;
        db.run(&mut tx, &g, Op::insert(2, "dup"))?;
        Ok("x")
    }
}

fn main() {}
