// E11 [d2] detached job keeps the request's Granted (instead of re-deriving at run time)
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
struct KeepCap { g: Granted<'static, DataCap<INSERT>> }
impl Job for KeepCap {
    fn run<'j, D: Db<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { let _ = self.g; Ok(()) }
}
impl ScopedHandler for H {
    type Response = &'static str;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<&'static str, SdkError> {
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        let done = db.commit(tx)?;
        ctx.detach(&done, KeepCap { g: ctx.grant::<INSERT>()? })?;
        Ok("created")
    }
}

fn main() {}
