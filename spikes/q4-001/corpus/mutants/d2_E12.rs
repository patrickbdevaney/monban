// E12 [d2] detached job keeps the request's tenant db handle
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
struct KeepDb<T: Send + Sync + 'static> { db: &'static T }
impl<T: Send + Sync + 'static> Job for KeepDb<T> {
    fn run<'j, D: Db<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { let _ = self.db; Ok(()) }
}
impl ScopedHandler for H {
    type Response = &'static str;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<&'static str, SdkError> {
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        let done = db.commit(tx)?;
        ctx.detach(&done, KeepDb { db })?;
        Ok("created")
    }
}

fn main() {}
