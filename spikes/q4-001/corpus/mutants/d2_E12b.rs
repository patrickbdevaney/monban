// E12b [d2] detached job keeps the request's &Principal (Sync, so only the lifetime can stop it)
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
struct KeepPrincipal { p: &'static Principal }
impl Job for KeepPrincipal {
    fn run<'j, D: Db<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { let _ = self.p.tenant(); Ok(()) }
}
impl ScopedHandler for H {
    type Response = &'static str;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<&'static str, SdkError> {
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        let done = db.commit(tx)?;
        ctx.detach(&done, KeepPrincipal { p: ctx.principal() })?;
        Ok("created")
    }
}

fn main() {}
