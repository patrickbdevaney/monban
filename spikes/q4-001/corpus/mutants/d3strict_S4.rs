// S4 [d3-strict] naive detached audit task after commit using F7 Ctx<'r>
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
struct H;
impl ScopedHandler for H {
    type Response = &'static str;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<&'static str, SdkError> {
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        db.commit(tx)?;
        tokio::spawn(async move { let Ok(g) = ctx.grant::<INSERT>() else { return }; let _ = g; });
        Ok("created")
    }
}
fn main() {}
