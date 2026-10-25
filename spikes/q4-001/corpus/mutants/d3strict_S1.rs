// S1 [d3-strict] naive spawn producer for a streamed body using F7 Ctx<'r>/&D
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
struct H;
impl ScopedHandler for H {
    type Response = tokio::sync::mpsc::Receiver<String>;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Response, SdkError> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let Ok(g) = ctx.grant::<SELECT>() else { return };
            let Ok(mut t) = db.begin() else { return };
            if db.run(&mut t, &g, Op::select(0)).is_ok() { let _ = tx.send("row".to_string()).await; }
        });
        Ok(rx)
    }
}
fn main() {}
