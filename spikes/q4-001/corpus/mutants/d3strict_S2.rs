// S2 [d3-strict] naive SSE ticker task holding only the Granted
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
        let g = ctx.grant::<SELECT>()?;
        tokio::spawn(async move { let _g = g; let _ = tx.send("tick".to_string()).await; });
        Ok(rx)
    }
}
fn main() {}
