// S3 [d3-strict] naive WS task holding Ctx for the session
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
struct H;
impl ScopedHandler for H {
    type Response = tokio::sync::mpsc::Sender<String>;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Response, SdkError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
        tokio::spawn(async move { while let Some(_m) = rx.recv().await { let _ = ctx.grant::<SELECT>(); } });
        Ok(tx)
    }
}
fn main() {}
