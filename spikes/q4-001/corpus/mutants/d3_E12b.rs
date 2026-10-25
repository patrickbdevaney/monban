// E12b [d3] detached job keeps the request's &Principal (Sync, so only the lifetime can stop it)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;

impl JobHandler for H {
    fn handle(&self, ctx: OwnedCtx, db: OwnedDb) -> Result<(), SdkError> {
        let p = ctx.clone();
        tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; let _ = p.principal().tenant(); });
        Ok(())
    }
}

fn main() {}
