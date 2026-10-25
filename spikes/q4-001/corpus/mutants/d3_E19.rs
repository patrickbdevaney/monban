// E19 [d3] WS outbound half moved into a spawned task that keeps writing with the session's capabilities
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d3::*;
struct H;
impl WsHandler for H {
    fn session(&self, ctx: OwnedCtx, db: OwnedDb, mut inbox: tokio::sync::mpsc::Receiver<String>, out: BodyTx<String>)
        -> Result<(), SdkError> {
        let (c2, o2) = (ctx.clone(), out.clone());
        tokio::spawn(async move { loop { tokio::time::sleep(std::time::Duration::from_millis(5)).await; if c2.grant::<SELECT>().is_err() || o2.send("push".to_string()).await.is_err() { return } } });
        Ok(())
    }
}

fn main() {}
