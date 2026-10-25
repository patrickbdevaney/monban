// E19 [d1] WS outbound half moved into a spawned task that keeps writing with the session's capabilities
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d1::*;
struct H;
impl WsHandler for H {
    fn session<'r, D: Db<'r>>(&'r self, ctx: Ctx<'r>, db: &'r D, mut ws: WsSession<'r>)
        -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
        async move {
            tokio::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(5)).await; let _ = ws.send("late".to_string()).await; });
            Ok(())
        }
    }
}

fn main() {}
