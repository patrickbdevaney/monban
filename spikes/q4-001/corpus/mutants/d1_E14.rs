// E14 [d1] WS session reuses the first message's Granted for every later message (no per-message re-derivation)
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
            let g = ctx.grant::<SELECT>()?;
            while let Some(m) = ws.recv().await {
                let line = { let mut tx = db.begin()?; db.run(&mut tx, &g, Op::select(1))?.len().to_string() };
                ws.send(line).await?;
            }
            Ok(())
        }
    }
}

fn main() {}
