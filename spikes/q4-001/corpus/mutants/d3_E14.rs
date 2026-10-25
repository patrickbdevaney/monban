// E14 [d3] WS session reuses the first message's Granted for every later message (no per-message re-derivation)
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
        let g = ctx.grant::<SELECT>()?;
        tokio::spawn(async move {
            while let Some(m) = inbox.recv().await {
                let Ok(mut tx) = db.begin() else { return };
                let n = db.run(&mut tx, &g, Op::select(1)).map(|r| r.len()).unwrap_or(0);
                if out.send(n.to_string()).await.is_err() { return }
            }
        });
        Ok(())
    }
}

fn main() {}
