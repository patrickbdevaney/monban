// E14 [d2] WS session reuses the first message's Granted for every later message (no per-message re-derivation)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
use f7x::d2::*;
struct H;
struct G { g: Granted<'static, DataCap<SELECT>> }
impl WsHandler for H {
    type Session = G;
    fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<G, SdkError> {
        Ok(G { g: ctx.grant::<SELECT>()? })
    }
}
impl WsSessionGen for G {
    fn on_message<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D, msg: &str) -> Result<WsReply, SdkError> {
        let mut tx = db.begin()?;
        let n = db.run(&mut tx, &self.g, Op::select(1))?.len();
        Ok(WsReply::Send(vec![n.to_string()]))
    }
}

fn main() {}
