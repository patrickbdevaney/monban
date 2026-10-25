// E7 [d1] Granted sent over a typed channel to a long-lived consumer (static Sender)
#![forbid(unsafe_code)]
#![allow(unused)]
use core::future::Future;
use core::marker::PhantomData;
use f7x::*;
static TX: std::sync::OnceLock<std::sync::Mutex<std::sync::mpsc::Sender<Granted<'static, DataCap<SELECT>>>>> = std::sync::OnceLock::new();
use f7x::d1::*;
struct H;
impl BodyHandler for H {
    fn stream<'r, D: Db<'r>>(&'r self, ctx: Ctx<'r>, db: &'r D, mut out: Sink<'r, Chunk>)
        -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
        async move {
            let g = ctx.grant::<SELECT>()?;
            if let Some(t) = TX.get() { if let Ok(t) = t.lock() { let _ = t.send(g); } }
            Ok(())
        }
    }
}

fn main() {}
