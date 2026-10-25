//! Baseline (non-mutated) handlers for the four features under each design. Mutants in `mutants/` are these
//! handlers with one smuggling edit. Domain: tenant rows (key, val); WS protocol `get:<key>` / `put:<key>:<val>`.
#![forbid(unsafe_code)]

/// Design 1: borrowing streams tied to `'r`, host-driven. (d) has no API in this design.
pub mod d1app {
    use core::future::Future;
    use f7x::d1::{BodyHandler, Chunk, Event, SseHandler, Sink, WsHandler, WsSession};
    use f7x::{Ctx, Db, Op, SdkError, INSERT, SELECT};

    /// (a) stream every row as one chunk, re-granting per chunk.
    pub struct ListBody;
    impl BodyHandler for ListBody {
        fn stream<'r, D: Db<'r>>(
            &'r self,
            ctx: Ctx<'r>,
            db: &'r D,
            mut out: Sink<'r, Chunk>,
        ) -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
            async move {
                let keys: Vec<u64> = {
                    let g = ctx.grant::<SELECT>()?;
                    let mut tx = db.begin()?;
                    db.run(&mut tx, &g, Op::select(0))?.into_iter().map(|(k, _)| k).collect()
                };
                for k in keys {
                    let line = {
                        let g = ctx.grant::<SELECT>()?;
                        let mut tx = db.begin()?;
                        db.run(&mut tx, &g, Op::select(k))?.into_iter().map(|(_, v)| v).collect::<Vec<_>>().join(",")
                    };
                    out.send(line).await?;
                }
                Ok(())
            }
        }
    }

    /// (b) one SSE event per row.
    pub struct RowEvents;
    impl SseHandler for RowEvents {
        fn events<'r, D: Db<'r>>(
            &'r self,
            ctx: Ctx<'r>,
            db: &'r D,
            mut out: Sink<'r, Event>,
        ) -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
            async move {
                let rows = {
                    let g = ctx.grant::<SELECT>()?;
                    let mut tx = db.begin()?;
                    db.run(&mut tx, &g, Op::select(0))?
                };
                for (k, v) in rows {
                    out.send(Event { id: k, data: v }).await?;
                }
                Ok(())
            }
        }
    }

    /// (c) WS: grant is re-derived for each inbound message.
    pub struct KvSocket;
    impl WsHandler for KvSocket {
        fn session<'r, D: Db<'r>>(
            &'r self,
            ctx: Ctx<'r>,
            db: &'r D,
            mut ws: WsSession<'r>,
        ) -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
            async move {
                while let Some(m) = ws.recv().await {
                    let reply = handle_msg(&ctx, db, &m);
                    ws.send(reply).await?;
                }
                Ok(())
            }
        }
    }

    pub fn handle_msg<'r, D: Db<'r>>(ctx: &Ctx<'r>, db: &D, m: &str) -> String {
        let r: Result<String, SdkError> = (|| {
            if let Some(k) = m.strip_prefix("get:") {
                let g = ctx.grant::<SELECT>()?;
                let mut tx = db.begin()?;
                let k = k.parse().map_err(|_| SdkError::Denied)?;
                Ok(db.run(&mut tx, &g, Op::select(k))?.into_iter().map(|(_, v)| v).collect::<Vec<_>>().join(","))
            } else if let Some(rest) = m.strip_prefix("put:") {
                let (k, v) = rest.split_once(':').ok_or(SdkError::Denied)?;
                let g = ctx.grant::<INSERT>()?;
                let mut tx = db.begin()?;
                db.run(&mut tx, &g, Op::insert(k.parse().map_err(|_| SdkError::Denied)?, v))?;
                db.commit(tx)?;
                Ok("ok".to_string())
            } else {
                Err(SdkError::Denied)
            }
        })();
        r.unwrap_or_else(|e| format!("err:{e:?}"))
    }
}

/// Design 2: host-owned stream capability. Generators are `'static` plain data; Ctx is re-minted per step.
pub mod d2app {
    use f7x::d2::{BodyHandler, Chunk, Event, Job, SseHandler, Step, StreamGen, WsHandler, WsReply, WsSessionGen};
    use f7x::{Ctx, Db, Op, ScopedHandler, SdkError, TenantDb, INSERT, SELECT};

    /// (a) body: the generator holds only a key cursor.
    pub struct ListBody;
    pub struct ListGen {
        keys: Vec<u64>,
        i: usize,
    }
    impl BodyHandler for ListBody {
        type Gen = ListGen;
        fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<ListGen, SdkError> {
            let g = ctx.grant::<SELECT>()?;
            let mut tx = db.begin()?;
            let keys = db.run(&mut tx, &g, Op::select(0))?.into_iter().map(|(k, _)| k).collect();
            Ok(ListGen { keys, i: 0 })
        }
    }
    impl StreamGen for ListGen {
        type Item = Chunk;
        fn next<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Chunk>, SdkError> {
            let Some(k) = self.keys.get(self.i).copied() else { return Ok(Step::Done) };
            self.i += 1;
            let g = ctx.grant::<SELECT>()?; // re-derived for this step
            let mut tx = db.begin()?;
            let v = db.run(&mut tx, &g, Op::select(k))?.into_iter().map(|(_, v)| v).collect::<Vec<_>>().join(",");
            Ok(Step::Item(v))
        }
    }

    /// (b) SSE with resume: the generator holds the last delivered id.
    pub struct RowEvents;
    pub struct RowEventGen {
        after: u64,
    }
    impl SseHandler for RowEvents {
        type Gen = RowEventGen;
        fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, _db: &D, last: Option<u64>) -> Result<RowEventGen, SdkError> {
            ctx.grant::<SELECT>()?; // fail at open if not allowed at all
            Ok(RowEventGen { after: last.unwrap_or(0) })
        }
    }
    impl StreamGen for RowEventGen {
        type Item = Event;
        fn next<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Event>, SdkError> {
            let g = ctx.grant::<SELECT>()?;
            let mut tx = db.begin()?;
            let next = db.run(&mut tx, &g, Op::select(0))?.into_iter().filter(|(k, _)| *k > self.after).min_by_key(|(k, _)| *k);
            match next {
                Some((k, v)) => {
                    self.after = k;
                    Ok(Step::Item(Event { id: k, data: v }))
                }
                None => Ok(Step::Done),
            }
        }
    }

    /// (c) WS: session state is a message counter; every message gets a fresh Ctx<'m>.
    pub struct KvSocket;
    pub struct KvSession {
        pub n: u64,
    }
    impl WsHandler for KvSocket {
        type Session = KvSession;
        fn open<'r, D: Db<'r>>(&self, _ctx: Ctx<'r>, _db: &D) -> Result<KvSession, SdkError> {
            Ok(KvSession { n: 0 })
        }
    }
    impl WsSessionGen for KvSession {
        fn on_message<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D, msg: &str) -> Result<WsReply, SdkError> {
            self.n += 1;
            Ok(WsReply::Send(vec![crate::d1app::handle_msg(&ctx, db, msg)]))
        }
    }

    /// (d) detached job: the frozen ScopedHandler commits, then detaches a `'static` job value.
    pub struct CreateThenAudit;
    pub struct AuditJob {
        pub key: u64,
    }
    impl ScopedHandler for CreateThenAudit {
        type Response = &'static str;
        fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<&'static str, SdkError> {
            let g = ctx.grant::<INSERT>()?;
            let mut tx = db.begin()?;
            db.run(&mut tx, &g, Op::insert(7, "created"))?;
            let done = db.commit(tx)?;
            ctx.detach(&done, AuditJob { key: 7 })?;
            Ok("created")
        }
    }
    impl Job for AuditJob {
        fn run<'j, D: Db<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> {
            let g = ctx.grant::<INSERT>()?; // re-derived when the job runs
            let mut tx = db.begin()?;
            db.run(&mut tx, &g, Op::insert(self.key, "audited"))?;
            db.commit(tx)?;
            Ok(())
        }
    }
}

/// Design 3: leaky `'static` owned handles; the handler spawns producers itself.
pub mod d3app {
    use f7x::d3::{BodyHandler, BodyTx, Chunk, Event, JobHandler, OwnedCtx, OwnedDb, SseHandler, WsHandler};
    use f7x::{Op, SdkError, INSERT, SELECT};

    fn read(ctx: &OwnedCtx, db: &OwnedDb, k: u64) -> Result<Vec<(u64, String)>, SdkError> {
        let g = ctx.grant::<SELECT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::select(k))
    }

    pub struct ListBody;
    impl BodyHandler for ListBody {
        fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
            tokio::spawn(async move {
                let Ok(rows) = read(&ctx, &db, 0) else { return };
                for (k, _) in rows {
                    let Ok(r) = read(&ctx, &db, k) else { return };
                    let line = r.into_iter().map(|(_, v)| v).collect::<Vec<_>>().join(",");
                    if out.send(line).await.is_err() {
                        return;
                    }
                }
            });
            Ok(())
        }
    }

    pub struct RowEvents;
    impl SseHandler for RowEvents {
        fn events(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Event>) -> Result<(), SdkError> {
            tokio::spawn(async move {
                let Ok(rows) = read(&ctx, &db, 0) else { return };
                for (k, v) in rows {
                    if out.send(Event { id: k, data: v }).await.is_err() {
                        return;
                    }
                }
            });
            Ok(())
        }
    }

    pub struct KvSocket;
    impl WsHandler for KvSocket {
        fn session(
            &self,
            ctx: OwnedCtx,
            db: OwnedDb,
            mut inbox: tokio::sync::mpsc::Receiver<String>,
            out: BodyTx<String>,
        ) -> Result<(), SdkError> {
            tokio::spawn(async move {
                while let Some(m) = inbox.recv().await {
                    let reply = match m.strip_prefix("get:").and_then(|k| k.parse().ok()) {
                        Some(k) => match read(&ctx, &db, k) {
                            Ok(r) => r.into_iter().map(|(_, v)| v).collect::<Vec<_>>().join(","),
                            Err(e) => format!("err:{e:?}"),
                        },
                        None => "err:Denied".to_string(),
                    };
                    if out.send(reply).await.is_err() {
                        return;
                    }
                }
            });
            Ok(())
        }
    }

    pub struct CreateThenAudit;
    impl JobHandler for CreateThenAudit {
        fn handle(&self, ctx: OwnedCtx, db: OwnedDb) -> Result<(), SdkError> {
            let g = ctx.grant::<INSERT>()?;
            let mut tx = db.begin()?;
            db.run(&mut tx, &g, Op::insert(7, "created"))?;
            db.commit(tx)?;
            tokio::spawn(async move {
                let Ok(g) = ctx.grant::<INSERT>() else { return };
                let Ok(mut tx) = db.begin() else { return };
                let _ = db.run(&mut tx, &g, Op::insert(7, "audited"));
                let _ = db.commit(tx);
            });
            Ok(())
        }
    }
}
