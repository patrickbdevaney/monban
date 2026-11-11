//! Live-engine checks of the pool and the NC3 release path (skipped unless `AEGIS_PG_DSNS` is set):
//!
//! ```text
//! ci/engines.sh with pg17 -- sh -c "AEGIS_PG_DSNS='@pg17' ci/heavy.sh cargo test -p monban-adapter-pg --test pool_live"
//! ```
//! C8 reset on recycle clears session GUCs; a cancelled request's connection with an in-flight statement, an open
//! transaction and a named statement is recovered within the budget without a CancelRequest (drain, ROLLBACK, Close,
//! DISCARD ALL); over budget it is discarded with a CancelRequest that stops the backend's statement; epoch
//! retirement closes idle connections.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::time::{Duration, Instant};

use monban_adapter_pg::wire::{ConnectConfig, Pipeline, TxnStatus};
use monban_adapter_pg::{
    AcquireError, Charge, ConnId, Nc3Observer, PgConn, PgSession, Pool, PoolConfig, PoolKey, Release, Released,
    TenantId, connect_admitted,
};

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[derive(Default)]
struct Rec(Vec<String>);

impl Nc3Observer<PgConn> for Rec {
    fn quarantine(&mut self, _: ConnId) {
        self.0.push("quarantine".into());
    }
    fn cancel_request(&mut self, _: ConnId) {
        self.0.push("cancel_request".into());
    }
    fn charge(&mut self, _: u64, why: Charge) {
        self.0.push(format!("charge {why:?}"));
    }
    fn recover(&mut self, _: ConnId, ticks: u64, ok: bool) {
        self.0.push(format!("recover {ok} {ticks}"));
    }
    fn checkin(&mut self, _: ConnId, c: &PgConn) {
        assert!(c.proto().is_clean());
        self.0.push("checkin".into());
    }
    fn discard(&mut self, _: ConnId) {
        self.0.push("discard".into());
    }
}

fn scalar(c: &mut PgConn, sql: &str) -> Option<String> {
    let r = c.connection().query(sql, &[], soon()).unwrap();
    r.rows.into_iter().next().and_then(|row| row.into_iter().next()).flatten()
}

#[test]
fn live_pool_nc3() {
    let Ok(dsns) = std::env::var("AEGIS_PG_DSNS") else {
        eprintln!("pool_live: AEGIS_PG_DSNS unset, skipped");
        return;
    };
    for dsn in dsns.split_whitespace() {
        let cfg = ConnectConfig::from_dsn(dsn).unwrap();
        let pool: Pool<PgConn> =
            Pool::new(PoolConfig { max_open: 4, max_idle_per_key: 1, acquire_timeout: Duration::from_millis(100) });
        let connect = |_: &PoolKey| connect_admitted(&cfg, None).map(|(c, _)| PgConn::new(c));
        let key = PoolKey::new(b"alice", TenantId::new(1).unwrap(), "t_0000000000000001", 0).unwrap();

        // C8: session state set by one checkout is gone at the next (reset on recycle).
        let mut co = pool.acquire(&key, connect).unwrap();
        co.session().unwrap().connection().simple_query("SET app.principal = 'alice'", soon()).unwrap();
        assert_eq!(pool.release(co, Release::Completed, 2000, &mut Rec::default()), Released::CheckedIn);
        let mut co = pool.acquire(&key, connect).unwrap();
        assert!(co.reused() && co.needs_reset());
        assert!(co.reset_send(2000).unwrap());
        let g = co.reset_finish(2000).unwrap();
        assert_eq!(g, 1);
        let v = scalar(co.session().unwrap(), "SELECT current_setting('app.principal', true)");
        assert!(v.as_deref().is_none_or(str::is_empty), "GUC survived the recycle reset: {v:?}");

        // Cancelled mid-statement inside a txn with a named statement: recovered without a CancelRequest.
        {
            let s = co.session().unwrap().connection();
            s.simple_query("BEGIN", soon()).unwrap();
            let mut p = Pipeline::default();
            p.parse("nc3_s1", "SELECT 1", &[]).unwrap().sync();
            s.send(p, soon()).unwrap();
            while s.state().outstanding() > 0 {
                s.read_event(soon()).unwrap();
            }
            let mut p = Pipeline::default();
            p.query("SELECT pg_sleep(0.3)").unwrap();
            s.send(p, soon()).unwrap(); // written; the cancel lands before the reply is read
            assert_eq!(s.state().txn_status(), Some(TxnStatus::InTransaction));
        }
        let mut rec = Rec::default();
        let r = pool.release(co, Release::Cancelled, 3000, &mut rec);
        assert!(matches!(r, Released::Recovered { .. }), "{r:?} {:?}", rec.0);
        assert!(!rec.0.contains(&"cancel_request".to_string()), "recovery sent a CancelRequest: {:?}", rec.0);
        let mut co = pool.acquire(&key, connect).unwrap();
        assert!(co.reused() && !co.needs_reset());
        let s = co.session().unwrap();
        assert_eq!(scalar(s, "SELECT count(*)::text FROM pg_prepared_statements").as_deref(), Some("0"));
        assert_eq!(s.proto().txn_status(), Some(TxnStatus::Idle));

        // Over budget: discarded with a CancelRequest, which stops the backend's statement.
        {
            let s = co.session().unwrap().connection();
            s.simple_query("BEGIN", soon()).unwrap();
            let mut p = Pipeline::default();
            p.query("SELECT pg_sleep(5) /* nc3-discard */").unwrap();
            s.send(p, soon()).unwrap();
        }
        let mut rec = Rec::default();
        assert_eq!(pool.release(co, Release::Cancelled, 100, &mut rec), Released::Discarded);
        assert!(rec.0.contains(&"cancel_request".to_string()) && rec.0.contains(&"charge Discard".to_string()));
        let mut probe = PgConn::new(connect_admitted(&cfg, None).unwrap().0);
        let t0 = Instant::now();
        loop {
            let n = scalar(
                &mut probe,
                "SELECT count(*)::text FROM pg_stat_activity WHERE query LIKE '%nc3-discard%' AND state = 'active' \
                 AND pid <> pg_backend_pid()",
            );
            if n.as_deref() == Some("0") {
                break;
            }
            assert!(t0.elapsed() < Duration::from_secs(3), "discarded backend still running its statement");
            std::thread::sleep(Duration::from_millis(50));
        }

        // Epoch retirement (C5).
        let co = pool.acquire(&key, connect).unwrap();
        pool.release(co, Release::Completed, 2000, &mut Rec::default());
        assert_eq!(pool.retire_before(1).len(), 1);
        assert!(matches!(pool.acquire(&key, connect), Err(AcquireError::StaleEpoch)));
        assert_eq!(pool.open(), 0);
        eprintln!("pool_live: ok");
    }
}
