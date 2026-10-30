//! Live-engine checks of the owned client (skipped unless `AEGIS_PG_DSNS` is set, space-separated DSNs):
//!
//! ```text
//! ci/engines.sh with pg17,pg18 -- sh -c "AEGIS_PG_DSNS='@pg17 @pg18' ci/heavy.sh cargo test -p aegis-adapter-pg --test wire_live"
//! ```
//! SCRAM-SHA-256 startup, the version gate, extended query with text params, server-reported txn status, named
//! statement/portal tracking, per-op statement_timeout, error recovery to a clean state, and CancelRequest.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::time::{Duration, Instant};

use aegis_adapter_pg::connect_admitted;
use aegis_adapter_pg::wire::{ConnectConfig, Error, Pipeline, TxnStatus, send_cancel};

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[test]
fn live_engines() {
    let Ok(dsns) = std::env::var("AEGIS_PG_DSNS") else {
        eprintln!("wire_live: AEGIS_PG_DSNS unset, skipped");
        return;
    };
    for dsn in dsns.split_whitespace() {
        let cfg = ConnectConfig::from_dsn(dsn).unwrap();
        let (mut c, v) = connect_admitted(&cfg, None).unwrap();
        eprintln!("wire_live: admitted {}", v.token());
        assert!(c.state().is_clean());

        let r =
            c.query("SELECT $1::text || 'x', $2::bigint + 1, NULL::text", &[Some("ab"), Some("41")], soon()).unwrap();
        assert_eq!(r.rows, vec![vec![Some("abx".into()), Some("42".into()), None]]);
        assert_eq!(r.tag, "SELECT 1");
        let r = c.query("SELECT $1::text", &[Some("a'; DROP TABLE x; --")], soon()).unwrap();
        assert_eq!(r.rows[0][0].as_deref(), Some("a'; DROP TABLE x; --"));

        match c.query("SELECT $1::int", &[Some("nope")], soon()) {
            Err(Error::Db(e)) => assert_eq!(e.code, "22P02"),
            other => panic!("{other:?}"),
        }
        assert!(c.state().is_clean());

        c.simple_query("BEGIN", soon()).unwrap();
        assert_eq!(c.state().txn_status(), Some(TxnStatus::InTransaction));
        c.set_local_statement_timeout(50, soon()).unwrap();
        match c.query("SELECT pg_sleep(2)", &[], soon()) {
            Err(Error::Db(e)) => assert_eq!(e.code, "57014", "statement_timeout"),
            other => panic!("{other:?}"),
        }
        assert_eq!(c.state().txn_status(), Some(TxnStatus::Failed));
        assert!(!c.state().is_clean());
        c.simple_query("ROLLBACK", soon()).unwrap();
        assert!(c.state().is_clean());

        // Named statement + named portal inside a transaction; portal gone at commit, statement until Close.
        c.simple_query("BEGIN", soon()).unwrap();
        let mut p = Pipeline::default();
        p.parse("s1", "SELECT generate_series(1, $1::int)", &[]).unwrap();
        p.bind("p1", "s1", &[Some("3")]).unwrap().execute("p1", 1).unwrap().sync();
        c.send(p, soon()).unwrap();
        assert_eq!(c.drain(soon()).unwrap(), TxnStatus::InTransaction);
        assert_eq!(c.state().open_statements().collect::<Vec<_>>(), vec!["s1"]);
        assert_eq!(c.state().open_portals().collect::<Vec<_>>(), vec!["p1"]);
        c.simple_query("COMMIT", soon()).unwrap();
        assert_eq!(c.state().open_portals().count(), 0);
        assert!(!c.state().is_clean());
        let mut p = Pipeline::default();
        p.close_statement("s1").unwrap().sync();
        c.send(p, soon()).unwrap();
        c.drain(soon()).unwrap();
        assert!(c.state().is_clean());

        // Timeout mid-statement leaves exact outstanding state; a CancelRequest (discard path) ends it server-side.
        let mut p = Pipeline::default();
        p.query("SELECT pg_sleep(30)").unwrap();
        c.send(p, soon()).unwrap();
        assert!(matches!(c.drain(Instant::now() + Duration::from_millis(200)), Err(Error::Timeout)));
        assert_eq!(c.state().pending_ready(), 1);
        assert!(c.state().unrecoverable().is_none());
        send_cancel(c.cancel_key().unwrap(), Duration::from_secs(2)).unwrap();
        let t0 = Instant::now();
        assert_eq!(c.drain(soon()).unwrap(), TxnStatus::Idle);
        assert!(t0.elapsed() < Duration::from_secs(5));
        assert_eq!(c.state().errors(), 3, "22P02, 57014, 57014 (canceled)");
        assert!(c.state().is_clean() && c.is_reusable());
        c.terminate(Duration::from_millis(200));
    }
}
