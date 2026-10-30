//! Live checks of the renderer and the schema gate (skipped unless `AEGIS_PG_DSNS` is set, space-separated DSNs of
//! THROWAWAY databases: the test creates and drops schema `aegis_lower_live` and role `aegis_lower_app`):
//!
//! ```text
//! ci/engines.sh with pg17,pg18 -- sh -c "AEGIS_PG_DSNS='@pg17 @pg18' ci/heavy.sh cargo test -p aegis-adapter-pg --test lower_live"
//! ```
//! * differential: a deterministic random corpus of filters over rows with NULLs, int/text classes, edge values
//!   and non-ASCII text; the rows PG returns for the rendered `lowerQ` must equal `aegis_data_ir::eval3` / `sql3`
//!   over the stored rows (refQ3 = keeps, `lowerQ_exact3`);
//! * the DDL of `rls_policy` on a C-collated (tenant, id) table is admitted by `check_live_schema`, whose PgTable
//!   then renders an upsert that runs; `rls_bind` under FORCE RLS scopes an unfiltered SELECT to the bound tenant;
//! * `check_live_schema` refuses the same table with a default-collation tenant, without FORCE, and with a policy
//!   that has no WITH CHECK.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::time::{Duration, Instant};

use aegis_adapter_pg::lower::{params_as_wire, render_op, rls_bind, rls_policy};
use aegis_adapter_pg::wire::{ConnectConfig, Connection};
use aegis_adapter_pg::{LiveSchemaError, check_live_schema, connect_admitted};
use aegis_data_ir::{
    Collation, Column, Field, OpKind, Pred, Schema, SchemaError, UniqueIndex, Value, eval3, tenant_text,
};
use aegis_types::TenantId;

const NS: &str = "aegis_lower_live";

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

fn exec(c: &mut Connection, sql: &str) {
    c.simple_query(sql, soon()).unwrap_or_else(|e| panic!("{sql}: {e}"));
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn pick<T: Clone>(&mut self, xs: &[T]) -> T {
        let n = u64::try_from(xs.len()).unwrap();
        xs[usize::try_from(self.next() % n).unwrap()].clone()
    }
}

// fields: 0 id, 1 tenant, 2 x (text), 3 y (bigint)
fn schema() -> Schema {
    let c = |field, name: &str, key| Column {
        field,
        name: name.into(),
        nullable: field != 1,
        collation: Collation::Binary,
        key,
    };
    Schema {
        collection: "t".into(),
        tenant_field: 1,
        columns: vec![c(0, "id", true), c(1, "tenant", true), c(2, "x", false), c(3, "y", false)],
        permitted: vec![0, 1, 2, 3],
        unique_indexes: vec![UniqueIndex { fields: vec![0, 1], prefix: false }],
    }
}

const TEXTS: &[&str] = &["", "a", "A", "ab", "a%b", "a_", "b", "ä", "z", "é", "\u{1F600}", "a\\", "10", "1"];
const INTS: &[i64] = &[i64::MIN, -1, 0, 1, 2, 10, i64::MAX];

fn lit(r: &mut Lcg) -> Value {
    if r.next().is_multiple_of(2) { Value::Str(r.pick(TEXTS).into()) } else { Value::Int(r.pick(INTS)) }
}

fn gen_pred(r: &mut Lcg, depth: u32) -> Pred {
    let f: Field = r.pick(&[0, 1, 2, 3]);
    if depth >= 4 || r.next().is_multiple_of(3) {
        return match r.next() % 7 {
            0 => Pred::Tt,
            1 => Pred::Ff,
            2 => Pred::Eq(f, lit(r)),
            3 => Pred::IsIn(f, (0..r.next() % 3).map(|_| lit(r)).collect()),
            4 => {
                let (a, b) = (lit(r), lit(r));
                Pred::Range(f, a, b)
            }
            _ => Pred::Pfx(f, r.pick(TEXTS).into()),
        };
    }
    match r.next() % 3 {
        0 => Pred::And(Box::new(gen_pred(r, depth + 1)), Box::new(gen_pred(r, depth + 1))),
        1 => Pred::Or(Box::new(gen_pred(r, depth + 1)), Box::new(gen_pred(r, depth + 1))),
        _ => Pred::Not(Box::new(gen_pred(r, depth + 1))),
    }
}

fn live_table(c: &mut Connection, sc: &Schema) -> Result<aegis_adapter_pg::LiveTable, LiveSchemaError> {
    check_live_schema(c, NS, sc, soon())
}

fn setup(c: &mut Connection, tenant_coll: &str, force: bool, check: bool) {
    exec(c, &format!("DROP SCHEMA IF EXISTS {NS} CASCADE"));
    exec(c, &format!("CREATE SCHEMA {NS}"));
    exec(
        c,
        &format!(
            "CREATE TABLE {NS}.t (id int NOT NULL, tenant text {tenant_coll} NOT NULL, x text COLLATE \"C\", y bigint, \
             PRIMARY KEY (tenant, id))"
        ),
    );
    exec(
        c,
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_lower_app') THEN CREATE ROLE aegis_lower_app; END IF; END $$",
    );
    exec(c, &format!("GRANT USAGE ON SCHEMA {NS} TO aegis_lower_app"));
    exec(c, &format!("GRANT SELECT, INSERT, UPDATE, DELETE ON {NS}.t TO aegis_lower_app"));
    let mut st = rls_policy(Some(NS), "t", "tenant", "aegis_lower_app", "aegis.tenant").unwrap();
    if !force {
        st.retain(|s| !s.contains("FORCE"));
    }
    if !check {
        let last = st.pop().unwrap();
        st.push(last.split(" WITH CHECK ").next().unwrap().to_owned());
    }
    for s in st {
        exec(c, &s);
    }
}

#[test]
fn live_renderer_and_gate() {
    let Ok(dsns) = std::env::var("AEGIS_PG_DSNS") else {
        eprintln!("lower_live: AEGIS_PG_DSNS unset, skipped");
        return;
    };
    for dsn in dsns.split_whitespace() {
        let (mut c, v) = connect_admitted(&ConnectConfig::from_dsn(dsn).unwrap(), None).unwrap();
        eprintln!("lower_live: {}", v.token());
        let sc = schema();

        // Gate: refusals, then the admitted shape.
        setup(&mut c, "", true, true);
        let e = live_table(&mut c, &sc).unwrap_err();
        // postgres images default to en_US.utf8; a C-default database would admit `default`.
        assert!(matches!(e, LiveSchemaError::Schema(SchemaError::NonBinaryCollation(1))), "{e:?}");
        setup(&mut c, "COLLATE \"C\"", false, true);
        assert!(matches!(live_table(&mut c, &sc), Err(LiveSchemaError::RlsNotForced)));
        setup(&mut c, "COLLATE \"C\"", true, false);
        assert!(matches!(live_table(&mut c, &sc), Err(LiveSchemaError::RlsPolicyWithoutCheck)));
        setup(&mut c, "COLLATE \"C\"", true, true);
        let lt = live_table(&mut c, &sc).unwrap();
        assert_eq!(lt.table.namespace.as_deref(), Some(NS));
        assert_eq!(lt.schema.unique_indexes.len(), 1);

        // Rows: two tenants, NULLs, edge values.
        let ta = TenantId::new(0xacce55).unwrap();
        let tb = TenantId::new(0xacce56).unwrap();
        let mut rows: Vec<(i64, String, Option<String>, Option<i64>)> = Vec::new();
        let mut r = Lcg(20_261_030);
        for id in 0..120i64 {
            let t = tenant_text(if r.next().is_multiple_of(3) { tb } else { ta });
            let x = if r.next().is_multiple_of(6) { None } else { Some(r.pick(TEXTS).to_owned()) };
            let y = if r.next().is_multiple_of(6) { None } else { Some(r.pick(INTS)) };
            rows.push((id, t, x, y));
        }
        for (id, t, x, y) in &rows {
            let ids = id.to_string();
            let ys = y.map(|v| v.to_string());
            c.query(
                &format!("INSERT INTO {NS}.t (id, tenant, x, y) VALUES ($1, $2, $3, $4)"),
                &[Some(&ids), Some(t), x.as_deref(), ys.as_deref()],
                soon(),
            )
            .unwrap();
        }

        // Differential against eval3 (= keeps over the exact backend).
        let mut cases = 0;
        for _ in 0..1500 {
            let p = gen_pred(&mut r, 0);
            let tenant = if r.next().is_multiple_of(2) { ta } else { tb };
            let op = aegis_data_ir::Op {
                tenant,
                collection: "t".into(),
                kind: OpKind::Select,
                filter: p.clone(),
                writes: vec![],
                returning: vec![0],
            };
            let rd = render_op(&op, &sc, &lt.table).unwrap();
            let texts = rd.param_texts();
            let got = c.query(&rd.sql, &params_as_wire(&texts), soon()).unwrap_or_else(|e| panic!("{}: {e}", rd.sql));
            let mut got: Vec<i64> = got.rows.iter().map(|row| row[0].as_deref().unwrap().parse().unwrap()).collect();
            got.sort_unstable();
            let tq = Pred::And(Box::new(Pred::Eq(1, Value::Str(tenant_text(tenant)))), Box::new(p.clone()));
            let mut want = Vec::new();
            for (id, t, x, y) in &rows {
                let vals = [Value::Int(*id), Value::Str(t.clone())];
                let xv = x.clone().map(Value::Str);
                let yv = y.map(Value::Int);
                let get = |f: Field| match f {
                    0 => vals.first(),
                    1 => vals.get(1),
                    2 => xv.as_ref(),
                    3 => yv.as_ref(),
                    _ => None,
                };
                if eval3(&get, &tq).unwrap() == Some(true) {
                    want.push(*id);
                }
            }
            assert_eq!(got, want, "pred {p:?}\nsql {}", rd.sql);
            cases += 1;
        }
        eprintln!("lower_live: {cases} differential cases equal to eval3");

        // Upsert through the introspected PgTable, as the owner.
        let ups = aegis_data_ir::Op {
            tenant: ta,
            collection: "t".into(),
            kind: OpKind::Upsert,
            filter: Pred::Tt,
            writes: vec![(0, Value::Int(5000)), (2, Value::Str("N".into()))],
            returning: vec![0, 2],
        };
        let rd = render_op(&ups, &sc, &lt.table).unwrap();
        let texts = rd.param_texts();
        let res = c.query(&rd.sql, &params_as_wire(&texts), soon()).unwrap();
        assert_eq!(res.rows, vec![vec![Some("5000".into()), Some("N".into())]]);

        // rls_bind under FORCE RLS: an unfiltered SELECT sees only the bound tenant's rows.
        exec(&mut c, "BEGIN");
        for st in rls_bind(tb, "aegis_lower_app", "aegis.tenant").unwrap() {
            let texts = st.param_texts();
            c.query(&st.sql, &params_as_wire(&texts), soon()).unwrap();
        }
        let seen = c.query(&format!("SELECT DISTINCT tenant FROM {NS}.t"), &[], soon()).unwrap();
        assert_eq!(seen.rows, vec![vec![Some(tenant_text(tb))]]);
        // WITH CHECK: writing another tenant's row is rejected.
        let ta_s = tenant_text(ta);
        assert!(
            c.query(&format!("INSERT INTO {NS}.t (id, tenant) VALUES (9999, $1)"), &[Some(&ta_s)], soon()).is_err()
        );
        exec(&mut c, "ROLLBACK");

        exec(&mut c, &format!("DROP SCHEMA {NS} CASCADE"));
        c.terminate(Duration::from_millis(200));
    }
}
