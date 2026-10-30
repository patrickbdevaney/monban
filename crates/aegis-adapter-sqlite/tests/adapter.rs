//! aegis-adapter-sqlite: open-time configuration, renderer exactness against `aegis_data_ir::eval3` (differential
//! over a real SQLite at the pin), W6 refusals and the live schema check. The full corpora are the oracles
//! (lowering-read, lowering-write, schema-gate); these are fast regressions.

use aegis_adapter_sqlite::{
    ForeignKey, LiveError, OpenError, OpenMode, RenderError, SQLITE_FLOOR, SqliteDb, Table, linked_version, render,
};
use aegis_data_ir::{
    Collation, Column, Field, LowerError, Op, OpKind, Pred, Schema, SchemaError, UniqueIndex, Value, eval3, tenant_text,
};
use aegis_types::TenantId;
use rusqlite::types::Value as SqlValue;
use std::path::PathBuf;

type R<T = ()> = Result<T, String>;

fn e<E: std::fmt::Debug>(x: E) -> String {
    format!("{x:?}")
}

/// A fresh database file built with `ddl`; removed on drop.
struct TmpDb(PathBuf);

impl TmpDb {
    fn new(tag: &str, ddl: &str) -> R<TmpDb> {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(e)?.as_nanos();
        let p = std::env::temp_dir().join(format!("aegis-sqlite-{tag}-{}-{n}.sqlite", std::process::id()));
        let c = rusqlite::Connection::open(&p).map_err(e)?;
        c.execute_batch(ddl).map_err(e)?;
        drop(c);
        Ok(TmpDb(p))
    }
}

impl Drop for TmpDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn t(n: u64) -> R<TenantId> {
    TenantId::new(n).map_err(e)
}

fn col(field: Field, name: &str, nullable: bool, key: bool) -> Column {
    Column { field, name: name.into(), nullable, collation: Collation::Binary, key }
}

/// notes(tenant 0, id 1, x 2, y 3, secret 4); key id; sole unique index (tenant, id).
fn declared() -> Schema {
    Schema {
        collection: "notes".into(),
        tenant_field: 0,
        columns: vec![
            col(0, "tenant", false, false),
            col(1, "id", false, true),
            col(2, "x", true, false),
            col(3, "y", true, false),
            col(4, "secret", true, false),
        ],
        permitted: vec![0, 1, 2, 3],
        unique_indexes: vec![UniqueIndex { fields: vec![0, 1], prefix: false }],
    }
}

const GOLDEN: &str =
    "create table notes(tenant text not null, id integer not null, x, y, secret, primary key(tenant,id))";

fn op(tenant: TenantId, kind: OpKind, filter: Pred, writes: Vec<(Field, Value)>, returning: Vec<Field>) -> Op {
    Op { tenant, collection: "notes".into(), kind, filter, writes, returning }
}

#[test]
fn open_asserts_floor_and_fixes_configuration() -> R {
    let v = linked_version().ok_or("version")?;
    assert!(v >= SQLITE_FLOOR, "{v:?}");
    assert_eq!((v.major, v.minor, v.patch), (3, 53, 2), "adapter pin is SQLite 3.53.2 (rusqlite =0.40.2 bundled)");
    let tmp = TmpDb::new("open", GOLDEN)?;
    let db = SqliteDb::open(&tmp.0, OpenMode::ReadWrite).map_err(e)?;
    let c = db.connection();
    use rusqlite::config::DbConfig as C;
    assert!(c.db_config(C::SQLITE_DBCONFIG_ENABLE_FKEY).map_err(e)?);
    assert!(!c.db_config(C::SQLITE_DBCONFIG_ENABLE_TRIGGER).map_err(e)?);
    assert!(!c.db_config(C::SQLITE_DBCONFIG_DQS_DML).map_err(e)?);
    assert!(c.db_config(C::SQLITE_DBCONFIG_DEFENSIVE).map_err(e)?);
    assert!(!c.db_config(C::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE).map_err(e)?);
    // No double-quoted string literals: a misspelt column is an error, never the string 'nosuch'.
    assert!(c.prepare("SELECT 1 FROM notes WHERE \"nosuch\" = 'nosuch'").is_err());
    // Read-only really is read-only.
    let ro = SqliteDb::open(&tmp.0, OpenMode::ReadOnly).map_err(e)?;
    assert!(ro.connection().execute("insert into notes(tenant,id) values ('a',1)", []).is_err());
    // A missing file is not created.
    let missing = std::env::temp_dir().join(format!("aegis-sqlite-missing-{}.sqlite", std::process::id()));
    assert!(matches!(SqliteDb::open(&missing, OpenMode::ReadWrite), Err(OpenError::Sqlite(_))));
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn utf16_database_refused() -> R {
    let tmp = TmpDb::new("utf16", &format!("pragma encoding = 'UTF-16le'; {GOLDEN}"))?;
    assert!(matches!(SqliteDb::open(&tmp.0, OpenMode::ReadOnly), Err(OpenError::Encoding(_))));
    Ok(())
}

// ------------------------------------------------------------------------------------------------ differential

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> Option<&'a T> {
        let n = u64::try_from(xs.len()).ok()?;
        xs.get(usize::try_from(self.next() % n.max(1)).ok()?)
    }
}

fn lits() -> Vec<Value> {
    let mut v: Vec<Value> = [0i64, 1, -1, 7, i64::MAX, i64::MIN].iter().map(|i| Value::Int(*i)).collect();
    for s in ["", "a", "A", "ab", "a\0b", "a%", "a_", "é", "\u{1F600}", "1", "acme ", "b"] {
        v.push(Value::Str(s.into()));
    }
    v
}

fn gen_pred(r: &mut Lcg, depth: u32) -> Pred {
    let ls = lits();
    let f: Field = *r.pick(&[1u32, 2, 3]).unwrap_or(&2);
    let lit = |r: &mut Lcg| r.pick(&ls).cloned().unwrap_or(Value::Int(0));
    let k = if depth >= 3 { r.next() % 6 } else { r.next() % 9 };
    match k {
        0 => Pred::Tt,
        1 => Pred::Ff,
        2 => Pred::Eq(f, lit(r)),
        3 => {
            let n = r.next() % 3;
            Pred::IsIn(f, (0..n).map(|_| lit(r)).collect())
        }
        4 => Pred::Range(f, lit(r), lit(r)),
        5 => match lit(r) {
            Value::Str(s) => Pred::Pfx(f, s),
            Value::Int(_) => Pred::Pfx(f, String::new()),
        },
        6 => Pred::And(Box::new(gen_pred(r, depth + 1)), Box::new(gen_pred(r, depth + 1))),
        7 => Pred::Or(Box::new(gen_pred(r, depth + 1)), Box::new(gen_pred(r, depth + 1))),
        _ => Pred::Not(Box::new(gen_pred(r, depth + 1))),
    }
}

fn from_sql(v: &SqlValue) -> Option<Value> {
    match v {
        SqlValue::Integer(i) => Some(Value::Int(*i)),
        SqlValue::Text(s) => Some(Value::Str(s.clone())),
        _ => None,
    }
}

/// Every rendered SELECT returns exactly `{r | refQ3 t p r}` over rows read back as stored, on four layouts
/// (untyped, NUMERIC affinity, NOCASE data columns, STRICT ANY), including NULLs, NUL bytes, case and trailing-space
/// confusers, int64 edges and astral code points.
#[test]
fn select_is_exact_against_eval3() -> R {
    let layouts = [
        "create table notes(tenant text not null, id integer not null, x, y, secret, primary key(tenant,id))",
        "create table notes(tenant text not null, id integer not null, x numeric, y numeric, secret, primary key(tenant,id))",
        "create table notes(tenant text not null, id integer not null, x text collate nocase, y text collate nocase, secret, primary key(tenant,id))",
        "create table notes(tenant text not null, id integer not null, x any, y any, secret any, primary key(tenant,id)) strict",
    ];
    let tenants = [t(1)?, t(0x2a)?, t(u64::MAX)?];
    let mut rng = Lcg(20261030);
    let stored: Vec<SqlValue> = {
        let mut v: Vec<SqlValue> = lits()
            .into_iter()
            .map(|l| match l {
                Value::Int(i) => SqlValue::Integer(i),
                Value::Str(s) => SqlValue::Text(s),
            })
            .collect();
        v.push(SqlValue::Null);
        v
    };
    let mut checked = 0u32;
    for (li, ddl) in layouts.iter().enumerate() {
        let tmp = TmpDb::new(&format!("diff{li}"), ddl)?;
        let db = SqliteDb::open(&tmp.0, OpenMode::ReadWrite).map_err(e)?;
        let c = db.connection();
        let mut id = 0i64;
        for tn in &tenants {
            for _ in 0..40 {
                id += 1;
                let x = rng.pick(&stored).cloned().unwrap_or(SqlValue::Null);
                let y = rng.pick(&stored).cloned().unwrap_or(SqlValue::Null);
                let st = c.execute(
                    "insert into notes(tenant,id,x,y) values (?1,?2,?3,?4)",
                    rusqlite::params![tenant_text(*tn), id, x, y],
                );
                // STRICT ANY accepts everything; typed layouts may coerce. Errors only skip the row.
                let _ = st;
            }
        }
        // Rows as stored (affinity conversions belong to the state, not the query).
        let mut q = c.prepare("select tenant, id, x, y from notes").map_err(e)?;
        let raw: Vec<(String, i64, SqlValue, SqlValue)> = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map_err(e)?
            .collect::<Result<_, _>>()
            .map_err(e)?;
        // Only Lean values or NULL are stored here (REAL/BLOB storage is the lowering-read oracle's corpus).
        let lean = |v: &SqlValue| -> R<Option<Value>> {
            if *v == SqlValue::Null { Ok(None) } else { from_sql(v).map(Some).ok_or_else(|| format!("stored {v:?}")) }
        };
        let rows: Vec<(String, i64, Option<Value>, Option<Value>)> =
            raw.iter().map(|(a, b, x, y)| Ok((a.clone(), *b, lean(x)?, lean(y)?))).collect::<R<_>>()?;
        let table = Table { schema: declared(), fks_out: vec![], fks_in: vec![] };
        for _ in 0..600 {
            let tn = *rng.pick(&tenants).ok_or("tenant")?;
            let p = gen_pred(&mut rng, 0);
            let r = render(&op(tn, OpKind::Select, p.clone(), vec![], vec![1]), &table).map_err(e)?;
            let mut got: Vec<i64> = db
                .run(&r)
                .map_err(|x| format!("{x}: {}", r.sql))?
                .iter()
                .filter_map(|row| match row.first() {
                    Some(SqlValue::Integer(i)) => Some(*i),
                    _ => None,
                })
                .collect();
            got.sort_unstable();
            let tv = Value::Str(tenant_text(tn));
            let mut want = Vec::new();
            for (rt, rid, x, y) in &rows {
                let tval = Value::Str(rt.clone());
                let idv = Value::Int(*rid);
                let get = |f: Field| match f {
                    0 => Some(&tval),
                    1 => Some(&idv),
                    2 => x.as_ref(),
                    3 => y.as_ref(),
                    _ => None,
                };
                let q = Pred::And(Box::new(Pred::Eq(0, tv.clone())), Box::new(p.clone()));
                if eval3(&get, &q).map_err(e)? == Some(true) {
                    want.push(*rid);
                }
            }
            want.sort_unstable();
            assert_eq!(got, want, "layout {li} pred {p:?}\nsql {}\nparams {:?}", r.sql, r.params);
            checked += 1;
        }
    }
    assert_eq!(checked, 2400);
    Ok(())
}

// ------------------------------------------------------------------------------------------------ writes

#[test]
fn write_forms_and_w6() -> R {
    let tn = t(0xacce55)?;
    let table = Table { schema: declared(), fks_out: vec![], fks_in: vec![] };
    let up = op(tn, OpKind::Upsert, Pred::Tt, vec![(1, Value::Int(7)), (2, Value::Str("N".into()))], vec![1, 2]);
    let r = render(&up, &table).map_err(e)?;
    assert_eq!(
        r.sql,
        "INSERT INTO \"notes\" (\"tenant\", \"id\", \"x\") VALUES (?, ?, ?) ON CONFLICT (\"tenant\", \"id\") DO UPDATE SET \
         \"x\" = excluded.\"x\" WHERE \"notes\".\"tenant\" = excluded.\"tenant\" COLLATE BINARY RETURNING \"id\", \"x\""
    );
    assert_eq!(r.params.first(), Some(&Value::Str("0000000000acce55".into())));
    let upd = op(tn, OpKind::Update, Pred::Eq(1, Value::Int(7)), vec![(2, Value::Str("U".into()))], vec![1]);
    let r = render(&upd, &table).map_err(e)?;
    assert!(r.sql.starts_with("UPDATE \"notes\" SET \"x\" = ? WHERE ((CASE WHEN \"tenant\" IS NULL"), "{}", r.sql);
    // Tenant written, key written, secret returned: refused by lower_op / check_schema.
    let bad = op(tn, OpKind::Update, Pred::Tt, vec![(0, Value::Str("0000000000000001".into()))], vec![]);
    assert_eq!(render(&bad, &table), Err(RenderError::Lower(LowerError::Schema(SchemaError::TenantFieldWritten))));
    let bad = op(tn, OpKind::Update, Pred::Tt, vec![(1, Value::Int(1))], vec![]);
    assert_eq!(render(&bad, &table), Err(RenderError::Lower(LowerError::KeyWritten(1))));
    let bad = op(tn, OpKind::Delete, Pred::Tt, vec![], vec![4]);
    assert_eq!(
        render(&bad, &table),
        Err(RenderError::Lower(LowerError::Schema(SchemaError::ReturningNotPermitted(4))))
    );

    // W6: a second, global unique key makes INSERT an existence oracle; an UPDATE writing into it too.
    let mut g = declared();
    g.unique_indexes.push(UniqueIndex { fields: vec![2], prefix: false });
    let gt = Table { schema: g, fks_out: vec![], fks_in: vec![] };
    let ins = op(tn, OpKind::Insert, Pred::Tt, vec![(1, Value::Int(9)), (2, Value::Str("N".into()))], vec![]);
    assert_eq!(render(&ins, &gt), Err(RenderError::UniqueKeyWithoutTenant));
    assert_eq!(render(&upd, &gt), Err(RenderError::UniqueKeyWithoutTenant));
    let upd_y = op(tn, OpKind::Update, Pred::Tt, vec![(3, Value::Int(1))], vec![]);
    assert!(render(&upd_y, &gt).is_ok());
    // W6: a foreign key that does not map tenant to tenant.
    let fk = |local: Vec<Field>, remote: &[&str]| ForeignKey {
        local,
        remote_table: "p".into(),
        remote: remote.iter().map(|s| s.to_string()).collect(),
        remote_tenant: Some("tenant".into()),
    };
    let ok = Table { schema: declared(), fks_out: vec![fk(vec![0, 3], &["tenant", "gid"])], fks_in: vec![] };
    assert!(render(&ins, &ok).is_ok());
    for bad_fk in [fk(vec![3], &["gid"]), fk(vec![0, 3], &["gid", "tenant"]), fk(vec![3, 0], &["tenant", "gid"])] {
        let tb = Table { schema: declared(), fks_out: vec![bad_fk.clone()], fks_in: vec![] };
        assert_eq!(render(&ins, &tb), Err(RenderError::ForeignKeyWithoutTenant));
        let del = op(tn, OpKind::Delete, Pred::Tt, vec![], vec![]);
        assert!(render(&del, &tb).is_ok(), "an outgoing FK cannot trip a DELETE of the child");
        let tin = Table { schema: declared(), fks_out: vec![], fks_in: vec![bad_fk] };
        assert_eq!(render(&del, &tin), Err(RenderError::ForeignKeyWithoutTenant));
    }
    let unknown = ForeignKey { remote_tenant: None, ..fk(vec![0, 3], &["tenant", "gid"]) };
    let tb = Table { schema: declared(), fks_out: vec![unknown], fks_in: vec![] };
    assert_eq!(render(&ins, &tb), Err(RenderError::ForeignKeyWithoutTenant));
    Ok(())
}

#[test]
fn upsert_cannot_touch_another_tenants_row() -> R {
    let tmp = TmpDb::new("upsert", GOLDEN)?;
    let db = SqliteDb::open(&tmp.0, OpenMode::ReadWrite).map_err(e)?;
    let table = db.check_schema(&declared(), &|_| None).map_err(e)?;
    let (a, b) = (t(0x1e5)?, t(0x100000)?);
    let w =
        |tn, x: &str| op(tn, OpKind::Upsert, Pred::Tt, vec![(1, Value::Int(1)), (2, Value::Str(x.into()))], vec![0, 2]);
    let ra = db.run(&render(&w(a, "A"), &table).map_err(e)?).map_err(e)?;
    let rb = db.run(&render(&w(b, "B"), &table).map_err(e)?).map_err(e)?;
    assert_eq!(ra, vec![vec![SqlValue::Text(tenant_text(a)), SqlValue::Text("A".into())]]);
    assert_eq!(rb, vec![vec![SqlValue::Text(tenant_text(b)), SqlValue::Text("B".into())]]);
    let n: i64 = db.connection().query_row("select count(*) from notes", [], |r| r.get(0)).map_err(e)?;
    assert_eq!(n, 2, "two tenants, two rows");
    Ok(())
}

// ------------------------------------------------------------------------------------------------ live schema

fn live(ddl: &str) -> R<Result<Table, LiveError>> {
    let tmp = TmpDb::new("live", ddl)?;
    let db = SqliteDb::open(&tmp.0, OpenMode::ReadOnly).map_err(e)?;
    Ok(db.check_schema(&declared(), &|t| (t == "p").then(|| "tenant".to_string())))
}

#[test]
fn live_check_reads_the_catalog() -> R {
    assert!(live(GOLDEN)?.is_ok());
    // INTEGER affinity: '00000000000001e5' and '0000000000100000' both store as 100000 (PLAN finding).
    assert_eq!(
        live("create table notes(tenant integer not null, id integer not null, x, y, secret, primary key(tenant,id))")?,
        Err(LiveError::TenantNotText)
    );
    assert_eq!(
        live(
            "create table notes(tenant text not null collate nocase, id integer not null, x, y, secret, primary key(tenant,id))"
        )?,
        Err(LiveError::Schema(SchemaError::NonBinaryCollation(0)))
    );
    assert_eq!(
        live("create table notes(tenant text, id integer not null, x, y, secret, primary key(tenant,id))")?,
        Err(LiveError::Schema(SchemaError::TenantFieldNullable))
    );
    assert_eq!(
        live(
            "create table notes(tenant text not null, id integer primary key, x, y, secret); create unique index u on notes(tenant,id)"
        )?,
        Err(LiveError::Schema(SchemaError::UpsertArbiterNotTenantScoped))
    );
    assert_eq!(
        live(&format!(
            "{GOLDEN}; create table a(v); create trigger tr after insert on notes begin insert into a values (1); end"
        ))?,
        Err(LiveError::TriggerOnCollection)
    );
    assert_eq!(live("create view notes as select 1 as tenant")?.map(|_| ()), Err(LiveError::NotATable));
    assert_eq!(live("create table other(v)")?.map(|_| ()), Err(LiveError::NotATable));
    // Foreign keys are introspected with their tenant mapping.
    let t = live(
        "create table p(tenant text not null, gid text not null, primary key(tenant,gid));\
         create table notes(tenant text not null, id integer not null, x, y, secret, primary key(tenant,id),\
         foreign key (tenant, y) references p(tenant, gid));\
         create table c(tenant text not null, nid integer, foreign key (nid) references notes(id))",
    )?
    .map_err(e)?;
    assert_eq!(t.fks_out.len(), 1);
    assert!(t.fks_out.iter().all(|k| k.carries_tenant(0)));
    assert_eq!(t.fks_in.len(), 1);
    assert!(t.fks_in.iter().all(|k| !k.carries_tenant(0)), "c(nid) -> notes(id) carries no tenant");
    let del = op(TenantId::new(1).map_err(e)?, OpKind::Delete, Pred::Tt, vec![], vec![]);
    assert_eq!(render(&del, &t), Err(RenderError::ForeignKeyWithoutTenant));
    Ok(())
}
