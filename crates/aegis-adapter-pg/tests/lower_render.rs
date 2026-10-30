//! Offline checks of the PG renderer (`aegis_adapter_pg::lower`): statement shapes, the exactness obligations
//! that can be seen in the text (every atom NULL-propagating, `In []` not constant FALSE, binary comparisons,
//! class-strict constants), the mandated write forms, refusals, RLS statements and the policy-shape matcher.
//! Live execution against PG is in `lower_live.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use aegis_adapter_pg::lower::{
    MAX_IDENT_BYTES, Param, PgClass, PgColumn, PgForeignKey, PgTable, RenderError, is_tenant_guard, quote_ident,
    render, render_filter, render_op, rls_bind, rls_policy,
};
use aegis_data_ir::{
    Collation, Column, Fidelity, LowerError, Op, OpKind, Pred, Schema, SchemaError, SqlExpr, UniqueIndex, Value,
    lower_op,
};
use aegis_types::TenantId;

// fields: 0 id (int, key), 1 tenant (text), 2 x (text), 3 y (bigint), 4 blob (bytea)
fn table(unique: Vec<Vec<u32>>) -> PgTable {
    let c = |field, name: &str, class| PgColumn { field, name: name.into(), class };
    PgTable {
        namespace: None,
        name: "t".into(),
        columns: vec![
            c(0, "id", PgClass::Int),
            c(1, "tenant", PgClass::Text),
            c(2, "x", PgClass::Text),
            c(3, "y", PgClass::Int),
            c(4, "blob", PgClass::Other),
        ],
        unique,
        fks: Vec::new(),
    }
}

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
        columns: vec![c(0, "id", true), c(1, "tenant", true), c(2, "x", false), c(3, "y", false), c(4, "blob", false)],
        permitted: vec![0, 1, 2, 3],
        unique_indexes: vec![UniqueIndex { fields: vec![1, 0], prefix: false }],
    }
}

fn t() -> TenantId {
    TenantId::new(0xacce55).unwrap()
}

fn op(kind: OpKind, filter: Pred, writes: Vec<(u32, Value)>, returning: Vec<u32>) -> Op {
    Op { tenant: t(), collection: "t".into(), kind, filter, writes, returning }
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

#[test]
fn select_filter_shape() {
    let p = Pred::And(
        Box::new(Pred::Not(Box::new(Pred::IsIn(2, vec![])))),
        Box::new(Pred::Or(
            Box::new(Pred::Pfx(2, "a%_".into())),
            Box::new(Pred::Range(3, Value::Int(-1), Value::Int(9))),
        )),
    );
    let r = render_op(&op(OpKind::Select, p, vec![], vec![0, 2]), &schema(), &table(vec![vec![1, 0]])).unwrap();
    assert_eq!(
        r.sql,
        "SELECT \"id\", \"x\" FROM \"t\" WHERE ((CASE WHEN \"tenant\" IS NULL THEN NULL ELSE (\"tenant\"::text = \
         $1::text COLLATE \"C\") END) AND ((NOT (CASE WHEN \"x\" IS NULL THEN NULL ELSE false END)) AND ((CASE WHEN \
         \"x\" IS NULL THEN NULL ELSE (left(\"x\"::text, $2::int) = $3::text COLLATE \"C\") END) OR (CASE WHEN \"y\" \
         IS NULL THEN NULL ELSE (\"y\" >= $4::bigint AND \"y\" <= $5::bigint) END))))"
    );
    assert_eq!(
        r.params,
        vec![
            Param::Text("0000000000acce55".into()),
            Param::Int(3),
            Param::Text("a%_".into()),
            Param::Int(-1),
            Param::Int(9)
        ]
    );
    assert!(!r.sql.contains("LIKE"));
}

#[test]
fn class_strict_constants_and_nul() {
    let tb = table(vec![]);
    let f = |e: SqlExpr| render_filter(&e, &tb, None, 0).unwrap();
    // Int literal on a text column, string on an int column, mixed range, prefix on int: constant false, still
    // NULL-propagating.
    for e in [
        SqlExpr::CmpEq(2, Value::Int(1)),
        SqlExpr::CmpEq(3, s("1")),
        SqlExpr::Between(3, Value::Int(1), s("z")),
        SqlExpr::Between(2, s("a"), Value::Int(3)),
        SqlExpr::Pfx(3, "1".into()),
        SqlExpr::CmpEq(2, s("a\0b")),
        SqlExpr::Pfx(2, "a\0".into()),
    ] {
        let r = f(e.clone());
        assert!(
            r.sql.starts_with("(CASE WHEN ") && r.sql.ends_with(" IS NULL THEN NULL ELSE false END)"),
            "{e:?}: {}",
            r.sql
        );
        assert!(r.params.is_empty());
    }
    let r = f(SqlExpr::InList(2, vec![Value::Int(1), s("a")]));
    assert_eq!(r.sql, "(CASE WHEN \"x\" IS NULL THEN NULL ELSE (false OR (\"x\"::text = $1::text COLLATE \"C\")) END)");
    assert_eq!(render_filter(&SqlExpr::Between(2, s("a\0"), s("b")), &tb, None, 0), Err(RenderError::NulInText(2)));
    assert_eq!(render_filter(&SqlExpr::CmpEq(4, s("a")), &tb, None, 0), Err(RenderError::ColumnType(4)));
    assert_eq!(render_filter(&SqlExpr::InList(4, vec![]), &tb, None, 0), Err(RenderError::ColumnType(4)));
    assert_eq!(render_filter(&SqlExpr::CmpEq(9, s("a")), &tb, None, 0), Err(RenderError::UnknownField(9)));
}

#[test]
fn alias_offset_and_depth() {
    let tb = table(vec![]);
    let r = render_filter(&SqlExpr::CmpEq(0, Value::Int(5)), &tb, Some("b"), 7).unwrap();
    assert_eq!(r.sql, "(CASE WHEN \"b\".\"id\" IS NULL THEN NULL ELSE (\"b\".\"id\" = $8::bigint) END)");
    let mut e = SqlExpr::Lit(true);
    for _ in 0..80 {
        e = SqlExpr::Not(Box::new(e));
    }
    assert_eq!(render_filter(&e, &tb, None, 0), Err(RenderError::TooDeep));
    assert_eq!(
        render_filter(&SqlExpr::Lit(true), &tb, None, 65_535),
        Ok(aegis_adapter_pg::Rendered { sql: "true".into(), params: vec![] })
    );
    assert_eq!(render_filter(&SqlExpr::CmpEq(0, Value::Int(1)), &tb, None, 65_535), Err(RenderError::TooManyParams));
}

#[test]
fn write_forms() {
    let tb = table(vec![vec![1, 0]]);
    let sc = schema();
    let r = render_op(&op(OpKind::Update, Pred::Tt, vec![(2, s("U")), (3, Value::Int(4))], vec![0]), &sc, &tb).unwrap();
    assert_eq!(
        r.sql,
        "UPDATE \"t\" SET \"x\" = $1::text, \"y\" = $2::bigint WHERE ((CASE WHEN \"tenant\" IS NULL THEN NULL ELSE \
         (\"tenant\"::text = $3::text COLLATE \"C\") END) AND true) RETURNING \"id\""
    );
    let r = render_op(&op(OpKind::Delete, Pred::Ff, vec![], vec![]), &sc, &tb).unwrap();
    assert!(r.sql.starts_with("DELETE FROM \"t\" WHERE (") && r.sql.ends_with(" AND false)"));
    let r =
        render_op(&op(OpKind::Insert, Pred::Tt, vec![(0, Value::Int(7)), (2, s("N"))], vec![0, 2]), &sc, &tb).unwrap();
    assert_eq!(
        r.sql,
        "INSERT INTO \"t\" (\"tenant\", \"id\", \"x\") VALUES ($1::text, $2::bigint, $3::text) RETURNING \"id\", \"x\""
    );
    let r = render_op(&op(OpKind::Upsert, Pred::Tt, vec![(0, Value::Int(7)), (2, s("N"))], vec![0]), &sc, &tb).unwrap();
    assert_eq!(
        r.sql,
        "INSERT INTO \"t\" (\"tenant\", \"id\", \"x\") VALUES ($1::text, $2::bigint, $3::text) ON CONFLICT (\"id\", \
         \"tenant\") DO UPDATE SET \"x\" = excluded.\"x\" WHERE (\"t\".\"tenant\"::text COLLATE \"C\") = \
         (excluded.\"tenant\"::text COLLATE \"C\") RETURNING \"id\""
    );
    let r = render_op(&op(OpKind::Upsert, Pred::Tt, vec![(0, Value::Int(7))], vec![]), &sc, &tb).unwrap();
    assert!(r.sql.ends_with("ON CONFLICT (\"id\", \"tenant\") DO NOTHING"));
    for w in ["MERGE", "WITH", "REPLACE", ";", "LIKE"] {
        assert!(!r.sql.contains(w));
    }
    let mut ns = tb.clone();
    ns.namespace = Some("app".into());
    let r = render_op(&op(OpKind::Delete, Pred::Tt, vec![], vec![]), &sc, &ns).unwrap();
    assert!(r.sql.starts_with("DELETE FROM \"app\".\"t\" WHERE"));
}

#[test]
fn write_refusals() {
    let sc = schema();
    let ins = op(OpKind::Insert, Pred::Tt, vec![(0, Value::Int(7))], vec![]);
    // A global unique key (W6 existence oracle) refuses inserts and upserts, not updates.
    let global = table(vec![vec![0]]);
    assert_eq!(render_op(&ins, &sc, &global), Err(RenderError::UniqueKeyWithoutTenant));
    let upd = op(OpKind::Update, Pred::Tt, vec![(2, s("U"))], vec![]);
    assert!(render_op(&upd, &sc, &global).is_ok());
    // Upsert arbiter must be the table's sole unique key.
    let two = table(vec![vec![1, 0], vec![1, 2]]);
    let ups = op(OpKind::Upsert, Pred::Tt, vec![(0, Value::Int(7)), (2, s("x"))], vec![]);
    assert_eq!(render_op(&ups, &sc, &two), Err(RenderError::ArbiterNotSoleUniqueKey));
    // Foreign keys must carry the tenant to the referenced tenant column, for every write.
    let mut fk = table(vec![vec![1, 0]]);
    fk.fks = vec![PgForeignKey {
        columns: vec![2],
        ref_table: "p".into(),
        ref_columns: vec!["gid".into()],
        ref_tenant_column: Some("tenant".into()),
    }];
    assert_eq!(render_op(&upd, &sc, &fk), Err(RenderError::ForeignKeyWithoutTenant));
    fk.fks[0] = PgForeignKey {
        columns: vec![1, 2],
        ref_table: "p".into(),
        ref_columns: vec!["gid".into(), "tenant".into()],
        ref_tenant_column: Some("tenant".into()),
    };
    assert_eq!(render_op(&ins, &sc, &fk), Err(RenderError::ForeignKeyWithoutTenant));
    fk.fks[0].ref_columns = vec!["tenant".into(), "gid".into()];
    assert!(render_op(&ins, &sc, &fk).is_ok());
    fk.fks[0].ref_tenant_column = None;
    assert_eq!(render_op(&ins, &sc, &fk), Err(RenderError::ForeignKeyWithoutTenant));
    let sel = op(OpKind::Select, Pred::Tt, vec![], vec![0]);
    assert!(render_op(&sel, &sc, &fk).is_ok());
    // Value classes, NUL, Other columns.
    let tb = table(vec![vec![1, 0]]);
    assert_eq!(
        render_op(&op(OpKind::Update, Pred::Tt, vec![(2, Value::Int(1))], vec![]), &sc, &tb),
        Err(RenderError::ValueClass(2))
    );
    assert_eq!(
        render_op(&op(OpKind::Update, Pred::Tt, vec![(3, s("1"))], vec![]), &sc, &tb),
        Err(RenderError::ValueClass(3))
    );
    assert_eq!(
        render_op(&op(OpKind::Update, Pred::Tt, vec![(2, s("a\0"))], vec![]), &sc, &tb),
        Err(RenderError::NulInText(2))
    );
    assert_eq!(
        render_op(&op(OpKind::Update, Pred::Tt, vec![(4, s("a"))], vec![]), &sc, &tb),
        Err(RenderError::ColumnType(4))
    );
    // F4 / lower_op refusals pass through.
    assert_eq!(
        render_op(&op(OpKind::Update, Pred::Tt, vec![(1, s("0000000000000001"))], vec![]), &sc, &tb),
        Err(RenderError::Lower(LowerError::Schema(SchemaError::TenantFieldWritten)))
    );
    assert_eq!(
        render_op(&op(OpKind::Update, Pred::Tt, vec![(0, Value::Int(1))], vec![]), &sc, &tb),
        Err(RenderError::Lower(LowerError::KeyWritten(0)))
    );
    // Tenant column must be text; collection must match.
    let mut bad = tb.clone();
    bad.columns[1].class = PgClass::Int;
    let l = lower_op(&sel, &sc, Fidelity::Exact).unwrap();
    assert_eq!(render(&l, &bad), Err(RenderError::ColumnType(1)));
    let mut other = tb.clone();
    other.name = "u".into();
    assert_eq!(render(&l, &other), Err(RenderError::CollectionMismatch));
}

#[test]
fn identifiers() {
    assert_eq!(quote_ident("a\"b").unwrap(), "\"a\"\"b\"");
    assert_eq!(quote_ident(""), Err(RenderError::BadIdentifier));
    assert_eq!(quote_ident("a\0"), Err(RenderError::BadIdentifier));
    assert_eq!(quote_ident(&"x".repeat(MAX_IDENT_BYTES + 1)), Err(RenderError::BadIdentifier));
    assert!(quote_ident(&"x".repeat(MAX_IDENT_BYTES)).is_ok());
    let mut tb = table(vec![vec![1, 0]]);
    tb.columns[2].name = "we\"ird".into();
    let r = render_filter(&SqlExpr::CmpEq(2, s("v")), &tb, None, 0).unwrap();
    assert!(r.sql.contains("\"we\"\"ird\"::text"));
}

#[test]
fn rls_statements() {
    let st = rls_policy(None, "t", "tenant", "app", "aegis.tenant").unwrap();
    assert_eq!(st.len(), 3);
    assert_eq!(st[0], "ALTER TABLE \"t\" ENABLE ROW LEVEL SECURITY");
    assert_eq!(st[1], "ALTER TABLE \"t\" FORCE ROW LEVEL SECURITY");
    assert_eq!(
        st[2],
        "CREATE POLICY aegis_tenant ON \"t\" AS PERMISSIVE FOR ALL TO \"app\" USING (\"tenant\" = \
         current_setting('aegis.tenant', true) COLLATE \"C\") WITH CHECK (\"tenant\" = \
         current_setting('aegis.tenant', true) COLLATE \"C\")"
    );
    for bad in ["", "Aegis.t", "a.b.c", "a'b", "a b", "1a", "a.", ".a"] {
        assert_eq!(rls_policy(None, "t", "tenant", "app", bad), Err(RenderError::BadRlsName), "{bad}");
        assert_eq!(rls_bind(t(), "app", bad), Err(RenderError::BadRlsName), "{bad}");
    }
    assert_eq!(rls_bind(t(), "", "aegis.tenant"), Err(RenderError::BadRlsName));
    let b = rls_bind(t(), "app", "aegis.tenant").unwrap();
    assert_eq!(b[0].sql, "SET LOCAL ROLE \"app\"");
    assert_eq!(b[1].sql, "SELECT pg_catalog.set_config($1, $2, true)");
    assert_eq!(b[1].params, vec![Param::Text("aegis.tenant".into()), Param::Text("0000000000acce55".into())]);
}

#[test]
fn tenant_guard_shapes() {
    for ok in [
        "(tenant = current_setting('aegis.tenant'::text))",
        "((tenant)::text = current_setting('aegis.tenant'::text))",
        "(tenant = (current_setting('aegis.tenant'::text, true) COLLATE \"C\"))",
        "(\"tenant\" = current_setting('aegis.tenant'::text, true))",
        "((tenant COLLATE \"C\") = current_setting('x'::text))",
    ] {
        assert!(is_tenant_guard(ok, "tenant"), "{ok}");
    }
    for bad in [
        "true",
        "((tenant = current_setting('aegis.tenant'::text)) OR (x IS NULL))",
        "((tenant = current_setting('aegis.tenant'::text)) AND true)",
        "(tenant = tenant)",
        "(tenant_x = current_setting('aegis.tenant'::text))",
        "(x = current_setting('aegis.tenant'::text))",
        "(tenant = current_setting('aegis.tenant'::text, false))",
        "(tenant = (current_setting('aegis.tenant'::text) COLLATE \"c\"))",
        "(tenant = lower(current_setting('aegis.tenant'::text)))",
        "(tenant = (current_setting('aegis.tenant'::text))::bpchar)",
        "(tenant <> current_setting('aegis.tenant'::text))",
        "(tenant = current_setting('Aegis'::text))",
    ] {
        assert!(!is_tenant_guard(bad, "tenant"), "{bad}");
    }
    // A mixed-case tenant column only matches quoted.
    assert!(is_tenant_guard("(\"Tenant\" = current_setting('a.b'::text))", "Tenant"));
    assert!(!is_tenant_guard("(tenant = current_setting('a.b'::text))", "Tenant"));
}

#[test]
fn class_of_type_names() {
    for (n, c) in [
        ("int", PgClass::Int),
        ("int4", PgClass::Int),
        ("BIGINT", PgClass::Int),
        ("smallint", PgClass::Int),
        ("text", PgClass::Text),
        ("varchar", PgClass::Text),
        ("character varying(16)", PgClass::Text),
        ("citext", PgClass::Text),
        ("bpchar", PgClass::Other),
        ("char(16)", PgClass::Other),
        ("numeric", PgClass::Other),
        ("", PgClass::Other),
    ] {
        assert_eq!(PgClass::of_type_name(n), c, "{n}");
    }
}
