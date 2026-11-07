# native-e2e: native handlers + data plane end to end (modes A/D)

Unit P4-oracle-e2e-001; gate `native-e2e` (owned by P4-bin-001). A black-box oracle. It boots a subject with an
oracle-written F8 config that binds apps/notes routes to real engines, mints F5 Tier-L tokens for two random tenants,
drives the subject over TLS (HTTP/1.1, plus HTTP/2 for RST_STREAM), and judges every outcome against durable rows
that it reads directly from the engines, never through the subject.

aegis-bin has no data plane yet (P4-bin-001 builds it). For now the oracle runs against `ref_subject.py`, a small
stdlib-Python server that follows the same contract. It PASSes on the reference, goes red on each reference mutant,
and accepts `--subject` for the real binary.

## Usage

```
oracles/native-e2e/run                                   # reference subject, SQLite backend
oracles/native-e2e/run --self-test                       # reference PASS + 6 reference mutants red
ci/engines.sh with pg18,valkey -- oracles/native-e2e/run --pg @pg18 --kv @valkey [--self-test]
ci/engines.sh with pg17 -- oracles/native-e2e/run --subject target/release/aegis --pg @pg17      # gate cmd
oracles/native-e2e/run --self-test --subject target/release/aegis   # judges target/e2e-mutants/release/aegis
```

SQLite is always exercised. PostgreSQL (`--pg DSN`) and Valkey/Redis (`--kv URL`) are added when given, and each
backend's suite runs in parallel. The last line is `NATIVE-E2E: PASS|FAIL (...)` or
`NATIVE-E2E SELF-TEST: PASS|FAIL (...)`, and the exit code is 0 only on PASS. The oracle needs the `openssl` CLI (it
mints a throwaway P-256 certificate). It is stdlib Python only, run as `python3 -I`. With `--self-test --subject X`
the judged binary is `--mutant-subject` or `target/e2e-mutants/release/aegis`, built through `ci/heavy.sh` with
`--features e2e-mutants` if missing. That build must PASS unmutated first. Each mutant is then selected with
`AEGIS_E2E_MUTANT=<name>`.

There is no `default-subject` yet: aegis would fail until P4-bin-001 lands, so the integrator adds
`target/release/aegis` there when that unit passes.

## Subject contract (what P4-bin-001 must implement)

**Command line.**
`<subject> --config <f8.json> --cert <pem> --key <pem> --audit-dir <d> --runtime-dir <d> --token-keyring <file>`.
`--token-keyring` is the one new flag. It points to a JSON file
`{"keys":[{"kid":"<hex of kid bytes>","key":"<64 hex = 32-byte issuer master key>"}]}` (mode 0600), which is the
F5 Tier-L `KeyRing`. A restart reuses the same `--runtime-dir` and `--audit-dir`, and any state needed for
idempotency replay must survive there or in the backends. Readiness is `GET /healthz` = 200 on `admin.bind` (plain
HTTP). A config the binary refuses means exit 78 before any listener accepts.

**Config (F8, as written by the oracle).** One listener `P-PUBLIC-WEB`, alpn `["h2","http/1.1"]`, vhost
`aegis.test`, plus:

```json
"data": {"backends": [
  {"id":"sq","engine":"sqlite","dsn_ref":"path:/<tmp>/notes.db","pin":"sqlite","op_budget_ms":5000},
  {"id":"pg","engine":"postgres","dsn_ref":"env:AEGIS_E2E_PG_DSN","pin":"pg17|pg18","op_budget_ms":5000},
  {"id":"kv","engine":"valkey|redis","dsn_ref":"env:AEGIS_E2E_KV_URL","pin":"valkey|redis","op_budget_ms":5000}]},
routes (all "authz":"allow-all", all "to":{"upstream":"app:notes"}):
  {"id":1..3,"path":"/<backend id>/","data":[{"backend":"<id>","collection":"notes",
     "ops":["select","insert","update","delete","upsert"],"columns":["id","body"]}]}
  {"id":90,"path":"/nocap/"}                                   (no data key: no capability)
  {"id":91,"path":"/ro/","data":[{"backend":"sq","collection":"notes","ops":["select"],"columns":["id","body"]}]}
```

- `to.upstream = "app:notes"` binds the route to the native apps/notes handler. F8 has no other way to name an app:
  today `upstream` is `host:port` or `unix:/path`, and the `app:` prefix is new to aegis-bin's plan, not to F8.
- The PG pin is `pg<major>` of the server the oracle connects to. The KV engine and pin are `valkey` if
  `INFO server` reports `valkey_version`, else `redis`.
- `columns` names the user columns. The tenant column is `tenant`, bound by the host and never listed.
- A notes route's caps name exactly one backend.
- `unrestricted` is not exercised (it is CI-gated by `ci/unrestricted.py`).

**Schema (created by the oracle before boot).** SQLite:
`notes(tenant TEXT NOT NULL COLLATE BINARY, id TEXT NOT NULL COLLATE BINARY, body TEXT NOT NULL,
PRIMARY KEY(tenant,id)) WITHOUT ROWID`, in WAL mode. PostgreSQL: the same with `COLLATE "C"`, provisioned so that
it passes the live schema gate (oracles/schema-gate pg mode, `aegis_adapter_pg::check_live_schema`) and recreated on
every run (role and tables dropped first):
  - login role `aegis_app` (aegis-bin's `PG_RLS_ROLE`): `LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
    NOREPLICATION NOINHERIT`, a fresh random password per run. It owns nothing and has no CREATE on any schema.
  - `public.notes` owned by the provisioning superuser, `ENABLE` + `FORCE ROW LEVEL SECURITY`, and the statements of
    `aegis_adapter_pg::rls_policy(Some("public"), "notes", "tenant", "aegis_app", "aegis.tenant")`: one policy
    `aegis_tenant AS PERMISSIVE FOR ALL TO "aegis_app" USING ("tenant" = current_setting('aegis.tenant', true)
    COLLATE "C") WITH CHECK (same)`. `GRANT SELECT, INSERT, UPDATE, DELETE` to `aegis_app`.
  - `public.aegis_idem(tenant, principal, k, status integer, body, PRIMARY KEY(principal, k))`, all text
    `COLLATE "C"`, same RLS shape, `GRANT SELECT, INSERT`: aegis-bin's in-band idempotency table, provisioned here so
    the RLS role never needs CREATE or owns a table. A subject that keeps idempotency elsewhere ignores it.

  `AEGIS_E2E_PG_DSN` logs in as `aegis_app`, never as the superuser. The subject binds each transaction with
  `SET LOCAL ROLE "aegis_app"` and `set_config('aegis.tenant', <tenant text>, true)` (`aegis_adapter_pg::rls_bind`);
  an unbound transaction sees no rows and can write none. The oracle provisions and reads durable rows with the
  superuser DSN it was given (a superuser is never subject to RLS). KV: key `t:{<tenant hex>}:notes:<id>`, value = body (F4 `kv_key`). In every
engine the tenant is the 16-lower-hex text of the u64 (D4, `tenant_text`).

**Tokens.** `Authorization: Bearer <base64url, no padding, of the F5 token-l CBOR>`. The oracle mints caveats
`[aud "aegis.test", exp now+600, depth 2, ops <mask>, tenant T]`. Verification uses `aegis_token::verify` with
`Req{aud = vhost host, ops = bit of the endpoint's OpKind, res = canonical path segments, tenant = the token's
tenant caveat, holder = none, tool = "", now = wall clock}`. Each request is acted on as the principal that
`verify` mints, and its tenant comes only from the token. A missing tenant caveat, an unknown kid, a bad tag, the
wrong audience or an expired token gets 401 or 403 with no effect.

**Endpoints.** `P` is the route path. `T` is the 16-hex tenant in the path, and it must equal the token's tenant,
otherwise the uniform denial below. Ids match `[a-z0-9][a-z0-9-]{0,63}`. Bodies are JSON.

| request | OpKind | success | failure |
|---|---|---|---|
| `GET P T/ID` | select | 200 `{"id","body"}` | 404 |
| `POST P T/` `{"id","body"}` | insert | 201 `{"id","body"}` | 409 if own row exists |
| `PATCH P T/ID` `{"body"}` | update | 200 `{"id","body"}` | 404 |
| `PUT P T/ID` `{"body"}` | upsert | 200 `{"id","body"}` | |
| `DELETE P T/ID` | delete | 200 | 404 |

- **Uniform denial (W6, `SdkError::Denied`).** A path tenant that is not the token's, an id that exists only under
  another tenant, and a missing capability all get a response whose status and body bytes equal the response for an
  id that does not exist. Inserting or upserting an id that another tenant owns creates the caller's own row (the
  arbiter is `(tenant, id)`): it never returns 409.
- **Idempotency (INV-IDEMP).** Every mutation (POST, PATCH, PUT, DELETE) needs `Idempotency-Key: [A-Za-z0-9_-]{1,64}`.
  Without one the answer is 428, with no effect. The key is scoped to the principal. Replaying a key whose request
  committed returns the stored status and body without re-executing. Requests that failed before CP are not latched.
- **App test fields.** apps/notes honours two optional integer body fields, 0..10000 ms. `hold_ms` sleeps after the
  write, inside the open transaction, before commit. `hold_after_ms` sleeps after commit, before the response is
  produced. They are app behaviour, so mutants do not touch them, and they let the oracle place a cancel exactly
  before or after CP.
- **Deadline.** The request header `aegis-deadline-ms: 1..60000` can only lower the deadline (out of range gives 400).
  The default deadline is the route backend's `op_budget_ms`.
  - Deadline before CP: 504, the transaction is rolled back, and nothing is durable.
  - Deadline after CP: 202 (`Idempotency-Key` echoed), and replaying the key returns the stored outcome once it is
    ready (202 until then).
- **Cancellation.** A client FIN, a TCP RST or an h2 `RST_STREAM(CANCEL)` before CP rolls the transaction back.
  After CP the outcome is latched and the effect stays. For KV, writes are applied only at commit (MULTI/EXEC).
- **NC7.** No response byte, headers included, is sent before CP. Any 2xx implies the effect is durable at the moment
  the first byte is sent.
- **SIGTERM (NC8).** Stop accepting, let in-flight requests finish (or fail them before CP), and exit 0 within
  T_drain = 10 s. A 2xx is never sent for an effect that is not durable.

**Mutants (`e2e-mutants` feature, env `AEGIS_E2E_MUTANT`).**

| mutant | behaviour |
|---|---|
| `tenant-from-path` | tenant taken from the path segment, not from the token |
| `commit-despite-cancel` | commits although the request was cancelled (disconnect, RST, deadline) before CP |
| `body-before-cp` | sends the response before commit |
| `empty-caps-means-all` | a route without caps (or `data: []`) is treated as all ops on a backend |
| `no-drain` | ignores SIGTERM while requests are in flight |
| `ack-then-drop` | on SIGTERM answers 2xx to in-flight requests and exits without committing |

## What is checked (spec ids: `spec/SPEC_INVARIANTS.md`)

| check group | clause |
|---|---|
| `boot.empty-data-list.*`, `boot.undeclared-backend.*`: exit 78, never listened | INV-NONEMPTY (an empty list is invalid, not "all"), F8 data block, fail-closed boot |
| `<b>.crud.*`: insert/select/update/upsert/delete with durable rows checked (tenant column = 16-hex) | modes A/D baseline, D4 tenant encoding |
| `<b>.idem.*`: replay gives the same outcome; stored (not re-executed) after a later change; key scoped by principal; 428 without a key | INV-IDEMP |
| `<b>.xt.*`: foreign id with the caller's own path tenant, and path tenant B with token A, for GET/PATCH/DELETE/PUT/POST; uniform with a missing id; B's rows unchanged; same-id insert/upsert creates own row (no 409) | F7 tenant isolation (logical), W1/W2, W6, INV-NO-AMBIENT (tenant from the token only) |
| `<b>.auth.*`: select-only ops caveat cannot write; no/tampered/wrong-aud/expired/no-tenant/unknown-kid tokens refused with no effect | INV-ATTEN (F2) at the host, INV-NO-AMBIENT |
| `<b>.nc1.*`: h1 FIN, TCP RST, h2 RST_STREAM and deadline (504) during `hold_ms` leave no row; upsert pre-image kept; h2 positive control commits | INV-NOMUT-C NC1 |
| `<b>.nc7.*`: first response byte not before hold end (−150 ms slack); row durable when the first byte arrives | NC7, INV-DURABLE (ack ⇒ durable) |
| `<b>.nc2.*`: deadline after CP gives 202 with the row already durable, then retrieval by key gives the stored 201; disconnect after CP leaves the row (latched) and replay returns it | NC2, INV-IDEMP |
| `cap.nocap.*`, `cap.ro.*`: route without `data` reaches no backend (read denied, writes no effect); select-only route cannot write, uniform | INV-NONEMPTY, F4 CapSet, capability-typed handlers |
| `nc8.*`: SIGTERM 350 ms into 2 in-flight holds per backend; exit 0 within T_drain = 10 s; every 2xx durable; after a restart, acked rows still served and any unacked row that exists is latched (replay returns 201) | NC8 (Decision Q3), INV-DURABLE |

**PASS** iff every check passes. With SQLite alone that is 88 checks.

## Provenance and in-repo runs

Written for this unit. No research artifact was ported or executed. The F5 minting (`mint`) follows
`interfaces/F5-token.cddl` and `crates/aegis-token/src/tier_l.rs` (HKDF info with length prefixes, HMAC chain).
The reference verifier in `ref_subject.py` is a separate implementation of the same rules. `wire.py` (PG v3 with
SCRAM-SHA-256, RESP2, a locked TLS wrapper) is shared infrastructure with no contract logic in it.

Runs on 2026-10-30, laptop:

- `run` → `NATIVE-E2E: PASS (88 checks; backends sqlite; drain 1.92 s, 2/2 in-flight completed)`, 4 of 4 repeats.
- `ci/heavy.sh oracles/native-e2e/run --self-test` → `NATIVE-E2E SELF-TEST: PASS (6/6 mutants caught: ...;
  backends sqlite)`. Checks caught per mutant: tenant-from-path 14, commit-despite-cancel 10, body-before-cp 16,
  empty-caps-means-all 11, no-drain 2, ack-then-drop 4.
- `ci/engines.sh with pg18,valkey -- oracles/native-e2e/run --pg @pg18 --kv @valkey` →
  `NATIVE-E2E: PASS (224 checks; backends sqlite+postgres+valkey; drain 1.93 s, 6/6 in-flight completed)`.
- `ci/engines.sh with pg18,valkey -- ci/heavy.sh oracles/native-e2e/run --self-test --pg @pg18 --kv @valkey` →
  `SELF-TEST: PASS (6/6 ...; backends sqlite+postgres+valkey)`. Checks caught: 42, 20, 38, 11, 2, 12.
- `run --subject target/release/aegis` (pre-P4-bin-001 build) → `NATIVE-E2E: FAIL (3 failed:
  boot.empty-data-list.exit78, boot.undeclared-backend.exit78, harness)`, as expected: it has no data plane.

## Known limits

- **Reference, not aegis.** The real binary has not been judged; that is P4-bin-001's acceptance. The reference's
  idempotency latch is a separate SQLite file written right after the data commit, not atomically with it. A crash
  in between is crash-harness territory (INV-DURABLE), not this oracle's.
- **Timing.** Holds are 1.2 s, the cancel lands at 350 ms and inspection waits 1 s after the hold. An extremely
  loaded machine could let the cancel arrive after CP, making a correct subject look committed-despite-cancel. NC7
  allows 150 ms of slack. Run heavy jobs serially (`ci/heavy.sh`).
- **h2.** The client sends HPACK literals without indexing and without Huffman, and does not decode HPACK response
  headers. h2 positive outcomes are judged by the response DATA and the durable row. The reference's h2 server
  accepts only that subset.
- **NC8.** Accepts either completing in-flight work or failing it before CP. It does not require all in-flight
  requests to complete; the PASS line reports how many did. T_drain = 10 s is fixed here because F8 has no drain
  field.
- **Not covered.** NC3 (pool quarantine and recovery: cancel-sweep/state-props), NC4–NC6, the schema gate's
  refusals (judged by oracles/schema-gate; this oracle only provisions an admitted PG table, see Schema), PG
  per-tenant credentials, and `unrestricted`. If P4-oracle-schema-001 requires more of the schema, the spec author
  amends `Store.setup` / `pg_provision` here.

## MariaDB backend (P8-oracle-001, gate native-e2e-mariadb; PREFLIGHT R4)

```
ci/engines.sh with mariadb -- oracles/native-e2e/run --engine mariadb --dsn @mariadb --binary target/release/aegis   # gate (aegis --features adapter-mariadb)
ci/engines.sh with mariadb -- oracles/native-e2e/run --self-test --engine mariadb --dsn @mariadb                     # reference + mutants
```

`--engine mariadb --dsn <mysql://root:..@127.0.0.1:P/aegis>` adds a backend `my` next to SQLite (`--binary` is an alias
of `--subject`; `--engine`/`--dsn` pair up in order). Every `<b>.*` check group above then runs for `my` too
(CRUD, idempotency, cross-tenant uniform denial, auth, NC1, NC7, NC2), plus `cap.*` on SQLite and the NC8 drain over
both backends.

**Config.** `{"id":"my","engine":"mariadb","dsn_ref":"env:AEGIS_E2E_MARIADB_DSN","pin":"mariadb","op_budget_ms":5000}`
and the route `{"id":N,"path":"/my/","to":{"upstream":"app:notes"},"authz":"allow-all","data":[{"backend":"my",
"collection":"notes","ops":[all five],"columns":["id","body"]}]}`.

**Schema (created by the oracle as root, recreated per run, database from the DSN path).** The golden MariaDB shape of
oracles/schema-gate (`aegis_adapter_mysql::check_live_schema`):

```sql
CREATE TABLE notes (tenant VARCHAR(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_nopad_bin NOT NULL,
                    id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_nopad_bin NOT NULL,
                    body TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_nopad_bin NOT NULL,
                    PRIMARY KEY (tenant, id)) ENGINE=InnoDB;
CREATE TABLE aegis_idem (tenant VARCHAR(16) .. nopad_bin NOT NULL, principal VARCHAR(255) .. nopad_bin NOT NULL,
                         k VARCHAR(64) .. nopad_bin NOT NULL, status INT NOT NULL, body MEDIUMTEXT .. nopad_bin NOT NULL,
                         PRIMARY KEY (principal, k)) ENGINE=InnoDB;
```

`aegis_idem` is the in-band idempotency table (PLAN D14) provisioned so the login user never needs DDL; a subject
that keeps idempotency elsewhere ignores it, and P8-bin-001 may ask the spec author for a different shape.
MariaDB has no row-level security: tenant isolation is the rendered tenant conjunct alone. The subject logs in as
`aegis_app@'%'` (`mysql_native_password`, fresh random password per run) with `SELECT, INSERT, UPDATE, DELETE` on
`notes` and `SELECT, INSERT` on `aegis_idem`, and no global privilege (the oracle checks `Super_priv`, `File_priv`,
`Create_priv` = N before boot). `AEGIS_E2E_MARIADB_DSN` = `mysql://aegis_app:<pw>@127.0.0.1:<port>/aegis`; root is
never given to the subject. Durable rows are read as root.

**Schema refusal (boot).** Before the real boot the oracle recreates `notes` wrongly and boots the subject with the
otherwise good config; it must exit 78 without ever accepting a connection:

| check | variant | live schema gate class |
|---|---|---|
| `boot.mariadb-schema-tenant-ci.exit78` / `.never-listened` | tenant `utf8mb4_general_ci` | `CaseInsensitive` (W3 amendment) |
| `boot.mariadb-schema-myisam.exit78` / `.never-listened` | `ENGINE=MyISAM` | `NonTransactionalEngine` |

**Reference.** `ref_subject.py` engine `mariadb` (`MyTx`, over `mywire.py`, a verbatim copy of
oracles/schema-gate/mywire.py): one connection per transaction, `START TRANSACTION`, prepared statements only, the
tenant conjunct in every WHERE, UPDATE/DELETE as `SELECT .. FOR UPDATE` then the write (the mandated MariaDB form, no
RETURNING), insert duplicate = error 1062 → 409, upsert `ON DUPLICATE KEY UPDATE` (safe: (tenant, id) is the only
unique key, which the reference's boot check also requires, with InnoDB and byte-equality collations).

**Mutant (reference only, run when `my` is present).** `drop-tenant`: the tenant conjunct is dropped from every
MariaDB statement. Caught by the `my.xt.*` checks (a foreign row is read, updated or deleted through its id).
aegis-bin's `e2e-mutants` build does not carry it; `--self-test --subject` runs the six shared mutants only (and
builds `native,e2e-mutants,adapter-mariadb` when `--engine mariadb` is given).

Today (base 0e27b11) aegis-bin refuses every MariaDB backend at boot (`adapters.rs`: no F4 denylist family, no
`allowlist.notes-mariadb.lock`), so the gate is red until P8-mariadb-001 and P8-bin-001 land. The recorded runs are in
the P8-oracle-001 report.

### CockroachDB engine of the reference (used by oracles/crdb-live)

`ref_subject.py` also has an engine `crdb` (`CrdbPool`, `CrdbTx`) and three reference-only mutants
(`crdb-40001-as-success`, `crdb-cancel-ignored`, `crdb-no-reset`). They are exercised by oracles/crdb-live, not here;
see its README. `wire.PgConn` now keeps BackendKeyData and can send a CancelRequest (`cancel()`).
