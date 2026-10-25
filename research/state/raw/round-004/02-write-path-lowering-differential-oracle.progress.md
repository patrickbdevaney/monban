# progress explorer 02 r4 (restart after crash; nothing existed). started Sun Oct 25 03:30:02 AM EDT 2026
- plan: containers aegis-r4e2-pg17 (55511), pg19rc1 (55512), valkey+redis alpine pulled; work dir 02-work/ (copied oracle.py, oracle_typed.py)
- cases: WRITE oracle with diff of full table pre/post image; lowerings naive vs hardened; native control = RLS / sqlite authorizer / redis ACL
## checkpoint 1 (executed; files in 02-work/: wporacle.py wp_run.py wp_run2.py wp_run3.py, wp_results*.json, wp_out.txt)
- engines: sqlite 3.45.3 (python), postgres 17.11, postgres 19rc1 (docker). N=300 cases/variant (seed 20261025), 60 rows, 8 tenants incl ACME/Acme/'acme '/a%.
- RESULTS (recomputed, executed): no-native lowering leaks (cross-tenant mutate): SET tenant=other naive 113/300 sqlite, 110/300 pg; hardened (SET tenant=handle) 0.
  upsert global PK DO UPDATE: 261/300 all 3 engines; guarded WHERE t.tenant=excluded.tenant 0; composite PK (tenant,id) 0; DO NOTHING 0.
  sqlite INSERT OR REPLACE / REPLACE INTO global PK 261/300; UPDATE OR REPLACE SET id=colliding 112/300; composite PK 0.
  sqlite authorizer deny SQLITE_DELETE does NOT stop REPLACE implicit delete (261/300 leak); authorizer deny UPDATE t.x blocks DO UPDATE (all 300 blocked, static).
  nondeterministic/NOCASE tenant col: UPDATE/DELETE cross-tenant 45/300 sqlite NOCASE, 44/300 pg ICU ks-level2 (read-path CEX carries to write).
  trigger propagate-by-grp: naive 127-129/300 cross-tenant; tenant-scoped trigger 0 cross but 78-79/300 in-tenant-outside-Pred (INV clause pre-image subset Pred catches it). Invoker trigger under RLS: cross 0 (RLS blocks), SECURITY DEFINER trigger: 127/300 leak.
  data-modifying CTE: propagate 127/300, CTE DELETE->INSERT other tenant 110/300; MERGE ON id only 261/300; MERGE guarded -> 0 leak, 261 unique-violation errors (existence oracle). MERGE NOT MATCHED BY SOURCE DELETE w/o guard 300/300 (PG17,19rc1).
  PG default en_US collation range predicate deviates from code-point ref: 2/300 in-tenant-outside-pred in plain UPDATE/DELETE (read-path CEX carries).
  RLS native: good ALL policy -> 0 leaks across U2/UP1/UP2/C1(cross)/C2/M1/P2 partition row movement; table OWNER w/o FORCE -> 110/300 leak, FORCE -> 0.
  KEY FINDING: RLS WITH CHECK(true) misconfig is MASKED when WHERE/RETURNING references a column (SELECT policy USING is applied to new row); `UPDATE t SET tenant=$1` (no column refs) or WHERE true leaks 100/100 on 17.11 (and 19rc1 same) with ALL USING=cur WITH CHECK(true), and with UPDATE USING(true). Column-ref WHERE -> blocked.
  PG: generated column subquery rejected ("cannot use subquery in column generation expression") -> generated cols cannot write/read other rows (negative result). PG19rc1 supports ON CONFLICT DO SELECT (17 syntax error) = new construct for denylist.
- TODO: redis/valkey oracle; web sources (>=25); nodeModifyTable.c; CVEs; JSON.
## checkpoint 2 (redis/valkey executed; 02-work/rd_run.py, rd_results_55513.json (valkey 9.1.2, redis_version compat 7.2.4), rd_results_55514.json (redis 8.10.2))
- hex-id tenant ns t:{hex}: + ACL ~t:{A}:* (+@all -@admin -flushdb -flushall -swapdb -keys): mutation-leak cmds 0/29 on both; but SCAN (no MATCH) returns foreign key NAMES (read leak, ACL does not filter SCAN) on both; RANDOMKEY leaks foreign key name when allowed; KEYS * leaks unless denied. +@all grants FLUSHDB/SWAPDB mutation (2 cmds). %R~/%W~ selectors same.
- naive raw tenant ids with glob chars in ACL pattern: 'a*' 13-15 mutation-leak cmds of 29 (SET/DEL/APPEND/RENAME both dirs/COPY/MOVE/SMOVE/LMOVE/SUNIONSTORE/BITOP/MSET/GETDEL/EVAL/RESTORE); 'a?' 13; 'a[b-c]' 5; backslash 5; delimiter confusion 0.
- negative results: ACL checks BOTH keys of RENAME/COPY/SMOVE/LMOVE (NOPERM); SORT BY/GET denied for keyed-restricted user ("BY option of SORT denied due to insufficient ACL permissions"); EVAL undeclared key blocked by script ACL.
## checkpoint 3 (sources 1-14 + exec)
- S1 PG docs sql-createpolicy (Table 300; UPDATE needs SELECT policy when WHERE/RETURNING reads cols; ON CONFLICT DO UPDATE existing row failing USING raises error never silent; MERGE same)
- S2 sqlite lang_conflict (REPLACE deletes pre-existing rows; delete triggers only if recursive_triggers; update hook NOT invoked; change counter not incremented) 
- S3 sqlite c3ref/set_authorizer (authorizer invoked at prepare only) -> explains executed result: authorizer deny SQLITE_DELETE does not stop REPLACE (261/300 leaks)
- S4 sqlite lang_upsert (DO UPDATE WHERE; excluded.; conflict target)
- S5 PG security page: RLS CVEs CVE-2026-14666 (18.6/17.11/16.15/15.19/14.24), CVE-2024-10976 (17.1..), CVE-2023-39418 (15.4, 2023-08-10, Dean Rasheed, CVSS 3.1), CVE-2023-2455.
- S6 postgres master nodeModifyTable.c (ExecOnConflictUpdate: lock row, visibility, evaluate ON CONFLICT WHERE qual, THEN WCO_RLS_CONFLICT_CHECK; ExecCrossPartitionUpdate delete then reinsert via root)
- S7 valkey.io/topics/acl, S8 redis.io ACL docs (explicit note: key patterns do not limit FLUSHALL/FLUSHDB/SWAPDB; side channels ignored for R permission; glob-style pattern)
- S9 CVE-2023-39418 page. S10-14 websearch: pgsql-hackers thread 2026-09-25 (shihao zhong) ON CONFLICT DO SELECT returns rows hidden by security_barrier view (PG19); Viktor Holmberg: ON CONFLICT WHERE can call function to peek hidden values in PG18.
- EXEC: reproduced both on 19rc1: DO SELECT via security_barrier view returns other-owner row (secretB). peek(): `INSERT .. ON CONFLICT (id) DO UPDATE SET .. WHERE peek(t.x)` as RLS tenant a calls peek on tenant b's row ('PEEK saw secretB') on 17.11 AND 19rc1 before RLS USING error; plain UPDATE/DELETE/MERGE WHERE peek see only own rows.
## DONE: JSON written Sun Oct 25 03:40:57 AM EDT 2026
