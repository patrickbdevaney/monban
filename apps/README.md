# apps/

Apps are linked only into the `native` build of monban-bin (`--features native`, PLAN D17; the default build is the
core and links none). A route binds an app with `to.upstream = "app:<name>"`; its F8 `data` caps name the backend.
Backends served in native mode: SQLite and PostgreSQL. Redis/Valkey backends are refused at boot (exit 78) until
PLAN D18 adds the MULTI/EXEC commit to the per-tenant ACL. Example: `apps/notes` (oracles/native-e2e).

Native handler applications (modes A/D). Each `apps/<name>/` is a workspace member (glob `apps/*`) with
`[package.metadata.monban] layer = "app"`.

Rules (machine-checked by `cargo xtask layering`):
- An app depends on `monban-sdk` only: no other workspace crate, and no tokio/axum (the SDK surface is synchronous,
  DEVIATIONS X-11). Only `monban-bin` (L5) may depend on an app.
- An app never enables the SDK feature `host` and never names `monban_sdk::host`. The host driving loop belongs to
  monban-adapter-host (decision D2(b)). An app cannot construct `Ctx`, `Granted` or `Tx`. It receives them from the
  host and obtains capability proofs only through `Ctx::grant`.
- `#![forbid(unsafe_code)]` and the workspace lints apply as everywhere else.
