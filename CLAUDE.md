# AEGIS: working rules for agents

AEGIS is a single-binary, formally-assured, agent-hardened, post-quantum middle-tier web server. The design is
`research/ARCHITECTURE.md`; the plan is `research/templates/IMPLEMENTATION_PLAN.md`; invariants are
`spec/SPEC_INVARIANTS.md` (frozen F1).

## Machine safety (non-negotiable)
- Every compile, test, fuzz, load test or simulation runs through `ci/heavy.sh <cmd>`, which serializes heavy work
  machine-wide (one job at a time, 6 GB memory cap, nice 15, 30 min timeout, refuses below 10 GB free disk).
  Never run `cargo build/test/clippy` bare. `cargo fmt` and `cargo xtask <gate>` are light and may run bare.
- No Docker image >500 MB, no apt/sudo, no model weights, no Mathlib. Delete build dirs you create outside `target/`.
- Offload: `ci/remote.sh <cmd>` runs a heavy command on the LAN desktop (Ryzen 9 5900X, shared with the operator's
  other builds; its own lock, 12 GB cap, nice 15, 8 jobs; isolated toolchain under ~/aegis-ci). Prefer it for long
  oracle runs and release builds. Provers (Kani, Verus, Cedar Lean) run on kamrui via ci/kani.sh.

## Privacy
- Never put the operator's name or email in requests to external services (User-Agent, headers, query strings).
  For crates.io and other APIs use `User-Agent: aegis-ci` (no hostnames, no contact details).

## Roles and write scope (IMPLEMENTATION_PLAN §6)
- Spec author / integrator: may change `spec/ interfaces/ oracles/ sdk/ ci/ gates/ tls/ supply-chain/ .github/`,
  `crates/aegis-types/`, `Cargo.toml`, `Cargo.lock`. Any change to a frozen file needs a re-freeze
  (`python3 -I ci/interfaces.py freeze`, `python3 -I ci/statements.py freeze spec`) in the same commit, with the reason.
- Implementer: edits only the files in its unit's `write_scope`. Implementer sessions load
  `ci/hooks/claude-settings.implementer.json`, whose hook denies writes to the verify wall and hub files.
- If a unit cannot be done without weakening a test, an oracle, a statement or a limit, stop and write
  `INFEASIBLE_REPORT.md` (spec clause, failing case, minimal reason). Weakening a check is never a resolution.

## Code rules
- Layering is machine-checked (`cargo xtask layering`): a crate depends only on lower layers (L1 types → L2 pure
  logic → L3 protocol shells → L4 effects → L5 assembly); the SDK sees L1/L2 only.
- `#![forbid(unsafe_code)]` everywhere except `aegis-iso` (≤20 audited sites, each with `// SAFETY:`).
- Workspace lints deny `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, and indexing. Stubs fail closed
  (return an error or `Decision::Deny`), never `todo!()`.
- Constructors of `Principal`, `Canon<K>` and `RawFor<S>` are owned by aegis-token, aegis-canon and aegis-transport.
- New dependencies: only with a pin in `[workspace.dependencies]`, ≥7 days since publish (`cargo xtask lock-age`),
  vet-covered with zero exemptions, and allowed by `deny.toml`. Lock targets live in `supply-chain/lock-targets.toml`.

## Gates
- `python3 -I ci/run-gates.py --phase N` runs gates/phase-N.toml. Every gate has a self-test that must show the
  check failing on a mutated input; a gate that cannot be made red is not a gate.
- Proof gate: `AEGIS_NO_SANDBOX=1 ci/heavy.sh ci/gate.sh` on this laptop (bwrap userns is blocked here).
- Oracles live in `oracles/<name>/` and follow `oracles/README.md`.

## Claims
Say which rung a claim reached (ARCHITECTURE §4.1). Proofs cover models, not the Rust code, unless a gate log
says otherwise. Laptop performance numbers are provisional.
