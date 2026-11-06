# INFEASIBLE: "OSV clean" on the spike lock (P7-libcrux-001)

**Failing criterion.** The unit acceptance includes "cargo-deny + OSV clean", and PREFLIGHT D-P7.5 asks for "an
advisories check" on the spike lock. Everything else in the gate passes: isolation, --locked, lock-age,
cargo-deny, build, clippy, KAT, interop and bench.

**What fails.**

```
osv: 115 lock packages queried (48 compiled for 3 shipped targets): 1 advisories
  proc-macro-error2@2.0.1: RUSTSEC-2026-0173 (not compiled for any of x86_64-unknown-linux-gnu,
  aarch64-unknown-linux-gnu, x86_64-unknown-linux-musl)
```

RUSTSEC-2026-0173 is the "proc-macro-error2 is unmaintained" advisory. It is not a vulnerability, and it has no
patched version.

**Why it cannot be removed (minimal reason).**

- The path is libcrux-intrinsics 0.0.9 → `[target.'cfg(hax)'.dependencies]` core-models 0.0.7 → hax-lib 0.3.7 →
  (optional) hax-lib-macros =0.3.7 → proc-macro-error2 ^2.0.
- Cargo writes target-specific and optional dependencies into Cargo.lock even though it never compiles them for a
  normal target. `cargo tree --target <t> --all-features` shows the crate absent for all three deny.toml targets.
- Every libcrux crate this spike needs pins `libcrux-intrinsics` exactly:
  - libcrux-ml-kem 0.0.11 and libcrux-aes 0.0.10 pin `=0.0.9`;
  - the older train (ml-kem 0.0.10) pins `=0.0.8`.
- Both intrinsics versions need `core-models ^0.0.7`, which on 0.0.x means exactly 0.0.7. The only release is
  2026-07-15, and it needs `hax-lib ^0.3.7`.
- hax-lib-macros 0.4.x no longer uses proc-macro-error2, but nothing at least 7 days old lets core-models move to
  hax-lib 0.4.
- Fixing this needs an upstream libcrux release, or a `[patch]`/git source, which deny.toml's `sources` policy
  forbids.

**What I did not do, and why.**

- I did not ledger an acceptance. I drafted one in a spike-local file. It was mechanically guarded: it applied
  only when the crate is compiled for no shipped target. I removed it before committing, following P6-cmvp-002:
  ledgering an advisory for a crate the build never compiles weakens the gate.
- I did not narrow OSV to the compiled graph. The unit asks for OSV on the lock.

The gate therefore stays red on this one line. It runs every other step anyway, so the rest stays visible.

**What would close it** (owner's choice):

1. An upstream libcrux release whose core-models depends on hax-lib 0.4, and that is at least 7 days old.
2. A spec-author or operator decision to accept RUSTSEC-2026-0173 for the spike lock. That would be a ledger entry
   with an expiry, valid only while `cargo tree` shows the crate is never compiled; `tools/supply.py` already
   prints that fact.
3. A spec-author decision that "OSV clean" applies to the compiled graph, the scope cargo-deny already uses.
