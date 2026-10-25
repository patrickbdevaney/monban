# aegis (working name)

A formally-assured, agent-hardened, post-quantum middle-tier web/application server for the agentic era: one
static binary in front of (or instead of) nginx / PHP-FPM / Node, with machine-checked core invariants.

**Read `SECURITY_CLAIMS.md` first.** It lists exactly what is proved, at which rung, and what is trusted but not
proven: hyper / h2 / tokio, the AWS-LC C crypto code, rustls, and the Rust compiler are in the trusted computing
base and are **not** formally verified.

- `crates/` — the server (layered L1 types → L5 assembly; `cargo xtask layering`). `aegis-bin` is the binary.
- `spec/` — Lean 4 specification and proofs (frozen statements). `interfaces/` — frozen interfaces F1–F13.
- `oracles/` — the verify wall: independent checkers, each proven able to fail. `gates/` — phase go/no-go.
- `spikes/` — Phase-1 decision experiments and how each verdict was applied (`spikes/APPLIED.md`).
- `DEVIATIONS.md` — where the implementation departs from `research/ARCHITECTURE.md` and why.
- `research/` — the deep-research track that produced the architecture and plan.
