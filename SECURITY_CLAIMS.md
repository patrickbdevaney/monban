# Security claims and their limits

AEGIS makes a finite, checkable set of claims about its **golden reference build**. Each claim names the rung it
reached (ARCHITECTURE §4.1): R4 = machine-checked proof of a model, R3 = enforced by types/capabilities, R2 =
differential/two-sided oracle, R1 = executed test harness, R0 = argued only. A proof covers its model, not the Rust
code, unless a gate log says otherwise.

## Not proven: the trusted computing base we rely on

These components are **trusted, not verified**. Their correctness is assumed by every claim below; we reduce the
risk (pinned versions, cooldown, advisories, fuzzing, conformance suites, reproducible builds), but we have not proved
them secure and do not claim to.

| component | role | what we do about it | what we do not claim |
|---|---|---|---|
| **hyper** (HTTP/1.1) | HTTP framing and server machinery | strict pre-filter in aegis-transport (CL+TE, duplicate CL, TE, bare CR/LF, obs-fold rejected before hyper sees the request); wrapper budgets; upstream framing regenerated from canonical values | that hyper's parser is free of bugs |
| **h2** (HTTP/2) | HTTP/2 framing, HPACK, flow control | AEGIS wrapper: per-connection send ledger, stream/handler caps, RST budget, stall and idle deadlines (TBI-1..9); h2spec 145/146; two known RFC deviations documented in `crates/aegis-transport/INFEASIBLE_REPORT.md` | that h2's state machine or HPACK decoder is correct |
| **tokio** (+ mio, socket2) | async runtime, I/O reactor | pinned, cooldown, advisories; `panic = "abort"` | runtime correctness or absence of scheduling bugs |
| **AWS-LC C code** (via aws-lc-rs / aws-lc-sys) | all cryptography: TLS key exchange incl. ML-KEM, signatures incl. ML-DSA, hashing | FIPS 140-3 validated module only in the cmvp profile (CMVP #5298/#5314, AL2023); KATs for our 0x11ED hybrid group; interop with OpenSSL and Go | that the C implementation is memory-safe or side-channel free outside its certification scope |
| **rustls** (+ webpki, pki-types) | TLS 1.3 protocol | profile-exact configs, 12 frozen TLS verdicts, security floors | protocol-implementation correctness beyond those tests |
| **The Rust compiler (rustc / LLVM)** and std | turning verified-intent source into machine code | pinned toolchain 1.99.1, reproducible double build (byte-identical binaries) | that the compiler is correct or free of miscompilation; there is no verified compiler in the path |
| **Linux kernel, libc, the hardware** | execution substrate | seccomp/Landlock plans, systemd hardening (exposure 1.6) | anything about them |
| **Third-party extensions** (adapters, modules, handlers written by others) | out-of-process or Wasm, behind contracts | host-side validation, capability-scoped inputs, crash budgets, fail-closed mapping | the internal security of their code (see "Responsibility boundary") |

## What is claimed (golden build)

| property | rung reached | evidence |
|---|---|---|
| Policy combiner fails closed (empty ⇒ deny, error ⇒ deny, allow iff unanimous) | R4 model + exhaustive Rust test | `spec/AegisIR/Combine.lean`, `crates/aegis-authz` |
| Capability tokens only narrow under attenuation; audience/expiry/depth bound | R4 model | `spec/AegisIR/Token.lean` (HMAC EUF-CMA, codec round-trip, constant-time compare are assumptions) |
| Tenant-scoped data lowering returns exactly the permitted rows on exact backends | R4 model + R2 oracle | `spec/AegisIR/Lowering.lean`, `ThreeValued.lean`, `oracles/lowering-read` (≥100k cases per engine) |
| Write path never touches another tenant's rows (W1/W2/W4) | R2 oracle | `oracles/lowering-write` (SQLite, PG, MariaDB, Cockroach with mandated forms) |
| One canonical reading of every identity (paths, hosts, JSON, …) | R2 oracle | `oracles/canon-diff` (G1 100k + G2 17,113 + G3 66, 0 disagreements) |
| Resource budgets (RST bucket, GCRA, admission I1/I2/I4/I5/I7/I8/I11) | R1 oracle; Kani on the real code in progress | `oracles/admission-props`, `ci/kani.sh` |
| PQ TLS profiles negotiate exactly as frozen | R1 | `tls/verdicts.toml`, `oracles/hrr-verdicts` |
| Tamper-evident audit log | R1 + independent verifier | `oracles/tlog-verify` (Go x/mod tlog) |
| Zero-downtime upgrade drops nothing | R1 | `oracles/upgrade-harness` (100 reloads, 0 drops) |
| Acked writes survive single crashes (SQLite WAL FULL / redb 2PC) | R1 | `oracles/crash-harness` |

Microarchitectural isolation (Spectre-class) is **not** claimed. No regulator credits code proofs; compliance claims
are in `research/templates/COMPLIANCE_MAP.md`.

## Responsibility boundary (golden extension contract, spec §H)

Every request and every extension call passes through the same host pipeline (admission → canonicalization →
authorization → capability-scoped effect), and extensions can only be attached through frozen contracts (F7 SDK
with sealed capabilities, F10 out-of-process module wire, Wasm with a capability-only linker). Therefore:

- **Holds no matter what downstream code does:** budgets and admission (I1, I2, I5), fail-closed authorization,
  tenant binding of every operation an extension receives, host-side validation of everything an extension returns,
  crash containment (a crashing or misbehaving extension becomes a deny for its own requests), and isolation of
  tenants served by golden adapters.
- **Holds only for golden components:** row-exactness of data lowering, write-subset W1–W7, crash durability of the
  golden stores.
- **Not our responsibility:** the internal correctness of third-party adapters, modules, handlers, client
  applications, or any path that bypasses AEGIS (e.g. an application talking to its database directly). A forked or
  modified binary is not the golden build; the conformance report (F13) labels it `fork`.
