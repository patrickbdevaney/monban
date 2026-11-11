# The path to security by design

How Monban turns a finite amount of code and proof into security that holds for an unbounded number of uses, where
that security stops, and the ordered path to strengthen it. Companion to `SECURITY_CLAIMS.md` (what is claimed
today, at which rung) and `research/ARCHITECTURE.md` (the design).

## 1. Principle: a small, proved reference monitor with finite grammars

Proofs quantify over all inputs; they do not enumerate cases. A theorem about the boundary therefore covers every
interaction that crosses it, including interactions nobody anticipated, provided three conditions hold:

1. **Complete mediation.** Every request and every extension call passes through one host pipeline:
   admission → canonicalization → authorization → capability-scoped effect. There is no side door.
2. **Tamper-proofness.** Callers cannot forge or alter the decision machinery: `Principal`, `Canon<K>` and
   capabilities have no public constructors; extensions run out of process or in Wasm with a capability-only linker.
3. **Verifiability.** The deciding parts are small enough to prove or to check with independent oracles.

Users and extensions may only speak to the server in **grammars we define and prove things about**:

| grammar | frozen interface | holds for every sentence |
|---|---|---|
| canonical requests (paths, hosts, queries, headers, cookies, JSON) | F2, F8, CANON-1..8 | one reading per identity; no component disagrees about what a request means |
| data operations (Op / Pred IR) | F4 | tenant isolation; exactly the permitted rows on exact backends (three-valued semantics); writes never touch another tenant |
| authority (capability tokens) | F5 | delegation only narrows; audience, expiry and depth bound |
| policy decisions | F6 + Cedar via `monban-pdp` | any error, timeout or crash ⇒ deny |
| extension calls | F7, F7b, F10, Wasm linker | an extension receives only work already authorized and tenant-bound; everything it returns is validated |
| resources | TBI-1..9, admission I1–I11 | no client, swarm or extension exceeds its budget or starves others |

**Scaling rule:** grow the grammars deliberately; never grow proof obligations per user or per application.

## 2. Cost model: finite per kind, not O(n) per use

| change | cost | who benefits |
|---|---|---|
| a new kind of effect (database family, protocol front end, agent protocol) | one adapter or front end + its two-sided oracle (+ a proof where the semantics can be stated) | every user of that kind, permanently |
| a new guaranteed property | one statement + proof or oracle at the boundary | every interaction |
| a trusted-component update (hyper, h2, tokio, rustls, AWS-LC, rustc) | re-run every gate | — |
| a new application, client or policy written by someone else | nothing for the golden build | — |

## 3. Responsibility boundary

| | golden build (us) | downstream users | neither (residual) |
|---|---|---|---|
| owns | the reference monitor, the grammars, the proofs and oracles, the release chain | their intent (policies), their extensions' logic within the authority granted, their clients, any path that bypasses Monban | the trusted computing base until it is replaced or verified; side channels |
| holds regardless of downstream code | budgets and admission; fail-closed authorization; tenant binding of every extension input; host-side validation of extension output; crash containment; isolation of tenants on golden adapters | — | — |
| holds only for golden components | row-exactness of lowering, write-subset W1–W7, store durability | — | — |

A downstream weak link can spend only the authority its own tokens and capabilities carry. A modified or forked
binary is not the golden build; its conformance report (F13) says `fork`.

## 4. What finite proofs can never cover

1. **Intent.** Enforcement is exact; whether a policy is wise is the operator's choice (mitigated by Cedar validation,
   deploy-time SMT checks, deny-by-default).
2. **Bypass paths.** An application talking to its database directly is outside mediation.
3. **Misuse of granted authority** within its own scope (narrowed by INV-CONFUSED-DEPUTY-NI and per-tenant credentials).
4. **The trusted computing base** (section 5).
5. **Microarchitectural side channels.**

## 5. Shrinking the trusted computing base

Ordered by attack exposure: parsers and framing first, then crypto paths, then the runtime and compiler.

| component | proved upstream today (not by us) | our path | target phase |
|---|---|---|---|
| HTTP/2 framing, HPACK (h2) | nothing | Vest (Verus-verified Rust parsers/serializers) for frame headers and HPACK primitives in front of h2; Kani harnesses on hyper/h2 parsing functions; keep the strict H1 pre-filter and the TBI wrapper | 4–5 |
| AWS-LC | ML-KEM and ML-DSA assembly (mlkem-native, mldsa-native): correctness, memory safety, constant time at object-code level; P-256/P-384/X25519/Ed25519 arithmetic (s2n-bignum, HOL Light); narrow SHA-2/HMAC/AES-GCM paths (SAW) | pin versions and CPU paths where the proved code is what executes; re-run upstream proofs in our CI; narrow SAW/CBMC proofs of the glue we use (HKDF, AES-GCM with AD); our 0x11ED group stays a thin combiner over proved primitives | 6 |
| crypto alternative | libcrux (HACL\*-derived primitives; ML-KEM largely; ML-DSA arithmetic) | libcrux-based rustls CryptoProvider for P-PUBLIC-WEB ("smaller, more-proved C surface"); FIPS profiles stay on AWS-LC | 7 |
| Rust compiler | nothing (Ferrocene is qualification, not proof) | reproducible byte-identical builds (done); diverse double compilation with mrustc; proof-critical crypto stays in proved assembly | 6 |
| tokio | bounded model checking (loom) and Miri upstream, no proofs | loom/shuttle on our own concurrency; minimize the async surface the core depends on | 4–6 |
| Linux kernel | nothing (seL4 is the only verified kernel) | hardened Linux: seccomp, Landlock, systemd exposure ≤2 (measured 1.6); seL4 appliance as research only | 5 |

## 6. Extension contracts (normative)

Each extension point gets a frozen contract: grammar or ABI, what the host guarantees, what the extension must
guarantee, the conformance suite it must pass, and the label its report carries (golden / adapter / module / fork).

1. **Data adapters** (F10, out of process): how to add a database family; the two-sided lowering oracle; mandated
   write forms (sole full-length tenant-scoped arbiter, no REPLACE/IGNORE, binary no-pad collations); golden criteria.
2. **Wasm handlers** (P2): capability-only linker; per-handler fuel derived from measured cost (≤100× handler
   cost); fork+Wasm per principal by default; host-state corruption is a tested fault class.
3. **SDK handlers** (F7, F7b): sealed capabilities; host-driven streaming; jobs only after commit.
4. **Policies** (Cedar via `monban-pdp`): validation and SMT checks at deploy; deny when absent.

## 7. Recipes (developer onboarding, tested against the real binary in CI)

1. **Ingress (client → Monban):** React/Next.js, Vue/Nuxt, SvelteKit, htmx, mobile, plain fetch; agents over MCP.
   Each covers the auth flow (cookies vs DPoP-bound tokens), Origin/CORS binding, CSRF, streaming, exact config.
2. **Egress (Monban → backends):** Postgres, SQLite, MariaDB, CockroachDB, Redis/Valkey (golden or golden-eligible);
   MySQL, Mongo and managed platforms as non-golden adapters until their oracles pass; upstream app servers
   (Node, PHP-FPM, Go, Python) in reverse-proxy mode.
3. **Reverse direction:** webhooks with raw-byte signature verification, the outbox pattern, server-sent events.
4. **Optional typed SDKs** generated from the frozen interfaces (TypeScript client; Rust SDK in-tree). Not required
   for agent-driven development; offered because many teams want abstractions.

## 8. How core updates stay proved

Every change to the golden distribution passes the same machine-checked path: statement changes need an explicit
re-freeze (`spec/STATEMENTS.sha256`, `interfaces/MANIFEST.sha256`); the proof gate runs six independent checkers;
every oracle and its negative control must pass; supply-chain gates (cooldown, advisories, vet ratchet, crate and
unsafe budgets) must pass; the build is reproducible; releases carry triple signatures (Ed25519, SLH-DSA, ML-DSA-87)
and a signed conformance report (Phase 6).

## 9. Order of work

1. Phase 2 GO (reverse proxy) → Phase 3 (agent gateway: token tiers, MCP listener gate, Cedar PDP, SSRF-guarded egress).
2. Extension contracts (§6), then ingress/egress recipes for the top three frameworks and the golden databases.
3. Phase 4 (data plane + native handlers), with Vest parsers in front of h2.
4. Phase 5 (P2 isolation) and Phase 6 (profiles, FIPS, release chain, AWS-LC proof re-runs, diverse compilation).
5. Phase 7 (deferred modules, libcrux provider, HTTP/3 when its stack matures).
