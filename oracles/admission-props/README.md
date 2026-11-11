# admission-props: property oracle for GCRA and the S0–S6 admission pipeline (a gate)

A blocking gate for the future `monban-admission` and `monban-budget` crates. It checks the admission invariants in
`spec/SPEC_INVARIANTS.md` §C ("Admission I1–I11") on seeded random event traces. A subject is judged only by the
decisions it returns. Until the crates exist, the subject is the stdlib reference model in `admission_ref.py`
(ARCHITECTURE §3.4, stages S0–S6).

```
oracles/admission-props/run                      # reference model, 10,000 traces, seed 1
oracles/admission-props/run --traces N --seed S
oracles/admission-props/run --subject '<cmd>'    # external subject speaking the event protocol below
oracles/admission-props/run --self-test          # 8 mutated limiters + a mutant over the protocol path; all must be caught
```
Last line: `ADMISSION-PROPS: PASS (...)` or `ADMISSION-PROPS: FAIL (...)`. The exit code is 0 only on PASS. Running
the 10k-trace default takes about 30 s, and the self-test about 65 s on this laptop. Run both through `ci/heavy.sh`.

## What is checked

| id | statement (SPEC §C) | how it is checked |
|---|---|---|
| I1 | admitted cost in any window ≤ b + r·W | For every S1 key and S3 identity bucket, within each LRU residency segment, it checks max over windows [tᵢ,tⱼ] of Σcost·T − (b·T + tⱼ − tᵢ) ≤ 0. The arithmetic is exact integer math in O(n). A spec-level shadow GCRA also flags any charged request that is non-conforming. |
| I2 | one identity never alters another's TAT | (a) Metamorphic: an isolation trace is re-run with every event of one other identity deleted, and the target identity's (decision, stage, status) sequence must be identical. These traces turn off the aggregate and set S0, S5 and store sizes so they cannot bind, so per-identity TAT is the only possible coupling. (b) Shadow: an S3/S1 429 on a request the per-identity shadow says conforms is flagged as a foreign-TAT symptom. |
| I4 | memory ≤ M; an evicted key restarts at the anonymous burst and never mints a verified budget | Churn traces use LRU stores of capacity M = 3–24 and flood them with distinct keys between same-instant bursts from anon, verified and established targets. Every (re)insertion segment may charge at most min(b_class, b_anon) units at its insertion instant, and an anon bucket never charges more than b_anon in one instant. |
| I5 | post-hoc debit with TAT ≤ now + 10 min | Overrun traces carry actual costs up to u64::MAX (2⁶⁰…2⁶⁴−1 included), with return probes before, at and after the 600 s cap. A capped and an uncapped shadow are kept per bucket. Two outcomes are violations: an S3 reject that only the uncapped shadow explains (lockout), and a charge that is non-conforming after a debit (debit lost or wrapped). |
| I7 | no fail-open: a stage error ⇒ reject; never HTTP 200 for a reject | Faults are injected at every stage S0–S6 (3% of arrivals in mixed traces, 40% in faults traces). A faulted request must be rejected. Every reject must carry 401/429/503. An admit must be 200 at stage S6. |
| I8 | expensive-tier aggregate: {fresh, anon} ≤ A_f·W + burst, {established} ≤ A_e·W + burst, regardless of identity count | Window check on the charged cost ≥ exp_cost per class group, over all traces. Swarm traces use N = ⌈B_f/b_anon⌉·k identities (k = 1–4, up to 600). |
| I11 | per-identity budgets are non-binding when N ≥ B/b and must not be cited as a swarm defence | Every swarm trace is built in the non-binding regime (N·b_anon ≥ B_f, counted as `i11_nonbinding`). It is re-run with every per-identity budget inflated 1000× (`inflated` role), and I8 must still hold. A violation there is reported as I11. So the aggregate bound is shown not to depend on per-identity budgets, and the model never relies on them. |
| S0 | ≤ max_conns open, ≤ prefix_cap per prefix | The open-connection set is mirrored from decisions and `close` events. |

**Vacuity guard.** The run FAILs if any of these coverage counters is 0: faults at each of S0–S6, S1 and S3 429s,
S3A rejects, S3 re-insertions after eviction, capped debits, u64-overflowing debits, I2 pairs, I4 insertion
bursts, non-binding swarm traces, inflated reruns, and aggregate-binding rejects in inflated reruns.

Not covered here: I3, I6, I9 and I10 (TLA+ per SPEC), and the S5 adaptive limit (the model uses a fixed L with
reservations and borrowing). Retry-After values are not checked, and neither is the S0 header deadline.

## Pass criterion

0 violations of PROTO, I1, I2, I4, I5, I7, I8, I11 and S0 over the trace set, and no zero coverage counter.

## Self-test (negative controls)

The self-test runs 2,400 traces per mutant. The reference must come out clean, and each mutant must trigger its
expected property:

| mutant (`admission_ref.MUTATIONS`) | bug | must fire |
|---|---|---|
| `tat_shared` | S3 TAT keyed by class only (identities share a TAT) | I2, and the metamorphic I2 check alone must catch it |
| `fail_open` | a stage error skips the stage | I7 |
| `no_burst_cap` | GCRA tests the old TAT against τ, so one request can exceed the burst | I1 |
| `evict_mint_verified` | a key re-inserted after eviction gets a full verified-class budget | I4 |
| `tat_overflow` | TAT add wraps mod 2⁶⁴ instead of saturating | I5 / I1 |
| `no_debit_cap` | post-hoc debit not capped at now + 10 min | I5 |
| `no_aggregate` | expensive-tier aggregate removed (relies on per-identity budgets) | I8 / I11 |
| `reject_200` | 429 rejects answered with HTTP 200 | I7 |

It also sends 300 traces through `ref_subject.py` over stdin/stdout. Their decision digest must equal the
in-process reference. `ref_subject.py --mutate tat_shared`, served over the protocol, must be caught by I2.

## Subject event protocol (for monban-admission / monban-budget)

`--subject '<cmd>'` is split with shlex (no shell). The oracle starts it once per chunk of 200 runs, writes JSON
lines to its stdin and reads JSON lines from its stdout. All times are u64 nanoseconds, and the subject must use
saturating u64 arithmetic.

Input lines, in time order (ties are processed in file order):
- `{"type":"config", "trace":k, "s1_T":ns, "s1_b":n, "s1_store":M1, "s3_store":M3,
  "cls":{"anon":{"T":ns,"b":n},"session":{"T":ns,"b":n},"verified":{"T":ns,"b":n}},
  "agg":{"F":{"T":ns,"b":n},"E":{"T":ns,"b":n}}, "exp_cost":20, "stepup_cost":100, "stepup_bits":16, "L":n,
  "max_conns":n, "prefix_cap":n, "fresh_age_ns":ns}`. This resets all state.
- `{"type":"arrive", "id":n, "t":ns, "ip":s, "prefix":s, "conn":s, "newconn":bool,
  "cred":{"kind":"none"} | {"kind":"verified","id":s} | {"kind":"cookie","id":s,"minted":ns,"promoted":bool},
  "cost":n, "pow":bits, "lane":"std"|"accessible", "fault":null|"S0".."S6"}`
- `{"type":"done", "id":n, "t":ns, "actual_cost":u64, "cancelled":bool}`: completion of request `id`. Ignore it
  if `id` was not admitted.
- `{"type":"close", "conn":s, "t":ns}`

Output: exactly one line per `arrive`, in order:
`{"id":n, "decision":"admit"|"reject", "status":200|401|429|503, "stage":"S0"|"S1"|"S2"|"S3"|"S3A"|"S4"|"S5"|"S6"}`.
For an admit, `stage` is `"S6"` and `status` is 200.

Normative semantics. The checker assumes these, and they are the contract for the Rust crates:
1. **GCRA.** Use emission interval T and burst b, with τ = b·T. A request of cost c at `now` conforms iff
   `new = max(tat, now) + c·T ≤ u64::MAX` and `new − now ≤ τ`. On conformance, `tat := new`. S1 charges 1 per request.
2. **Stores.** S1 is keyed by `ip`. S3 is keyed by `("v",cred.id)` for verified, `("s",cred.id)` for
   fresh/established, and `("a",ip)` for anon. Both are LRU with capacity M and are touched on lookup. A new entry
   starts at `tat = now + (b − min(b, b_anon))·T`, so it gets at most the anonymous burst (I4), whether it was first
   seen or re-seen after eviction.
3. **S2 class.** `verified` comes from a verified credential. For a cookie: `established` iff `now − minted ≥
   fresh_age_ns` and `promoted` (I9: age alone does not promote); a cookie minted in the future counts as anon;
   otherwise `fresh`. No credential means `anon`.
4. **S3 is atomic.** The per-identity budget is checked (429 at `S3`), then for cost ≥ exp_cost the group aggregate
   (fresh+anon → F, established → E; 503 at `S3A`). An S3A reject leaves the identity uncharged but touched. A
   request is **charged** iff it passes S3, meaning it is admitted or rejected at S4, S5 or S6.
5. **S4.** An anon request with cost ≥ stepup_cost and pow < stepup_bits is rejected with 401, unless
   `lane == "accessible"`. **S5:** in-flight < L, with per-class reservations ⌊share·L⌋ (verified .30,
   established .40, fresh .10, anon .20) and work-conserving borrowing; otherwise 503. **S6:** dispatch.
6. **Post-hoc debit (S6, on `done` of an admitted id).** Compute `d = max(0, actual − cost)`. If the S3 entry is
   still resident, set `tat := min(sat(max(tat, t) + d·T), t + 600 s)` (no insert, no LRU touch). Cancels are not
   refunded.
7. **Faults.** `fault: "Sk"` fires on entry to Sk, before any state access, and rejects with 503 at Sk.

The exact shadow (rules 1, 2 and 6) pins the GCRA arithmetic. If governor's tolerance convention differs (its
burst n corresponds to τ = (n−1)·T in some versions), the Rust subject adapts at its boundary. The oracle is not
loosened.

## Research provenance (untrusted input: read and re-derived, never executed in place)

| source | sha256 | used for |
|---|---|---|
| research/state/raw/round-003/07-work/swarm_sim.py | 8a5558be9fd69858c6217e46ae3aa7584c8e598d007e54541bb2182bb2fe92d9 | GCRA form (`gcra()`: conforming iff new TAT − now ≤ burst/rate), stage order, S3 cost budgets, the tuned aggregate GCRA charged at S5 (moved into S3 here) |
| research/state/raw/round-003/07-work/gcra_bench.rs | 707732bc0bb116e749d433c3dd51da5b5e22d1190735b3cbca9224d364fd4df1 | integer-ns GCRA. Lesson kept: eviction must be O(1) (its `keys().next()` cost 3.5 µs at 1M churn). Not run. |
| research/state/raw/round-003/07-work/tuned.json | 567201de35e33503944ee8b6522b6a47277a8fe08e16413de12f6e1f4902d5ea | default parameter magnitudes (S1 10/s burst 50, anon 600/min burst 600, A_f 300, A_e 400, step-up at cost 100) |
| research/state/raw/round-003/07-abuse-economics-and-swarm-simulation.json | 04c75684df1185f11a0b33c55189172592e3fca71db0380d1d738ebb6ca8df28 | I8–I11 text (`r3e07-L5-budget-invariants-additions`), C11 "not tested in sim" |
| research/state/raw/round-002/04-abuse-admission-control-under-swarms.json | 6b8b0649f5d0ad1c0327ae8a5502e1b866eec8191d7a2c96d7a73d0af8006177 | S0–S6 defaults (`abuse-L5-admission-pipeline-1vcpu`), post-hoc debit, "never 200", swarm-spec criteria (5) I1, (6) I4, (8) I7 |
| spec/SPEC_INVARIANTS.md | c2001009e5c9e33f01231d17f83159083926db0eb58b380e0dc562bc86e49269 | I1–I11 statements |
| research/ARCHITECTURE.md | 22848c5159ea2c6479def0f6e53aaa92c6b47458d3fced567fa5e7e0993a6dae | §3.4 stage table and reject statuses |

## Re-run in repo (2026-10-25)

- `ci/heavy.sh oracles/admission-props/run`: 13,334 runs (10,000 traces plus isolation-perturbed and inflated
  reruns), 5,786,163 events, decision digest `287907bda757bf41`, 0 violations, and every coverage counter is
  nonzero (for example debit_overflow=4890, s3_reinsert=42770, i11_agg_binds=91459). Last line:
  `ADMISSION-PROPS: PASS (10000 traces, seed 1, 5786163 events; I1 I2 I4 I5 I7 I8 I11 S0 hold, 0 violations)`
- `ci/heavy.sh oracles/admission-props/run --self-test`: reference clean; 8/8 mutants caught (`tat_shared`
  metamorphic I2 alone: 149/200 pairs at 1,200 traces); the protocol digest equals the in-process digest; the
  protocol-path `tat_shared` is caught. Last line: `ADMISSION-PROPS SELF-TEST: PASS (8/8 mutants caught: ...)`

## Known limits

- The I2 metamorphic check deletes one other identity. It does not explore every perturbation.
- I4 is exact only for LRU stores (rule 2). A subject using another bounded-store policy needs a declared policy
  and an oracle change, made by the spec author and never by an implementer.
- The reference model and the checker were written by the same porter. The checker restates the spec rather than
  importing the pipeline, but correlated misreadings of the spec are still possible. Freezing this oracle should
  therefore include a second-model review.
- The parameters are randomized per trace around the D-grade §3.4 magnitudes. They are not calibrated numbers.
