# Operator steps: status and what each one needs from you (2026-11-06)

The agent did every operator step it can do. What's left needs a human, a legal choice, or hardware. Each item
says exactly what to do.

## 1. GCP CPU quota for the 64-core run: DONE

- 2026-11-06: the request was auto-denied on the free trial. The operator activated the full account, and the
  re-filed preference `aegis-cpus-80` was approved: CPUS_ALL_REGIONS is now 80. C2D in us-central1 allows 100.
- **Queued:** the c2d-standard-64 run (about 1 h, about $2.9/h, paid from the credit) runs after P8-bin-001 wires
  `runtime.worker_threads`. Until then aegis-bin is capped at 2 tokio workers, and a 64-core curve would only
  measure that cap.
- **Real-money tripwire** (operator request):
  - Budget "aegis tripwire: any real-money spend": USD 1, with credits netted out (INCLUDE_ALL_CREDITS). It
    emails the billing admins at 1% and 100%, and publishes to Pub/Sub `aegis-budget`.
  - `ci/release/spend-guard.py` refuses every `vm.sh start` once net spend is above 0. A laptop cron runs it every
    30 min (`~/.cache/aegis-tools/bin/aegis-spend-guard.py enforce`) and also stops any RUNNING instance.
  - A second budget, "aegis gross spend vs 300 credit", emails at 25/50/80/95% of $300 gross.
  - **Limits:** GCP evaluates budgets hours behind actual usage, so a trip can follow cents to a few dollars of real
    spend. A stopped VM's disk is still billed, at cents per day. The credit's expiry date is shown only in the
    console (Billing → Credits). An expired credit shows up as net spend, so it trips the same way.
  - **Remove:** delete the cron line and the two budgets.

## 2. io-uring 0.7.15 audit countersign: PACKET READY, needs a human

The audit in supply-chain/audits.toml (`[[audits.io-uring]]`) is an agent review. A countersign means a person has
read it and agrees.

**Check these points, about 20–30 min:**
1. Read the `notes` of that audit entry: the scope, the unsafe argument and the two caveats.
2. Confirm aegis-uring never calls `Submitter::register_ifq`:
   `grep -rn register_ifq crates/aegis-uring` must return nothing.
3. Read the one unsafe block in aegis-uring, `crates/aegis-uring/src/driver.rs:93-120`, against the
   buffer-ownership argument in `crates/aegis-uring/src/lib.rs:13-22` (DEVIATIONS X-19, cap 6, 1 used).
4. Optional: spot-read the crate source,
   `~/.cargo/registry/src/*/io-uring-0.7.15/src/{squeue,cqueue,submit}.rs`.

**To countersign:** edit that entry's `who` to `"<your name> (countersigned <date>); AEGIS integrator agent
(P7-spec-002)"`, then commit. If you'd rather not, the feature stays off in every shipped profile, as it is today.

## 3. Real release keys: NOT AGENT-DOABLE

This needs 5 TUF root holders, hardware tokens and a ceremony (Phase 6 PREFLIGHT §P4 item 3). Test keys are used
everywhere until then. Nothing blocks on it before a public release.

## 4. License, CRA publication, GitHub Actions: deferred by you on 2026-11-04

These are your decisions, and you said "not yet", so the agent has not chosen a license or published anything.
The CRA drafts exist (D-P1, drafts only). The legal deadline is 2027-12-11, for SECURITY.md contact, CVD policy,
support period and EU DoC. To start, say which license to use and the agent will do the rest.

## Already closed

- D-P4: accepted 2026-11-04.
- Keep aegis-quiet: kept.
- HTTP/3 re-check: agent-scheduled for 2027-03-30 (ci/h3-precondition.py).
