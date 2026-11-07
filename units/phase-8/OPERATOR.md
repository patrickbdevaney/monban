# Operator steps: status and what each one needs from you (2026-11-06)

The agent did every operator step it can do. What's left needs a human, a legal choice, or hardware. Each item
says exactly what to do.

## 1. GCP CPU quota for the 64-core run: SUBMITTED, AUTO-DENIED (needs the account owner)

- **Request:** quota preference `aegis-cpus-80` (CPUS_ALL_REGIONS 12 → 80), filed 2026-11-06. 80 covers a
  c2d-standard-64 plus the 8-vCPU aegis-quiet VM. C2D in us-central1 already allows 100.
- **Check:** `gcloud alpha quotas preferences describe aegis-cpus-80 --project=project-333565b3-9b4b-4ae4-b75`.
  The request is granted when `grantedValue` reads 80.
- **Outcome:** denied automatically 2 s after filing (`stateDetail: Quota request denied`), the usual result for a
  free-trial billing account.
- **Fix:** Google refuses increases on free-trial billing accounts. The fix is console → Billing →
  "Activate full account". Remaining credit is kept, and it's a step only the account owner can take. Then
  re-file with the same command, or tell the agent to.
- **Cost once granted:** c2d-standard-64 at about $2.9/h on demand. One run (bench/scaling/README.md
  "`--gcp`") takes about 1 h.

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
