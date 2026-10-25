# Resuming a research run after a crash

Long runs leave progress on disk at four layers. Recover from the cheapest layer that still exists.

| Layer | What is on disk | Written when |
|---|---|---|
| Agent cache | `~/.claude/projects/-home-patrickd/<session>/subagents/workflows/<run>/journal.jsonl`. It holds every finished agent's return value. | After each agent finishes |
| Journal mirror | `state/raw/_journals/<run>.journal.jsonl` | Every 10 min, by `tools/checkpoint.sh` |
| Explorer | `state/raw/round-NNN/II-label.progress.md` and `II-label.json` | Every ~5 sources, and at explorer end |
| Round | `state/*.jsonl`, `reports/round-NNN.md`, `ARCHITECTURE-DRAFT.md` | Integrator, each round |
| Offsite | Branch `checkpoints` on `forge:patrickd/aegis`: research/ without build output, plus the journals | Every 10 min, by cron |

## 1. Machine crashed, Claude session still resumable (same session)

```
Workflow({scriptPath: "/home/patrickd/aegis/research/aegis.workflow.js",
          resumeFromRunId: "<run id from .inflight-run>", args: <identical args>})
```

- Finished agents return from cache instantly.
- Explorers that were cut off restart and pick up their progress file.
- The script and args must be byte-identical. Steer through `AEGIS_QUESTION.md` only.
- `derive_workflow.py` refuses to run while `.inflight-run` exists.

## 2. Claude session lost (resumeFromRunId is same-session only)

1. Find the first round N with no `reports/round-N.md`. If the last integrator crashed partway, roll that round's state back first:

   ```
   git -C ~/aegis restore --source=checkpoints -- research/state research/reports
   ```

   Then pick a checkpoint commit that came before integrate:rN started (`git log checkpoints`).
2. Start a new run of the same script with `args.round = N`. Keep the remaining `rounds` count and the other args as they were.
   - Explorers rerun, but they read their progress file and only extend it, so they don't start from scratch.
   - Rounds before N are not rerun; the planner reads their results from the state files.
3. Delete `.inflight-run`, then run `python3 -I tools/derive_workflow.py` so future runs get the hardened prompts:
   - an explorer reuses its finished raw JSON instead of redoing it;
   - the integrator skips ids and URLs already appended for this round, and rewrites files via temp file plus rename.
4. If you need an exact agent output, read `state/raw/_journals/<run>.journal.jsonl`.

## 3. Laptop disk lost

```
git clone forge:patrickd/aegis
git checkout checkpoints
```

Then follow §2.
