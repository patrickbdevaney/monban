# q2-007: double fault and fsync EIO

No new harness: the Phase-0 port of the crash harness (`oracles/crash-harness/`) added the double-fault and EIO
stages this spike asked for. See `verdict.json` for the numbers. Verdict: keep SQLite WAL FULL as the default,
with four new startup assertions for monban-state (journal-mode re-check after first write, atomic create,
bootstrap directory fsync, fsync errors fatal). The journal-mode fallback is a new finding with no counterpart in
the research.
