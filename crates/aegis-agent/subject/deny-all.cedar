// Negative control for crates/aegis-agent/subject/mcp-gate.sh self-test: nothing is permitted, so the corpus
// baselines must fail (the oracle observes the PDP decision through the shipped binary).
forbid (principal, action, resource);
