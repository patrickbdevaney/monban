#!/usr/bin/env python3
"""Claude Code PreToolUse hook: implementer agents may not write the verify wall or hub files
(IMPLEMENTATION_PLAN §1, §6.1). Writers in the spec-author or integrator role export AEGIS_ROLE accordingly.

Blocks Edit/Write/NotebookEdit on protected paths, and Bash commands that visibly write to them (redirection,
tee, sed -i, mv/cp/rm targets). The Bash check is best-effort; the binding guards are CODEOWNERS plus the hash gates
(ci/interfaces.py, ci/statements.py), which fail any change that slips past this hook.
Output follows the hook contract: JSON decision on stdout, exit 0 (never exit 2, which fails open in some versions).
"""
import json, os, re, sys

PROTECTED = ("spec/", "oracles/", "sdk/", "ci/", "gates/", "interfaces/", "tls/verdicts.toml", "Cargo.lock",
             "Cargo.toml", ".github/", "supply-chain/", "deny.toml", "rust-toolchain.toml", "crates/aegis-types/",
             "CODEOWNERS", ".claude/", "CLAUDE.md")
ROLE = os.environ.get("AEGIS_ROLE", "implementer")


def rel(p):
    root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    try:
        return os.path.relpath(os.path.abspath(p), root)
    except ValueError:
        return p


def protected(p):
    r = rel(p)
    return not r.startswith("..") and any(r == x.rstrip("/") or r.startswith(x) for x in PROTECTED)


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))
    sys.exit(0)


def main():
    if ROLE in ("spec-author", "integrator"):
        return
    ev = json.load(sys.stdin)
    tool, inp = ev.get("tool_name", ""), ev.get("tool_input", {}) or {}
    if tool in ("Edit", "Write", "NotebookEdit", "MultiEdit"):
        p = inp.get("file_path") or inp.get("notebook_path") or ""
        if p and protected(p):
            deny(f"{rel(p)} is outside the implementer write scope (spec/oracles/sdk/ci/hub files). "
                 "If the unit cannot be done without changing it, write INFEASIBLE_REPORT.md instead.")
    elif tool == "Bash":
        cmd = inp.get("command", "")
        targets = re.findall(r"(?:>>?|\btee(?:\s+-a)?|\bsed\s+-i\S*(?:\s+'[^']*'|\s+\"[^\"]*\"|\s+\S+)*?|\b(?:mv|cp|rm|truncate|install)\b[^;&|]*?)\s+([^\s;&|<>]+)", cmd)
        for t in targets:
            if protected(t.strip("'\"")):
                deny(f"command writes {t}, which is outside the implementer write scope")


if __name__ == "__main__":
    main()
