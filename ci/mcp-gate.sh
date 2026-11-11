#!/usr/bin/env bash
# Gate mcp-gateway: the MCP corpus against the shipped monban binary (subject wiring owned by P3-agent-001).
#   ci/mcp-gate.sh run [--flood-n N] | self-test
exec "$(cd "$(dirname "$0")/.." && pwd)/crates/monban-agent/subject/mcp-gate.sh" "$@"
