#!/usr/bin/env bash
# Assert that none of the named crates is in a package's resolved build graph (normal + build edges, proc-macros
# included, every target platform). Gate no-pg-query-in-bin (ARCHITECTURE §3.8: normalizers that link C such as
# pg_query run at build time of tooling or out of process, never inside aegis-bin).
#   ci/no-crate.sh <package> <crate>...    PASS iff no listed crate appears in `cargo tree -p <package>`
#   ci/no-crate.sh --self-test             the filter must go red on ci/fixtures/tree-pg_query.txt and stay green on
#                                          the same fixture with the pg_query lines removed
# Light (no compile): reads Cargo.lock offline.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# filter <crate>... < tree  -> prints offending "name version" lines; exit 1 iff any found.
filter() {
  awk -v names="$*" '
    BEGIN { n = split(names, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
    { sub(/^[ │├└─`|\\-]+/, ""); if ($1 in want) { print $1 " " $2; bad = 1 } }
    END { exit bad ? 1 : 0 }' | sort -u
}

if [ "${1:-}" = --self-test ]; then
  fx="$ROOT/ci/fixtures/tree-pg_query.txt"
  [ -s "$fx" ] || { echo "NO-CRATE SELF-TEST: FAIL (missing fixture $fx)"; exit 1; }
  if hits=$(filter pg_query libpg_query pg_query_sys < "$fx"); then
    echo "NO-CRATE SELF-TEST: FAIL (fixture containing pg_query was not rejected)"; exit 1
  fi
  if ! grep -v -E '(^|[ │├└─`|\\-])(pg_query|libpg_query|pg_query_sys) ' "$fx" | filter pg_query libpg_query pg_query_sys >/dev/null; then
    echo "NO-CRATE SELF-TEST: FAIL (clean control was rejected)"; exit 1
  fi
  echo "NO-CRATE SELF-TEST: PASS (mutated tree rejected: $(echo "$hits" | tr '\n' ';' | sed 's/;$//'); clean control accepted)"
  exit 0
fi

[ $# -ge 2 ] || { echo "usage: ci/no-crate.sh <package> <crate>... | --self-test" >&2; exit 2; }
pkg=$1; shift
tree=$(cd "$ROOT" && cargo tree --locked --offline -e normal,build --target all -p "$pkg" --prefix none --no-dedupe)
[ -n "$tree" ] || { echo "NO-CRATE: FAIL (empty cargo tree for $pkg)"; exit 1; }
if hits=$(printf '%s\n' "$tree" | filter "$@"); then
  echo "NO-CRATE: PASS ($pkg: $(printf '%s\n' "$tree" | awk '{print $1" "$2}' | sort -u | wc -l) graph nodes, none of: $*)"
else
  echo "NO-CRATE: FAIL ($pkg graph contains: $(echo "$hits" | tr '\n' ';' | sed 's/;$//'))"; exit 1
fi
