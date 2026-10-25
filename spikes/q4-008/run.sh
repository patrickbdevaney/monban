#!/usr/bin/env bash
# q4-008 reproduction. DL = download dir (outside the repo; untrusted data). Results land in spikes/q4-008/results/.
# Downloads (sha256 recorded in README): NASA Jul/Aug95 from ita.ee.lbl.gov/traces/, SecRepo self.logs
# access.log.YYYY-MM-DD.gz from www.secrepo.com/self.logs/, Common Crawl CC-MAIN-2026-43 cluster.idx.
set -euo pipefail
DL=${DL:?set DL to the download dir}
H=$(cd "$(dirname "$0")" && pwd); R=$H/results; mkdir -p "$R"
HEAVY=$H/../../ci/heavy.sh
# Common Crawl sample (network only; ~250 MB transferred, ~1M URLs kept as a temporary tsv.gz)
[ -s "$DL/cc/cc_urls.tsv.gz" ] || "$HEAVY" python3 -I -B "$H/cc_sample.py" "$DL/cc/cluster.idx" "$DL/cc/cc_urls.tsv.gz" \
  --crawl CC-MAIN-2026-43 --blocks 1000 --every 3 --seed 8
"$HEAVY" python3 -I -B "$H/analyze.py" --source nasa-1995 --format clf --no-apache-escapes \
  --out "$R/nasa-1995.json" "$DL"/nasa/NASA_access_log_Jul95.gz "$DL"/nasa/NASA_access_log_Aug95.gz
"$HEAVY" python3 -I -B "$H/analyze.py" --source secrepo-2024-2026 --format clf --static-site \
  --out "$R/secrepo-2024-2026.json" "$DL"/secrepo/access.log.202[456]-*.gz
"$HEAVY" python3 -I -B "$H/analyze.py" --source secrepo-2017-2023 --format clf --static-site \
  --out "$R/secrepo-2017-2023.json" "$DL"/secrepo/access.log.20{17,18,19,20,21,22,23}-*.gz
"$HEAVY" python3 -I -B "$H/analyze.py" --source cc-main-2026-43 --format cc --out "$R/cc-main-2026-43.json" \
  "$DL/cc/cc_urls.tsv.gz"
python3 -I -B "$H/summarize.py" "$R" > "$R/table.md"
