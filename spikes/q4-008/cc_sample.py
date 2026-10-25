"""q4-008: sample request targets from the Common Crawl CDXJ URL index (stdlib only; run with python3 -I).

usage: python3 -I cc_sample.py CLUSTER_IDX OUT_TSV_GZ [--crawl CC-MAIN-2026-43] [--blocks 1000] [--every 3] [--seed 8]

The index is a set of cdx-NNNNN.gz files made of independent gzip members (one per ~3000-line block); cluster.idx
gives (file, offset, length) per block. We pick --blocks blocks uniformly at random (fixed seed), range-fetch each
member, keep every --every-th line, and write "status<TAB>url" lines. Nothing else is stored.
"""
import gzip
import json
import random
import sys
import time
import urllib.request
import zlib

BASE = "https://data.commoncrawl.org/cc-index/collections/%s/indexes/%s"


def main(argv):
    args = {"--crawl": "CC-MAIN-2026-43", "--blocks": "1000", "--every": "3", "--seed": "8"}
    pos = []
    i = 0
    while i < len(argv):
        if argv[i] in args:
            args[argv[i]] = argv[i + 1]
            i += 2
        else:
            pos.append(argv[i])
            i += 1
    idx, out = pos
    blocks = []
    with open(idx, "rb") as f:
        for ln in f:
            parts = ln.rstrip(b"\n").split(b"\t")
            if len(parts) >= 4:
                blocks.append((parts[1].decode(), int(parts[2]), int(parts[3])))
    rng = random.Random(int(args["--seed"]))
    pick = sorted(rng.sample(range(len(blocks)), int(args["--blocks"])))
    every = int(args["--every"])
    n_lines = n_kept = 0
    t0 = time.time()
    with gzip.open(out, "wt", encoding="utf-8", newline="\n") as w:
        for k, bi in enumerate(pick):
            fn, off, ln = blocks[bi]
            req = urllib.request.Request(BASE % (args["--crawl"], fn),
                                         headers={"Range": "bytes=%d-%d" % (off, off + ln - 1),
                                                  "User-Agent": "aegis-q4-008-research/1.0"})
            data = None
            for attempt in range(4):
                try:
                    with urllib.request.urlopen(req, timeout=60) as r:
                        data = r.read()
                    break
                except Exception as e:                    # noqa: BLE001 (retry any network error)
                    sys.stderr.write("retry %s %s: %s\n" % (fn, off, e))
                    time.sleep(2 + 3 * attempt)
            if data is None:
                continue
            text = zlib.decompress(data, 16 + zlib.MAX_WBITS).decode("utf-8", "replace")
            for j, line in enumerate(text.splitlines()):
                n_lines += 1
                if j % every:
                    continue
                sp = line.find(" {")
                if sp < 0:
                    continue
                try:
                    rec = json.loads(line[sp + 1:])
                except ValueError:
                    continue
                url = rec.get("url", "")
                if "\t" in url or "\n" in url:
                    continue
                w.write("%s\t%s\n" % (rec.get("status", "-"), url))
                n_kept += 1
            if k % 50 == 0:
                sys.stderr.write("%d/%d blocks, kept %d, %.0fs\n" % (k, len(pick), n_kept, time.time() - t0))
    sys.stderr.write("done: blocks=%d index_lines=%d kept=%d of %d total blocks\n"
                     % (len(pick), n_lines, n_kept, len(blocks)))


if __name__ == "__main__":
    main(sys.argv[1:])
