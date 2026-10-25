"""q4-008: of the CC paths with percent-encoded non-ASCII octets, how many decode to invalid UTF-8 / non-NFC text.
usage: python3 -I -B utf8_check.py CC_URLS_TSV_GZ"""
import gzip
import re
import sys
import unicodedata

tot = enc = bad = nfc = 0
for ln in gzip.open(sys.argv[1], "rt", encoding="utf-8"):
    url = ln.rstrip("\n").split("\t", 1)[1]
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#]*([^?#]*)", url)
    p = m.group(1) if m else ""
    tot += 1
    if not re.search(r"%[89A-Fa-f][0-9A-Fa-f]", p):
        continue
    enc += 1
    raw = re.sub(r"%([0-9A-Fa-f]{2})", lambda mm: chr(int(mm.group(1), 16)), p).encode("latin-1", "replace")
    try:
        s = raw.decode("utf-8")                          # strict: rejects overlong forms and surrogates
        if unicodedata.normalize("NFC", s) != s:
            nfc += 1
    except UnicodeDecodeError:
        bad += 1
print("paths=%d with_pct_nonascii=%d invalid_utf8=%d valid_not_nfc=%d" % (tot, enc, bad, nfc))
