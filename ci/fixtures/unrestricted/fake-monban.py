"""Stand-in for `monban check-config <path> --print-effective`, used only by ci/unrestricted.py --self-test.

Prints the file as canonical JSON (its "effective form"). Exits 78 if the document carries "_reject" (a config that
cannot boot), and prints nothing for "_hide" members (an effective form that drops part of the source).
"""
import json
import sys


def strip(v):
    if isinstance(v, dict):
        return {k: strip(x) for k, x in v.items() if k != "_hide"}
    if isinstance(v, list):
        return [strip(x) for x in v]
    return v


def main():
    if len(sys.argv) != 4 or sys.argv[1] != "check-config" or sys.argv[3] != "--print-effective":
        sys.stderr.write("fake-monban: usage: check-config <path> --print-effective\n")
        return 64
    with open(sys.argv[2], "rb") as f:
        doc = json.loads(f.read())
    if "_reject" in doc:
        sys.stderr.write("fake-monban: rejected\n")
        return 78
    print(json.dumps(strip(doc), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
