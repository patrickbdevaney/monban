"""Reference subject speaking the admission event protocol on stdin/stdout (see README.md).

    python3 -I -B oracles/admission-props/ref_subject.py [--mutate <mutation>]

Reads JSON lines: {"type":"config",...} resets all state; "arrive" lines produce exactly one decision line each;
"done" and "close" lines produce no output. Used to exercise the --subject plumbing until the Rust crates exist.
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_sp = importlib.util.spec_from_file_location("monban_admission_ref", os.path.join(HERE, "admission_ref.py"))
R = importlib.util.module_from_spec(_sp)
_sp.loader.exec_module(R)


def main():
    mut = None
    if len(sys.argv) == 3 and sys.argv[1] == "--mutate":
        mut = sys.argv[2]
    elif len(sys.argv) != 1:
        sys.stderr.write("usage: ref_subject.py [--mutate <mutation>]\n")
        return 2
    p = None
    w = sys.stdout.write
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        ev = json.loads(line)
        ty = ev["type"]
        if ty == "config":
            p = R.Pipeline(ev, mut)
        elif ty == "arrive":
            w(json.dumps(p.arrive(ev), separators=(",", ":")) + "\n")
        elif ty == "done":
            p.done(ev)
        elif ty == "close":
            p.close(ev)
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
