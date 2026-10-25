#!/bin/sh
cd "$(dirname "$0")"
python3 crashsim.py $1 $2 300 400 $3 results.jsonl >/dev/null 2>>errs.log || echo "FAIL $1 $2 $3" >> errs.log
