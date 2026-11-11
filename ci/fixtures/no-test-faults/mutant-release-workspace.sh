#!/usr/bin/env bash
# FIXTURE (ci/no-test-faults.py --self-test, T4): a release script that unifies features across the workspace.
cargo build --release --locked --workspace
cargo build --release --locked -p monban-bin -p acme-subject
