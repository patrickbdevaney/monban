#!/usr/bin/env bash
# Install elan (isolated) and build the Cedar Lean theorem closure at cedar-spec v4.14.0. Run on kamrui.
set -euxo pipefail
CI=$HOME/aegis-ci
export ELAN_HOME=$CI/elan PATH=$CI/elan/bin:$PATH
if [ ! -x $CI/elan/bin/elan ]; then
  curl -sSfL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -o $CI/dl/elan-init.sh
  sh $CI/dl/elan-init.sh -y --no-modify-path --default-toolchain none
fi
cd $CI/src/cedar-spec/cedar-lean
git rev-parse HEAD
elan toolchain install $(cat lean-toolchain)
lean --version
lake env true   # fetches batteries per the committed manifest (no update)
git status --short
MEM=8G TMO=14400 $CI/bin/heavy lake build Cedar.Thm Cedar.Thm.Verification Cedar.Thm.SymbolicCompilation
