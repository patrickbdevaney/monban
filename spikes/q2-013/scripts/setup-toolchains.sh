#!/usr/bin/env bash
# Installs Rust (rustup, isolated), Verus release, CBMC 6.11.0 (extracted .deb, no dpkg install) and Kani from a
# main commit >= PR #4910 into ~/aegis-ci only. No sudo. Run on kamrui.
set -euxo pipefail
CI=$HOME/aegis-ci
export RUSTUP_HOME=$CI/rustup CARGO_HOME=$CI/cargo PATH=$CI/cargo/bin:$CI/cbmc/usr/bin:$PATH
KANI_SHA=9461e07af7ec929f050aa4192f29363c9be07779   # main 2026-10-14, after #4910 merge 16c774cf (2026-09-30)
VERUS_TAG=release/0.2026.10.18.7d82994
VERUS_ZIP=verus-0.2026.10.18.7d82994-x86-linux.zip
mkdir -p $CI/dl $CI/src
# 1 rustup (no PATH edits)
if [ ! -x $CI/cargo/bin/rustup ]; then
  curl -sSf https://sh.rustup.rs -o $CI/dl/rustup-init.sh
  sh $CI/dl/rustup-init.sh -y --no-modify-path --profile minimal --default-toolchain none
fi
# 2 Verus
if [ ! -d $CI/verus ]; then
  curl -sSL -o $CI/dl/$VERUS_ZIP https://github.com/verus-lang/verus/releases/download/$VERUS_TAG/$VERUS_ZIP
  sha256sum $CI/dl/$VERUS_ZIP | tee $CI/dl/$VERUS_ZIP.sha256
  mkdir -p $CI/verus && (cd $CI/verus && unzip -q $CI/dl/$VERUS_ZIP)
fi
# 3 CBMC 6.11.0
if [ ! -d $CI/cbmc ]; then
  curl -sSL -o $CI/dl/cbmc.deb https://github.com/diffblue/cbmc/releases/download/cbmc-6.11.0/ubuntu-24.04-cbmc-6.11.0-Linux.deb
  sha256sum $CI/dl/cbmc.deb | tee $CI/dl/cbmc.deb.sha256
  mkdir -p $CI/cbmc && dpkg-deb -x $CI/dl/cbmc.deb $CI/cbmc
fi
cbmc --version
# 4 Kani source at pinned main commit
if [ ! -d $CI/src/kani ]; then
  git clone -q https://github.com/model-checking/kani.git $CI/src/kani
fi
cd $CI/src/kani && git checkout -q $KANI_SHA && git submodule update --init --depth 1
git log -1 --format='%H %cI %s'
git merge-base --is-ancestor 16c774cf47ec80f01a7681091aa89162040c1204 HEAD && echo "PR4910 merge commit IS ancestor"
