# P6-oracle-fips-002 report (spec author, 2026-11-04, base 93e3022)

Follow-up to P6-oracle-fips-001. It fixes P6-cmvp-002 open items 5 and 6. Only files in `oracles/cmvp-binary/**` and
this report were written. `profiles/cmvp/build.sh` and `gates/` are unchanged.

## 1. Relative `--binary` (F4 red)

**Cause.** `fips_binary.py` ran `<binary> --fips-check` with cwd `/`. It did so without resolving `--binary` first.

**Fix.** Both entry points now resolve every path argument to an absolute path when they parse it.
- `run`: `--binary`, `--metadata`.
- `client-policy`: `--binary`, `--manifest`, `--target-dir`, `--work`, `--map`, `--twin`, `--clippy-log`,
  `--probe`, `--src`, `--mtls-justification`.

## 2. R0 ERROR on the real tree

**Measured on kamrui.** I compared `cargo build -v` (build.sh's flags) with `cargo rustc -v` (the oracle's relink)
inside the AL2023 image, on the rustc line of the aegis bin. The only differences:

```
+ --cfg 'feature="default"'
- -C metadata=62d2707210deaffc      + -C metadata=467c67da420f17cb
+ -C link-arg=-Wl,-Map=/out/diag.map   (intended)
```

The relink lacked `--no-default-features`. aegis-bin's `default = []`, so no code changes. But cargo still passes
`feature="default"`, and that changes `-C metadata`, then the symbol hashes, then `.text` and `.rodata`. Nothing
else differed: RUSTFLAGS, remap-path-prefix, the profile flags, the target dir and the env were all the same.

**Fix (the preferred route).** The docker relink now uses `DOCKER_CARGO_FLAGS = --locked --release
--no-default-features`, which are build.sh's compile-relevant flags. The `cargo tree` graph view gets
`--no-default-features` on the real run too. R0 is unchanged and still a real sha256 check.

**Result.** The relink is byte-identical to the judged binary: `ba7e8c30...` on both sides. The twin's `.text` and
`.rodata` are identical to the shipped binary's.

**A second bug, found by the new relative-path self-test case.** The host relink (used by the fixtures) ran
`cargo rustc` from the caller's cwd. Cargo finds `.cargo/config.toml` from its cwd. That file holds the repo's
rustflags (`--remap-path-prefix=/home=/build`, `-Cforce-frame-pointers=yes`). So a caller outside the repo relinked
with other flags, and R0 was ERROR. On kamrui `target` is a symlink out of the repo, which is why it showed up. The
host relink now runs from the manifest dir, like docker's `-w /src`.

## New self-test cases

- **`run`:** the entry point with a relative `--binary` and `--metadata`, from another cwd. Total 21/21.
- **`client-policy`, entry point:** relative `--binary`, `--manifest`, `--target-dir`, `--work` and
  `--mtls-justification` from another cwd, with a host relink. R0 must hold and the line must be
  `CLIENT-POLICY: PASS (compiled-out)`.
- **`client-policy`, flag drift:** build.sh's `flags=(...)` line is parsed. Every compile-relevant flag must be in
  `DOCKER_CARGO_FLAGS`. The mutant (the list without `--no-default-features`) must be reported. Total 34/34.

**Red, with the path resolution reverted (kamrui):**
- `CMVP-BINARY SELF-TEST: FAIL (1/21 mismatches)`: the relative case failed at F4.
- `CLIENT-POLICY SELF-TEST: FAIL (1/34 mismatches)`: the relative case was ERROR, because the relink's manifest path
  did not exist.

**Red, before the cwd fix:** `CLIENT-POLICY SELF-TEST: FAIL (1/34 mismatches)`. The relative case was R0 ERROR
(`115785f6... != 7454a5c0...`).

**Green (kamrui):**
- `CMVP-BINARY SELF-TEST: PASS (21/21: 2 baselines PASS (cmvp fixture on the real cmvp graph, floor negative control), 18 mutants caught with the expected check id, entry point with relative paths)`
- `CLIENT-POLICY SELF-TEST: PASS (34/34: spike's 12 ported (5 binaries + 7 mutants), cross-mode, map/twin/R0 mutants, D13 mTLS mutants, entry point with relative paths, relink flags vs build.sh, real cmvp graph M1 + D13 source baseline)`

## Acceptance (kamrui)

The command:

```
ci/remote.sh --host kamrui bash -c 'profiles/cmvp/build.sh && oracles/cmvp-binary/run --binary target/cmvp/release/aegis && oracles/cmvp-binary/client-policy --mode compiled-out --binary target/cmvp/release/aegis'
```

The output:

```
CMVP-BINARY: PASS (module "AWS-LC FIPS 3.1.0" contiguous, sole identity, one fips-sys node, --fips-check matches)
R0 relink: {... 'R0_identical': True, 'judged_restored': True, 'twin_sections_identical': {'.text': True, '.rodata': True}}
twin/nm (twin (twin)): 6092 symbols, server 100, client 0 []
map: client refs 0, server refs 82
CLIENT-POLICY: PASS (compiled-out)
```

Exit 0.

**The gates.** The `fips-binary` and `cmvp-client-policy` commands in `gates/phase-6.toml` are exactly the two halves
of this command, run from the repo root. They work as written, and no gate change is needed.

## Open

- The docker relink still copies build.sh's mounts and env by hand. The cargo flags now have a drift check; the
  mounts and env do not. If they drift, R0 fails closed (ERROR), so no false PASS can result.
