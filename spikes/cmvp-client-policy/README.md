# cmvp-client-policy: the `fips_client_policy` gate (P-PQ6, RUSTSEC-2026-0349 ledger)

**Verdict: keep.** Both P-PQ6 modes can be checked mechanically. The prototype gate gives the expected verdict in
12 of 12 self-test cases (5 binaries and 7 mutants). The 0349 exception stays valid as long as the gate passes on
the cmvp artifact.
- **Recommended cmvp mode: compiled-out.**
- **Fallback: pq-only.**

This was measured on the **floor** profile (rustls 0.23.46 + aws-lc-rs 1.18.2), not the cmvp lock. See Limits.

## Why rustls features alone cannot prove "no client"
rustls 0.23.46 has these features: `aws-lc-rs, aws_lc_rs, brotli, custom-provider, default, fips, logging,
prefer-post-quantum, read_buf, ring, std, tls12, zlib`. There is **no client/server split**, so every rustls build
contains the client code. "No reachable client" therefore has to come from three things:
- a first-party feature (`tls-client`) being off;
- the linked binary;
- a positive control, which proves the binary scan can actually see rustls code.

## Gate design (`fips_client_policy.py`)
PASS iff mode A or mode B holds. Exit codes: 0 PASS, 1 FAIL, 2 ERROR (cannot judge).

**Mode A, compiled-out.** All of these must hold:
| check | what | source |
|---|---|---|
| M1 | `tls-client` is off in the cmvp feature set | `cargo metadata` resolve features (in the workspace: `monban-tls` features via `cargo tree -e features`) |
| B0 | positive control: rustls::server symbols are present. If not, ERROR: the scan is blind (stripped or wrong artifact) | `nm -C` |
| B1 | 0 `rustls::client::` symbols | `nm -C --defined-only` on the unstripped twin |
| B2 | 0 `6rustls6client` sections (matches legacy and v0 mangling) | linker map of the **shipped** link (`-C link-arg=-Wl,-Map=…`) |

**Mode B, pq-only.** All of these must hold:
| check | what |
|---|---|
| S1 | clippy is clean with `disallowed-methods` = `rustls::ClientConfig::{builder, builder_with_provider, builder_with_protocol_versions}` and `rustls::client::Resumption::{in_memory_sessions, store}`, plus `disallowed-types` = `ClientSessionMemoryCache` (`tlsbins/clippy.toml`). The rustls paths are re-exports, and clippy 1.99.1 resolves them. |
| S2 | first-party source contains exactly one `#[expect/allow(clippy::disallowed_*)]`, and it sits on `pq_only_client_config` |
| M2 | no third-party crate in the resolved graph has source that builds a `ClientConfig` (`ClientConfig::builder`, `with_platform_verifier(`, `ClientConfig {`), unless it is allowlisted as taking an injected config. The scan flags hyper-rustls, reqwest, tonic and rustls-platform-verifier. It does not flag tokio-rustls, hyper-util or opentelemetry-http (`results/m2-registry-scan.txt`). |
| P1 | a probe runs per blessed constructor, doing two in-memory handshakes against a server that supports X25519 first and issues tickets. Required: `kx_groups == [secp256r1MLKEM768]`; resumption is `NoClientSessionStorage` + `Tls12Resumption::Disabled`; both ClientHellos have supported_groups = key_share = `[0x11EB]`; the 2nd hello has no `pre_shared_key` or `early_data` and the same key_share as the 1st; the negotiated group is SECP256R1MLKEM768. |

**Type-level rule.** Every first-party dial-out API takes the opaque `PqClientConfig`.
- Its only constructor is `pqclient::pq_only_client_config()`.
- That constructor sets TLS 1.3 only, `kx=[SECP256R1MLKEM768]`, `Resumption::disabled()` and no early data.
- It runs `assert_pq_only` as the startup assertion.
- `assert_pq_only` checks the provider groups and the Debug form of `Resumption`.

## Results
`results/selftest.txt`:
```
srv_only                     expect PASS  compiled-out  got PASS  compiled-out  ok
pq_client                    expect PASS  pq-only       got PASS  pq-only       ok
bad_client                   expect FAIL                got FAIL                ok
bad_resume                   expect FAIL                got FAIL                ok
dead_client                  expect FAIL                got FAIL                ok
mut_srv_feature_on           expect FAIL                got FAIL                ok
mut_srv_stripped             expect ERROR               got ERROR               ok
mut_srv_client_bin           expect FAIL                got FAIL                ok
mut_pq_no_probe              expect FAIL                got FAIL                ok
mut_pq_bad_probe             expect FAIL                got FAIL                ok
mut_pq_clippy_dirty          expect FAIL                got FAIL                ok
mut_pq_second_suppression    expect FAIL                got FAIL                ok
self-test mismatches: 0
```
Binary evidence from `results/binary-scan.txt`:

| binary | nm client symbols | nm server symbols | map client refs |
|---|---|---|---|
| srv_only | 0 | 98 | 0 |
| dead_client | 0 | 98 | 0 |
| pq_client | 151 | 95 | 175 |
| bad_client | 143 | 95 | 167 |
| bad_resume | 143 | 95 | 167 |

Probe results (`results/probe-*.json`):
- **bad_client** (rustls default client): hello 1 shares `[0x11EC, 0x001D]` and negotiates X25519. Hello 2 still
  lists `0x11EC` first in supported_groups but shares **only `0x001D`** and adds `pre_shared_key`. This is the
  exact ClientHello shape of RUSTSEC-2026-0349. Here it comes from an authenticated server choosing X25519; under
  the 0349 bug an unauthenticated ServerHello can cause the same thing.
- **bad_resume** (PQ-only groups, default store): resumes (sends a PSK). It fails "no key-share-prediction
  store".
- **pq_client**: both hellos `[0x11EB]/[0x11EB]`, full handshakes, no PSK.

## Findings that shape the gate
1. **The unstripped twin is not byte-identical to the shipped binary.** Changing `strip` changes crate hashes and
   layout (.text sha256 differs). The linker maps list the same symbol set once crate-hash and back-reference
   encodings are normalised. So B2 reads the map **of the shipped link**, and B1 on the twin is a second,
   demangled view. Do not claim the twin is the shipped artifact.
2. **"No store" cannot be decided from symbols.** pq_client still links `ClientSessionMemoryCache` drop glue,
   because `ClientConfig::builder` installs the default store before it is replaced. Only P1 (probe) and the
   startup assertion decide it.
3. **LTO removes unreachable client code** (dead_client: 0 client symbols). The gate still fails that binary on
   M1 (feature on) and S1 (clippy), so it never depends on what the optimiser happens to keep or drop.
4. **cargo metadata over-reports weak `dep?/feat` deps** (see `../otlp-footprint`). M2 therefore takes the
   package set from `cargo tree` (the real resolver) and only the source directories from metadata.

## Reproduce
```
cd /home/patrickd/aegis/spikes/cmvp-client-policy
python3 -I lockage.py tlsbins/Cargo.lock --today 2026-10-25      # 35 packages, 0 violations
HEAVY_TIMEOUT=3600 ../../ci/heavy.sh ./build.sh > out-build.log 2>&1
./selftest.sh                                                    # self-test mismatches: 0
rm -rf target out
```
`build.sh` builds the 5 binaries unstripped with linker maps, builds srv_only and pq_client again with
strip=symbols (+ map), and runs clippy on each binary. `selftest.sh` is light: it runs the probes, the gate and
the mutants.

## Limits
- **Floor profile, not cmvp.** aws-lc-fips-sys 0.13.11 (Go/CMake, AL2023 OE) was not built. The APIs the gate uses
  are confirmed in the rustls 0.23.40 sources; 0.23.43 is not cached locally. The gate must be re-run on the real
  cmvp artifact.
  - In rustls 0.23.40, and so presumably 0.23.43, the kx hint is recorded while processing the ServerHello, before
    the server is authenticated: that is the 0349 bug.
  - pq-only is still safe there, for two reasons: a single-group client has nothing to downgrade to, and
    `NoClientSessionStorage` stores nothing. The advisory itself says clients with resumption disabled are not
    affected.
- **Symbol and map absence means "not linked"**, which over-approximates reachability; that is the safe
  direction. The client handshake runs through vtable-dispatched `State` impls, which cannot be inlined away.
- **M2 is a source grep.** It flags crates whose code is never compiled in, and it misses construction done
  through macros. It is a backstop, not a proof.
- **The probe uses a well-behaved in-memory server**, not an active attacker.
- **S1 and S2 cover first-party code only.**
- **This prototype checks M1 on the root package.** The workspace version must check `monban-tls`'s features.
