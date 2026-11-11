# kx-interop: PQ key-exchange interop matrix (PLAN-6 D4, PREFLIGHT D-P4)

Runs real TLS 1.3 handshakes between the Monban subject and three independent TLS stacks, over loopback TCP on
kamrui, and checks the negotiated group, HelloRetryRequest, handshake completion and an application-data echo.

```
oracles/kx-interop/run [--subject "CMD ARGS"] [--only REGEX]   # default subject: target/release/tls-subject
oracles/kx-interop/run --self-test
```

Last line `KX-INTEROP: PASS (...)` / `KX-INTEROP: FAIL (...)`; exit 0 only on PASS. Gate `kx-interop`
(`gates/phase-6.toml`, `remote = "kamrui"`). `needs` = `kamrui`: launched on another host (for example by
`ci/oracles.sh run --where local` on the laptop), `run` re-runs itself through `ci/remote.sh --host kamrui` and refuses
(FAIL) when it can't reach kamrui or when a host-local `--subject` was given.

## What is checked

Spec: section F P-PQ2 (configured group set = profile), F12 profile rows for P-UNIVERSAL `[0x11ED]`,
P-BSI-ALT `[0x11ED, 0x11EB]`, P-CNSA `[0x0202]`, P-PUBLIC-WEB `[0x11EC, ...]`. RFC 10024 (0x11ED/0x11EB wire format and
combiner order; an order error shows up as a Finished/record MAC failure against an independent peer).

Peers (all on kamrui):

| peer | version | how |
|---|---|---|
| OpenSSL | 3.5.3 (`/usr/bin/openssl`, checked by `run`) | `s_client` / `s_server` |
| Go crypto/tls | go1.27.3 (`~/aegis-ci/go1.27.3`, `GOTOOLCHAIN=local`, `GOPROXY=off`, stdlib only) | `go/main.go` (`gopeer`) |
| BoringSSL | commit `e651545da6e2` (2026-10-26, pinned 2026-11-04 in `bssl/LOCK` with tarball sha256) | `bssl client` / `bssl server` in image `monban-bssl:e651545da6e2` (267 MB) |

BoringSSL is built by `bssl/build.sh` in a throwaway `amazonlinux:2023` container pinned by digest (cmake,
gcc-c++, libstdc++-static from dnf; static `bssl`), then copied into a runtime image of the same base
(`bssl/Containerfile`). `deploy/build/al2023.Containerfile` doesn't exist yet, so this is the inline
equivalent. `ci/tools.lock` has no BoringSSL row, so `bssl/LOCK` is the pin for now. `build.sh` refuses a commit less
than 7 days old and reuses the image while the tag exists.

Matrix (`matrix.toml`, 20 cells). "srv" means the subject is the server and the peer is the client; "cli" is the
reverse.

| group / profile | OpenSSL | Go | BoringSSL |
|---|---|---|---|
| 0x11ED / P-UNIVERSAL | srv, cli, srv+HRR (client offers X25519 share first) | srv, cli, srv+HRR (Go shares 0x11EC first) | (none: BoringSSL has no 0x11ED, D-P4) |
| X25519-only peer vs P-UNIVERSAL | must be refused | must be refused | |
| 0x11EB / P-BSI-ALT | srv, cli+HRR (subject shares 0x11ED, server HRRs to 0x11EB) | srv, cli+HRR | (none: no 0x11EB) |
| 0x0202 / P-CNSA | srv, cli | srv, cli | srv, cli |
| 0x11EC / P-PUBLIC-WEB | | | srv, cli |

A 0x11ED HRR in the client direction can't happen: both profiles that contain 0x11ED list it first, so the subject
client always sends a 0x11ED share.

Per cell, all of these must hold:

- **Wire**: the oracle bridges the subject's stdio to the TCP socket and parses every plaintext record in both
  directions. The ServerHello `key_share` group must be the target and `supported_versions` must be 0x0304. HRR
  cells need three things: (a) the first ClientHello carries no share for the target, (b) the HelloRetryRequest
  (random = the RFC 8446 HRR constant) selects the target, and (c) the second ClientHello has a share for it.
  Non-HRR cells must have no HRR. There must be no plaintext alert.
- **Peer**: the peer reports a completed handshake. OpenSSL `s_client`, bssl and Go report the group, and it must
  equal the target. Go also reports HRR, and it must equal the cell's `hrr`.
- **Application data**: the oracle makes up a random nonce per cell.
  - Subject is the server: the peer client sends the nonce, and the peer itself must receive it back. The subject
    has to echo.
  - Subject is the client: the subject sends the nonce. It must show up at the peer: in the `s_server`/bssl
    output, or in Go's echoed byte count. The oracle (OpenSSL/bssl) or Go echoes it back, and the subject must
    report the echo and exit 0.

  So decryption is checked by the independent side, not only by the subject's own report.
- **Subject**: exit 0, and its `interop: handshake ok group=0x....` line names the target group.
- **Refusal cells**: no ServerHello on the wire, no completed handshake at the peer, and no application data.

Before running anything, the matrix is validated against a **capability probe of each peer**, not against a table:
`openssl list -tls-groups -tls1_3`, `gopeer probe` (in-memory Go handshake per group), and `bssl client -curves <name>`
for each name. A cell claiming a peer x group that the probe says is absent (for example BoringSSL x 0x11ED) gets the
whole matrix refused. So does a matrix that lacks any cell of the required coverage (`REQUIRED`, `REQUIRED_REFUSE` in
`oracle.py`), which means the matrix can't be thinned.

Peer server credential: an ECDSA P-384 leaf for `monban.test` under a fresh ECDSA P-384 test CA, generated with
`openssl` per run and deleted afterwards. The subject client gets the CA file.

## Subject contract (what P6-tls-001 must add to tls-subject)

`--subject "CMD ARGS"` is split on whitespace. The oracle appends one of the following. Both modes speak raw TLS
records on stdin/stdout, as the existing `serve` does, and need no networking.

```
CMD ARGS interop-server <PROFILE>
    One TLS server connection on stdin/stdout, config from monban_tls::server_config(PROFILE, <credential>), with a
    credential valid for the profile's sigalgs (P-UNIVERSAL/P-BSI-ALT: ECDSA-P384 or ML-DSA-87; P-CNSA: ML-DSA-87;
    P-PUBLIC-WEB: ECDSA-P256).
    After the handshake: print to stderr exactly one line
        interop: handshake ok group=0x<hex4> version=0x<hex4> suite=0x<hex4>
    then echo every application-data byte back verbatim. On close_notify from the peer: send close_notify, flush,
    exit 0. On a TLS error: write any pending alert to stdout, print "interop: error <msg>" to stderr, exit 1.

CMD ARGS interop-client <PROFILE> <CA_PEM> <NONCE>
    One TLS client connection on stdin/stdout to server name "monban.test", config from
    monban_tls::client_config(PROFILE, roots), where roots = the certificates in CA_PEM (no other trust anchors, no
    verifier override). Write the ClientHello before reading anything.
    After the handshake: print the same "interop: handshake ok ..." line, send "<NONCE>\n" as application data,
    read until "<NONCE>\n" has come back, print "interop: echo=ok", send close_notify, flush, exit 0.
    TLS error or EOF before the echo: "interop: error <msg>" on stderr, exit 1.
```

An unknown mode must exit non-zero with a line containing `usage` on stderr. The oracle then reports
`subject has no interop-<role> mode` for that cell, and the cell is red (fail closed).

What P6-tls-001 needs beyond `subjects/tls-subject/src/**`:
- `interop-client` uses `monban_tls::client_config`. That function only exists with monban-tls feature `tls-client`,
  so `subjects/tls-subject/Cargo.toml` must enable it:
  `monban-tls = { workspace = true, features = ["tls-client"] }`. That file is outside P6-tls-001's `write_scope`
  (`subjects/tls-subject/src/**`), so the integrator (or a write_scope change) has to make this edit.
- P-UNIVERSAL, P-BSI-ALT and P-CNSA must be Active (today `server_config`/`client_config` refuse them as Pending).

The reference subject `ref-subject/` (`kx-ref`, used only by `--self-test`) implements this contract exactly and is
the worked example.

## Self-test (`--self-test`)

The reference subject is plain rustls 0.23.46 + aws-lc-rs 1.18.2 + a copy of the spike q4-026 0x11ED group
(`ref-subject/src/kx.rs`). It is built with its own lock (= `oracles/hrr-verdicts/Cargo.lock`, root renamed) through
`ci/heavy.sh`.

| step | mutation | must happen |
|---|---|---|
| M0 baseline | none | shipped matrix accepted; **every** cell green (otherwise the self-test fails) |
| M1 `order` | 0x11ED combiner ML-KEM secret first (`kx::ORDER_MUTANT`, both roles) | every 0x11ED cell red, every other cell still green |
| M2 `x25519-fallback` | P-UNIVERSAL accepts `[0x11ED, X25519]` | both X25519-only refusal cells red |
| M3 `no-echo` | server never echoes; client never sends the nonce but still prints `echo=ok` and exits 0 | every completing cell red (proves the subject's self-report isn't trusted) |
| M4 `hrr-precondition` | subject-server HRR cells: the peer client offers the target first; subject-client HRR cells: reference mutant `bsi-11eb-first` (P-BSI-ALT `[0x11EB, 0x11ED]`, so the 0x11EB share goes first and the group still matches) | every HRR cell red |
| M5 `matrix-bssl-11ed` | matrix plus a BoringSSL x 0x11ED cell | matrix refused (probe: bssl lacks 0x11ED) |
| M6 `matrix-missing-cell` | Go 0x11ED HRR cell removed | matrix refused |
| M7 `matrix-missing-refusal` | X25519-only refusal cells removed | matrix refused |

The unit's order mutant is "the monban-tls `order-mutant` feature" (PLAN-6 D4). That feature doesn't exist yet: it is
defined by P6-spec-002 in `crates/monban-tls/Cargo.toml`, and the KAT half is gated as kx-kat by P6-tls-001. Until it
exists, M1 runs the same mutation (ECDHE/ML-KEM order swapped in the combiner) on the reference subject. Once the
feature is there, `run --subject "<target-dir>/release/tls-subject"` with a binary built with
`--features monban-tls/order-mutant` must turn every 0x11ED cell red. That run is the same check against the
production code.

## Provenance

- `spikes/q4-026/interop/` (in-repo, 2026-10-25): OpenSSL 3.5.9 and Go 1.26.10 transcripts for 0x11ED, HRR and the
  order mutant. The Go peer and the cell shapes start from there. Nothing from it is executed. The spike's
  `src/kx.rs` is copied into `ref-subject/src/kx.rs`, with the `ORDER_MUTANT` switch added and the KAT constructor
  removed.
- BoringSSL capability (PREFLIGHT P2): `ssl/ssl_key_share.cc` at the pinned commit lists X25519MLKEM768 and
  MLKEM1024 as its only PQ groups. The runtime probe confirms this on every run.

## Results in this repo

2026-11-04, kamrui, through `ci/remote.sh --host kamrui`:
- `run` against the current tls-subject (35125f0): `KX-INTEROP: FAIL (20/20 cells failed: ...)`. Every cell reports
  `subject has no interop-server|interop-client mode`. This is the expected red until P6-tls-001.
- `run --self-test`: `KX-INTEROP SELF-TEST: PASS (baseline 20/20 green; order 6/6 0x11ED cells red, 12 other cells
  green; x25519-fallback 2/2 refusal cells red; no-echo 18/18 cells red; hrr-precondition 4/4 HRR cells red;
  matrix-bssl-11ed refused; matrix-missing-cell refused; matrix-missing-refusal refused)`.
- Peer probe: openssl = 0x0017,0x0018,0x001d,0x0202,0x11eb,0x11ec,0x11ed; go = the same plus 0x0019;
  bssl = 0x0017,0x0018,0x001d,0x0202,0x11ec.
- Order mutant failure modes, as in the spike: OpenSSL client sends alert 20 (bad_record_mac); Go, and the
  subject as client, report "cannot decrypt peer's message".

## Known limits

- The wire observer reads only plaintext records: the ServerHello and HelloRetryRequest group and the ClientHello
  groups/shares. Everything after ServerHello is encrypted, and completion is judged by the peers.
- OpenSSL `s_server` does not print the negotiated group. For those cells the group comes from the wire and the
  subject (both must agree).
- Peer servers present ECDSA P-384 certificates in every cell, including P-CNSA client cells. The subject client's
  signature policy is not what this oracle checks (that is hrr-verdicts / P-PQ2).
- Loopback only; no timing claims. Each cell has a 25 s cap and an 8 s echo wait.
- s_client treats input lines starting with `Q`, `R`, `k` or `K` as commands, which is why it runs with
  `-nocommands`. The first nonce prefix (`kxi-`) triggered a KeyUpdate and looked like a missing echo.
- Disk on kamrui after a self-test: `target/` = 178 MB (Go cache 72 MB, gopeer 7.6 MB, reference build 99 MB).
  Delete it after measuring. The BoringSSL image is outside the tree (docker, 267 MB).
