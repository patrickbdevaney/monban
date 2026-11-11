# tlog-verify

An independent verifier for the monban audit log (unit P2-audit-001). It is written in Go against
`golang.org/x/mod/sumdb/note` and `golang.org/x/mod/sumdb/tlog` (v0.42.0, pinned in `src/go.mod` / `src/go.sum`),
so it shares no code with `crates/monban-audit`. That makes it the "independent verification" evidence for Audit I5.

## Usage

    oracles/tlog-verify/run --subject target/release/audit-subject   # last line: TLOG-VERIFY: PASS (...)
    oracles/tlog-verify/run --self-test [--subject <cmd>]            # last line: TLOG-VERIFY SELF-TEST: PASS (...)

Subject protocol: `<cmd> --out DIR` writes a c2sp.org/tlog-tiles directory:

- `checkpoint`
- `history/<size>`: every published checkpoint, a local extension used for the consistency checks
- `tile/<L>/<N>[.p/<W>]`
- `tile/entries/<N>[.p/<W>]`
- `vkey`: Ed25519 log key, as a signed-note vkey
- `vkey.mldsa87`: optional ML-DSA-87 cosigner key

The self-test also passes `--n --checkpoints --origin --key-seed --pq-seed --variant`.

Build: the verifier is built on first use, and again whenever `src/` changes. The build runs `go build` in
`golang:1.26-alpine@sha256:d1f3216e…` (Go 1.26.10, 241 MB) through `ci/heavy.sh` and puts the static binary in
`.build/`, which is gitignored. The Go module and build caches are deleted after each build. Only sources are
committed.

## What is checked

| Check | Spec |
|---|---|
| The checkpoint is a signed note that opens with the trusted Ed25519 key (`note.Open`). Signatures from unknown keys are ignored. A missing or bad log signature fails. | Audit I5; c2sp.org/signed-note@v1.1.0 |
| If an ML-DSA-87 key is trusted, every checkpoint carries a cosignature line with the matching key name and key ID, and the decoded length is 4+4627 bytes. | ARCHITECTURE §3.10 (gov cosignature) |
| Checkpoint text has exactly origin / size / root. The size is canonical decimal, the root is canonical base64 of 32 bytes, and the origin equals the log key name. | c2sp.org/tlog-checkpoint@v1.1.0 |
| The head's tiles authenticate and rebuild the signed root (`tlog.TileHashReader` + `tlog.TreeHash`). Every tile has exactly W×32 bytes, so full tiles are 8,192 bytes. Paths are parsed here from tlog-tiles (`x001/x234/067`, `.p/<W>`). | Audit I3; c2sp.org/tlog-tiles |
| Each entry bundle has exactly W big-endian u16-framed entries. Each entry's RFC 6962 leaf hash equals its authenticated level-0 tile hash. Each entry has an inclusion proof (`ProveRecord` / `CheckRecord`) against the head. | Audit I1, I3; RFC 6962 §2.1 |
| Leaf `seq` equals the leaf index for every index in `[0, size)`. | Audit I2 (gapless seq) |
| Each leaf matches the F9 schema shape: properties, required set, `v`=1, RFC 3339 `ts`, enums, regex patterns, `object` ≤ 512 characters, `detail` ≤ 16 string/integer/boolean values. Each leaf is also checked for no duplicate keys, no trailing data, and printable ASCII only (attacker bytes must be escaped). | F9; Audit I6; ARCHITECTURE §3.10 log hygiene |
| No two signed checkpoints of the same size may have different roots (fork), and no history checkpoint may be larger than the head (rollback). Each successive pair of checkpoints must be consistent (`ProveTree` / `CheckTree`), and each older checkpoint's own partial tiles must still rebuild its root. | Audit I1; tlog-checkpoint "MUST NOT sign inconsistent checkpoints" |

Ordering (Audit I4, checkpoint only after fsync) and the failure policy (I7) are runtime properties. The oracle
cannot observe them; the `monban-audit` unit tests cover them (`tests.rs`: sync precedes every publish, a failed
sync publishes nothing, admin events fail closed, dropped data-plane events are counted and consume no seq).

**Pass criterion:** every check above holds for the subject's output → `TLOG-VERIFY: PASS`.

## Self-test (negative controls)

The self-test runs two controls first, and both must pass:

1. The unmutated subject output verifies.
2. An independent x/mod `tlog` writer (`writeLog`) rebuilds the same entries, reproduces the monban root bit for
   bit, and verifies.

Then it applies 17 mutations, each to a fresh copy. Each mutation must fail with its intended error category,
and a failure for any other reason counts as a self-test failure:

- tampered leaf byte → `leaf-hash`
- reordered entries → `leaf-hash`
- swapped full tiles → `tree`
- forked history checkpoint (validly signed, same size, different root; made by re-running the subject with the
  same seeds and `--variant 1`) → `consistency`
- forked head of the same size → `fork`
- forked head plus history → `tree`
- rollback → `fork`
- missing log signature → `signature`
- unsigned checkpoint → `signature`
- missing ML-DSA-87 cosignature → `cosignature`
- untrusted key → `signature`
- seq gap (log rebuilt and re-signed, so only `seq` is wrong) → `seq`
- extra property → `schema`
- duplicate key → `schema`
- unescaped attacker byte → `schema`
- truncated bundle → `entries`
- missing partial tile → `tree`

## OpenSSL ML-DSA-87 cosignature check (`--openssl-mldsa`, P8-audit-001, gate `tlog-mldsa-openssl`)

This mode closes residual R10 from Phase 8 (see Known limits below). It checks the ML-DSA-87 cosignature
cryptographically, with code independent of monban: OpenSSL 3.5.3 verifies it. Neither aws-lc nor any monban crate is
on the verify path.

    oracles/tlog-verify/run --openssl-mldsa --binary target/release/monban   # last line: TLOG-MLDSA-OPENSSL: PASS (...)
    oracles/tlog-verify/run --openssl-mldsa --self-test [--binary <monban>]  # last line: TLOG-MLDSA-OPENSSL SELF-TEST: PASS (...)

Host: kamrui (`/usr/bin/openssl` must report `OpenSSL 3.5.3`; `TLOG_MLDSA_OPENSSL` overrides the path). The checker
is `openssl_mldsa.py` (python3 -I, stdlib only). No Go build and no container.

**Subject.** The real `monban` binary (monban-bin): `--config <f8.json> --cert --key --audit-dir <d>`. The checker:

1. boots it and waits for `/healthz`;
2. applies one config change (SIGHUP, waiting for `generation` + 1);
3. stops it (SIGTERM).

It snapshots `<d>/<ms>-<pid>/checkpoint` after each step and verifies every distinct checkpoint it saw (at least 2).
Keys come from the binary's `vkey` file, trust on first use, the same as `--subject`.

**Per checkpoint:**

| Check | Category |
|---|---|
| `vkey` holds exactly one Ed25519 key (`0x01`) and one ML-DSA-87 key (`0xff "aegis-mldsa87-note-v1"`, 2592 bytes). Each key ID equals SHA-256(name ‖ 0x0A ‖ type ‖ pk)[:4]. | `key` |
| The note is text ‖ `\n` ‖ `— name base64` lines. The text is exactly origin / canonical size / canonical 32-byte root, and the origin is the log key name. | `parse` |
| Exactly one signature line has the ML-DSA-87 key name and key ID, and its signature is exactly 4627 bytes. | `cosignature-missing` / `parse` |
| `openssl pkeyutl -verify -pubin -rawin` verifies the 4627-byte signature over the note text bytes. The public key is a SubjectPublicKeyInfo (id-ml-dsa-87, 2.16.840.1.101.3.4.3.19) built from the published key. OpenSSL defaults apply: pure ML-DSA-87, empty context string, message-encoding 1, no prehash. OpenSSL has to print `Signature Verified Successfully` and exit 0. Any other OpenSSL result is an error, not a pass. | `mldsa-verify` |
| The Ed25519 log signature is verified the same way (id-Ed25519 SPKI). | `ed25519-verify` |

**Self-test.** Both controls must verify:

1. A reference note in monban-bin's encoding, signed by OpenSSL-generated ML-DSA-87 and Ed25519 keys. This checks
   the encoding (SPKI, key ID, note framing) without trusting monban.
2. The head checkpoint of a real monban-bin log.

Then 11 mutants run on each of those two notes, plus one parameter mutant on the reference. Each must fail with its
intended category:

- cosignature byte flipped (first, middle and last byte) → `mldsa-verify`
- **wrong public key**: another valid ML-DSA-87 key, with the vkey ID and the note's key ID both rewritten so lookup
  succeeds and only OpenSSL can refuse it → `mldsa-verify`
- one public-key bit flipped (IDs rewritten the same way) → `mldsa-verify`
- one root byte flipped in the body → `mldsa-verify`
- cosignature line removed → `cosignature-missing`
- cosignature key ID mismatch → `cosignature-missing`
- cosignature truncated → `parse`
- ML-DSA-87 vkey absent → `key`
- Ed25519 signature byte flipped → `ed25519-verify`
- reference signed with `context-string:monban` → `mldsa-verify`. This pins the empty context.

**Limits.**

- Keys are trusted on first use from the binary's own `vkey`. The check proves that the cosignature verifies under
  the published key, not that the key is the right one. That needs a pinned key or a witness (ARCHITECTURE §3.10).
- monban-bin makes a fresh ML-DSA-87 key per process, so a log does not survive a restart.
- On the cmvp build ML-DSA-87 is compiled out (PLAN-6 D15). There is no cosignature there, and this mode would
  report `key`. The gate builds the floor monban-bin.
- Rung: R2 (an independent implementation verifies the real binary's output). The gate covers only the checkpoints
  that one boot/reload/stop run produces.

## Provenance

No research artifacts were ported. This oracle was written from these specs, read at C2SP editor's copies, repo
commit `fea9004f73fb` (2026-10-22):

- c2sp.org/tlog-tiles (links tlog-checkpoint@v1.1.0 and signed-note@v1.1.0)
- c2sp.org/tlog-checkpoint
- c2sp.org/signed-note
- RFC 6962 §2.1
- `interfaces/F9-audit-event.schema.json`

## Re-run in repo (2026-10-25)

- `run --subject target/release/audit-subject`: 70,000 entries, 42 checkpoints; tile levels 0–2, including the spec's
  70,000 example (273 full L0 tiles + `.p/112`, L1 `000` + `.p/17`, L2 `.p/1`). Result: PASS in about 17 s with a
  warm build.
- `run --self-test`: both controls pass and 17/17 mutations are caught.

## Known limits

- **In `--subject` mode, the ML-DSA-87 cosignature is checked for presence and shape only, not cryptographically.**
  `--openssl-mldsa` (above) checks it cryptographically with OpenSSL 3.5.3, against monban-bin's log. Go 1.26 has ML-DSA
  only in `crypto/internal/fips140/mldsa`, which cannot be imported, and no new Go dependency was allowed. The
  cosignature is verified cryptographically in Rust (aws-lc-rs `ML_DSA_87`) by the `monban-audit` unit tests
  (`note::tests`, `tests::gapless_tiles_rebuild_root_and_checkpoints_consistent`). That is self-graded, not
  independent.
- signed-note assigns no type byte to ML-DSA-87. monban uses `0xff || "aegis-mldsa87-note-v1"` as the signed-note
  "longer identifier", and signs the plain note text with no timestamp. This is not interoperable with
  c2sp.org/tlog-cosignature witnesses, which use timestamped ML-DSA-44 under type `0x06`.
- Keys are trusted on first use: `run` copies the subject's `vkey*` files out before verifying. A real deployment
  pins the keys in configuration and needs an external witness for tamper evidence (ARCHITECTURE §3.10).
- `history/` is a local extension that lets one run check consistency across checkpoints. A remote verifier would
  instead keep the checkpoints it has seen.
