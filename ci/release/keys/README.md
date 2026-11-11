# Release keys: operator runbook

This is the setup for signing real Monban releases as a solo maintainer. No hardware tokens needed.

The rules the verifier enforces do not change. A release needs three signatures over its checksums (Ed25519,
SLH-DSA-SHA2-128s, ML-DSA-87), a provenance signed by a separate attest key, and TUF metadata whose root is 5
Ed25519 keys with threshold 3 (REL-1..REL-5 in `ci/release/verify.py`).

## The idea

- You hold all 5 root keys yourself. Each one is a separate file, encrypted with a passphrase, kept in a different
  place. Signing a new root takes any 3 of them, so you can lose 2 copies (or have 2 stolen) and still recover.
- Every day, releases need only the 7 **online** keys: the 3 release signing keys, the attest key, and the TUF
  targets/snapshot/timestamp keys. They all share one passphrase, and it is different from the root passphrase.
  The root keys never touch the build box.
- Every private key on disk is an encrypted PKCS#8 file (PBKDF2-HMAC-SHA256 with 600,000 iterations, AES-256-CBC).
  A key is only ever decrypted into a private folder in RAM (`/dev/shm`), and that copy is shredded when the job
  ends.
- The public half goes in the repo under `release-keys/`: 12 public keys, `KEYS.txt` (fingerprints) and the TUF
  root chain (`1.root.json`, later `2.root.json`, ...). Anyone verifying a release trusts `release-keys/1.root.json`.

## 1. The ceremony (once)

Use a machine with OpenSSL 3.5 or later and the python-tuf venv. kamrui has both. Your laptop works too if
`AEGIS_OPENSSL` points at an OpenSSL >= 3.5 and `AEGIS_PY_TUF_PYTHON` points at the venv python. Do it in a
terminal (`ssh -t`), not through `ci/remote.sh`, because it asks for passphrases.

```sh
cd ~/aegis-ci/repo            # or your checkout
ci/release/keys/ceremony.sh new --private ~/monban-keys-ceremony --public release-keys
```

- `--private` must be outside the repo (and outside any git checkout), and empty or missing. The script refuses
  otherwise.
- `--public` must be empty or missing.
- You are asked for two passphrases, each twice. Each must be at least 12 characters and they must differ:
  1. the **root passphrase**, for the 5 root copies;
  2. the **online passphrase**, for the 7 keys used on every release.
  Save both in your password manager right away.
- The script prints where each file should go. The same text is saved as `WHERE-TO-STORE.txt`.
- When it finishes, check the result and commit the public half:

```sh
ci/release/keys/ceremony.sh check --private ~/monban-keys-ceremony --public release-keys
git add release-keys && git commit -m "release keys: production root v1"
```

## 2. Where to keep things

| File | Where | Notes |
|---|---|---|
| `root-1.key.enc.pem` | external drive A, at home | |
| `root-2.key.enc.pem` | USB stick B, at home, in a different spot from A | |
| `root-3.key.enc.pem` | USB stick C, in another building (office, family, safe deposit box) | |
| `root-4.key.enc.pem` | encrypted cloud backup or a password-manager file attachment | |
| `root-5.key.enc.pem` | USB stick D, in a second other building | |
| root passphrase | password manager, plus a paper copy in a sealed envelope | never stored with a USB stick |
| `online/` (7 files) | the build box: `kamrui:~/monban-release-keys/online` (mode 0700) | plus one backup on drive A |
| online passphrase | password manager | |

Never put two root copies on one device, and never leave all of them on one computer. When the copies are in
place, remove the root files from the ceremony folder: `shred -u ~/monban-keys-ceremony/root-*.key.enc.pem`.
Once a year, check that each copy still opens (any 3 is enough):

```sh
openssl pkey -in /media/usb/root-3.key.enc.pem -noout   # asks for the root passphrase; silence means OK
```

## 3. Cutting a release

The pipeline runs on kamrui (docker, OpenSSL 3.5, py-tuf). Sync the tree, then run it in a terminal so it can ask
for the online passphrase:

```sh
ci/remote.sh --host kamrui true                     # sync this checkout to kamrui:~/aegis-ci/repo
ssh -t kamrui
cd ~/aegis-ci/repo
export RUSTUP_HOME=~/aegis-ci/rustup CARGO_HOME=~/aegis-ci/cargo AEGIS_TOOLS=~/aegis-ci/tools
export PATH=~/aegis-ci/cargo/bin:~/aegis-ci/tools/bin:$PATH
ci/release/pipeline.sh --profile floor --out target/release-prod --keys ~/monban-release-keys/online
ci/release/verify.py --trusted-root release-keys/1.root.json target/release-prod
```

The pipeline asks for the passphrase before it builds and checks that it opens every key. It also checks that the
keys match `release-keys/`. Each keyed job decrypts only its own keys into its own RAM folder and shreds them. The
release has no `TEST_KEYS` file and no `test_keys` markers, so it passes only with `--trusted-root` and never needs
`--allow-test-keys`. For automation, `--passphrase-fd N` reads the passphrase as one line from file descriptor N.
Never pass it as an argument or an environment variable.

Without `--keys`, the pipeline behaves exactly as before: fresh throwaway test keys, a `TEST_KEYS` marker, and
`verify.py --allow-test-keys`. That is what the `release-verify` gate runs.

Timing: the TUF timestamp in a release is valid for 1 day, and targets/snapshot for 7 days (`jobs/tuf.py`). Run
the verify step right after the build. A verify on an older release dir fails with `REL-2 expired`. That is the
existing policy, not a fault.

## 4. Renewing and rotating (any 3 root copies)

The root in `release-keys/` expires after 365 days (`--root-days` changes this, 30..3650). Renew it about a month
before it expires. Bring any 3 root copies to the ceremony machine:

```sh
ci/release/keys/ceremony.sh next-root --public release-keys \
  --root-key /media/a/root-1.key.enc.pem --root-key /media/b/root-2.key.enc.pem --root-key /media/c/root-3.key.enc.pem
git add release-keys && git commit -m "release keys: root v2 (renewal)"
```

This writes `release-keys/2.root.json`, signed by the 3 keys you brought. Releases ship every root version, and a
verifier holding `1.root.json` walks the chain to the newest one. Nobody needs a new trust anchor.

**One root copy lost or stolen.** Replace that key using 3 of the others:

```sh
ci/release/keys/ceremony.sh next-root --public release-keys --replace-root 2 --new-private ~/monban-keys-new \
  --root-key /media/a/root-1.key.enc.pem --root-key /media/c/root-3.key.enc.pem --root-key /media/d/root-4.key.enc.pem
```

Store `~/monban-keys-new/root-2.key.enc.pem` where the old copy lived, and commit `release-keys`. The old root-2 can
no longer sign anything. Two copies lost or stolen: do the same with `--replace-root` given twice. Three or more:
you can no longer prove a new root. Run a fresh `ceremony.sh new`, publish the new `1.root.json` through a separate
channel, and tell users to re-pin it.

**Online keys leaked, or the build box is compromised.** Replace all 7 online keys with a new online passphrase.
This also needs 3 root copies:

```sh
ci/release/keys/ceremony.sh next-root --public release-keys --replace-online --new-private ~/monban-keys-new \
  --root-key ... --root-key ... --root-key ...
```

Copy `~/monban-keys-new/online` to the build box and its backup, shred the old `online/`, and commit `release-keys`.
Releases signed with the old keys still verify through their own root version. The new root no longer trusts the
old TUF online keys for new metadata.

**Forgot a passphrase.** Without the root passphrase, the root copies are useless. Treat that like losing all 5 and
run a fresh ceremony. Without the online passphrase, run `next-root --replace-online` (it needs the root
passphrase).

## 5. Checks and self-test

- `ci/release/keys/ceremony.sh check --private DIR --public release-keys` audits the files. Every key must be
  encrypted with the right parameters, nothing else may sit in the private folder, the public folder must hold no
  private material, and the root chain must be 3 of 5 Ed25519 with no `test_keys`.
- `ci/remote.sh --host kamrui ci/release/keys/ceremony.sh --self-test` runs the full path with throwaway keys on
  tmpfs. It covers the ceremony, the production signing jobs on a fake release, `verify.py --trusted-root`,
  renewal and rotation. It also checks that each mistake is refused: wrong passphrase, a root signed by only 2 of
  5, `test_keys` markers in production mode, a plaintext key left behind, mismatched public keys, old online keys
  after rotation, and the private folder inside the repo or not empty. Last line:
  `CEREMONY: PASS (self-test: ...)`. This is not a phase-8 gate (phase 8 already reached GO); run it after any
  change under `ci/release/`.

Files: `ceremony.sh` (entry point), `lib.sh` (passphrase and encryption helpers), `root.py` (TUF root, py-tuf),
`keycheck.py` (file audit), `selftest.sh` and `selftest_mut.py` (self-test), `../sign-release.sh` (the keyed half
of the pipeline, shared by both modes).
