# token-drt: Rust Tier-L verifier vs the Lean Token model

Differential random testing (DRT) of `monban-token` (unit P3-token-001) against the definitions in
`spec/AegisIR/Token.lean`, evaluated by a compiled core-Lean program.

## What is checked

- **INV-ATTEN (F2)**: verify = MAC ∧ conjunction of EVERY caveat ∧ `depthOk`; D1 segment-prefix resources, D2 op-mask
  subset, D3 depth at verify, D4 a missing argument denies; `now` is a parameter. F5 additions: the mint-shape check
  (`[aud, exp, depth_left]` first) and 1..64 caveats. Holder `attenuate` (T5') is exercised on every case.
- **INV-NO-AMBIENT (F1)** only indirectly: the subject's `verify` result is "a `Principal` was minted".
- Per case the oracle compares four bits: `verify` (Rust: `monban_token::verify` on the **encoded wire bytes**, so
  the det-CBOR encoder and decoder are in the loop), `denote`, `depthOk`, `shapeOk`.

**Pass criterion:** 0 divergences over N cases (default N = 1e6, `--cases` or `TOKEN_DRT_CASES` to change), no
parse errors, every case answered. Last line `TOKEN-DRT: PASS (...)`.

## How

1. `token_drt.py` generates N cases (seeded, `--seed`, default 20261026). Each case is: a request; a minted caveat
   list (90% well shaped, 10% shuffled/ill-shaped, as a key holder could chain); k holder-appended caveats (k around
   the depth budget, so D3 is hit both ways); one tamper step (none 55%; drop-last, drop i, replace i, swap, insert,
   append-without-MAC, flipped tag, swapped kid, new nonce); a verifier key ring (5% unknown kid, 5% wrong master,
   10% extra key). Caveats are generated "satisfied" with probability ~0.85-0.9 and otherwise random, with traps
   for each ratified decision (a segment that is a strict string prefix or extension of the request's: `t1`/`t10`;
   a tool constraint on an absent argument; depth caveats that lower the bound; audiences/kids whose plain concatenation
   collides, `"api"‖"k1"` = `"apik"‖"1"`; with F5's length prefixes these must now derive different keys).
2. `lean/TokenDrt.lean` (compiled once with `lean -c` + `leanc` into `.lake/build/`, gitignored) evaluates each case.
   Its section 1 is a copy of Token.lean's definitions (no theorems); `run` checks that every non-extension line of
   that copy occurs verbatim in `spec/AegisIR/Token.lean` and FAILs on drift. Two marked extensions: X1
   `ArgCon.strPrefix` (the F5 wire's `argpred [3, tstr]`, absent from Token.lean) and X2 `shapeOk`/`countOk`.
   The MAC parameter `H` is instantiated with a free (injective, length-prefixed) function, so `macChain` equality
   holds iff key, `kid ‖ nonce` and caveats are equal: the ideal-MAC reading of T5. K_aud is modelled as
   `master ‖ "aegis-cap-v1" ‖ be16|aud| ‖ aud ‖ be16|kid| ‖ kid`, the exact F5 HKDF info (length-prefixed since 2026-10-29). Lean `tenant : Bytes` is the 8-byte
   big-endian encoding of the wire uint.
3. The subject (`subjects/token-subject`, default `target/release/token-subject`) builds the same token with the
   crate's public API (issuer `chain_tag`, holder `attenuate`, tamper, `encode`) and runs real HMAC-SHA256/HKDF.
   Agreement with the free model can only break on an HMAC collision.

### Case line format (space-separated tokens)

`id mMaster mAud mKid mNonce <mint list> <attenuate list> <tamper> nKeys (kid master)* <req>`

- string `s<hex of UTF-8>` (`s` alone = ""); bytes `x<hex>`; ints decimal; list = count then items.
- caveat: `A str` · `E n` · `N n` · `O n` · `R k str*` · `C bytes` · `T n` · `L name k (key pred)*` · `D n`;
  pred: `q val` · `o k val*` · `r lo hi` · `p str`; val: `I int` · `S str`.
- tamper: `none` · `droplast` · `drop i` · `repl i cav` · `swap i j` · `ins i cav` · `app cav` · `tag` ·
  `kid bytes` · `nonce bytes` (out-of-range indices are no-ops on both sides).
- req: `aud ops k seg* tenant holder tool k (key val)* now`. Master `m` is the key `[m; 32]` in Rust.
- Output: `id VDKS` (four 0/1 bits) or `id PARSE_ERROR`.

## Self-test (`run --self-test`)

On 50,000 fresh cases the real subject must show 0 divergences, then each mutant (implemented in token-subject,
`--mutant NAME`, never in the crate) must show ≥1 divergence: `leaf-only` (verify only the last caveat),
`plain-prefix` (string prefix of the joined path), `missing-arg-allow` (D4 inverted), `depth-unchecked` (D3 off).
A non-constant-time compare is not observable by DRT; it is covered by the crate's timing report test.

## Results in-repo (2026-10-26, laptop, Lean 4.35.0)

- `oracles/token-drt/run --subject target/release/token-subject`: 1,000,000 cases, 0 divergences
  (verify=1 160,947; denote=1 499,388; depthOk=0 453,518; shapeOk=0 196,175); generate 24 s, evaluate 33 s.
- `--self-test`: leaf-only 17,339 / plain-prefix 132 / missing-arg-allow 156 / depth-unchecked 22,631 divergences
  per 50,000 cases; baseline 0.

## Provenance

Not ported from research code. Inputs: `spec/AegisIR/Token.lean` (sha256 d41cccfa…e1513),
`interfaces/F5-token.cddl` (fd23c657…11540); the r4 check of the Lean theorems is
`research/state/raw/round-004/01-lean-check-lowering-and-token-proofs.json` (7215e7d6…54267), not executed here.

## Placement and limits

- `needs`: lean (Lean is not installed on the LAN desktop), so `ci/oracles.sh --where local` runs it. The subject
  can be built remotely (`ci/remote.sh cargo build --release -p token-subject`) and copied to `target/release/`.
- Cases stay inside the wire limits (≤ 64 caveats, ≤ 4096 bytes, i64 argument ints, int/str argument values), so
  size-cap behaviour, the decoder's rejection paths and Tier 0 / Tier X are covered by the crate's unit and fuzz
  tests, not here. The issuer TTL check (exp − mint_time ≤ 900) is issuer-side and not modelled.
- The free-MAC model makes the MAC check exact up to HMAC collisions; it says nothing about HMAC's security
  (EUF-CMA is assumed, as in Token.lean).
- `plain-prefix` and `missing-arg-allow` are caught at a low rate (~0.3%) because they need specific coincidences;
  1e6 cases give thousands of discriminating instances.
