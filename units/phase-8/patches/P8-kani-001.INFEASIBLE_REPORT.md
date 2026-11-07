# P8-kani-001: the parts of the client-path obligations Kani cannot check on the real code

Unit P8-kani-001, gate `kani-kx-client`. This report covers part of acceptance.must only. The gate itself is
implemented, and it is red-capable (see the self-test). Nothing was weakened: every harness asserts the full
property for the code it reaches. The obligations below are listed as not checked. They are not passed off as checked.

## 1. The 0x11ED client share encoding (`kx::Active::new`): needs a kx.rs patch

- Spec clause: acceptance.must, "client key-share encoding length".
- Failing case: no harness can build an `Active`, or reach `Active::new`. Both take an `agreement::PrivateKey` and a
  `kem::DecapsulationKey`. Only aws-lc C code can produce these (through `EVP_PKEY_keygen` / `CBB_finish`
  out-parameters). aegis-tls is `#![forbid(unsafe_code)]`, so a Kani stub cannot write those out-parameters. A
  `-Z c-ffi` havoc leaves the out-pointers unwritten, so keygen always fails, and it also creates spurious
  out-of-bounds reports in aws-lc-rs (`PublicKey::as_ref` slices by a C-returned length).
- Minimal reason: the encoding sits inline in a constructor whose arguments are opaque C handles.
- Resolution (in scope for the integrator): `units/phase-8/patches/P8-kani-001.patch`. It moves the encoding and
  the point check into the pure functions `kx::encode_client_share` and `kx::is_uncompressed_p384`. Behaviour and
  error order are unchanged. It also adds the harnesses `client_share_encoding_0x11ed` and `client_point_check_0x11ed`,
  which `--only client_` picks up. The patched tree was run through `ci/kani.sh --only client_` on kamrui (the result
  is in the unit's final report).

## 2. 0x11EB and 0x0202 client `complete`: rustls code that is not reachable

- Spec clause: acceptance.must, "server-share parse bounds for 0x11EB/0x0202, decapsulation input length checks".
- Failing case: rustls 0.23.46 builds `ActiveHybrid` (0x11EB) and `pq::mlkem::Active` (0x0202) only in
  `Hybrid::start` / `MlKem::start`, from aws-lc keygen (as in item 1). Their types are `pub(crate)`, so a Kani stub
  cannot name them in its signature either.
- What was tried: the harness `client_rustls_hybrid_split_0x11eb`. It passed every share length 0..=1250 through
  `SECP256R1MLKEM768.start_and_complete`, with `aws_lc_rs::agreement::PrivateKey::generate` stubbed, to run rustls'
  `Layout::split`. The client's `split_received_server_share` calls that same function with `pq_len = 1088`. On
  kamrui the harness was oom-killed at the gate's 6G MemoryMax twice (2026-11-06, about 11 min each). The first run
  had symbolic bytes; the second had fixed bytes and `#[kani::unwind(4)]`. Cause, from the CBMC log: rustls' default
  `start_and_complete` calls `complete` through `dyn ActiveKeyExchange`. CBMC expands that call to every impl, and
  `ActiveHybrid::complete_hybrid_component` recurses through `dyn` again ("Unwinding recursion ...
  complete_hybrid_component iteration 88"). Raising the memory limit would change a kani.sh limit, so the harness was
  removed. 0x11EB is not covered by Kani.
- Finding (0x0202): rustls' `mlkem::Active::complete` passes the server share directly to aws-lc-rs
  `DecapsulationKey::decapsulate`. Neither one checks the length in Rust (aws-lc-rs 1.18.2 `kem.rs`). The ML-KEM-1024
  ciphertext length bound for a 0x0202 client is enforced only in AWS-LC C (`EVP_PKEY_decapsulate`). That code is
  trusted, not verified (SECURITY_CLAIMS). No Kani proof on Rust code can show this bound. One option for a later
  unit: an AEGIS wrapper around rustls' MLKEM1024 / SECP256R1MLKEM768 client groups that checks the exact
  server-share length before it delegates. Kani could check that wrapper with a mock inner `ActiveKeyExchange`.
- Minimal reason: the client-side state is built only by C, and the length check under test is in C (0x0202).

## Rungs

- `client_server_share_split_0x11ed` (and the patched
  `client_share_encoding_0x11ed`, `client_point_check_0x11ed`): R2. These are bounded Kani proofs on the Rust
  functions named above, over every length up to one byte past the exact share, and every byte value.
- The call composition inside `Active::complete` / `Active::new`, all of rustls' 0x11EB share handling, and the
  0x0202 client bound: argued from the code, or trusted (rustls, AWS-LC C). They are not checked by Kani.
