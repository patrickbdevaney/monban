# pdp-dst: fault injection on the Cedar PDP channel

Unit P3-pdp-001. Judges `aegis-pdp` (the out-of-process Cedar PDP, DEVIATIONS X-8) together with the production
client path, `aegis_authz::pdp::PdpClient` + `combine`, which `aegis-pdp-probe` drives over the UDS transport.

## What is checked
- **INV-FAILCLOSED, host mapping** (spec/SPEC_INVARIANTS.md §A): a PDP stage timeout, crash or garbage reply ↦
  `Error` before `combine`, so the combined decision is Deny. Each of 14 faults is applied to every ALLOW case
  and one DENY case of each policy set. The client decision must be `ERROR` and `combine` must give `DENY`.
  - Reply path: `delay` (held 3× past the deadline), `drop`, `kill_before` (SIGKILL after the PDP got the request,
    so the client sees EOF), `kill_mid` (5 bytes of the reply, then SIGKILL + EOF), `truncate` (1/6/11 bytes),
    `empty`, `garble` (magic/version/kind/decision byte), `oversize` (13/64/70000 bytes), `swap_id` (+1/−1/top bit),
    `replay` (an earlier ALLOW reply). Every one that still sends bytes sets the decision byte to ALLOW first, so a
    lenient client prints ALLOW.
  - Request path: `req_trailing`, `req_truncate`, `req_magic`, `req_oversize`. The PDP must answer `Error` under
    the request id, or close.
  - Each faulted exchange is followed by an unfaulted one, which must still match the reference. This catches
    clients that keep a poisoned connection (a late reply read as the next answer).
- **Cedar agreement**: three example policy sets in `policies/` (`rbac`: nested roles; `tenant`: tenant-scoped
  resources with a cross-tenant guard; `deny-overrides`: banking forbids, including an overflowing forbid). For
  each case, `aegis-pdp eval` decides through Cedar's own JSON parsers, a path that shares nothing with the
  PDP-1 codec. Its answer must equal the hand-written `expect`, and so must the answer over the wire
  (driver → proxy → PDP). AEGIS mapping: a request/schema error or any policy evaluation error is `ERROR`
  (ARCHITECTURE §3.5: "an error in a forbid yields Deny"). The overflow case records that Cedar alone would say
  Allow (`cedar_raw`).
- **Startup validation**: `check` accepts each valid set. `serve` refuses each `invalid.cedar` (a strict-validation
  error, a type error, a parse error): it must exit non-zero and never bind its socket.
- **Socketpair mode**: `serve --stdio` on a SOCK_SEQPACKET socketpair end passed as fd 0 gives the same answers.

Pass: zero violations. The last line is `PDP-DST: PASS (...)`.

## Self-test
`--self-test` swaps the driver for `pyclient.py`, a Python reference client. The correct client must PASS. These
mutants must FAIL: `timeout-allow` (a timeout is read as ALLOW), `ignore-id` (no request-id check),
`accept-oversize` (judges a long packet on its first 12 bytes) and `no-reset` (keeps the connection after a
fault). Mutant runs stop at the first violation.

## Subject
`default-subject` = `target/release/aegis-pdp`. The probe is taken from the same directory
(`aegis-pdp-probe`), or from `--probe`. Defaults: deadline `--deadline-ms 300`, seed `--seed aegis-pdp-dst-1`.
The fault schedule (which recovery case follows each fault, and the order) is a pure function of the seed.

## Provenance
No research artifact was ported. The harness and the policy sets were written in-repo for this unit. Design
inputs: DEVIATIONS X-8, interfaces/F10-module-wire.cddl (framing conventions), ARCHITECTURE §3.5. Cedar's own
semantics are cited from spikes/cedar-axioms: `forbid_trumps_permit`, `default_deny` and
`allowed_iff_explicitly_permitted_and_not_denied` are at A (Lean, v4.14.0). This oracle tests the Rust
evaluator against the hand-written expectations (R1). It does not test against the Lean model.

Policy files (sha256):

    d62ffbe5dda55e635f545bcf43c528328914800f7b8299d8fe84732b362259fc  policies/deny-overrides/cases.json
    ea39f21652c15fad0767c959a436b9510a993b546efae3b0994257445e376f29  policies/deny-overrides/invalid.cedar
    008294dc30c3eb4cf440e83af36fa5231b8c916ea8901a1813352847a7dec784  policies/deny-overrides/policies.cedar
    b6fac1afac5aec48a525ea18342528d2cc46d00018d82d4e1b696782f211ff74  policies/deny-overrides/schema.cedarschema
    7ab6f89c9af308c35c5049b82db02ceb223008669040d873f3d6014b5fcbe7b7  policies/rbac/cases.json
    e9f801ce2d49a5cda0bca558078709ef0cff2c30567dca093fe1d1e6c852a771  policies/rbac/invalid.cedar
    1cd6cc97b5919b656c8708cb1bd507f723adeeae6ba33db7db4b3d28fab17597  policies/rbac/policies.cedar
    8e28e8a9e085eaaefd566093e914a7b360e6add85f47a89f58bef8bfd5f248c8  policies/rbac/schema.cedarschema
    62e0a1cc6c1f961a1cc27eb91ea36172f72b3b261444b62570b7ca3c71c02fe5  policies/tenant/cases.json
    d17a16b2e28e1fbbed47c140c939fbf8fffa56ced5fe20fa036063ec3c81d2b9  policies/tenant/invalid.cedar
    1c55256ac151dccf8343e3f18a52cc237ed9a5177938fc3aa9bae31dc6e10867  policies/tenant/policies.cedar
    ca7a97e0782168aff2faf621848601a339bd7b84d3deaef1594a4e21531c7d50  policies/tenant/schema.cedarschema

## Re-run in repo (desktop via ci/remote.sh, 2026-10-26)
- `oracles/pdp-dst/run --subject target/release/aegis-pdp`: PASS. 40 cases match Cedar; 224 faulted exchanges
  all ERROR→DENY; 224 recoveries; 32 PDP kills; 3 invalid sets refused; stdio mode OK.
- `oracles/pdp-dst/run --self-test`: PASS. The reference client passes, and all four mutants are caught.

## Known limits
- Lockstep, one request in flight per client. Concurrency and pipelining on one connection are not exercised.
- Garbling is targeted (header bytes, decision byte), not random. A bit flip that turns a valid DENY reply into a
  valid ALLOW reply cannot be detected: the local UDS channel is trusted and has no integrity tag (this is
  outside the fault model).
- The deadline is the client's own SO_RCVTIMEO per exchange. Slow-loris on the PDP side (a slow request write)
  is not modeled.
- The self-test mutants are Python re-implementations of the client. The Rust client's fault mapping is
  also unit-tested with a scripted transport (`crates/aegis-authz/src/pdp.rs`).
- Rung: R1 (executed tests). No proof covers the Rust client or the Cedar Rust evaluator.
