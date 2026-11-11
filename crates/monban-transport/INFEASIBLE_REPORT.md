# INFEASIBLE_REPORT: monban-transport (P2-transport-002)

None of the 9 h2spec cases in P2-transport-002 fails any more (oracles/h2-conformance passes; only the
allow-listed invalid-preface case still fails). This report records two RFC 9113 deviations that remain **inside
h2 0.4.20**. h2spec v2.6.0 does not catch either one, but the stricter frame-level tests in `tests/h2_frames.rs`
do. The wrapper cannot fix them, because h2 decodes the frames and decides the outcome before any of our code
runs. Each one has an `#[ignore]`d strict test that fails today; un-ignore it when h2 is fixed or replaced.

## 1. HEADERS on a stream the client reset: GOAWAY(PROTOCOL_ERROR) instead of stream error STREAM_CLOSED

- Spec: RFC 9113 §5.1 "closed": "An endpoint that receives any frame other than PRIORITY after receiving a
  RST_STREAM MUST treat that as a stream error (Section 5.4.2) of type STREAM_CLOSED."
- Case: h2spec http2/5.1/9 ("closed: Sends a HEADERS frame after sending RST_STREAM frame"). It passes only
  because h2spec's `VerifyStreamError` (spec/verifier.go) also accepts "Connection closed". The strict test is
  `strict_closed_headers_after_rst_stream_code`.
- Where h2 does it (h2-0.4.20):
  - The stream is still in the store, in state `Closed(Cause::Error(remote reset))`. `Inner::recv_headers`
    (src/proto/streams/streams.rs:585-593, the `else` branch) treats the frame as trailers and calls
    `Recv::recv_trailers` (src/proto/streams/recv.rs:417). That calls `State::recv_close`
    (src/proto/streams/state.rs:235-252), whose catch-all arm returns
    `Error::library_go_away(Reason::PROTOCOL_ERROR)`.
  - The stream has already been released. The vacant-entry path in `Inner::recv_headers` (streams.rs:497) only
    answers STREAM_CLOSED for clients. For a server it calls `Recv::open` (recv.rs:138-140), which fails with
    `id < next_id` and returns `library_go_away(PROTOCOL_ERROR)`.
- Why the wrapper cannot fix it: h2 handles the frame inside `Connection::poll`, so the wrapper never sees it.
  `poll_accept` yields nothing for it. The only alternative is a frame parser in front of h2 with its own HPACK
  decoder that tracks h2's dynamic table, which means a new dependency or a second decoder.
- What it means: the result is still fail-closed. RFC 9113 §5.4.1 allows any stream error to be escalated to a
  connection error. The deviation is the error code (PROTOCOL_ERROR instead of STREAM_CLOSED) and the loss of
  the other streams on the connection.

## 2. Pseudo-header fields in a trailer block with END_STREAM are accepted

- Spec: RFC 9113 §8.1: "Pseudo-header fields MUST NOT appear in a trailer section". §8.1.1 says a malformed
  request is a stream error of type PROTOCOL_ERROR.
- Case: h2spec http2/8.1.2.1/3 sends its trailer HEADERS **without** END_STREAM. h2 rejects that for a different
  reason: "trailers frame was not EOS" (streams.rs:589). So the
  h2spec case passes, but not because of the pseudo-header check. Sending the same trailers with END_STREAM gets
  a 200 response. The strict test is `strict_pseudo_header_in_end_stream_trailers`.
- Where h2 does it (h2-0.4.20):
  - `HeaderBlock::load` (src/frame/headers.rs, the `set_pseudo!` macro around lines 891-912) only marks
    pseudo-headers as malformed when they come after a regular field or repeat. It does not know whether the
    block is a trailer section.
  - `Recv::recv_trailers` (recv.rs:417-439) then calls `frame.into_fields()` (recv.rs:430). That drops the
    decoded `Pseudo` without checking it.
- Why the wrapper cannot fix it: `RecvStream::poll_trailers` returns only the regular-field `HeaderMap`. The
  pseudo-headers are thrown away before any public API exposes them, and the same frame-parser alternative as
  in §1 applies.
- What it means: the dropped pseudo-headers never reach a handler and do not change routing, because routing was
  decided from the request head. The deviation is that a malformed request is answered instead of reset.
