//! Kani harnesses for aegis-wire (gate kani-wire; F1 PROXY-3, L4-1).
//!
//! Obligations, over symbolic bytes:
//! - no panic (Kani checks every arithmetic overflow, slice bound and unwrap on the paths below);
//! - `consumed <= input.len()`, and consumed = the declared size (16 + len, 5 + record length) within the caps;
//! - no read past the declared length: with symbolic bytes after the declared size, the result equals the result on
//!   the declared prefix alone, and every borrowed field lies inside it;
//! - a declared length that is not all there is never accepted, and one over the cap is refused from the fixed header
//!   alone, whatever follows.
//!
//! Shape and bounds (rung R2 on the Rust code, bounded). A symbolic input length or declared length multiplies
//! symbolic-execution paths: CBMC unwinds every loop of the parser at every reachable symbolic size. A first version
//! with symbolic lengths up to 40/64 bytes did not finish in 1800 s, and neither did a `for len in ..` loop, whose
//! counter is merged into a symbolic value. So every harness fixes the input length and the declared length as
//! concrete bytes (written into the buffer, or passed as literals to a per-case helper). Every other byte stays
//! symbolic, and so does every inner TLV / extension / vector length.
//! - PROXY, compositionally over its two stages (`parse_v2` = fixed part and address block, then `check_tlvs` on the
//!   rest):
//!   - `proxy_exact_*`: the whole parse at L = 16 (empty block) and 28 (INET) with family/protocol symbolic, and at
//!     52 (INET6) with that byte concrete. Every one of them leaves an empty TLV region. The UNIX block (L = 232) is
//!     not covered here: a buffer over 64 bytes exceeds CBMC's field-sensitivity limit, so the concrete length bytes
//!     no longer propagate and the run did not finish in 900 s. The UNIX branch (two checked splits of the 216-byte
//!     block) is covered by the oracle vectors and the fuzz target;
//!   - `proxy_tlvs_total`: `check_tlvs` alone on regions of 0..=10 fully symbolic bytes (CRC32C, AUTHORITY,
//!     UNIQUE_ID, SSL, duplicates).
//!
//!   Whole-parse harnesses with a non-empty TLV region (L = 32, 35) did not finish in 900 s: the TLV loop and the
//!   UTF-8 loop inside it unroll to the global bound over symbolic offsets.
//! - ClientHello, compositionally over its three stages (`client_hello` = `record` then `hello_body` then
//!   `extensions`):
//!   - `peek_exact_*`: the whole peek at L = 50 (a minimal hello), 56 (a 4-byte extensions block) and 62 (a 10-byte
//!     block), with the hello-field lengths concrete;
//!   - `peek_body_total`: `hello_body` alone on bodies of 44..=64 fully symbolic bytes (symbolic session_id,
//!     cipher_suites and compression lengths);
//!   - `peek_ext_total`, `peek_ext_10`, `peek_ext_12`: `extensions` alone on blocks of 0..=12 fully symbolic bytes;
//!   - `peek_record_prefix_determined`: the record stage (the only stage that sees the raw input) gives the same
//!     result on the input and on its declared prefix;
//!   - `peek_iterators_total`: the list iterators over any field bytes.
//!
//!   A whole-peek harness with symbolic hello-field lengths did not finish in 1200 s: every later offset becomes
//!   symbolic and the extension loops fan out.
//!
//!   The duplicate-extension check is generic (`TypeSet`). The shipped `client_hello` uses the 65 536-bit `BitSet`;
//!   any harness that runs `extensions` with it ran out of the 6 G cap, so `peek_exact_*` and `peek_ext_*` run the
//!   same generic code with `ListSet`, an exact list-backed set. `BitSet` is held to the same set contract by the
//!   exhaustive unit test `bitset_is_an_exact_set` (all 65 536 values: the value-to-bit map is injective and insert
//!   records). A Kani harness of three symbolic inserts into `BitSet` alone did not finish in 1200 s (a symbolic
//!   index into a 1024-word array), so that link is a test, not a proof. The short-input and cap harnesses call the
//!   shipped `client_hello` itself.
//!
//! The negative control is compiled only with `--cfg aegis_kani_negative`. It runs a planted copy of a length check
//! that reports one byte more than the input holds and asserts the bound. It must FAIL on its own "NEGATIVE CONTROL"
//! assertion, which shows the harness setup can go red.

// `kani` (and `aegis_kani_negative`) are not cfg names Cargo knows; see aegis-budget/src/kani_proofs.rs.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod harnesses {
    use crate::proxy::{Addresses, FIXED_LEN, MAX_DECLARED_LEN, MAX_HEADER_LEN, ProxyError, SIGNATURE, parse_v2};
    use crate::tls_peek::{MAX_RECORD, PeekError, RECORD_HEADER, TypeSet, client_hello, client_hello_with};

    /// Symbolic bytes appended after the declared size ("no read past the declared length").
    const TAIL: usize = 2;

    fn inside(input: &[u8], consumed: usize, f: &[u8]) -> bool {
        let (d, s) = (input.as_ptr() as usize, f.as_ptr() as usize);
        f.is_empty() || (s >= d && s - d <= consumed && f.len() <= consumed - (s - d))
    }

    /// An exact set of up to 4 extension types (a linear scan): the duplicate check the peek harnesses run the generic
    /// `extensions` code with, in place of the 8 KiB `BitSet` (beyond CBMC's memory bound inside a parse). The
    /// harness blocks hold at most 3 extensions; a 5th insert would fail the assertion, not pass silently.
    struct ListSet {
        items: [u16; 4],
        len: usize,
    }

    impl ListSet {
        fn new() -> ListSet {
            ListSet { items: [0; 4], len: 0 }
        }
    }

    impl TypeSet for ListSet {
        fn insert(&mut self, t: u16) -> bool {
            // Four guarded comparisons, no loop: a `contains` scan here is a loop nested in the extension loop, which
            // is what Kani cannot unroll cheaply.
            let has = |k: usize| k < self.len && self.items.get(k) == Some(&t);
            if has(0) || has(1) || has(2) || has(3) {
                return false;
            }
            assert!(self.len < 4, "ListSet capacity");
            if let Some(slot) = self.items.get_mut(self.len) {
                *slot = t;
            }
            self.len += 1;
            true
        }
    }

    /// Overwrite `buf[at..]` with the concrete bytes `src` (concrete, not assumed, so symbolic execution can prune on
    /// them).
    fn put(buf: &mut [u8], at: usize, src: &[u8]) {
        for (i, &s) in src.iter().enumerate() {
            if let Some(d) = buf.get_mut(at + i) {
                *d = s;
            }
        }
    }

    /// The whole PROXY parse on a header of total length `L` declared exactly (n = L - 16) with `TAIL` symbolic bytes
    /// after it. Concrete: the signature, the length field and, when `fp` is given, the family/protocol byte.
    /// Symbolic: the version/command byte, the family/protocol byte otherwise, and every block byte. Every `L` here
    /// leaves an empty TLV region for the families that fit (16: none; 28: INET; 52: INET6; 232: UNIX), so the TLV
    /// stage is reached only through `proxy_tlvs_total`, which bounds it on its own.
    fn proxy_exact<const L: usize, const B: usize>(fp: Option<u8>) {
        assert!(B == L + TAIL);
        let mut buf: [u8; B] = kani::any();
        put(&mut buf, 0, &SIGNATURE);
        if let Some(fp) = fp {
            put(&mut buf, 13, &[fp]);
        }
        let n = u16::try_from(L - FIXED_LEN).unwrap_or(0);
        put(&mut buf, 14, &n.to_be_bytes());
        let r = parse_v2(&buf);
        let declared = parse_v2(buf.get(..L).unwrap_or(&[]));
        assert!(r == declared);
        if let Ok((h, consumed)) = r {
            assert!(consumed == L);
            assert!(consumed <= buf.len() && consumed <= MAX_HEADER_LEN);
            for t in h.tlvs() {
                assert!(inside(&buf, consumed, t.value));
            }
            if let Addresses::Unix { src, dst } = h.addresses {
                assert!(inside(&buf, consumed, src) && inside(&buf, consumed, dst));
            }
        } else {
            assert!(r != Err(ProxyError::Incomplete));
        }
    }

    #[kani::proof]
    #[kani::unwind(22)]
    fn proxy_exact_16() {
        proxy_exact::<16, 18>(None);
    }

    #[kani::proof]
    #[kani::unwind(34)]
    fn proxy_exact_28() {
        proxy_exact::<28, 30>(None);
    }

    #[kani::proof]
    #[kani::unwind(36)]
    fn proxy_exact_32() {
        proxy_exact::<32, 34>(None);
    }

    #[kani::proof]
    #[kani::unwind(39)]
    fn proxy_exact_35() {
        proxy_exact::<35, 37>(None);
    }

    #[kani::proof]
    #[kani::unwind(58)]
    fn proxy_exact_52_inet6() {
        proxy_exact::<52, 54>(Some(0x21));
    }

    /// `check_tlvs` on a region of exactly `R` symbolic bytes (the region is its own header for the CRC32C position):
    /// total, and every walked TLV inside the region.
    fn proxy_tlvs_case<const R: usize>() {
        let region: [u8; R] = kani::any();
        if crate::proxy::check_tlvs(&region, 0, &region).is_ok() {
            for t in crate::proxy::walk(&region) {
                assert!(inside(&region, R, t.value));
            }
        }
    }

    /// The TLV stage for regions of 0..=8 bytes: one TLV with up to 5 value bytes (CRC32C with its 4-byte value,
    /// AUTHORITY UTF-8 up to 4-byte sequences, UNIQUE_ID, SSL with its 5-byte fixed part), or two short TLVs.
    #[kani::proof]
    #[kani::unwind(10)]
    fn proxy_tlvs_total() {
        proxy_tlvs_case::<0>();
        proxy_tlvs_case::<3>();
        proxy_tlvs_case::<4>();
        proxy_tlvs_case::<6>();
        proxy_tlvs_case::<7>();
        proxy_tlvs_case::<8>();
    }

    /// The TLV stage on a 10-byte region (its own harness to keep each run's memory under the 6 G cap): one TLV with
    /// 7 value bytes (SSL with a sub-TLV), or a CRC32C followed by a second TLV header (a duplicate CRC32C).
    #[kani::proof]
    #[kani::unwind(12)]
    fn proxy_tlvs_10() {
        proxy_tlvs_case::<10>();
    }

    /// One short PROXY input of exactly `len` bytes (a literal at every call site, so symbolic execution sees a
    /// concrete length; a `for len in ..` loop gets its counter merged into a symbolic value and explodes).
    fn proxy_short_case(len: usize) {
        let mut buf: [u8; FIXED_LEN] = kani::any();
        put(&mut buf, 14, &[0, 0]);
        let input = buf.get(..len).unwrap_or(&[]);
        let r = parse_v2(input);
        if let Ok((_, consumed)) = r {
            assert!(len == FIXED_LEN && consumed == FIXED_LEN);
        }
        let v1 = b"PROXY";
        if len > 0 && input.iter().zip(v1.iter()).all(|(a, b)| a == b) {
            assert!(r == Err(ProxyError::V1Refused));
        }
        if len <= SIGNATURE.len() && input.iter().zip(SIGNATURE.iter()).all(|(a, b)| a == b) {
            assert!(r == Err(ProxyError::Incomplete));
        }
    }

    /// PROXY: total on every input of 0..=16 bytes with any signature bytes (mismatch, v1 and fixed-part paths); v1 or
    /// a prefix of it is refused; a prefix of the signature is Incomplete; nothing shorter than 16 is accepted (the
    /// declared length of the 16-byte case is 0).
    #[kani::proof]
    #[kani::unwind(18)]
    fn proxy_short_total() {
        proxy_short_case(0);
        proxy_short_case(1);
        proxy_short_case(2);
        proxy_short_case(3);
        proxy_short_case(4);
        proxy_short_case(5);
        proxy_short_case(6);
        proxy_short_case(7);
        proxy_short_case(8);
        proxy_short_case(9);
        proxy_short_case(10);
        proxy_short_case(11);
        proxy_short_case(12);
        proxy_short_case(13);
        proxy_short_case(14);
        proxy_short_case(15);
        proxy_short_case(16);
    }

    /// A PROXY header declaring `n` body bytes cut at `len` bytes, with 16 + n > len.
    fn proxy_cut_case(n: u16, len: usize) {
        let mut buf: [u8; 24] = kani::any();
        put(&mut buf, 0, &SIGNATURE);
        put(&mut buf, 14, &n.to_be_bytes());
        assert!(FIXED_LEN + usize::from(n) > len);
        let r = parse_v2(buf.get(..len).unwrap_or(&[]));
        assert!(r == Err(ProxyError::Incomplete) || r == Err(ProxyError::Malformed));
    }

    /// PROXY: a declared length that is not all there is never accepted: Incomplete, or Malformed when the fixed
    /// part is already bad (n in {1, 9, 100, 536}, cut at 16, 17, 20, 24 bytes).
    #[kani::proof]
    #[kani::unwind(26)]
    fn proxy_not_all_there_never_ok() {
        proxy_cut_case(1, 16);
        proxy_cut_case(9, 16);
        proxy_cut_case(9, 17);
        proxy_cut_case(9, 24);
        proxy_cut_case(100, 20);
        proxy_cut_case(536, 16);
        proxy_cut_case(536, 24);
    }

    /// A 16-byte PROXY fixed part declaring `n` > 536 (version/command/family bytes symbolic).
    fn proxy_cap_case(n: u16) {
        let mut buf: [u8; FIXED_LEN] = kani::any();
        put(&mut buf, 0, &SIGNATURE);
        put(&mut buf, 14, &n.to_be_bytes());
        assert!(usize::from(n) > MAX_DECLARED_LEN);
        let r = parse_v2(&buf);
        assert!(r == Err(ProxyError::TooLong) || r == Err(ProxyError::Malformed));
    }

    /// PROXY: a declared length over 536 is refused as soon as the fixed part is in, without waiting for the body.
    #[kani::proof]
    #[kani::unwind(18)]
    fn proxy_declared_length_cap() {
        proxy_cap_case(537);
        proxy_cap_case(538);
        proxy_cap_case(4096);
        proxy_cap_case(u16::MAX);
    }

    /// The whole peek on a ClientHello of total length `L` (record length L - 5) with `TAIL` symbolic bytes after it.
    /// Concrete: the record length, the handshake length (L - 9), session_id length 0, cipher_suites length 2,
    /// compression length 1 and, when L > 50, the extensions block length (L - 52). Symbolic: content type, record
    /// version, handshake type, legacy_version, random, the suite and compression bytes, and every byte of the
    /// extensions block (so every extension type and length). Symbolic hello-field lengths are covered by
    /// `peek_body_*`, symbolic block contents of other sizes by `peek_ext_*`.
    fn peek_exact<const L: usize, const B: usize>() {
        assert!(B == L + TAIL && L >= 50);
        let mut buf: [u8; B] = kani::any();
        put(&mut buf, 3, &u16::try_from(L - RECORD_HEADER).unwrap_or(0).to_be_bytes());
        let hl = u32::try_from(L - 9).unwrap_or(0).to_be_bytes();
        put(&mut buf, 6, hl.get(1..).unwrap_or(&[]));
        put(&mut buf, 43, &[0, 0, 2]); // session_id <0>, cipher_suites length 2
        put(&mut buf, 48, &[1]); // compression_methods length 1
        if L > 50 {
            put(&mut buf, 50, &u16::try_from(L - 52).unwrap_or(0).to_be_bytes());
        }
        // One parse (two did not fit the 6 G cap): no read past the declared length is the fields-inside check here
        // plus `peek_record_prefix_determined` (the record stage is the only one that sees the raw input).
        let r = client_hello_with(&buf, &mut ListSet::new());
        if let Ok(p) = r {
            assert!(p.consumed == L);
            assert!(p.consumed <= buf.len() && p.consumed <= RECORD_HEADER + MAX_RECORD);
            assert!(fields_inside(&p, &buf, p.consumed));
        } else {
            assert!(r != Err(PeekError::Incomplete));
        }
    }

    /// The record stage on `L` bytes declared exactly (record length L - 5) plus `TAIL` symbolic bytes: the result on
    /// the whole input equals the result on the declared prefix, and the body is input[5..L].
    fn peek_record_case<const L: usize, const B: usize>() {
        assert!(B == L + TAIL);
        let mut buf: [u8; B] = kani::any();
        put(&mut buf, 3, &u16::try_from(L - RECORD_HEADER).unwrap_or(0).to_be_bytes());
        // Compared by location and length (the same bytes of `buf`), not by content.
        let key = |r: Result<(&[u8], usize), PeekError>| r.map(|(b, c)| (b.as_ptr() as usize, b.len(), c));
        let r = crate::tls_peek::record(&buf);
        assert!(key(r) == key(crate::tls_peek::record(buf.get(..L).unwrap_or(&[]))));
        if let Ok((body, consumed)) = r {
            assert!(consumed == L && body.len() == L - RECORD_HEADER);
            assert!(body.as_ptr() as usize == buf.as_ptr() as usize + RECORD_HEADER);
        }
    }

    /// The record stage reads nothing past its declared length (record lengths 1, 15, 45, 57).
    #[kani::proof]
    #[kani::unwind(8)]
    fn peek_record_prefix_determined() {
        peek_record_case::<6, 8>();
        peek_record_case::<20, 22>();
        peek_record_case::<50, 52>();
        peek_record_case::<62, 64>();
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn peek_exact_50() {
        peek_exact::<50, 52>();
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn peek_exact_56() {
        peek_exact::<56, 58>();
    }

    #[kani::proof]
    #[kani::unwind(14)]
    fn peek_exact_62() {
        peek_exact::<62, 64>();
    }

    /// `hello_body` on a record body of exactly `P` symbolic bytes (every length field symbolic).
    fn peek_body_case<const P: usize>() {
        let payload: [u8; P] = kani::any();
        if let Ok(Some(block)) = crate::tls_peek::hello_body(&payload) {
            assert!(inside(&payload, P, block));
        }
    }

    /// The hello body stage: total, and the extensions block lies inside the record body, for bodies of 44 (one
    /// short of a minimal hello) to 64 bytes.
    #[kani::proof]
    #[kani::unwind(4)]
    fn peek_body_total() {
        peek_body_case::<44>();
        peek_body_case::<45>();
        peek_body_case::<47>();
        peek_body_case::<51>();
        peek_body_case::<57>();
        peek_body_case::<64>();
    }

    /// `extensions` on a block of exactly `E` symbolic bytes: total, and every field inside the block (the list
    /// iterators over the fields are bounded by `peek_iterators_total`).
    fn peek_ext_case<const E: usize>() {
        let block: [u8; E] = kani::any();
        if let Ok(p) = crate::tls_peek::extensions(&block, 7, &mut ListSet::new()) {
            assert!(p.consumed == 7);
            assert!(fields_inside(&p, &block, E));
        }
    }

    /// Every extracted field lies inside `base[..len]` (written out per field: an iterator over the six fields is a
    /// loop Kani unrolls at every symbolic length).
    fn fields_inside(p: &crate::tls_peek::Peek<'_>, base: &[u8], len: usize) -> bool {
        let ok = |f: Option<&[u8]>| f.is_none_or(|f| inside(base, len, f));
        ok(p.sni) && ok(p.alpn) && ok(p.versions) && ok(p.sigalgs) && ok(p.groups) && ok(p.trust_anchors)
    }

    /// The list iterators are total on any field bytes (they read through the bounds-checked reader): every field
    /// set to a symbolic slice of 0..=6 bytes.
    fn peek_iter_case<const K: usize>() {
        let f: [u8; K] = kani::any();
        let s = Some(f.as_slice());
        let p = crate::tls_peek::Peek {
            sni: s,
            alpn: s,
            versions: s,
            sigalgs: s,
            groups: s,
            trust_anchors: s,
            consumed: 0,
        };
        for a in p.alpn_protocols() {
            assert!(inside(&f, K, a));
        }
        for i in p.trust_anchor_ids() {
            assert!(inside(&f, K, i));
        }
        let n = p.version_list().count() + p.sigalg_list().count() + p.group_list().count();
        assert!(n <= 3 * (K / 2));
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn peek_iterators_total() {
        peek_iter_case::<0>();
        peek_iter_case::<1>();
        peek_iter_case::<2>();
        peek_iter_case::<3>();
        peek_iter_case::<6>();
    }

    /// The extensions stage for blocks of 0..=8 bytes (no extension, one with up to 4 data bytes, two empty ones;
    /// reaches ALPN, the u16 lists and trust_anchors). The block sizes are split over three harnesses so each run
    /// stays well under the 6 G cap (all of them in one harness peaked at 5.3 G).
    #[kani::proof]
    #[kani::unwind(10)]
    fn peek_ext_total() {
        peek_ext_case::<0>();
        peek_ext_case::<4>();
        peek_ext_case::<5>();
        peek_ext_case::<6>();
        peek_ext_case::<8>();
    }

    /// Blocks of 9 and 10 bytes: server_name with a one-byte name (10), ALPN with two names, two short extensions.
    #[kani::proof]
    #[kani::unwind(12)]
    fn peek_ext_10() {
        peek_ext_case::<9>();
        peek_ext_case::<10>();
    }

    /// A 12-byte block: three empty extensions (a duplicate among them), or one with 8 data bytes.
    #[kani::proof]
    #[kani::unwind(14)]
    fn peek_ext_12() {
        peek_ext_case::<12>();
    }

    /// A ClientHello input of `len` bytes whose record header (if present) declares `n` > len - 5 body bytes.
    fn peek_cut_case(n: u16, len: usize) {
        let mut buf: [u8; 24] = kani::any();
        put(&mut buf, 3, &n.to_be_bytes());
        assert!(RECORD_HEADER + usize::from(n) > len);
        let r = client_hello(buf.get(..len).unwrap_or(&[]));
        assert!(r.is_err());
        let hs = buf.first() == Some(&0x16);
        let ver = matches!(buf.get(1..3), Some([0x03, 0x01..=0x03]));
        if (len < RECORD_HEADER && (len == 0 || hs)) || (len >= RECORD_HEADER && hs && ver) {
            assert!(r == Err(PeekError::Incomplete));
        }
    }

    /// ClientHello: total on every input of 0..=4 bytes, and a record that is not all there is never accepted; with a
    /// handshake header it is Incomplete (n in {20, 1000, 16384}).
    #[kani::proof]
    #[kani::unwind(26)]
    fn peek_not_all_there_never_ok() {
        peek_cut_case(20, 0);
        peek_cut_case(20, 1);
        peek_cut_case(20, 2);
        peek_cut_case(20, 3);
        peek_cut_case(20, 4);
        peek_cut_case(20, 5);
        peek_cut_case(20, 6);
        peek_cut_case(20, 24);
        peek_cut_case(1000, 5);
        peek_cut_case(1000, 24);
        peek_cut_case(16384, 9);
        peek_cut_case(16384, 24);
    }

    /// A 5-byte record header declaring `n` > 16384 (content type and version symbolic).
    fn peek_cap_case(n: u16) {
        let mut buf: [u8; RECORD_HEADER] = kani::any();
        put(&mut buf, 3, &n.to_be_bytes());
        assert!(usize::from(n) > MAX_RECORD);
        let r = client_hello(&buf);
        assert!(r == Err(PeekError::TooLong) || r == Err(PeekError::NotClientHello));
    }

    /// ClientHello: a record length over 16 KiB is refused from the 5-byte header alone (never Incomplete, never Ok).
    #[kani::proof]
    #[kani::unwind(8)]
    fn peek_record_length_cap() {
        peek_cap_case(16385);
        peek_cap_case(20000);
        peek_cap_case(u16::MAX);
    }

    /// A planted copy of a consumed-length computation with an off-by-one (the bug class PROXY-3 / L4-1 bound).
    #[cfg(aegis_kani_negative)]
    fn planted_consumed(input: &[u8]) -> usize {
        input.len() + 1
    }

    #[kani::proof]
    fn negative_control_planted_oob() {
        #[cfg(aegis_kani_negative)]
        {
            let buf: [u8; 8] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= 8);
            let input = buf.get(..len).unwrap_or(&[]);
            let consumed = planted_consumed(input);
            assert!(consumed <= input.len(), "NEGATIVE CONTROL: consumed past the input");
        }
    }
}
