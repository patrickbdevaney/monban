//! SASLprep (RFC 4013, a stringprep profile of RFC 3454) as PostgreSQL applies it to SCRAM passwords
//! (src/common/saslprep.c `pg_saslprep`, used the same way by libpq and by the server when it stores a SCRAM secret;
//! PREFLIGHT R14).
//!
//! PostgreSQL's procedure, mirrored here:
//! 1. a pure-ASCII password is used as is;
//! 2. map: non-ASCII space (C.1.2) -> U+0020, "commonly mapped to nothing" (B.1) -> removed; an empty result is
//!    prohibited;
//! 3. normalize with Unicode NFKC;
//! 4. prohibit C.1.2, C.2.1, C.2.2, C.3-C.9 and the code points unassigned in Unicode 3.2 (A.1);
//! 5. bidi: a string with a RandALCat character (D.1) has no LCat character (D.2) and starts and ends with RandALCat.
//!
//! If steps 2-5 succeed the prepared string's UTF-8 is hashed; if the password is prohibited, both libpq and the
//! server fall back to the raw password bytes. [`scram_password`] returns those bytes.
//!
//! Exactness, fail closed: the NFKC tables are generated from Unicode [`tables::UNICODE_VERSION`]
//! (`gen_tables.py`, Python's `unicodedata`; the RFC 3454 tables from Python's `stringprep`). Two inputs are refused
//! ([`Prep::Ambiguous`]) instead of guessed: a code point unassigned in that Unicode version (a newer server may
//! normalize it differently), and a string whose step 4/5 verdict differs between checking the mapped input and
//! the NFKC output (the RFC checks the output; refusing avoids depending on which one a server checks).
//! Verified against Python's own NFKC: every scalar value singly (a sha256 over all of them) and 2,800+ generated
//! strings (`vectors.txt`).

#[rustfmt::skip]
mod tables;

/// The SASLprep verdict for one password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prep {
    /// Pure ASCII: used unchanged.
    Ascii,
    /// Prepared (steps 2-5 succeeded): the normalized string.
    Prepared(String),
    /// Prohibited output, bidi violation or empty after mapping: PostgreSQL uses the raw password.
    Prohibited,
    /// Refused by this client (see the module docs); the reason.
    Ambiguous(&'static str),
}

fn in_ranges(t: &[(u32, u32)], c: u32) -> bool {
    t.binary_search_by(|&(a, b)| {
        if b < c {
            core::cmp::Ordering::Less
        } else if a > c {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    })
    .is_ok()
}

fn ccc(c: u32) -> u8 {
    match tables::CCC.binary_search_by(|&(a, b, _)| {
        if b < c {
            core::cmp::Ordering::Less
        } else if a > c {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    }) {
        Ok(i) => tables::CCC.get(i).map_or(0, |e| e.2),
        Err(_) => 0,
    }
}

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

fn decompose(c: u32, out: &mut Vec<u32>) {
    if (S_BASE..S_BASE + S_COUNT).contains(&c) {
        let s = c - S_BASE;
        out.push(L_BASE + s / N_COUNT);
        out.push(V_BASE + (s % N_COUNT) / T_COUNT);
        if !s.is_multiple_of(T_COUNT) {
            out.push(T_BASE + s % T_COUNT);
        }
        return;
    }
    match tables::DECOMP.binary_search_by_key(&c, |&(k, _)| k) {
        Ok(i) => {
            let v = tables::DECOMP.get(i).map_or(0, |e| e.1);
            let (off, len) = ((v >> 8) as usize, (v & 0xFF) as usize);
            match tables::DECOMP_DATA.get(off..off + len) {
                Some(d) => out.extend_from_slice(d),
                None => out.push(c),
            }
        }
        Err(_) => out.push(c),
    }
}

fn compose_pair(a: u32, b: u32) -> Option<u32> {
    if (L_BASE..L_BASE + L_COUNT).contains(&a) && (V_BASE..V_BASE + V_COUNT).contains(&b) {
        return Some(S_BASE + ((a - L_BASE) * V_COUNT + (b - V_BASE)) * T_COUNT);
    }
    if (S_BASE..S_BASE + S_COUNT).contains(&a)
        && (a - S_BASE).is_multiple_of(T_COUNT)
        && (T_BASE + 1..T_BASE + T_COUNT).contains(&b)
    {
        return Some(a + (b - T_BASE));
    }
    tables::COMPOSE
        .binary_search_by(|&(x, y, _)| (x, y).cmp(&(a, b)))
        .ok()
        .and_then(|i| tables::COMPOSE.get(i))
        .map(|e| e.2)
}

/// Unicode NFKC (UAX #15): full compatibility decomposition, canonical ordering, canonical composition.
pub fn nfkc(input: &[u32]) -> Vec<u32> {
    let mut d = Vec::with_capacity(input.len());
    for &c in input {
        decompose(c, &mut d);
    }
    // Canonical ordering: stable sort of every run of non-starters by combining class.
    let mut i = 0;
    while i < d.len() {
        if ccc(d.get(i).copied().unwrap_or(0)) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < d.len() && ccc(d.get(i).copied().unwrap_or(0)) != 0 {
            i += 1;
        }
        if let Some(run) = d.get_mut(start..i) {
            run.sort_by_key(|&c| ccc(c));
        }
    }
    // Canonical composition.
    let mut out: Vec<u32> = Vec::with_capacity(d.len());
    let mut starter: Option<usize> = None;
    let mut last: Option<u8> = None; // class of the last character appended after the starter
    for c in d {
        let cc = ccc(c);
        if let Some(sp) = starter {
            let blocked = matches!(last, Some(l) if l == 0 || l >= cc);
            if !blocked
                && let Some(s) = out.get(sp).copied()
                && let Some(composed) = compose_pair(s, c)
                && let Some(slot) = out.get_mut(sp)
            {
                *slot = composed;
                continue;
            }
        }
        if cc == 0 {
            starter = Some(out.len());
            last = None;
        } else {
            last = Some(cc);
        }
        out.push(c);
    }
    out
}

/// Steps 4 and 5 on one code point sequence: `true` when allowed.
fn allowed(s: &[u32]) -> bool {
    if s.iter().any(|&c| in_ranges(tables::PROHIBITED, c) || in_ranges(tables::A1, c)) {
        return false;
    }
    if s.iter().any(|&c| in_ranges(tables::D1, c)) {
        if s.iter().any(|&c| in_ranges(tables::D2, c)) {
            return false;
        }
        let ends = s.first().zip(s.last());
        if !ends.is_some_and(|(&a, &b)| in_ranges(tables::D1, a) && in_ranges(tables::D1, b)) {
            return false;
        }
    }
    true
}

/// PostgreSQL's SASLprep of `password`.
pub fn saslprep(password: &str) -> Prep {
    if password.is_ascii() {
        return Prep::Ascii;
    }
    let mut mapped = Vec::with_capacity(password.len());
    for ch in password.chars() {
        let c = u32::from(ch);
        if in_ranges(tables::C12, c) {
            mapped.push(0x20);
        } else if !in_ranges(tables::B1, c) {
            mapped.push(c);
        }
    }
    if mapped.iter().any(|&c| in_ranges(tables::UNASSIGNED_NOW, c)) {
        return Prep::Ambiguous("a code point unassigned in the client's Unicode tables");
    }
    if mapped.is_empty() {
        return Prep::Prohibited;
    }
    let out = nfkc(&mapped);
    let (before, after) = (allowed(&mapped), allowed(&out));
    if before != after {
        return Prep::Ambiguous("the prohibition verdict differs before and after NFKC");
    }
    if !after {
        return Prep::Prohibited;
    }
    match out.iter().map(|&c| char::from_u32(c)).collect::<Option<String>>() {
        Some(s) => Prep::Prepared(s),
        None => Prep::Ambiguous("normalization produced a non-scalar value"),
    }
}

/// The bytes PostgreSQL hashes for `password` (SaltedPassword input): the prepared string, or the raw password when
/// SASLprep prohibits it (libpq and the server both fall back to the raw bytes). `Err` with the reason for an
/// input this client refuses ([`Prep::Ambiguous`]).
pub fn scram_password(password: &str) -> Result<Vec<u8>, &'static str> {
    match saslprep(password) {
        Prep::Ascii | Prep::Prohibited => Ok(password.as_bytes().to_vec()),
        Prep::Prepared(s) => Ok(s.into_bytes()),
        Prep::Ambiguous(why) => Err(why),
    }
}

/// The Unicode version of the normalization tables.
pub fn unicode_version() -> &'static str {
    tables::UNICODE_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).filter_map(|i| s.get(2 * i..2 * i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect()
    }

    #[test]
    fn rfc4013_examples() {
        assert_eq!(saslprep("I\u{AD}X"), Prep::Prepared("IX".into()), "1: SOFT HYPHEN mapped to nothing");
        assert_eq!(saslprep("user"), Prep::Ascii, "2");
        assert_eq!(saslprep("USER"), Prep::Ascii, "3: case preserved");
        assert_eq!(saslprep("\u{AA}"), Prep::Prepared("a".into()), "4: output is NFKC");
        assert_eq!(saslprep("\u{2168}"), Prep::Prepared("IX".into()), "5: output is NFKC");
        // 6: U+0007 is prohibited by the RFC; PostgreSQL's ASCII fast path uses it as is (same bytes either way).
        assert_eq!(saslprep("\u{7}"), Prep::Ascii);
        assert_eq!(scram_password("\u{7}"), Ok(vec![7]));
        assert_eq!(saslprep("\u{627}1"), Prep::Prohibited, "7: bidi rule");
        assert_eq!(scram_password("\u{627}1"), Ok("\u{627}1".as_bytes().to_vec()), "prohibited: raw bytes");
        assert_eq!(saslprep("\u{AD}"), Prep::Prohibited, "empty after mapping");
        assert_eq!(saslprep("a\u{A0}b"), Prep::Prepared("a b".into()), "non-ASCII space");
        assert_eq!(saslprep("\u{1100}\u{1161}\u{11A8}"), Prep::Prepared("\u{AC01}".into()), "Hangul composes");
        assert_eq!(saslprep("e\u{323}\u{302}"), Prep::Prepared("\u{1EC7}".into()), "reorder then compose");
    }

    /// Every vector generated by gen_tables.py with Python's own NFKC and stringprep predicates.
    #[test]
    fn python_reference_vectors() -> Result<(), String> {
        let mut n = 0;
        for line in include_str!("vectors.txt").lines().filter(|l| !l.starts_with('#')) {
            let mut f = line.split(' ');
            let (Some(i), Some(v), Some(o)) = (f.next(), f.next(), f.next()) else {
                return Err(format!("bad vector {line}"));
            };
            let input = String::from_utf8(unhex(i)).unwrap_or_default();
            let got = saslprep(&input);
            match v {
                "ascii" => assert_eq!(got, Prep::Ascii, "{line}"),
                "prohibited" => assert_eq!(got, Prep::Prohibited, "{line}"),
                "ambiguous" => assert!(matches!(got, Prep::Ambiguous(_)), "{line}: {got:?}"),
                "ok" => assert_eq!(got, Prep::Prepared(String::from_utf8(unhex(o)).unwrap_or_default()), "{line}"),
                other => return Err(format!("bad verdict {other}")),
            }
            n += 1;
        }
        assert!(n > 2000, "only {n} vectors");
        Ok(())
    }

    /// NFKC of every Unicode scalar value, hashed the way gen_tables.py hashed Python's NFKC.
    #[test]
    fn nfkc_every_scalar_value_matches_python() {
        let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        let mut buf = [0u8; 4];
        for c in (0u32..0x11_0000).filter(|c| !(0xD800..=0xDFFF).contains(c)) {
            ctx.update(&c.to_be_bytes());
            for o in nfkc(&[c]) {
                if let Some(ch) = char::from_u32(o) {
                    ctx.update(ch.encode_utf8(&mut buf).as_bytes());
                }
            }
        }
        let got: String = ctx.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got,
            tables::NFKC_SINGLE_SHA256,
            "NFKC tables disagree with Python unicodedata {}",
            unicode_version()
        );
    }

    #[test]
    fn tables_are_sorted() {
        assert!(tables::DECOMP.windows(2).all(|w| matches!(w, [a, b] if a.0 < b.0)));
        assert!(tables::COMPOSE.windows(2).all(|w| matches!(w, [a, b] if (a.0, a.1) < (b.0, b.1))));
        for t in
            [tables::B1, tables::C12, tables::PROHIBITED, tables::A1, tables::D1, tables::D2, tables::UNASSIGNED_NOW]
        {
            assert!(t.windows(2).all(|w| matches!(w, [a, b] if a.0 <= a.1 && a.1 < b.0)));
        }
    }
}
