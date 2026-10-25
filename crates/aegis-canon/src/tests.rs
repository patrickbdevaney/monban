//! Unit vectors (from the canon-diff README, ledger and reference), CANON-7 idempotence, and a deterministic
//! random-bytes totality loop per kind (>= 100k inputs each).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

extern crate std;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use std::println;

use super::*;

fn ok_path(x: &str) -> String {
    String::from_utf8(canon_path(x.as_bytes()).unwrap().as_bytes().to_vec()).unwrap()
}

fn rej_str<T: core::fmt::Debug>(r: Result<T, Reject>) -> String {
    format!("{}", r.unwrap_err())
}

#[test]
fn path_vectors() {
    assert_eq!(ok_path("/admin/"), "/admin/");
    assert_eq!(ok_path("/"), "/");
    assert_eq!(ok_path("/%ef%bc%a1dmin"), "/%EF%BC%A1dmin");
    assert_eq!(ok_path("/%41%7e"), "/A~");
    assert_eq!(ok_path("/%e2%80%8b"), "/%E2%80%8B");
    assert_eq!(rej_str(canon_path(b"//admin")), "308 path: empty segment, redirect to /admin");
    assert_eq!(rej_str(canon_path(b"///////")), "308 path: empty segment, redirect to /");
    assert_eq!(rej_str(canon_path(b"//x/")), "308 path: empty segment, redirect to /x/");
    assert_eq!(canon_path(b"//admin").unwrap_err().redirect_target(), Some(&b"/admin"[..]));
    for bad in ["/a/./b", "/a/..", "/%2e%2E", "/a%2Fb", "/a%5cb", "/a;b", "/a\\b", "/%00", "/%25", "a", "", "/a?b"] {
        assert_eq!(canon_path(bad.as_bytes()).unwrap_err().status(), 400, "{bad}");
    }
    // Encoded octets: strict UTF-8 and NFC only.
    assert!(canon_path(b"/foo%C2%91%91").is_err());
    assert!(canon_path(b"/%ED%A0%80").is_err()); // surrogate
    assert!(canon_path(b"/%C0%AF").is_err()); // overlong
    assert!(canon_path(b"/e%CC%81").is_err()); // e + combining acute: not NFC
    assert!(canon_path(b"/%C3%A9").is_ok()); // precomposed
    assert!(canon_path("/\u{e9}".as_bytes()).is_err()); // raw non-ASCII
    let long = format!("/{}", "a".repeat(8192));
    assert_eq!(canon_path(long.as_bytes()).unwrap_err().status(), 414);
}

#[test]
fn query_vectors() {
    let o = |x: &str| {
        canon_query(x.as_bytes(), QueryMode::Opaque).map(|c| String::from_utf8(c.as_bytes().to_vec()).unwrap())
    };
    let t = |x: &str| {
        canon_query(x.as_bytes(), QueryMode::Typed).map(|c| String::from_utf8(c.as_bytes().to_vec()).unwrap())
    };
    assert_eq!(o("").unwrap(), "");
    assert_eq!(o("b=2&a=1").unwrap(), "b=2&a=1");
    assert_eq!(o("a=1&%61=2").unwrap(), "a=1&a=2");
    assert_eq!(o("a=1;b=2").unwrap(), "a=1;b=2");
    assert_eq!(o("a+b=1").unwrap(), "a+b=1");
    assert_eq!(o("a=%c3%a9").unwrap(), "a=%C3%A9");
    assert_eq!(o("q").unwrap(), "q");
    for bad in ["a=%2B", "a=%00", "&a", "a&&b", "a&", "=v", "a b", "a#", "%zz", "a=\u{e9}"] {
        assert!(o(bad).is_err(), "{bad}");
    }
    assert_eq!(t("b=2&a=%41").unwrap(), "b=2&a=A");
    for bad in ["a=1&a=2", "a=1&%61=2", "a", "a=1;b=2", "a+b=1", "a=%26", "a=%3D", "=1", "a=b=c", "a=%C3%A9"] {
        assert!(t(bad).is_err(), "{bad}");
    }
}

#[test]
fn host_vectors() {
    let h = |x: &str| canon_sni(x.as_bytes()).map(|c| String::from_utf8(c.as_bytes().to_vec()).unwrap());
    assert_eq!(h("EXAMPLE.com").unwrap(), "example.com");
    assert_eq!(h("xn--fa-hia.de").unwrap(), "xn--fa-hia.de");
    assert_eq!(h("xn--mnchen-3ya.de").unwrap(), "xn--mnchen-3ya.de");
    assert_eq!(h("127.0.0.1").unwrap(), "127.0.0.1");
    for bad in [
        "example.com.",
        "faß.de",
        "\u{212a}example.com",
        "0x7f.0.0.1",
        "127.1",
        "127.0.0.01",
        "256.0.0.1",
        "1.2.3.4.5",
        "ab--c.com",
        "xn--",
        "xn--a",
        "-a.com",
        "a-.com",
        "a..b",
        "",
        "a_b",
        "example.com\n",
        "xn--Fa-hia.de\u{0}",
    ] {
        assert!(h(bad).is_err(), "{bad:?}");
    }
    // Uppercase A-label input is lowercased (ASCII only) and then checked structurally.
    assert_eq!(h("XN--FA-HIA.DE").unwrap(), "xn--fa-hia.de");
    // A punycode label that decodes to uppercase (not lowercase) is malformed.
    assert!(h("xn--Fa-hia.de").is_ok()); // ASCII-lowercased first, so this is the same label
}

#[test]
fn authority_origin_vectors() {
    let a = |x: &str, s| canon_authority(x.as_bytes(), s).map(|c| String::from_utf8(c.as_bytes().to_vec()).unwrap());
    assert_eq!(a("Example.com:443", Scheme::Https).unwrap(), "example.com");
    assert_eq!(a("example.com:443", Scheme::Http).unwrap(), "example.com:443");
    assert_eq!(a("example.com:8443", Scheme::Https).unwrap(), "example.com:8443");
    for bad in ["u@example.com", "[::1]", "example.com:", "example.com:0443", "example.com:0", "example.com:99999"] {
        assert!(a(bad, Scheme::Https).is_err(), "{bad}");
    }
    let o = |x: &str| canon_origin(x.as_bytes()).map(|c| String::from_utf8(c.as_bytes().to_vec()).unwrap());
    assert_eq!(o("HTTPS://EXAMPLE.com:443").unwrap(), "https://example.com");
    assert_eq!(o("http://example.com:8080").unwrap(), "http://example.com:8080");
    for bad in ["null", "https://example.com/", "wss://example.com", "https://u@example.com", "https://ex%61mple.com"] {
        assert_eq!(canon_origin(bad.as_bytes()).unwrap_err().status(), 403, "{bad}");
    }
}

#[test]
fn cookie_media_tenant_vectors() {
    let c = |x: &str| canon_cookie(x.as_bytes()).map(|c| String::from_utf8(c.as_bytes().to_vec()).unwrap());
    assert_eq!(c(" sid=1;x=abc ").unwrap(), "sid=1; x=abc");
    assert_eq!(c("__Host-sid=1").unwrap(), "__Host-sid=1");
    for bad in
        ["sid=1; SID=2", "__host-sid=1", "$Version=1", "a%5F=1", "a=\"q\"", "a =1", "a=1 2", "a\u{a0}=1", ";", "x"]
    {
        assert!(c(bad).is_err(), "{bad}");
    }
    let m = |x: &str| canon_media_type(x.as_bytes()).map(|c| String::from_utf8(c.as_bytes().to_vec()).unwrap());
    assert_eq!(m("APPLICATION/JSON;Charset=UTF-8").unwrap(), "application/json; charset=utf-8");
    assert_eq!(m("multipart/form-data; boundary=AbC").unwrap(), "multipart/form-data; boundary=AbC");
    for bad in ["*/*", "application /json", "a/b;", "a/b; charset=\"x\"", "a/b; x", "a/b;a=1;A=2", " a/b"] {
        assert_eq!(canon_media_type(bad.as_bytes()).unwrap_err().status(), 415, "{bad}");
    }
    assert!(canon_tenant(b"acme-1").is_ok());
    for bad in ["Acme", "-a", "a-", "", "a_b", "\u{212a}"] {
        assert!(canon_tenant(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn header_vectors() {
    let h = |ls: &[&str]| {
        let v: Vec<&[u8]> = ls.iter().map(|s| s.as_bytes()).collect();
        canon_headers(&v)
    };
    let c = h(&["Host: example.com", "Accept: a", "accept: b", "X:\tv "]).unwrap();
    let f: Vec<(&[u8], &[u8])> = header_fields(&c).collect();
    assert_eq!(f, vec![(&b"host"[..], &b"example.com"[..]), (b"accept", b"a"), (b"accept", b"b"), (b"x", b"v")]);
    for bad in [
        &["Host: a", "host: b"][..],
        &["Content-Length: 5", "Transfer-Encoding: chunked"],
        &["Transfer-Encoding: Chunked"],
        &["Content-Length: 05"],
        &[" folded"],
        &["Host : a"],
        &["X: caf\u{e9}"],
        &["Host:"],
    ] {
        assert!(h(bad).is_err(), "{bad:?}");
    }
    assert_eq!(header_fields(&h(&["X:"]).unwrap()).collect::<Vec<_>>(), vec![(&b"x"[..], &b""[..])]);
}

#[test]
fn json_vectors() {
    let j = |x: &str| canon_json(x.as_bytes()).map(|c| String::from_utf8(c.as_bytes().to_vec()).unwrap());
    assert_eq!(j(r#" {"b":1, "a":[true,false,null]} "#).unwrap(), r#"{"a":[true,false,null],"b":1}"#);
    assert_eq!(
        j(r#"{"a":1e2,"b":1.5e300,"c":0.0001,"d":1e16,"e":1E-5,"f":1.0,"g":-2.50}"#).unwrap(),
        r#"{"a":100.0,"b":1.5e+300,"c":0.0001,"d":1e+16,"e":1e-05,"f":1.0,"g":-2.5}"#
    );
    assert_eq!(j(r#""\u00e9\uDBFF\uDFFF\/\u001f\u007f""#).unwrap(), "\"\u{e9}\u{10ffff}/\\u001f\u{7f}\"");
    assert_eq!(j("9007199254740991").unwrap(), "9007199254740991");
    assert_eq!(j("123456789012345680.0").unwrap(), "1.2345678901234568e+17");
    assert_eq!(j("0.1").unwrap(), "0.1");
    // Two 17-digit strings round-trip; the closest to the binary value wins (CPython repr), not the first found.
    assert_eq!(j("1840145148449258.2").unwrap(), "1840145148449258.2");
    assert_eq!(j("94483824082457.12").unwrap(), "94483824082457.12");
    assert_eq!(j("5e-324").unwrap(), "5e-324");
    assert_eq!(j("0.0").unwrap(), "0.0");
    for bad in [
        r#"{"a":1,"a":2}"#,
        r#"{"role":1,"r\u006fle":2}"#,
        r#"{"role":1,"ROLE":2}"#,
        r#""\ud800""#,
        r#""\udc00""#,
        r#""\ud800\u0041""#,
        r#""a\u0000""#,
        "-0",
        "-0.0",
        "1e400",
        "0.1e-400",
        "9007199254740992",
        "12345678901234567890.5",
        "NaN",
        "Infinity",
        "[1,]",
        r#"{"a":1,}"#,
        "01",
        "1.",
        ".5",
        "1e",
        "",
        "{}{}",
        "\u{feff}{}",
        "\"a\u{1}\"",
        "'a'",
        "[1 2]",
        "tru",
        "\"\\x\"",
    ] {
        assert!(j(bad).is_err(), "{bad:?}");
    }
    // Depth: the top-level value is depth 0; any node deeper than 64 is rejected.
    let ok = format!("{}{}", "[".repeat(65), "]".repeat(65));
    assert!(j(&ok).is_ok());
    let deep = format!("{}{}", "[".repeat(66), "]".repeat(66));
    assert!(j(&deep).is_err());
    let deep_scalar = format!("{}1{}", "[".repeat(65), "]".repeat(65));
    assert!(j(&deep_scalar).is_err());
    assert!(canon_json(&[b'"', 0xFF, b'"']).is_err());
    let big = format!("\"{}\"", "a".repeat(1 << 20));
    assert_eq!(canon_json(big.as_bytes()).unwrap_err().status(), 413);
}

fn vh() -> Vec<(&'static [u8], Vec<&'static [u8]>)> {
    vec![
        (b"example.com", vec![b"https://example.com"]),
        (b"api.example.com", vec![b"https://example.com", b"https://api.example.com"]),
        (b"example.com:8443", vec![b"https://example.com:8443"]),
    ]
}

#[test]
fn request_vectors() {
    let table = vh();
    let vhosts: Vec<Vhost<'_>> = table.iter().map(|(a, o)| Vhost { authority: a, origins: o }).collect();
    let base = RequestIdentity {
        proto: Proto::H2,
        scheme: Scheme::Https,
        sni: Some(b"example.com"),
        authority: Some(b"EXAMPLE.com:443"),
        host: &[],
        origin: Some(b"https://EXAMPLE.com:443"),
    };
    assert_eq!(canon_request(&base, &vhosts).unwrap().as_bytes(), b"example.com");
    let code = |r: RequestIdentity<'_>| canon_request(&r, &vhosts).unwrap_err().status();
    assert_eq!(code(RequestIdentity { sni: Some(b"evil.example"), ..base }), 421);
    assert_eq!(code(RequestIdentity { origin: Some(b"https://evil.example"), ..base }), 421);
    assert_eq!(code(RequestIdentity { origin: Some(b"null"), ..base }), 403);
    assert_eq!(code(RequestIdentity { authority: Some(b"evil.example"), ..base }), 421);
    assert_eq!(code(RequestIdentity { proto: Proto::H1, authority: None, host: &[b"evil.example"], ..base }), 404);
    assert_eq!(code(RequestIdentity { authority: Some(b"u@example.com"), ..base }), 400);
    assert_eq!(code(RequestIdentity { host: &[b"api.example.com"], ..base }), 400);
    assert_eq!(code(RequestIdentity { proto: Proto::H1, authority: None, host: &[b"a", b"a"], ..base }), 400);
    assert_eq!(
        code(RequestIdentity { scheme: Scheme::Http, authority: Some(b"example.com"), origin: None, ..base }),
        400
    ); // SNI on cleartext
    assert!(Proto::parse(b"h3").is_err() && Scheme::parse(b"ftp").is_err());
}

// ---------------------------------------------------------------- deterministic random-bytes properties

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
}

const PIECES: &[&[u8]] = &[
    b"/",
    b"//",
    b"%",
    b"%2F",
    b"%2e",
    b"%25",
    b"%41",
    b"%c3%a9",
    b"%e2%80%8b",
    b"%CC%81",
    b"%ED%A0%80",
    b"%FF",
    b".",
    b"..",
    b";",
    b"\\",
    b"?",
    b"#",
    b"&",
    b"=",
    b"+",
    b"a",
    b"Z",
    b"0",
    b"9",
    b"-",
    b"_",
    b"~",
    b":",
    b"@",
    b"[",
    b"]",
    b" ",
    b"\t",
    b"\"",
    b"xn--",
    b"xn--fa-hia",
    b"de",
    b"com",
    b"0x",
    b"255",
    b"\xc3\xa9",
    b"\xe2\x84\xaa",
    b"\xff",
    b"\x00",
    b"\r\n",
    b"{",
    b"}",
    b"[",
    b"]",
    b",",
    b"\\u00e9",
    b"\\ud800",
    b"1e400",
    b"-0",
    b"1.5",
    b"true",
    b"null",
    b"https://",
    b"http://",
    b"__Host-",
    b"$",
    b"charset",
    b"chunked",
    b"Host: ",
    b"Content-Length: ",
];

fn gen_input(rng: &mut Rng) -> Vec<u8> {
    let mut v = Vec::new();
    if rng.below(2) == 0 {
        v.push(b'/'); // reach deeper into the path grammar
    }
    if rng.below(4) == 0 {
        for _ in 0..rng.below(40) {
            v.push((rng.next() & 0xFF) as u8);
        }
    } else {
        for _ in 0..rng.below(12) {
            v.extend_from_slice(PIECES[rng.below(PIECES.len())]);
        }
    }
    v
}

const N: usize = 100_000;

fn prop<K: CanonKind>(seed: u64, f: impl Fn(&[u8]) -> Result<Canon<K>, Reject>) -> usize {
    let mut rng = Rng(seed);
    let mut accepted = 0usize;
    for _ in 0..N {
        let x = gen_input(&mut rng);
        match f(&x) {
            Ok(c) => {
                accepted += 1;
                let again = f(c.as_bytes()).unwrap_or_else(|e| panic!("CANON-7: {:?} -> {:?} -> {e}", x, c.as_bytes()));
                assert_eq!(again.as_bytes(), c.as_bytes(), "CANON-7 on {x:?}");
            }
            Err(e) => {
                assert!(matches!(e.status(), 308 | 400 | 403 | 404 | 413 | 414 | 415 | 421));
                assert_eq!(e.redirect_target().is_some(), e.status() == 308);
                if let Some(t) = e.redirect_target() {
                    let c = f(t).unwrap_or_else(|e2| panic!("308 target {t:?} of {x:?} rejected: {e2}"));
                    assert_eq!(c.as_bytes(), t);
                }
                let _ = format!("{e}");
            }
        }
    }
    accepted
}

#[test]
fn random_bytes_totality_and_idempotence() {
    let n = [
        ("path", prop(1, canon_path)),
        ("query", prop(2, |x| canon_query(x, QueryMode::Opaque))),
        ("query_typed", prop(3, |x| canon_query(x, QueryMode::Typed))),
        ("sni", prop(4, canon_sni)),
        ("authority", prop(5, |x| canon_authority(x, Scheme::Https))),
        ("origin", prop(6, canon_origin)),
        ("cookie", prop(7, canon_cookie)),
        ("media", prop(8, canon_media_type)),
        ("json", prop(9, canon_json)),
    ];
    println!("accepted per kind over {N} random inputs: {n:?}");
    // Tenant has no Canon kind.
    let mut rng = Rng(10);
    for _ in 0..N {
        let x = gen_input(&mut rng);
        if let Ok(t) = canon_tenant(&x) {
            assert_eq!(t.as_bytes(), &x[..]);
        }
    }
    // Header set: random field lines; the canonical re-serialization must be accepted unchanged.
    let mut rng = Rng(11);
    for _ in 0..N {
        let lines: Vec<Vec<u8>> = (0..rng.below(5)).map(|_| gen_input(&mut rng)).collect();
        let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
        if let Ok(c) = canon_headers(&refs) {
            let back: Vec<Vec<u8>> = header_fields(&c).map(|(n, v)| [n, b": ", v].concat()).collect();
            let back_refs: Vec<&[u8]> = back.iter().map(Vec::as_slice).collect();
            assert_eq!(canon_headers(&back_refs).unwrap().as_bytes(), c.as_bytes());
        }
    }
    // Request binding: random parts; an accepted binding re-checked as h2 with Host = the canonical authority.
    let table = vh();
    let vhosts: Vec<Vhost<'_>> = table.iter().map(|(a, o)| Vhost { authority: a, origins: o }).collect();
    let pool: &[&[u8]] = &[
        b"example.com",
        b"EXAMPLE.com:443",
        b"example.com:8443",
        b"api.example.com",
        b"u@example.com",
        b"evil.example",
        b"https://example.com",
        b"https://api.example.com:443",
        b"null",
        b"example.com.",
        b"\xe2\x84\xaaexample.com",
    ];
    let mut rng = Rng(12);
    for _ in 0..N {
        let pick = |rng: &mut Rng| -> Vec<u8> {
            if rng.below(3) == 0 { gen_input(rng) } else { pool[rng.below(pool.len())].to_vec() }
        };
        let (sni, auth, h1, h2, origin) =
            (pick(&mut rng), pick(&mut rng), pick(&mut rng), pick(&mut rng), pick(&mut rng));
        let hosts: Vec<&[u8]> = match rng.below(4) {
            0 => vec![],
            1 => vec![&h1],
            2 => vec![&h1, &h2],
            _ => vec![&auth],
        };
        let r = RequestIdentity {
            proto: if rng.below(2) == 0 { Proto::H1 } else { Proto::H2 },
            scheme: if rng.below(3) == 0 { Scheme::Http } else { Scheme::Https },
            sni: (rng.below(2) == 0).then_some(sni.as_slice()),
            authority: (rng.below(2) == 0).then_some(auth.as_slice()),
            host: &hosts,
            origin: (rng.below(2) == 0).then_some(origin.as_slice()),
        };
        match canon_request(&r, &vhosts) {
            Ok(a) => {
                let sni_c = r.sni.map(|s| canon_sni(s).unwrap().as_bytes().to_vec());
                let origin_c = r.origin.map(|o| canon_origin(o).unwrap().as_bytes().to_vec());
                let host = [a.as_bytes()];
                let again = RequestIdentity {
                    proto: Proto::H2,
                    authority: Some(a.as_bytes()),
                    host: &host,
                    sni: sni_c.as_deref(),
                    origin: origin_c.as_deref(),
                    ..r
                };
                assert_eq!(canon_request(&again, &vhosts).unwrap().as_bytes(), a.as_bytes());
            }
            Err(e) => assert!(matches!(e.status(), 400 | 403 | 404 | 421)),
        }
    }
}

#[test]
fn nfc_matches_known_cases() {
    assert!(unicode::is_nfc("\u{e9}"));
    assert!(!unicode::is_nfc("e\u{301}"));
    assert!(unicode::is_nfc("\u{ac00}")); // Hangul LV
    assert!(!unicode::is_nfc("\u{1100}\u{1161}")); // L V composes
    assert!(!unicode::is_nfc("\u{212b}")); // singleton (Angstrom -> A-ring)
    assert!(!unicode::is_nfc("a\u{301}\u{323}")); // wrong canonical order
    assert!(unicode::is_nfc("\u{1e0d}\u{307}")); // d-dot-below + dot-above
    assert!(!unicode::is_nfc("\u{344}")); // composition exclusion
    assert_eq!(unicode_tables::UNICODE_VERSION, "15.0.0");
}

#[test]
fn punycode_round_trip() {
    let u: Vec<char> = "faß".chars().collect();
    assert_eq!(punycode::encode(&u).unwrap(), b"fa-hia");
    assert_eq!(punycode::decode(b"fa-hia").unwrap(), u);
    assert_eq!(punycode::decode(b"mnchen-3ya").unwrap(), "münchen".chars().collect::<Vec<_>>());
    assert!(punycode::decode(b"99999999999999999999").is_none());
}
