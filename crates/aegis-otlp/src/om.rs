//! Bounded OpenMetrics 1.0 text parser (the subset aegis's admin listener renders, plus histograms).
//!
//! The whole exposition is rejected (no points exported) when it is not UTF-8, exceeds [`MAX_SCRAPE`] bytes, lacks
//! the terminating `# EOF`, has content after it, or contains a malformed line, an unknown escape, a duplicate
//! label name, a non-numeric value, a sample whose suffix does not fit its family's type, more than
//! [`MAX_SERIES`] samples, [`MAX_FAMILIES`] families or [`MAX_LABELS`] labels on one sample.
//!
//! Families typed `info`, `stateset`, `summary` or `gaugehistogram` are parsed for syntax and then skipped (not
//! exported). Per-sample timestamps and exemplars are accepted and ignored.

use std::collections::HashMap;

/// Largest exposition accepted (bytes).
pub const MAX_SCRAPE: usize = 4 * 1024 * 1024;
/// Most samples in one exposition.
pub const MAX_SERIES: usize = 10_000;
/// Most metric families in one exposition.
pub const MAX_FAMILIES: usize = 2_000;
/// Most labels on one sample.
pub const MAX_LABELS: usize = 64;
/// Longest line.
pub const MAX_LINE: usize = 65_536;

/// Why an exposition was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OmError(pub &'static str);

impl core::fmt::Display for OmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

/// Family type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `counter`.
    Counter,
    /// `gauge`.
    Gauge,
    /// `histogram`.
    Histogram,
    /// `unknown` (or no TYPE line): exported as a gauge.
    Unknown,
    /// A valid OpenMetrics type this exporter does not map (skipped).
    Skipped,
}

/// A sample value: exact integer when the token is `-?[0-9]+` within i64, else a double.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Num {
    /// Integer token.
    Int(i64),
    /// Any other numeric token.
    Double(f64),
}

impl Num {
    /// The value as a double (histogram bucket counts, sums, `_created`).
    pub fn as_f64(self) -> f64 {
        match self {
            Self::Int(i) => i as f64,
            Self::Double(d) => d,
        }
    }
}

/// One sample line.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    /// The suffix after the family name (`""`, `_total`, `_created`, `_bucket`, `_count`, `_sum`).
    pub suffix: &'static str,
    /// Labels in input order, unescaped.
    pub labels: Vec<(String, String)>,
    /// Value.
    pub value: Num,
    /// The raw value token (for exact `_created` conversion).
    pub token: String,
}

/// A metric family.
#[derive(Clone, Debug, PartialEq)]
pub struct Family {
    /// Family name.
    pub name: String,
    /// Type.
    pub kind: Kind,
    /// `# UNIT` (verbatim) or empty.
    pub unit: String,
    /// `# HELP`, unescaped, or empty.
    pub help: String,
    /// Samples in input order.
    pub samples: Vec<Sample>,
}

const SUFFIXES: [&str; 5] = ["_total", "_created", "_bucket", "_count", "_sum"];

fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b':'
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b':'
}

fn valid_metric_name(s: &str) -> bool {
    let b = s.as_bytes();
    b.first().is_some_and(|&c| is_name_start(c)) && b.iter().all(|&c| is_name_char(c))
}

/// Unescape `\\`, `\"` and `\n` (the only OpenMetrics escapes); anything else after a backslash is an error.
fn unescape(s: &str) -> Result<String, OmError> {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('n') => out.push('\n'),
            _ => return Err(OmError("bad escape")),
        }
    }
    Ok(out)
}

/// Parse a numeric value token. Integers `-?[0-9]+` within i64 stay exact; other tokens must be decimal floats,
/// exponent forms, `NaN`, `+Inf`, `-Inf` or `Inf`.
pub fn number(tok: &str) -> Result<Num, OmError> {
    let digits = tok.strip_prefix('-').unwrap_or(tok);
    if !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && let Ok(i) = tok.parse::<i64>()
    {
        return Ok(Num::Int(i));
    }
    match tok {
        "NaN" => return Ok(Num::Double(f64::NAN)),
        "+Inf" | "Inf" => return Ok(Num::Double(f64::INFINITY)),
        "-Inf" => return Ok(Num::Double(f64::NEG_INFINITY)),
        _ => {}
    }
    let ok_chars = tok.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'));
    if tok.is_empty() || !ok_chars || !tok.bytes().any(|b| b.is_ascii_digit()) {
        return Err(OmError("bad value"));
    }
    tok.parse::<f64>().map(Num::Double).map_err(|_| OmError("bad value"))
}

/// `_created` token (seconds since the epoch) to nanoseconds: exact for plain decimals, via f64 for exponent forms.
pub fn created_ns(tok: &str) -> Result<u64, OmError> {
    let (whole, frac) = tok.split_once('.').unwrap_or((tok, ""));
    let plain =
        !whole.is_empty() && whole.bytes().all(|b| b.is_ascii_digit()) && frac.bytes().all(|b| b.is_ascii_digit());
    if plain {
        let w: u64 = whole.parse().map_err(|_| OmError("bad _created"))?;
        let mut f: u64 = 0;
        let mut n = 0;
        for b in frac.bytes().take(9) {
            f = f.saturating_mul(10).saturating_add(u64::from(b - b'0'));
            n += 1;
        }
        while n < 9 {
            f = f.saturating_mul(10);
            n += 1;
        }
        return w.checked_mul(1_000_000_000).and_then(|x| x.checked_add(f)).ok_or(OmError("bad _created"));
    }
    let v = number(tok)?.as_f64();
    if !v.is_finite() || v < 0.0 || v > 1.8e10 {
        return Err(OmError("bad _created"));
    }
    Ok((v * 1e9) as u64)
}

struct Labels<'a> {
    s: &'a [u8],
    i: usize,
}

impl Labels<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /// Parse `{k="v",...}`; `self.i` is at `{`. Leaves `self.i` after `}`.
    fn parse(&mut self, text: &str) -> Result<Vec<(String, String)>, OmError> {
        let mut out: Vec<(String, String)> = Vec::new();
        self.i += 1;
        loop {
            match self.peek() {
                Some(b'}') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(c) if c.is_ascii_alphabetic() || c == b'_' => {}
                _ => return Err(OmError("bad label name")),
            }
            let ks = self.i;
            while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_') {
                self.i += 1;
            }
            let k = text.get(ks..self.i).ok_or(OmError("bad label"))?;
            if self.peek() != Some(b'=') {
                return Err(OmError("bad label"));
            }
            self.i += 1;
            if self.peek() != Some(b'"') {
                return Err(OmError("bad label"));
            }
            self.i += 1;
            let vs = self.i;
            loop {
                match self.peek() {
                    None | Some(b'\n') => return Err(OmError("unterminated label value")),
                    Some(b'\\') => self.i += 2,
                    Some(b'"') => break,
                    Some(_) => self.i += 1,
                }
            }
            let raw = text.get(vs..self.i).ok_or(OmError("bad label value"))?;
            self.i += 1;
            if out.iter().any(|(n, _)| n == k) {
                return Err(OmError("duplicate label"));
            }
            if out.len() >= MAX_LABELS {
                return Err(OmError("too many labels"));
            }
            out.push((k.to_string(), unescape(raw)?));
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {}
                _ => return Err(OmError("bad label separator")),
            }
        }
    }
}

struct Builder {
    fams: Vec<Family>,
    index: HashMap<String, usize>,
    samples: usize,
}

impl Builder {
    fn family(&mut self, name: &str) -> Result<&mut Family, OmError> {
        let idx = match self.index.get(name) {
            Some(&i) => i,
            None => {
                if self.fams.len() >= MAX_FAMILIES {
                    return Err(OmError("too many families"));
                }
                self.fams.push(Family {
                    name: name.to_string(),
                    kind: Kind::Unknown,
                    unit: String::new(),
                    help: String::new(),
                    samples: Vec::new(),
                });
                let i = self.fams.len() - 1;
                self.index.insert(name.to_string(), i);
                i
            }
        };
        self.fams.get_mut(idx).ok_or(OmError("internal"))
    }

    fn meta(&mut self, line: &str) -> Result<(), OmError> {
        let mut parts = line.splitn(4, ' ');
        let _hash = parts.next();
        let (Some(what), Some(name)) = (parts.next(), parts.next()) else {
            return Ok(()); // a bare comment
        };
        let rest = parts.next().unwrap_or("");
        if !matches!(what, "TYPE" | "UNIT" | "HELP") {
            return Ok(());
        }
        if !valid_metric_name(name) {
            return Err(OmError("bad metric name in metadata"));
        }
        let f = self.family(name)?;
        match what {
            "TYPE" => {
                f.kind = match rest {
                    "counter" => Kind::Counter,
                    "gauge" => Kind::Gauge,
                    "histogram" => Kind::Histogram,
                    "unknown" => Kind::Unknown,
                    "info" | "stateset" | "summary" | "gaugehistogram" => Kind::Skipped,
                    _ => return Err(OmError("bad TYPE")),
                }
            }
            "UNIT" => f.unit = rest.to_string(),
            _ => f.help = unescape(rest)?,
        }
        Ok(())
    }

    fn sample(&mut self, line: &str) -> Result<(), OmError> {
        let b = line.as_bytes();
        if !b.first().is_some_and(|&c| is_name_start(c)) {
            return Err(OmError("bad sample name"));
        }
        let end = b.iter().position(|&c| !is_name_char(c)).unwrap_or(b.len());
        let sname = line.get(..end).ok_or(OmError("bad sample"))?;
        let mut lp = Labels { s: b, i: end };
        let labels = if lp.peek() == Some(b'{') { lp.parse(line)? } else { Vec::new() };
        let rest = line.get(lp.i..).ok_or(OmError("bad sample"))?;
        let rest = rest.strip_prefix(' ').ok_or(OmError("bad sample"))?;
        let mut toks = rest.split(' ');
        let tok = toks.next().unwrap_or("");
        let value = number(tok)?;
        // Optional timestamp, then optional exemplar (`# {...} v [ts]`): syntax-checked loosely and ignored.
        if let Some(t) = toks.next()
            && t != "#"
        {
            number(t)?;
            if toks.next().is_some_and(|h| h != "#") {
                return Err(OmError("trailing data after sample"));
            }
        }
        // Family: the exact name, else the name minus a known suffix.
        let (fam, suffix) = if self.index.contains_key(sname) {
            (sname, "")
        } else {
            SUFFIXES
                .iter()
                .find_map(|s| sname.strip_suffix(s).filter(|f| self.index.contains_key(*f)).map(|f| (f, *s)))
                .unwrap_or((sname, ""))
        };
        self.samples += 1;
        if self.samples > MAX_SERIES {
            return Err(OmError("too many series"));
        }
        let f = self.family(fam)?;
        let fits = match f.kind {
            Kind::Counter => matches!(suffix, "_total" | "_created"),
            Kind::Gauge | Kind::Unknown => suffix.is_empty(),
            Kind::Histogram => matches!(suffix, "_bucket" | "_count" | "_sum" | "_created"),
            Kind::Skipped => true,
        };
        if !fits {
            return Err(OmError("sample suffix does not fit the family type"));
        }
        f.samples.push(Sample { suffix, labels, value, token: tok.to_string() });
        Ok(())
    }
}

/// Parse an exposition. See the module docs for what is rejected.
pub fn parse(body: &[u8]) -> Result<Vec<Family>, OmError> {
    if body.len() > MAX_SCRAPE {
        return Err(OmError("exposition too large"));
    }
    let text = core::str::from_utf8(body).map_err(|_| OmError("exposition is not UTF-8"))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix("# EOF").ok_or(OmError("no terminating # EOF"))?;
    if !(text.is_empty() || text.ends_with('\n')) {
        return Err(OmError("no terminating # EOF"));
    }
    let mut b = Builder { fams: Vec::new(), index: HashMap::new(), samples: 0 };
    for line in text.split_terminator('\n') {
        if line.len() > MAX_LINE {
            return Err(OmError("line too long"));
        }
        if line.is_empty() {
            return Err(OmError("empty line"));
        }
        if line == "# EOF" {
            return Err(OmError("content after # EOF"));
        }
        if line.starts_with('#') {
            b.meta(line)?;
        } else {
            b.sample(line)?;
        }
    }
    Ok(b.fams)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_eof_and_trailing() {
        assert_eq!(parse(b"# TYPE a gauge\na 1\n"), Err(OmError("no terminating # EOF")));
        assert!(parse(b"# TYPE a gauge\na 1\n# EOF\nb 2\n").is_err());
        assert!(parse(b"# EOF\n").is_ok_and(|f| f.is_empty()));
    }

    #[test]
    fn counter_labels_and_values() {
        let t = b"# TYPE x counter\n# HELP x a \\\"b\\\" c\\\\d\\ne\nx_total{k=\"a\\\"b\",l=\"c\\\\d\\ne\"} 9007199254740993\nx_created{k=\"a\\\"b\",l=\"c\\\\d\\ne\"} 1793900000.25\n# EOF\n";
        let f = parse(t);
        assert!(f.is_ok());
        let f = f.unwrap_or_default();
        let fam = f.first();
        assert!(fam.is_some_and(|x| x.help == "a \"b\" c\\d\ne" && x.kind == Kind::Counter));
        let s = fam.and_then(|x| x.samples.first());
        assert!(s.is_some_and(|s| s.value == Num::Int(9_007_199_254_740_993) && s.suffix == "_total"));
        assert!(s.is_some_and(|s| s.labels == vec![("k".into(), "a\"b".into()), ("l".into(), "c\\d\ne".into())]));
        assert_eq!(created_ns("1793900000.25"), Ok(1_793_900_000_250_000_000));
    }

    #[test]
    fn bad_inputs() {
        assert!(parse(b"# TYPE x gauge\nx{a=\"\\q\"} 1\n# EOF\n").is_err());
        assert!(parse(b"# TYPE x gauge\nx{a=\"1\",a=\"2\"} 1\n# EOF\n").is_err());
        assert!(parse(b"# TYPE x gauge\nx abc\n# EOF\n").is_err());
        assert!(parse(b"# TYPE x counter\nx 1\n# EOF\n").is_err());
        assert!(parse(b"# TYPE x gauge\nx  1\n# EOF\n").is_err());
        assert_eq!(number("-1.5e3"), Ok(Num::Double(-1500.0)));
        assert_eq!(number("-42"), Ok(Num::Int(-42)));
        assert!(number("1e").is_err());
        assert!(number("inf").is_err());
    }
}
