//! token-subject: evaluates oracles/token-drt cases (one per stdin line, format in oracles/token-drt/README.md)
//! with monban-token's public API, printing `<id> <verify><denote><depthOk><shapeOk>` per line.
//!
//! The token is built exactly as the case says (issuer `chain_tag` over the minted list, holder `attenuate` for
//! each appended caveat, then the tamper step), ENCODED to wire bytes, and judged by `monban_token::verify` on those
//! bytes. `--mutant NAME` swaps in a deliberately wrong semantics (for the oracle's self-test only):
//! leaf-only, plain-prefix, missing-arg-allow, depth-unchecked.
#![forbid(unsafe_code)]

use std::io::{BufRead, BufWriter, Write};

use monban_token::{
    ArgPred, ArgVal, Caveat, KeyRing, Req, TokenL, attenuate, chain_tag, denote, depth_ok, mac_valid, mint_shape_ok,
    sat, verify,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mutant {
    None,
    LeafOnly,
    PlainPrefix,
    MissingArgAllow,
    DepthUnchecked,
}

struct Toks<'a>(std::str::Split<'a, char>);

impl<'a> Toks<'a> {
    fn tok(&mut self) -> Option<&'a str> {
        self.0.next()
    }
    fn nat(&mut self) -> Option<u64> {
        self.tok()?.parse().ok()
    }
    fn int(&mut self) -> Option<i64> {
        self.tok()?.parse().ok()
    }
    fn usize(&mut self) -> Option<usize> {
        self.tok()?.parse().ok()
    }
    fn hex(h: &str) -> Option<Vec<u8>> {
        if !h.len().is_multiple_of(2) {
            return None;
        }
        (0..h.len()).step_by(2).map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok()).collect()
    }
    fn bytes(&mut self) -> Option<Vec<u8>> {
        Self::hex(self.tok()?.strip_prefix('x')?)
    }
    fn str(&mut self) -> Option<String> {
        String::from_utf8(Self::hex(self.tok()?.strip_prefix('s')?)?).ok()
    }
    fn list<T>(&mut self, f: impl Fn(&mut Self) -> Option<T>) -> Option<Vec<T>> {
        let n = self.usize()?;
        (0..n).map(|_| f(self)).collect()
    }
    fn val(&mut self) -> Option<ArgVal> {
        match self.tok()? {
            "I" => Some(ArgVal::Int(self.int()?)),
            "S" => Some(ArgVal::Str(self.str()?)),
            _ => None,
        }
    }
    fn pred(&mut self) -> Option<ArgPred> {
        match self.tok()? {
            "q" => Some(ArgPred::Eq(self.val()?)),
            "o" => Some(ArgPred::OneOf(self.list(Self::val)?)),
            "r" => Some(ArgPred::Range(self.int()?, self.int()?)),
            "p" => Some(ArgPred::StrPrefix(self.str()?)),
            _ => None,
        }
    }
    fn cav(&mut self) -> Option<Caveat> {
        Some(match self.tok()? {
            "A" => Caveat::Aud(self.str()?),
            "E" => Caveat::Exp(self.nat()?),
            "N" => Caveat::Nbf(self.nat()?),
            "O" => Caveat::Ops(u8::try_from(self.nat()?).ok()?),
            "R" => Caveat::Res(self.list(Self::str)?),
            "C" => Caveat::Cnf(self.bytes()?.try_into().ok()?),
            "T" => Caveat::Tenant(self.nat()?),
            "L" => {
                let name = self.str()?;
                let cons = self.list(|t| Some((t.str()?, t.pred()?)))?;
                Caveat::Tool(name, cons)
            }
            "D" => Caveat::Depth(u8::try_from(self.nat()?).ok()?),
            _ => return None,
        })
    }
}

fn tamper(t: &mut TokenL, p: &mut Toks<'_>) -> Option<()> {
    let cs = &mut t.caveats;
    match p.tok()? {
        "none" => {}
        "droplast" => {
            cs.pop();
        }
        "drop" => {
            let i = p.usize()?;
            if i < cs.len() {
                cs.remove(i);
            }
        }
        "repl" => {
            let i = p.usize()?;
            let c = p.cav()?;
            if let Some(slot) = cs.get_mut(i) {
                *slot = c;
            }
        }
        "swap" => {
            let (i, j) = (p.usize()?, p.usize()?);
            if i < cs.len() && j < cs.len() {
                cs.swap(i, j);
            }
        }
        "ins" => {
            let i = p.usize()?;
            let c = p.cav()?;
            if i <= cs.len() {
                cs.insert(i, c);
            }
        }
        "app" => cs.push(p.cav()?),
        "tag" => {
            if let Some(b) = t.tag.first_mut() {
                *b ^= 1;
            }
        }
        "kid" => t.kid = p.bytes()?,
        "nonce" => t.nonce = p.bytes()?.try_into().ok()?,
        _ => return None,
    }
    Some(())
}

// ---------------------------------------------------------------------------------- self-test mutants
fn sat_m(r: &Req, c: &Caveat, m: Mutant) -> bool {
    match (m, c) {
        (Mutant::PlainPrefix, Caveat::Res(p)) => {
            let want = format!("/{}", p.join("/"));
            let have = format!("/{}", r.res.join("/"));
            have.starts_with(&want)
        }
        (Mutant::MissingArgAllow, Caveat::Tool(n, cons)) => {
            r.tool == *n
                && cons.iter().all(|(k, pr)| match r.args.iter().find(|(rk, _)| rk == k) {
                    Some((_, v)) => pr.sat(v),
                    None => true,
                })
        }
        _ => sat(r, c),
    }
}

fn denote_m(cs: &[Caveat], r: &Req, m: Mutant) -> bool {
    match m {
        Mutant::None => denote(cs, r),
        Mutant::LeafOnly => cs.last().is_none_or(|c| sat(r, c)),
        _ => cs.iter().all(|c| sat_m(r, c, m)),
    }
}

fn depth_m(cs: &[Caveat], m: Mutant) -> bool {
    m == Mutant::DepthUnchecked || depth_ok(cs)
}

fn eval(line: &str, m: Mutant) -> Option<String> {
    let mut p = Toks(line.split(' '));
    let id = p.tok()?;
    let master = [u8::try_from(p.nat()?).ok()?; 32];
    let m_aud = p.str()?;
    let m_kid = p.bytes()?;
    let m_nonce: [u8; 16] = p.bytes()?.try_into().ok()?;
    let mint_cs = p.list(Toks::cav)?;
    let att = p.list(Toks::cav)?;
    let tag = chain_tag(&master, &m_aud, &m_kid, &m_nonce, &mint_cs).ok()?;
    let mut t = TokenL { kid: m_kid, nonce: m_nonce, caveats: mint_cs, tag };
    for c in att {
        t = attenuate(&t, c).ok()?;
    }
    tamper(&mut t, &mut p)?;
    let mut keys = KeyRing::new();
    for (kid, mk) in p.list(|t| Some((t.bytes()?, t.nat()?)))? {
        keys.insert(&kid, [u8::try_from(mk).ok()?; 32]).ok()?;
    }
    let r = Req {
        aud: p.str()?,
        ops: p.nat()?,
        res: p.list(Toks::str)?,
        tenant: p.nat()?,
        holder: p.bytes()?,
        tool: p.str()?,
        args: p.list(|t| Some((t.str()?, t.val()?)))?,
        now: p.nat()?,
    };
    if p.tok().is_some() {
        return None;
    }
    let wire = t.encode().ok()?;
    let (v, d, k) = if m == Mutant::None {
        (verify(&wire, &keys, &r).is_ok(), denote(&t.caveats, &r), depth_ok(&t.caveats))
    } else {
        let d = denote_m(&t.caveats, &r, m);
        let k = depth_m(&t.caveats, m);
        let decoded = TokenL::decode(&wire).ok()?;
        (mac_valid(&keys, &decoded, &r.aud) && d && k && mint_shape_ok(&decoded.caveats), d, k)
    };
    let b = |x: bool| if x { '1' } else { '0' };
    Some(format!("{id} {}{}{}{}", b(v), b(d), b(k), b(mint_shape_ok(&t.caveats))))
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let m = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => Mutant::None,
        ["--mutant", "leaf-only"] => Mutant::LeafOnly,
        ["--mutant", "plain-prefix"] => Mutant::PlainPrefix,
        ["--mutant", "missing-arg-allow"] => Mutant::MissingArgAllow,
        ["--mutant", "depth-unchecked"] => Mutant::DepthUnchecked,
        _ => {
            eprintln!("usage: token-subject [--mutant leaf-only|plain-prefix|missing-arg-allow|depth-unchecked]");
            return std::process::ExitCode::from(2);
        }
    };
    let stdin = std::io::stdin();
    let mut out = BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim_end();
        let res = eval(line, m).unwrap_or_else(|| {
            let id = line.split(' ').next().unwrap_or("?");
            format!("{id} PARSE_ERROR")
        });
        if writeln!(out, "{res}").is_err() {
            return std::process::ExitCode::from(1);
        }
    }
    if out.flush().is_err() {
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}
