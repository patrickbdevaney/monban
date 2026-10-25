//! Readers for `Cargo.lock` and flat `key = "value"` TOML files. Only the subset cargo emits is accepted.

use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct LockPkg {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    /// Raw dependency entries ("name" or "name version").
    pub deps: Vec<String>,
}

fn unquote(v: &str) -> Option<String> {
    let v = v.trim();
    v.strip_prefix('"').and_then(|s| s.strip_suffix('"')).map(String::from)
}

pub fn parse_lock(s: &str) -> Result<Vec<LockPkg>, String> {
    let mut out = Vec::new();
    for block in s.split("[[package]]").skip(1) {
        let mut name = None;
        let mut version = None;
        let mut source = None;
        let mut deps = Vec::new();
        let mut in_deps = false;
        for line in block.lines() {
            let l = line.trim();
            if in_deps {
                if l == "]" {
                    in_deps = false;
                } else if let Some(d) = unquote(l.trim_end_matches(',')) {
                    deps.push(d);
                }
                continue;
            }
            if let Some((k, v)) = l.split_once('=') {
                match k.trim() {
                    "name" => name = unquote(v),
                    "version" => version = unquote(v),
                    "source" => source = unquote(v),
                    "dependencies" => {
                        let v = v.trim();
                        if v == "[" {
                            in_deps = true;
                        } else {
                            deps.extend(v.trim_matches(['[', ']']).split(',').filter_map(unquote));
                        }
                    }
                    _ => {}
                }
            }
        }
        match (name, version) {
            (Some(name), Some(version)) => out.push(LockPkg { name, version, source, deps }),
            _ => return Err("Cargo.lock package without name/version".into()),
        }
    }
    Ok(out)
}

/// `key = "value"` lines; comments and section headers ignored. Duplicate keys are an error-free last-wins
/// only in tests; real files are checked by `check-config`-style review.
pub fn parse_kv(s: &str) -> BTreeMap<String, String> {
    s.lines()
        .map(|l| l.split('#').next().unwrap_or_default())
        .filter_map(|l| l.split_once('='))
        .filter_map(|(k, v)| Some((k.trim().trim_matches('"').to_string(), unquote(v)?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_roundtrip() {
        let s = "version = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\n \"b 0.1.0\",\n \"c\",\n]\n\n[[package]]\nname = \"b\"\nversion = \"0.1.0\"\n";
        let p = parse_lock(s).unwrap_or_default();
        assert_eq!(p.len(), 2);
        assert_eq!(p.first().map(|x| x.deps.len()), Some(2));
        assert_eq!(parse_kv("x = \"1\" # c\n[s]\ny=\"2\"").len(), 2);
    }
}
