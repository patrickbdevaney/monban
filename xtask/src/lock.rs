//! Readers for `Cargo.lock` and flat `key = "value"` TOML files. Only the subset cargo emits is accepted.

use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct LockPkg {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
}

fn unquote(v: &str) -> Option<String> {
    let v = v.trim();
    v.strip_prefix('"').and_then(|s| s.strip_suffix('"')).map(String::from)
}

/// Package (name, version, source) entries. Dependency lists are skipped: dependency structure and features are read
/// from `cargo metadata --locked` (`parse_metadata`), never from lock text.
pub fn parse_lock(s: &str) -> Result<Vec<LockPkg>, String> {
    let mut out = Vec::new();
    for block in s.split("[[package]]").skip(1) {
        let mut name = None;
        let mut version = None;
        let mut source = None;
        let mut in_deps = false;
        for line in block.lines() {
            let l = line.trim();
            if in_deps {
                in_deps = l != "]";
                continue;
            }
            if let Some((k, v)) = l.split_once('=') {
                match k.trim() {
                    "name" => name = unquote(v),
                    "version" => version = unquote(v),
                    "source" => source = unquote(v),
                    "dependencies" => in_deps = v.trim() == "[",
                    _ => {}
                }
            }
        }
        if in_deps {
            return Err("Cargo.lock dependency list not terminated".into());
        }
        match (name, version) {
            (Some(name), Some(version)) => out.push(LockPkg { name, version, source }),
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

/// One node of the `cargo metadata --locked` resolve graph (BACKLOG G7): the package plus its unified features and
/// the (name, version) of every resolved dependency.
#[derive(Clone, Debug)]
pub struct Node {
    pub name: String,
    pub version: String,
    /// `None` for path packages (workspace members, the cmvp void crate).
    pub source: Option<String>,
    pub manifest: String,
    pub features: Vec<String>,
    pub deps: Vec<(String, String)>,
    pub build_script: bool,
}

impl Node {
    pub fn has_feature(&self, f: &str) -> bool {
        self.features.iter().any(|x| x == f)
    }
}

/// Resolve graph of a `cargo metadata --format-version 1` document (with deps). A node without its package entry, or
/// a document without `resolve`, is an error: the gate never judges a partial graph.
pub fn parse_metadata(meta: &crate::json::Json) -> Result<Vec<Node>, String> {
    use crate::json::Json;
    let s = |j: &Json, k: &str| j.get(k).and_then(Json::str).map(String::from);
    let mut pkgs = BTreeMap::new();
    for p in meta.get("packages").map(Json::arr).unwrap_or(&[]) {
        let id = s(p, "id").ok_or("metadata: package without id")?;
        let build = p
            .get("targets")
            .map(Json::arr)
            .unwrap_or(&[])
            .iter()
            .any(|t| t.get("kind").map(Json::arr).unwrap_or(&[]).iter().any(|k| k.str() == Some("custom-build")));
        let name = s(p, "name").ok_or("metadata: package without name")?;
        let version = s(p, "version").ok_or("metadata: package without version")?;
        pkgs.insert(id, (name, version, s(p, "source"), s(p, "manifest_path").unwrap_or_default(), build));
    }
    let nodes = meta.path(&["resolve", "nodes"]).ok_or("metadata: no resolve graph (was --no-deps used?)")?;
    let mut out = Vec::new();
    for n in nodes.arr() {
        let id = s(n, "id").ok_or("metadata: node without id")?;
        let (name, version, source, manifest, build_script) =
            pkgs.get(&id).cloned().ok_or(format!("metadata: node {id} has no package"))?;
        let features = n.get("features").map(Json::arr).unwrap_or(&[]).iter().filter_map(Json::str).map(String::from);
        let mut deps = Vec::new();
        for d in n.get("deps").map(Json::arr).unwrap_or(&[]) {
            let pid = s(d, "pkg").ok_or("metadata: dep without pkg")?;
            let (dn, dv, ..) = pkgs.get(&pid).ok_or(format!("metadata: dep {pid} has no package"))?;
            deps.push((dn.clone(), dv.clone()));
        }
        out.push(Node { name, version, source, manifest, features: features.collect(), deps, build_script });
    }
    Ok(out)
}

/// `major.minor.patch` (pre-release and build suffixes are rejected: no pre-release may satisfy a floor or window).
pub fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.split('.');
    let t = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
    if it.next().is_some() {
        return None;
    }
    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_roundtrip() {
        let s = "version = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\n \"b 0.1.0\",\n \"c\",\n]\n\n[[package]]\nname = \"b\"\nversion = \"0.1.0\"\n";
        let p = parse_lock(s).unwrap_or_default();
        assert_eq!(p.len(), 2);
        assert_eq!(p.first().map(|x| x.name.as_str()), Some("a"));
        assert_eq!(parse_kv("x = \"1\" # c\n[s]\ny=\"2\"").len(), 2);
    }
}
