//! The F5 Tier-L key ring file (`--token-keyring`), shared by the app routes (feature `native`, PLAN D16) and the
//! P2 `wasm:` routes (feature `p2`): both verify the request's Tier-L token before anything else runs.

use std::path::Path;

use aegis_token::KeyRing;

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| {
            let h = char::from(*c.first()?).to_digit(16)?;
            let l = char::from(*c.get(1)?).to_digit(16)?;
            u8::try_from(h * 16 + l).ok()
        })
        .collect()
}

/// Load the Tier-L key ring: `{"keys":[{"kid":"<hex>","key":"<64 hex>"}]}`, a regular file not readable by group or
/// others.
pub fn load(p: &Path) -> Result<KeyRing, String> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    let f = std::fs::File::open(p).map_err(|e| format!("token keyring {}: {e}", p.display()))?;
    let md = f.metadata().map_err(|e| format!("token keyring {}: {e}", p.display()))?;
    if !md.is_file() || md.permissions().mode() & 0o077 != 0 {
        return Err(format!("token keyring {}: must be a regular file with mode 0600", p.display()));
    }
    let mut b = Vec::new();
    f.take(1 << 20).read_to_end(&mut b).map_err(|e| format!("token keyring {}: {e}", p.display()))?;
    let bad = |w: &str| format!("token keyring {}: {w}", p.display());
    let doc = aegis_canon::parse_json(&b).map_err(|_| bad("not JSON"))?;
    let aegis_canon::JsonValue::Object(top) = doc else { return Err(bad("not an object")) };
    let Some((_, aegis_canon::JsonValue::Array(keys))) = top.iter().find(|(k, _)| k == "keys") else {
        return Err(bad("no keys array"));
    };
    let mut ring = KeyRing::new();
    for k in keys {
        let aegis_canon::JsonValue::Object(m) = k else { return Err(bad("key entry not an object")) };
        let field = |n: &str| match m.iter().find(|(k, _)| k == n) {
            Some((_, aegis_canon::JsonValue::String(s))) => unhex(s),
            _ => None,
        };
        let kid = field("kid").ok_or_else(|| bad("kid"))?;
        let key: [u8; 32] = field("key").and_then(|v| v.try_into().ok()).ok_or_else(|| bad("key (32 bytes hex)"))?;
        ring.insert(&kid, key).map_err(|e| bad(&format!("kid: {e:?}")))?;
    }
    if keys.is_empty() {
        return Err(bad("no keys"));
    }
    Ok(ring)
}
