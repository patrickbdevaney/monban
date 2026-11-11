//! F8: config parse (monban-config `parse_config`, `ConfigStore`).
//!
//! Properties:
//! - `parse_config` is total; an error always carries a JSON pointer that is empty or starts with `/`;
//! - accept => the effective JSON is canonical (a `canon_json` fixed point), within the size cap, hashes to
//!   `config_hash`, and re-parses to an equal config with the same hash (defaults applied once are stable);
//! - `ConfigStore::apply` keeps the last-known-good config on a reject (CFG-3) and installs exactly the parsed
//!   config on success.
#![no_main]

use monban_canon::canon_json;
use monban_config::{ConfigStore, MAX_CONFIG_BYTES, parse_config, sha256};
use monban_fuzz::selftest;
use libfuzzer_sys::fuzz_target;

const GOOD: &[u8] = br#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],
  "vhosts":[{"host":"a","routes":[{"id":1,"path":"/","to":{"static":"x"}}]}]}"#;

fuzz_target!(|data: &[u8]| {
    let parsed = parse_config(data);
    match &parsed {
        Ok(c) => {
            let eff = c.effective_json();
            assert!(eff.len() <= MAX_CONFIG_BYTES, "effective config over the cap");
            assert_eq!(sha256(eff), c.config_hash(), "config_hash is not SHA-256 of the effective JSON");
            let canon = canon_json(eff);
            assert_eq!(canon.as_ref().map(|x| x.as_bytes()), Ok(eff), "effective JSON is not canonical");
            match parse_config(eff) {
                Ok(c2) => {
                    assert_eq!(c2.config_hash(), c.config_hash(), "effective JSON re-parses to another hash");
                    assert_eq!(&c2, c, "effective JSON re-parses to a different config");
                }
                Err(e) => panic!("effective JSON of an accepted config is rejected: {e}"),
            }
            selftest!(c.vhosts().iter().any(|v| v.host.len() >= 12)); // examples/seeds.rs hosts: "example.com" (11), "a"
        }
        Err(e) => {
            let p = e.pointer();
            assert!(p.is_empty() || p.starts_with('/'), "error pointer is not an RFC 6901 pointer: {p:?}");
            assert!(!e.to_string().is_empty());
        }
    }

    let mut store = ConfigStore::new();
    let Ok(g0) = store.apply(GOOD) else { panic!("baseline config rejected") };
    let h0 = store.config_hash();
    match store.apply(data) {
        Ok(g1) => {
            assert!(g1 != g0, "new generation not distinct");
            let Ok(c) = &parsed else { panic!("store accepted what parse_config rejects") };
            assert_eq!(store.config_hash(), Some(c.config_hash()), "store installed a different config");
        }
        Err(_) => {
            assert!(parsed.is_err(), "store rejected what parse_config accepts");
            assert_eq!(store.config_hash(), h0, "a rejected apply changed the live config (CFG-3)");
            assert_eq!(store.generation(), Some(g0), "a rejected apply changed the generation");
            assert!(store.last_error().is_some(), "a rejected apply left no last_error");
        }
    }
});
