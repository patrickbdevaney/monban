//! 2025-11-25 session table: a session id is bound to the (subject, route) that created it and is refused for any
//! other pair (session-principal-binding, session-route-pin). Bounded (C7): a global cap, a per-subject cap (the
//! subject's oldest session is evicted, so one principal can only crowd out itself) and an idle TTL. Ids are 128-bit
//! values from the AWS-LC DRBG, hex-encoded; nothing about them is derived from the request.

use std::collections::{HashMap, VecDeque};
use std::string::String;

use crate::b64::hex;
use crate::config::SessionCfg;

#[derive(Debug)]
struct Entry {
    sub: String,
    route: usize,
    expires: u64,
}

/// Why a session operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The global cap is reached and nothing has expired.
    Full,
    /// The DRBG failed.
    Rng,
}

/// The bounded session table.
#[derive(Debug)]
pub struct SessionTable {
    cfg: SessionCfg,
    map: HashMap<String, Entry>,
    by_sub: HashMap<String, VecDeque<String>>,
}

impl SessionTable {
    pub fn new(cfg: SessionCfg) -> Self {
        Self { cfg, map: HashMap::new(), by_sub: HashMap::new() }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn remove(&mut self, sid: &str) {
        if let Some(e) = self.map.remove(sid)
            && let Some(q) = self.by_sub.get_mut(&e.sub)
        {
            q.retain(|s| s != sid);
            if q.is_empty() {
                self.by_sub.remove(&e.sub);
            }
        }
    }

    fn sweep(&mut self, now: u64) {
        let dead: std::vec::Vec<String> =
            self.map.iter().filter(|(_, e)| e.expires <= now).map(|(k, _)| k.clone()).collect();
        for k in dead {
            self.remove(&k);
        }
    }

    /// Whether a new session could be created now (checked before the upstream is contacted, so a refusal never
    /// reaches a handler).
    pub fn has_room(&mut self, sub: &str, now: u64) -> bool {
        if self.map.len() < self.cfg.max {
            return true;
        }
        // At the global cap: a subject at its own cap can still rotate (its oldest is evicted); otherwise only
        // expired entries free room.
        if self.by_sub.get(sub).is_some_and(|q| q.len() >= self.cfg.per_principal) {
            return true;
        }
        self.sweep(now);
        self.map.len() < self.cfg.max
    }

    /// Create a session bound to (`sub`, `route`).
    pub fn create(&mut self, sub: &str, route: usize, now: u64) -> Result<String, SessionError> {
        let mut raw = [0u8; 16];
        aws_lc_rs::rand::fill(&mut raw).map_err(|_| SessionError::Rng)?;
        let sid = hex(&raw);
        while self.by_sub.get(sub).is_some_and(|q| q.len() >= self.cfg.per_principal) {
            let oldest = self.by_sub.get_mut(sub).and_then(VecDeque::pop_front);
            match oldest {
                Some(o) => {
                    self.map.remove(&o);
                }
                None => break,
            }
        }
        if self.map.len() >= self.cfg.max {
            self.sweep(now);
            if self.map.len() >= self.cfg.max {
                return Err(SessionError::Full);
            }
        }
        let expires = now.saturating_add(self.cfg.idle_ttl_s);
        self.map.insert(sid.clone(), Entry { sub: sub.into(), route, expires });
        self.by_sub.entry(sub.into()).or_default().push_back(sid.clone());
        Ok(sid)
    }

    /// Look up a session for (`sub`, `route`): `true` only if it exists, is live and is bound to exactly that pair.
    /// A live use extends the idle TTL.
    pub fn check(&mut self, sid: &str, sub: &str, route: usize, now: u64) -> bool {
        let expired = match self.map.get_mut(sid) {
            None => return false,
            Some(e) if e.expires <= now => true,
            Some(e) => {
                if e.sub != sub || e.route != route {
                    return false;
                }
                e.expires = now.saturating_add(self.cfg.idle_ttl_s);
                false
            }
        };
        if expired {
            self.remove(sid);
            return false;
        }
        true
    }

    /// End a session (DELETE). `true` only if it was live and bound to (`sub`, `route`).
    pub fn delete(&mut self, sid: &str, sub: &str, route: usize, now: u64) -> bool {
        if self.check(sid, sub, route, now) {
            self.remove(sid);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn binding_ttl_and_caps() {
        let mut t = SessionTable::new(SessionCfg { max: 4, per_principal: 2, idle_ttl_s: 10 });
        let a = t.create("alice", 0, 100).unwrap();
        assert_eq!(a.len(), 32);
        assert!(t.check(&a, "alice", 0, 101));
        assert!(!t.check(&a, "bob", 0, 101), "principal binding");
        assert!(!t.check(&a, "alice", 1, 101), "route binding");
        assert!(!t.check("nope", "alice", 0, 101));
        // Per-principal cap: the third session evicts alice's oldest.
        let a2 = t.create("alice", 0, 102).unwrap();
        let a3 = t.create("alice", 0, 103).unwrap();
        assert!(!t.check(&a, "alice", 0, 104));
        assert!(t.check(&a2, "alice", 0, 104) && t.check(&a3, "alice", 0, 104));
        // Global cap: bob and carol fill it; dave is refused until something expires.
        t.create("bob", 0, 104).unwrap();
        t.create("carol", 0, 104).unwrap();
        assert!(!t.has_room("dave", 105));
        assert_eq!(t.create("dave", 0, 105), Err(SessionError::Full));
        assert!(t.has_room("alice", 105), "alice rotates within her own quota");
        assert!(t.has_room("dave", 200), "everything expired");
        assert!(!t.check(&a2, "alice", 0, 200), "idle TTL");
        // DELETE: only by the binding pair, once.
        let d = t.create("dave", 1, 201).unwrap();
        assert!(!t.delete(&d, "dave", 0, 202));
        assert!(t.delete(&d, "dave", 1, 202));
        assert!(!t.check(&d, "dave", 1, 202));
        assert!(t.len() <= 4);
    }
}
