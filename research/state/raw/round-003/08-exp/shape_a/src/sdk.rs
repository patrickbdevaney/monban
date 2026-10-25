// Shape A: plain axum-like. Extractor-ish Ctx, pub fields, Default principal, clonable handles, ambient effects.
use std::{cell::RefCell, collections::HashMap, sync::{Arc, Mutex}};
thread_local! { pub static EV: RefCell<Vec<String>> = RefCell::new(vec![]); }
pub fn ev(s: String) { EV.with(|e| e.borrow_mut().push(s)) }
#[derive(Clone, Debug, Default)] pub struct Principal { pub user: String, pub tenant: String, pub role: String }
#[derive(Clone, Debug)] pub struct Note { pub id: u64, pub tenant: String, pub owner: String, pub body: String, pub archived: bool }
#[derive(Clone, Default)] pub struct Db { pub rows: Arc<Mutex<Vec<Note>>> }
pub struct Tx { db: Db, pending: Vec<Note> }
impl Db {
    pub fn query(&self, sql: &str) -> Vec<Note> { ev(format!("query:{sql}")); self.rows.lock().unwrap().clone() }
    pub fn notes_for(&self, t: &str) -> Vec<Note> { self.rows.lock().unwrap().iter().filter(|n| n.tenant == t).cloned().collect() }
    pub fn begin(&self) -> Tx { Tx { db: self.clone(), pending: vec![] } }
    pub fn delete(&self, id: u64) { ev(format!("delete:{id}")); self.rows.lock().unwrap().retain(|n| n.id != id) }
}
impl Tx {
    pub fn insert(&mut self, n: Note) { self.pending.push(n) }
    pub fn commit(self) { ev("commit".into()); self.db.rows.lock().unwrap().extend(self.pending) }
    pub fn rollback(self) {}
}
#[derive(Clone, Default)] pub struct Cache(Arc<Mutex<HashMap<String, String>>>);
impl Cache {
    pub fn get(&self, k: &str) -> Option<String> { self.0.lock().unwrap().get(k).cloned() }
    pub fn set(&self, k: &str, v: &str) { self.0.lock().unwrap().insert(k.into(), v.into()); }
}
pub struct Response { pub status: u16, pub body: String }
impl Response {
    pub fn html(s: impl Into<String>) -> Self { Response { status: 200, body: s.into() } }
    pub fn text(s: impl Into<String>) -> Self { Response { status: 200, body: s.into() } }
    pub fn status(c: u16) -> Self { Response { status: c, body: String::new() } }
}
pub struct Request { pub path_tenant: String, pub header_tenant: Option<String>, pub param: String, pub token: String }
pub struct Ctx { pub req: Request, pub principal: Option<Principal>, pub db: Db, pub cache: Cache }
pub fn escape(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;") }
pub fn send_email(_to: &str, _body: &str) { ev("email".into()) }
pub fn http_get(url: &str) -> String { ev(format!("http_get:{url}")); String::new() }
pub fn log(m: &str) { ev(format!("log:{m}")) }
pub struct World { pub db: Db, pub cache: Cache, pub users: HashMap<String, Principal> }
impl World {
    pub fn new() -> Self { World { db: Db::default(), cache: Cache::default(), users: HashMap::new() } }
    pub fn user(&mut self, tok: &str, u: &str, t: &str, role: &str) { self.users.insert(tok.into(), Principal { user: u.into(), tenant: t.into(), role: role.into() }); }
    pub fn seed(&mut self, id: u64, t: &str, owner: &str, body: &str, archived: bool) { self.db.rows.lock().unwrap().push(Note { id, tenant: t.into(), owner: owner.into(), body: body.into(), archived }); }
    pub fn count(&self) -> usize { self.db.rows.lock().unwrap().len() }
    pub fn call(&self, req: Request, f: fn(&Ctx) -> Response) -> Response {
        let principal = self.users.get(&req.token).cloned();
        f(&Ctx { req, principal, db: self.db.clone(), cache: self.cache.clone() })
    }
}
