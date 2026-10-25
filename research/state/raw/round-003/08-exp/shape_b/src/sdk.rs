// Shape B: capability-typed. Private-field Principal (no Default), tenant-scoped non-Clone handles,
// effect-class markers on Ctx, typestate Tx -> Committed, escape-by-construction Html, validated Url, Secret.
use std::{cell::RefCell, collections::HashMap, marker::PhantomData, sync::{Arc, Mutex}};
thread_local! { pub static EV: RefCell<Vec<String>> = RefCell::new(vec![]); }
fn ev(s: String) { EV.with(|e| e.borrow_mut().push(s)) }
#[derive(Clone, PartialEq, Eq, Debug)] pub struct TenantId(String);
#[derive(Clone, PartialEq, Eq, Debug)] pub struct UserId(String);
#[derive(Clone, Copy, PartialEq, Eq, Debug)] pub enum Role { Admin, Member }
pub struct Principal { user: UserId, tenant: TenantId, role: Role }
pub trait Cap { fn ok(r: Role) -> bool; }
pub struct DeleteNote; impl Cap for DeleteNote { fn ok(r: Role) -> bool { r == Role::Admin } }
pub struct Granted<C>(PhantomData<C>);
impl Principal {
    pub fn user(&self) -> &UserId { &self.user }
    pub fn tenant(&self) -> &TenantId { &self.tenant }
    pub fn can<C: Cap>(&self) -> Option<Granted<C>> { if C::ok(self.role) { Some(Granted(PhantomData)) } else { None } }
}
pub struct Secret(String);
pub struct Raw { pub path_tenant: String, pub header_tenant: Option<String>, pub param: String, pub token: Secret }
impl Raw { pub fn new(pt: &str, p: &str, tok: &str) -> Raw { Raw { path_tenant: pt.into(), header_tenant: Some(pt.into()), param: p.into(), token: Secret(tok.into()) } } }
#[derive(Clone, Debug)] pub struct Note { pub id: u64, pub owner: UserId, pub body: String, pub archived: bool }
pub struct NewNote { pub owner: UserId, pub body: String }
#[derive(Clone, Default)] struct Store(Arc<Mutex<Vec<(TenantId, Note)>>>);
#[derive(Clone, Default)] struct Cache(Arc<Mutex<HashMap<String, String>>>);
pub struct TenantDb<'r> { store: &'r Store, tenant: &'r TenantId }          // not Clone, not 'static
impl TenantDb<'_> {
    pub fn notes(&self) -> Vec<Note> { self.store.0.lock().unwrap().iter().filter(|(t, _)| t == self.tenant).map(|(_, n)| n.clone()).collect() }
    pub fn get(&self, id: u64) -> Option<Note> { self.notes().into_iter().find(|n| n.id == id) }
}
pub struct TenantCache<'r> { c: &'r Cache, tenant: &'r TenantId }          // keys are namespaced by construction
impl TenantCache<'_> {
    pub fn get(&self, k: &str) -> Option<String> { self.c.0.lock().unwrap().get(&format!("{}/{k}", self.tenant.0)).cloned() }
    pub fn set(&self, k: &str, v: &str) { self.c.0.lock().unwrap().insert(format!("{}/{k}", self.tenant.0), v.into()); }
}
pub trait Effect {} pub struct Read; pub struct Write; pub struct Net;
impl Effect for Read {} impl Effect for Write {} impl Effect for Net {}
pub struct Ctx<'r, E: Effect> { pub principal: &'r Principal, pub db: TenantDb<'r>, pub cache: TenantCache<'r>, pub raw: &'r Raw, store: &'r Store, tenant: &'r TenantId, _e: PhantomData<E> }
pub struct Open; pub struct Tx<'r, S> { store: &'r Store, tenant: &'r TenantId, pending: Vec<Note>, _s: PhantomData<S> }
pub struct Committed(());
impl<'r> Ctx<'r, Write> {
    pub fn begin(&self) -> Tx<'r, Open> { Tx { store: self.store, tenant: self.tenant, pending: vec![], _s: PhantomData } }
    pub fn delete(&self, id: u64, _g: &Granted<DeleteNote>) { ev(format!("delete:{id}")); self.store.0.lock().unwrap().retain(|(t, n)| !(t == self.tenant && n.id == id)) }
}
impl Tx<'_, Open> {
    pub fn insert(&mut self, n: NewNote) { self.pending.push(Note { id: 1, owner: n.owner, body: n.body, archived: false }) }
    pub fn commit(self) -> Committed { ev("commit".into()); let mut s = self.store.0.lock().unwrap(); for n in self.pending { s.push((self.tenant.clone(), n)); } Committed(()) }
}
impl Committed { pub fn send_email(&self, _to: &UserId, _body: &str) { ev("email".into()) } }
pub struct Url(String);
impl Url { pub fn allowlisted(s: &str) -> Option<Url> { if s.starts_with("https://example.com/") { Some(Url(s.into())) } else { None } } }
impl Ctx<'_, Net> { pub fn http_get(&self, u: &Url) -> String { ev(format!("http_get:{}", u.0)); String::new() } }
pub struct Html(String);
impl Html {
    pub fn text(s: &str) -> Html { Html(s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")) }
    pub fn raw_static(s: &'static str) -> Html { Html(s.into()) }
    pub fn join(mut self, o: Html) -> Html { self.0.push_str(&o.0); self }
}
pub struct Response { pub status: u16, pub body: String }
impl Response {
    pub fn html(h: Html) -> Self { Response { status: 200, body: h.0 } }
    pub fn text(s: &'static str) -> Self { Response { status: 200, body: s.into() } }
    pub fn status(c: u16) -> Self { Response { status: c, body: String::new() } }
}
pub fn log(m: &str) { ev(format!("log:{m}")) }
pub struct World { store: Store, cache: Cache, users: HashMap<String, Principal> }
impl World {
    pub fn new() -> Self { World { store: Store::default(), cache: Cache::default(), users: HashMap::new() } }
    pub fn user(&mut self, tok: &str, u: &str, t: &str, admin: bool) { self.users.insert(tok.into(), Principal { user: UserId(u.into()), tenant: TenantId(t.into()), role: if admin { Role::Admin } else { Role::Member } }); }
    pub fn seed(&mut self, id: u64, t: &str, owner: &str, body: &str, archived: bool) { self.store.0.lock().unwrap().push((TenantId(t.into()), Note { id, owner: UserId(owner.into()), body: body.into(), archived })); }
    pub fn count(&self) -> usize { self.store.0.lock().unwrap().len() }
    pub fn call<E: Effect>(&self, raw: Raw, f: for<'r> fn(Ctx<'r, E>) -> Response) -> Response {
        let Some(p) = self.users.get(&raw.token.0) else { return Response::status(401) };
        f(Ctx { principal: p, db: TenantDb { store: &self.store, tenant: &p.tenant }, cache: TenantCache { c: &self.cache, tenant: &p.tenant }, raw: &raw, store: &self.store, tenant: &p.tenant, _e: PhantomData })
    }
}
