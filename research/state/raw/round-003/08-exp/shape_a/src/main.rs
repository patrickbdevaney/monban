#![allow(dead_code, unused)]
mod sdk; mod app;
use sdk::*;
fn rq(tok: &str, param: &str, pt: &str) -> Request { Request { path_tenant: pt.into(), header_tenant: Some(pt.into()), param: param.into(), token: tok.into() } }
fn main() {
    let mut w = World::new();
    w.user("tok-u1", "u1", "t1", "admin"); w.user("tok-u2", "u2", "t2", "admin"); w.user("tok-u3", "u3", "t1", "member");
    w.seed(100, "t1", "u3", "u3-secret", false); w.seed(101, "t1", "u3", "ARCH", true);
    let mut v: Vec<(&str, bool)> = vec![];
    w.call(rq("tok-u1", "<b>pwn</b>", "t1"), app::create_note);
    let l1 = w.call(rq("tok-u1", "k", "t1"), app::list_notes);
    let l2 = w.call(rq("tok-u2", "k", "t1"), app::list_notes);
    v.push(("leak", l2.body.contains("pwn") || l2.body.contains("u3-secret")));
    v.push(("xss", l1.body.contains("<b>pwn</b>")));
    v.push(("archived", l1.body.contains("ARCH")));
    let before = w.count(); w.call(rq("tok-u1", "z", "t1"), app::list_notes); v.push(("readwrite", w.count() != before));
    let before = w.count(); w.call(rq("none", "evil", "t1"), app::create_note); v.push(("unauth", w.count() != before));
    w.call(rq("tok-u1", "http://169.254.169.254/", "t1"), app::fetch_preview);
    w.call(rq("tok-u1", "x' OR '1'='1", "t1"), app::list_notes);
    w.call(rq("tok-u3", "100", "t1"), app::delete_note); let d3 = w.count();
    v.push(("authz_delete", sdk::EV.with(|e| e.borrow().iter().any(|s| s == "delete:100"))));
    sdk::EV.with(|e| e.borrow_mut().retain(|s| s != "delete:100"));
    w.call(rq("tok-u1", "100", "t1"), app::delete_note);
    v.push(("owner_delete", sdk::EV.with(|e| e.borrow().iter().any(|s| s == "delete:100"))));
    let ev = sdk::EV.with(|e| e.borrow().clone());
    v.push(("ssrf", ev.iter().any(|s| s.starts_with("http_get:http://169"))));
    v.push(("sqli", ev.iter().any(|s| s.starts_with("query:") && s.contains("OR '1'='1"))));
    v.push(("tokenlog", ev.iter().any(|s| s.starts_with("log:") && s.contains("tok-"))));
    let (ic, ie) = (ev.iter().position(|s| s == "commit"), ev.iter().position(|s| s == "email"));
    v.push(("effect_order", matches!((ic, ie), (Some(c), Some(e)) if e < c)));
    println!("ORACLE {}", v.iter().map(|(k, b)| format!("{k}={}", *b as u8)).collect::<Vec<_>>().join(" "));
}
