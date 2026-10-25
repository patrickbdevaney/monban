#![allow(dead_code, unused)]
mod sdk; mod app;
use sdk::*;
fn main() {
    let mut w = World::new();
    w.user("tok-u1", "u1", "t1", true); w.user("tok-u2", "u2", "t2", true); w.user("tok-u3", "u3", "t1", false);
    w.seed(100, "t1", "u3", "u3-secret", false); w.seed(101, "t1", "u3", "ARCH", true);
    let mut v: Vec<(&str, bool)> = vec![];
    w.call(Raw::new("t1", "<b>pwn</b>", "tok-u1"), app::create_note);
    let l1 = w.call(Raw::new("t1", "k", "tok-u1"), app::list_notes);
    let l2 = w.call(Raw::new("t1", "k", "tok-u2"), app::list_notes);
    v.push(("leak", l2.body.contains("pwn") || l2.body.contains("u3-secret")));
    v.push(("xss", l1.body.contains("<b>pwn</b>")));
    v.push(("archived", l1.body.contains("ARCH")));
    let before = w.count(); w.call(Raw::new("t1", "z", "tok-u1"), app::list_notes); v.push(("readwrite", w.count() != before));
    let before = w.count(); w.call(Raw::new("t1", "evil", "none"), app::create_note); v.push(("unauth", w.count() != before));
    w.call(Raw::new("t1", "http://169.254.169.254/", "tok-u1"), app::fetch_preview);
    w.call(Raw::new("t1", "x' OR '1'='1", "tok-u1"), app::list_notes);
    w.call(Raw::new("t1", "100", "tok-u3"), app::delete_note);
    v.push(("authz_delete", sdk::EV.with(|e| e.borrow().iter().any(|s| s == "delete:100"))));
    sdk::EV.with(|e| e.borrow_mut().retain(|s| s != "delete:100"));
    w.call(Raw::new("t1", "100", "tok-u1"), app::delete_note);
    v.push(("owner_delete", sdk::EV.with(|e| e.borrow().iter().any(|s| s == "delete:100"))));
    let ev = sdk::EV.with(|e| e.borrow().clone());
    v.push(("ssrf", ev.iter().any(|s| s.starts_with("http_get:http://169"))));
    v.push(("sqli", ev.iter().any(|s| s.starts_with("query:") && s.contains("OR '1'='1"))));
    v.push(("tokenlog", ev.iter().any(|s| s.starts_with("log:") && s.contains("tok-"))));
    let (ic, ie) = (ev.iter().position(|s| s == "commit"), ev.iter().position(|s| s == "email"));
    v.push(("effect_order", matches!((ic, ie), (Some(c), Some(e)) if e < c)));
    println!("ORACLE {}", v.iter().map(|(k, b)| format!("{k}={}", *b as u8)).collect::<Vec<_>>().join(" "));
}
