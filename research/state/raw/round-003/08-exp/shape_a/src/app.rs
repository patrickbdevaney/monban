use crate::sdk::*;
pub fn list_notes(ctx: &Ctx) -> Response {
    let Some(p) = ctx.principal.clone() else { return Response::status(401) };
    let key = format!("notes:{}:{}", p.tenant, ctx.req.param);
    if let Some(c) = ctx.cache.get(&key) { return Response::html(c); }
    let notes = ctx.db.notes_for(&p.tenant);
    let mut out = String::new();
    for n in notes.iter().filter(|n| !n.archived) { out.push_str(&format!("<li>{}</li>", escape(&n.body))); }
    ctx.cache.set(&key, &out);
    log(&format!("list ok tenant={}", p.tenant));
    Response::html(out)
}
pub fn create_note(ctx: &Ctx) -> Response {
    let Some(p) = ctx.principal.clone() else { return Response::status(401) };
    let mut tx = ctx.db.begin();
    tx.insert(Note { id: 1, tenant: p.tenant.clone(), owner: p.user.clone(), body: ctx.req.param.clone(), archived: false });
    tx.commit();
    send_email(&p.user, "note created");
    Response::text("ok")
}
pub fn delete_note(ctx: &Ctx) -> Response {
    let Some(p) = ctx.principal.clone() else { return Response::status(401) };
    if p.role != "admin" { return Response::status(403); }
    let id: u64 = ctx.req.param.parse().unwrap_or(0);
    let mine = ctx.db.notes_for(&p.tenant);
    if !mine.iter().any(|x| x.id == id && x.owner == p.user) { return Response::status(404); }
    ctx.db.delete(id);
    Response::text("deleted")
}
pub fn fetch_preview(ctx: &Ctx) -> Response {
    let Some(_p) = ctx.principal.clone() else { return Response::status(401) };
    if !ctx.req.param.starts_with("https://example.com/") { return Response::status(403); }
    Response::text(http_get(&ctx.req.param))
}
