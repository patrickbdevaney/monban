#![allow(dead_code)]
use sdk::*;
pub fn list_notes(ctx: Ctx<'_, Read>) -> Response {
    let key = format!("notes:{}", ctx.raw.param);
    if let Some(c) = ctx.cache.get(&key) { return Response::html(Html::raw_static("").join(Html::text(&c))); }
    let notes = ctx.db.notes();
    let mut out = Html::raw_static("");
    for n in notes.iter().filter(|n| !n.archived) { out = out.join(Html::raw_static("<li>")).join(Html::text(&n.body)).join(Html::raw_static("</li>")); }
    ctx.cache.set(&key, "");
    log(&format!("list ok tenant={:?}", ctx.principal.tenant()));
    Response::html(out)
}
pub fn create_note(ctx: Ctx<'_, Write>) -> Response {
    let p = Principal { user: ctx.principal.user().clone(), tenant: TenantId(ctx.raw.header_tenant.clone().unwrap()), role: Role::Admin };
    let mut tx = ctx.begin();
    tx.insert(NewNote { owner: p.user().clone(), body: ctx.raw.param.clone() });
    let done = tx.commit();
    done.send_email(ctx.principal.user(), "note created");
    Response::text("ok")
}
pub fn delete_note(ctx: Ctx<'_, Write>) -> Response {
    let Some(g) = ctx.principal.can::<DeleteNote>() else { return Response::status(403) };
    let id: u64 = ctx.raw.param.parse().unwrap_or(0);
    match ctx.db.get(id) { Some(n) if &n.owner == ctx.principal.user() => {}, _ => return Response::status(404) }
    ctx.delete(id, &g);
    Response::text("deleted")
}
pub fn fetch_preview(ctx: Ctx<'_, Net>) -> Response {
    let Some(u) = Url::allowlisted(&ctx.raw.param) else { return Response::status(403) };
    let _ = ctx.http_get(&u);
    Response::text("fetched")
}

fn main(){}
