import subprocess, shutil, json, re, os, sys
R='/home/patrickd/aegis/research/state/raw/round-003/08-exp'
M=[
 ("M1","missing tenant filter",
  ("let notes = ctx.db.notes_for(&p.tenant);",'let notes = ctx.db.query("select * from notes");'),
  ("let notes = ctx.db.notes();","let notes = ctx.db.all_notes();")),
 ("M2","default principal",
  ("let Some(p) = ctx.principal.clone() else { return Response::status(401) };\n    let mut tx","let p = ctx.principal.clone().unwrap_or_default();\n    let mut tx"),
  ("let mut tx = ctx.begin();\n    tx.insert(NewNote { owner: ctx.principal.user().clone()","let p = Principal::default();\n    let mut tx = ctx.begin();\n    tx.insert(NewNote { owner: p.user().clone()")),
 ("M3","cross-tenant cache key",
  ('format!("notes:{}:{}", p.tenant, ctx.req.param)','format!("notes:{}", ctx.req.param)'),
  ('format!("notes:{}", ctx.raw.param)','format!("notes:{}", ctx.raw.param)')),  # B base already omits tenant: the SDK namespaces it
 ("M4","unescaped HTML",
  ("escape(&n.body)","n.body"),
  ('out = out.join(Html::raw_static("<li>")).join(Html::text(&n.body)).join(Html::raw_static("</li>"));','return Response::html(format!("<li>{}</li>", n.body));')),
 ("M5","effect before commit",
  ("    tx.commit();\n    send_email(&p.user, \"note created\");","    send_email(&p.user, \"note created\");\n    tx.commit();"),
  ('    let done = tx.commit();\n    done.send_email(ctx.principal.user(), "note created");','    tx.send_email(ctx.principal.user(), "note created");\n    let done = tx.commit();')),
 ("M6","write in read-only (GET) handler",
  ('    ctx.cache.set(&key, &out);','    let mut tx = ctx.db.begin(); tx.insert(Note { id: 9, tenant: p.tenant.clone(), owner: p.user.clone(), body: "audit".into(), archived: false }); tx.commit();\n    ctx.cache.set(&key, &out);'),
  ('    ctx.cache.set(&key, "");','    let mut tx = ctx.begin(); tx.insert(NewNote { owner: ctx.principal.user().clone(), body: "audit".into() }); tx.commit();\n    ctx.cache.set(&key, "");')),
 ("M7","forge principal from request header",
  ("let Some(p) = ctx.principal.clone() else { return Response::status(401) };\n    let mut tx","let p = Principal { user: \"hdr\".into(), tenant: ctx.req.header_tenant.clone().unwrap_or_default(), role: \"admin\".into() };\n    let mut tx"),
  ("let mut tx = ctx.begin();\n    tx.insert(NewNote { owner: ctx.principal.user().clone()","let p = Principal { user: ctx.principal.user().clone(), tenant: TenantId(ctx.raw.header_tenant.clone().unwrap()), role: Role::Admin };\n    let mut tx = ctx.begin();\n    tx.insert(NewNote { owner: p.user().clone()")),
 ("M8","tenant from request path (IDOR)",
  ("ctx.db.notes_for(&p.tenant);\n    let mut out","ctx.db.notes_for(&ctx.req.path_tenant);\n    let mut out"),
  ("let notes = ctx.db.notes();","let notes = ctx.db.notes_for(&ctx.raw.path_tenant);")),
 ("M9","SQL string concatenation of user input",
  ("let notes = ctx.db.notes_for(&p.tenant);","let sql = format!(\"select * from notes where tenant='{}' and q='{}'\", p.tenant, ctx.req.param); let notes: Vec<Note> = ctx.db.query(&sql).into_iter().filter(|n| n.tenant == p.tenant).collect();"),
  ("let notes = ctx.db.notes();","let sql = format!(\"select * from notes where q='{}'\", ctx.raw.param); let notes = ctx.db.query(&sql);")),
 ("M10","missing authz check on delete",
  ('    if p.role != "admin" { return Response::status(403); }\n',''),
  ("    let Some(g) = ctx.principal.can::<DeleteNote>() else { return Response::status(403) };\n","")),
 ("M11","DB handle escapes request (stashed in static)",
  ("pub fn list_notes(ctx: &Ctx) -> Response {","static STASH: std::sync::Mutex<Vec<Db>> = std::sync::Mutex::new(Vec::new());\npub fn list_notes(ctx: &Ctx) -> Response {\n    STASH.lock().unwrap().push(ctx.db.clone());"),
  ("pub fn list_notes(ctx: Ctx<'_, Read>) -> Response {","static STASH: std::sync::Mutex<Vec<TenantDb<'static>>> = std::sync::Mutex::new(Vec::new());\npub fn list_notes(ctx: Ctx<'_, Read>) -> Response {\n    STASH.lock().unwrap().push(ctx.db);")),
 ("M12","SSRF: unvalidated URL fetched",
  ('    if !ctx.req.param.starts_with("https://example.com/") { return Response::status(403); }\n',''),
  ("let Some(u) = Url::allowlisted(&ctx.raw.param) else { return Response::status(403) };\n    let _ = ctx.http_get(&u);","let _ = ctx.http_get(&ctx.raw.param);")),
 ("M13","bearer token written to log",
  ('log(&format!("list ok tenant={}", p.tenant));','log(&format!("list ok tenant={} token={}", p.tenant, ctx.req.token));'),
  ('log(&format!("list ok tenant={:?}", ctx.principal.tenant()));','log(&format!("list ok tenant={:?} token={}", ctx.principal.tenant(), ctx.raw.token));')),
 ("M14","use transaction after commit",
  ("    tx.commit();\n    send_email","    tx.commit();\n    tx.insert(Note { id: 2, tenant: p.tenant.clone(), owner: p.user.clone(), body: \"dup\".into(), archived: false });\n    send_email"),
  ("    let done = tx.commit();","    let done = tx.commit();\n    tx.insert(NewNote { owner: ctx.principal.user().clone(), body: \"dup\".into() });")),
 ("M15","semantic: skip same-tenant ownership check on delete",
  ("x.id == id && x.owner == p.user","x.id == id"),
  ("Some(n) if &n.owner == ctx.principal.user() => {}","Some(n) => {}")),
 ("M16","semantic: archived rows leaked into listing",
  ("notes.iter().filter(|n| !n.archived)","notes.iter()"),
  ("notes.iter().filter(|n| !n.archived)","notes.iter()")),
]
def run(shape, cmd):
    p=subprocess.run(['/home/patrickd/aegis/research/tools/heavy.sh','cargo']+cmd+['--offline','--manifest-path',f'{R}/shape_{shape}/Cargo.toml'],capture_output=True,text=True)
    return p
res=[]
for shape in 'ab':
    app=open(f'{R}/shape_{shape}/src/app.rs').read(); base=app
    for mid,cls,a,b in M:
        old,new=a if shape=='a' else b
        if old not in base: print('MISSING',shape,mid); res.append(dict(shape=shape,id=mid,status='ERR_NOMATCH')); continue
        open(f'{R}/shape_{shape}/src/app.rs','w').write(base.replace(old,new,1))
        c=run(shape,['check','--color','never'])
        err=c.stderr
        errs=re.findall(r'^error(\[E\d+\])?: (.*)$',err,re.M)
        errs=[e for e in errs if not e[1].startswith('aborting')]
        d=dict(shape=shape,id=mid,cls=cls)
        if c.returncode!=0:
            d.update(status='REJECTED',codes=sorted(set(e[0] for e in errs if e[0])),first=errs[0][1] if errs else '?',n_errors=len(errs),stderr_lines=len(err.strip().splitlines()),stderr_chars=len(err))
            # note: lines of "help:" / "note:" suggestions
            d['help_lines']=len(re.findall(r'^\s*(= help|help):',err,re.M))
        else:
            r=run(shape,['run','-q'])
            m=re.search(r'ORACLE (.*)',r.stdout)
            kv=dict(x.split('=') for x in m.group(1).split()) if m else {}
            viol=[k for k,v in kv.items() if v=='1']
            d.update(status='COMPILED_VIOLATION' if (viol or mid in('M11','M14')) else 'COMPILED_NEUTRALIZED',violations=viol,oracle=m.group(1) if m else r.stderr[-300:])
        res.append(d); print(shape,mid,d['status'],d.get('codes'),d.get('violations'),d.get('stderr_lines'))
    open(f'{R}/shape_{shape}/src/app.rs','w').write(base)
json.dump(res,open(f'{R}/results.json','w'),indent=1)
