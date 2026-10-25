import json
from collections import Counter
items=json.load(open('adv.json'));items.sort(key=lambda x:x['published_at'])
# idx: (tags, impact, note)  tags = REQUIRED feature preconditions (all must be enabled)
# impact: ESC (sandbox escape / host memory corruption / arb r/w), LEAK (info leak), POLICY (host policy bypass), DOS-PANIC, DOS-RES, UB/other
# 'embedder' tag = not guest-triggerable; requires specific embedder API usage
T={
0:("core cranelift","ESC"),1:("embedder","OTHER"),2:("core reftypes","ESC"),3:("core reftypes embedder","ESC"),
4:("pooling reftypes","ESC"),5:("core reftypes epoch","ESC"),6:("core cranelift x64 simd","ESC"),7:("core reftypes","ESC"),
8:("aarch64","ESC"),9:("capi embedder","OTHER"),10:("pooling","LEAK"),11:("core knob:zero-pages","ESC"),
12:("core cranelift x64 simd","ESC"),13:("core cranelift x64","ESC"),14:("core","ESC"),15:("core cranelift x64 simd","ESC"),
16:("core reftypes","DOS-PANIC"),17:("embedder threads","ESC"),18:("core tailcall","DOS-PANIC"),19:("wasi-fs windows","POLICY"),
20:("wasip1","DOS-PANIC"),21:("capi embedder","OTHER"),22:("component","DOS-PANIC"),23:("embedder threads","OTHER"),
24:("core cranelift x64 knob:signals-off-or-noguard","ESC-nonexploitable"),25:("component wasi-http","DOS-PANIC"),26:("embedder-async","DOS-PANIC"),27:("wasi","DOS-RES"),
28:("component","ESC"),29:("embedder","OTHER"),30:("pooling knob:guard0+reservation<4G","LEAK"),31:("winch memory64","LEAK"),
32:("winch","DOS-PANIC"),33:("core cranelift x64 knob:sse3-off+signals-off","ESC-nonexploitable"),34:("winch","ESC"),35:("component","DOS-PANIC"),
36:("component","DOS-PANIC"),37:("aarch64 memory64 knob:spectre-or-signals-off","ESC"),38:("winch","ESC"),39:("component","ESC"),
40:("memory64 on-demand","DOS-PANIC"),41:("wasi-fs","POLICY"),42:("wasip1","LEAK"),43:("wasi-fs","POLICY"),
44:("embedder","ESC"),45:("epoch-or-fuel gc embedder","ESC"),46:("wasi-fs","ESC"),47:("cm-async wasi-fs-or-http","DOS-RES"),
48:("wasi-fs","DOS-PANIC"),49:("wasi-http","DOS-RES"),50:("component embedder","DOS-RES"),51:("fuel exceptions","DOS-RES"),
52:("wasip1 wasi-fs","LEAK"),53:("gc exceptions","ESC"),54:("wasip1 fuel","DOS-RES"),55:("wasi","DOS-RES"),
56:("wasi-http","DOS-PANIC"),57:("gc exceptions","ESC"),58:("cm-async","ESC"),59:("cm-async wasi-fs","DOS-PANIC"),
60:("wasi-fs","ESC"),61:("wasi-http","POLICY"),62:("wasi-http","DOS-PANIC"),63:("component","DOS-PANIC"),
64:("exceptions","UB"),65:("component","DOS-RES"),66:("cm-async","DOS-PANIC"),67:("cm-async embedder","OTHER"),
68:("cm-async","DOS-PANIC"),69:("cm-async","DOS-PANIC"),70:("component","DOS-PANIC"),71:("cm-async","DOS-PANIC"),
72:("cm-async","DOS-PANIC"),73:("cm-async","DOS-PANIC"),74:("gc","DOS-PANIC"),75:("wasi-http","POLICY"),
76:("wasi-http cm-async","POLICY"),77:("wasi-http cm-async","POLICY"),78:("aarch64","ESC"),79:("core cranelift","ESC"),80:("cm-async","DOS-PANIC"),
}
assert len(T)==81
# enabled feature sets (tags that an advisory may require and still 'hit')
BASE={"core","cranelift","x64","simd","tailcall","reftypes","epoch","fuel","pooling"}
CFG={
 "M0_core_only":BASE,
 "M1_core+P2components(no fs,no async)":BASE|{"component","wasi","wasip1","wasi-http","knob:none"},
 "M2_M1+wasi-fs":BASE|{"component","wasi","wasip1","wasi-http","wasi-fs"},
}
rows=[]
for i,x in enumerate(items):
    tags,imp=T[i];ts=set(tags.split())
    emb='embedder' in ts or 'embedder-async' in ts or 'capi' in ts
    knob=[t for t in ts if t.startswith('knob:')]
    req=ts-{'embedder','embedder-async','capi'}-set(knob)
    hit={}
    for c,en in CFG.items():
        en2=en|{"knob:none"}
        hit[c]=req<=en2 and not (('windows' in req))
    rows.append(dict(i=i,ghsa=x['ghsa_id'],cve=x.get('cve_id'),date=x['published_at'][:10],year=x['published_at'][:4],sev=x['severity'],impact=imp,tags=tags,emb=emb,knob=knob,hit=hit,summary=x['summary']))
json.dump(rows,open('classified.json','w'),indent=1)
def rep(name,sel):
    r=[a for a in rows if sel(a)];n=len(r)
    print(f"\n### {name}: n={n}")
    for c in CFG:
        h=[a for a in r if a['hit'][c]]
        hg=[a for a in h if not a['emb']]
        esc=[a for a in hg if a['impact'].startswith('ESC') and a['impact']=='ESC']
        print(f" {c}: hit={len(h)} ({100*len(h)/n:.0f}%); guest-triggerable hit={len(hg)} ({100*len(hg)/n:.0f}%); ESC-class guest hit={len(esc)}; sev={dict(Counter(a['sev'] for a in hg))}; knob-gated={sum(1 for a in hg if a['knob'])}")
rep("ALL 81",lambda a:True)
rep("2024-2026 (65)",lambda a:a['year']>='2024')
rep("2026 (57)",lambda a:a['year']=='2026')
rep("2026 excl <=24.x/36.x-only... n/a",lambda a:a['year']=='2026' and a['i']!=0)
print("\nFeature tag frequency (2026):",Counter(t for a in rows if a['year']=='2026' for t in a['tags'].split()).most_common())
print("\nM0 hits guest-trigger 2024-26:")
for a in rows:
    if a['year']>='2024' and a['hit']["M0_core_only"] and not a['emb']: print(a['ghsa'],a['sev'],a['impact'],a['tags'],a['summary'][:70])
print("\nM1 hits ESC-class 2024-26:")
for a in rows:
    if a['year']>='2024' and a['hit']["M1_core+P2components(no fs,no async)"] and not a['emb'] and a['impact'].startswith('ESC'): print(a['ghsa'],a['sev'],a['impact'],a['tags'],a['summary'][:70])
print("\nNo-feature-gate (hits any config incl. aarch64-agnostic):")
cnt=Counter()
for a in rows:
    if a['year']>='2024':
        ts=set(a['tags'].split())
        grp=('cm-async' if 'cm-async' in ts or 'embedder-async' in ts else 'gc/exceptions' if ts&{'gc','exceptions'} else 'winch' if 'winch' in ts else 'aarch64' if 'aarch64' in ts else 'memory64' if 'memory64' in ts else 'wasi-fs' if 'wasi-fs' in ts else 'wasi-http' if 'wasi-http' in ts else 'component' if 'component' in ts else 'wasip1/wasi' if ts&{'wasip1','wasi'} else 'embedder-only' if a['emb'] else 'core/x64-cranelift/other')
        cnt[grp]+=1
print(cnt)
