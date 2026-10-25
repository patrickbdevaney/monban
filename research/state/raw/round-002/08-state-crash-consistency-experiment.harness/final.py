import json,collections
rows=collections.defaultdict(lambda:{'seeds':set(),'states':0,'cls':collections.Counter(),'bypol':collections.defaultdict(collections.Counter)})
seen=set()
for l in open('results.jsonl'):
    d=json.loads(l);k=(d['store'],d['cfg'],d['seed'])
    if k in seen: continue
    seen.add(k); r=rows[(d['store'],d['cfg'])]; r['seeds'].add(d['seed']); r['states']+=d['states']
    for pr,t in d['tally'].items():
        for c,n in t.items():
            r['cls'][c]+=n; r['bypol'][pr][c]+=n
    for pr,t in d.get('lag',{}).items():
        for g,n in t.items(): r.setdefault('lag',collections.Counter())[int(g)]+=n
out=[]
for (s,c),r in sorted(rows.items()):
    viol={k:v for k,v in r['cls'].items() if k not in('ok',) }
    out.append({'store':s,'cfg':c,'seeds':sorted(r['seeds']),'states':r['states'],'classes':dict(r['cls']),
      'sigkill_all_full':dict(r['bypol'].get('all/full',{})),
      'strict_dropall':dict(r['bypol'].get('dropall/strict',{})),'journal_dropall':dict(r['bypol'].get('dropall/journal',{})),
      'journal_subset':dict(r['bypol'].get('subset/journal',{})),'lag':dict(r.get('lag',{}))})
json.dump(out,open('final_table.json','w'),indent=1)
for o in out: print(o['store'],o['cfg'],o['seeds'],o['states'],o['classes'])
