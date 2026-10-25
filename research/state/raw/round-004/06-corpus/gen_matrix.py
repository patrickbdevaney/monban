import json, sys, collections, os
def load(p):
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []
rows=[r for r in load('out/results.jsonl') if not r['target'].startswith('agentgateway') and not r['target'].startswith('docker')]+load('out_ag/results.jsonl')+load('out_extra/results.jsonl')+load('out_docker/results.jsonl')+load('out_drp/results.jsonl')+load('out_manual/results.jsonl')
tg=collections.OrderedDict(); cases=collections.OrderedDict()
for r in rows:
    if r['case']=='BASELINE': continue
    k=(r['target'],r['era']); tg.setdefault(k,{})[r['case']]=r; cases.setdefault(r['case'],1)
cols=list(tg.keys())
ab={'PASS':'P','FAIL':'F','WARN':'W','NA':'-','ERR':'E'}
print('| case | '+' | '.join(f"{t.split('/')[0][:18]}/{t.split('/')[1][:14]}:{e[0]}" for t,e in cols)+' |')
for c in cases:
    print('| '+c+' | '+' | '.join(ab.get(tg[k].get(c,{}).get('verdict'),' ') if c in tg[k] else ' ' for k in cols)+' |')
json.dump(rows,open('all_results.json','w'))
