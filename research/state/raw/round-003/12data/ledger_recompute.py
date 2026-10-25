import json,re,collections,math,sys
d=json.load(open(sys.argv[1]))
par={}
def f(x):
    par.setdefault(x,x)
    while par[x]!=x: par[x]=par[par[x]]; x=par[x]
    return x
def u(a,b): par[f(a)]=f(b)
for r in d:
    for a in r['aliases']+[r['id']]: u(r['id'],a)
cl=collections.defaultdict(list)
for r in d: cl[f(r['id'])].append(r)
def cls(t):
    t=t.lower()
    if re.search(r'smuggl|content-length|transfer-encoding|chunk|newline|split|desync|lenient|request line|header.*pars|pars.*header',t): return 'smuggling/parse'
    if re.search(r'exhaust|dos\b|denial|memory (growth|consumption|leak)|unbounded|flood|reset|continuation|oom|cpu|infinite loop|loop|amplif|resource|slow|stack overflow|overflow.*recurs|panic|crash|abort|hang|excessive|large|memory usage|stalls?|deadlock',t): return 'resource/DoS'
    if re.search(r'cert|tls|verif|hostname|x509|mitm|crl|name constraint|signature|ocsp|downgrade|handshake|key',t): return 'tls/cert-logic'
    if re.search(r'unsound|uninit|use.after|double free|out.of.bounds|memory|data race|soundness|ffi|undefined',t): return 'unsound/memory'
    return 'other'
rows=[]
for k,rs in cl.items():
    dates=sorted(r['published'] for r in rs)
    rustsec=[r for r in rs if r['id'].startswith('RUSTSEC')]
    rsdate=min((r['published'] for r in rustsec),default=None)
    summ=' | '.join(sorted(set(r['summary'] or '' for r in rs)))
    rows.append(dict(k=k,pkgs=sorted(set(r['pkg'] for r in rs)),first=dates[0],rsdate=rsdate,ghsa_only=not rustsec,cls=cls(summ),summ=summ[:160]))
def wil(k,n,z=1.96):
    if n==0: return (0,0)
    p=k/n;den=1+z*z/n;c=(p+z*z/(2*n))/den;h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den;return(round(c-h,2),round(c+h,2))
print('raw records',len(d),'deduped clusters',len(rows))
for datekey in ('first',):
  sel=[r for r in rows if r[datekey]>='2023']
  n=len(sel);c=collections.Counter(r['cls'] for r in sel)
  print('2023+ n=',n,{k:(v,round(v/n,2),wil(v,n)) for k,v in c.items()})
  for y in ('2023','2024','2025','2026'):
    s=[r for r in sel if r[datekey].startswith(y)];n=len(s);c=collections.Counter(r['cls'] for r in s)
    print(y,n,{k:(v,wil(v,n)) for k,v in c.items()})
pk=collections.Counter(p for r in rows if r['first']>='2023' for p in r['pkgs'])
print(pk)
json.dump(rows,open(sys.argv[2],'w'),indent=0)
for r in sorted(rows,key=lambda r:r['first']):
    if r['first']>='2023': print(r['first'],r['cls'][:8],','.join(r['pkgs'])[:20],r['summ'][:100])
