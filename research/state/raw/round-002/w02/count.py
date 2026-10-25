import subprocess,sys,os,re,glob,json
proj=sys.argv[1]
out=subprocess.check_output(['cargo','tree']+(['--features',os.environ['FE']] if os.environ.get('FE') else [])+['-e','no-build,no-dev,no-proc-macro','--prefix','none','-f','{p}'],cwd=proj,text=True,stderr=subprocess.DEVNULL)
pk=sorted({l.split(' (')[0].strip() for l in out.splitlines() if l.strip()})
reg=glob.glob(os.path.expanduser('~/.cargo/registry/src/*/'))[0]
rows=[];kw=re.compile(r'\bunsafe\b')
for p in pk:
    n,v=p.split(' v'); d=reg+n+'-'+v
    if not os.path.isdir(d): rows.append((n,v,None,None,0,0));continue
    u=l=0;c=0
    for r,_,fs in os.walk(d):
        if re.search(r'/(tests|benches|examples|target)(/|$)',r): continue
        for f in fs:
            fp=os.path.join(r,f)
            if f.endswith('.rs'):
                for line in open(fp,errors='ignore'):
                    s=line.strip()
                    if not s or s.startswith('//'): continue
                    l+=1
                    if kw.search(s): u+=1
            elif f.endswith(('.c','.h','.S','.s','.cc','.cpp')) and ('aws-lc' in n or 'sys' in n):
                try: c+=sum(1 for _ in open(fp,errors='ignore'))
                except: pass
    rows.append((n,v,l,u,c))
tot_l=sum(r[2] or 0 for r in rows);tot_u=sum(r[3] or 0 for r in rows)
print(proj,'crates',len(rows),'rustLOC',tot_l,'unsafe-lines',tot_u,'C/asm LOC in -sys',sum(r[4] for r in rows if len(r)>4 and r[4]))
non=[r for r in rows if r[2] is not None and not r[0].startswith('aws-lc')]
print(' excl aws-lc-*: rustLOC',sum(r[2] for r in non),'unsafe',sum(r[3] for r in non))
rows2=sorted([r for r in rows if r[2]],key=lambda r:-r[3])[:12]
for r in rows2: print('  ',r[0],r[1],'rustLOC',r[2],'unsafe',r[3],'C',r[4])
print(' missing dirs:',[r[0] for r in rows if r[2] is None])
json.dump(rows,open(proj+'.unsafe.json','w'))
