#!/usr/bin/env python3
"""AEGIS crash-state simulator (ALICE-style logical-op replay over an LD_PRELOAD op trace).
usage: crashsim.py store cfg N cuts seed [outjsonl]
Fault model. At cut k (after op k of the trace; acked = last M marker <= k) the crash image =
  durable data (fsync/fdatasync/O_DSYNC'd before k) + survivors among unsynced data ops (policy) + namespace per regime.
 policies: dropall | all (== SIGKILL, page cache intact) | subset (each 4KiB page of each unsynced write survives w.p. .5, arbitrary reorder)
           | prefix (random prefix of unsynced ops in issue order across files, last write torn at 512B sector granularity)
 ns regimes: full (SIGKILL: all ns ops kept), fsfile (create durable at fsync(file); rename/unlink need dir fsync; ext4/xfs-practice-like), journal (a random prefix of namespace ops since the last fsync of anything survives; ext4 data=ordered-like)
             strict  (a ns op is durable only after fsync of its parent dir; else survives w.p. .5 independently)
NOT modelled: mmap stores (logged as MMAPW), partial-sector tearing below 512B, bit rot, misdirected writes, fsync error semantics."""
import sys, os, random, subprocess, shutil, json, collections, concurrent.futures as cf, time
HERE=os.path.dirname(os.path.abspath(__file__)); WL=os.environ.get('WL',HERE+'/wl/target-libc/release/wl'); SHIM=HERE+'/shim/libaegis.so'
PAGE=4096; SECT=512
def apply(buf,op):
    if op[1]=='w':
        off,d=op[2],op[3]
        if len(buf)<off: buf.extend(b'\0'*(off-len(buf)))
        buf[off:off+len(d)]=d
    elif op[1]=='x':
        if len(buf)<op[2]: buf.extend(b'\0'*(op[2]-len(buf)))
    else:
        n=op[2]
        if n<len(buf): del buf[n:]
        else: buf.extend(b'\0'*(n-len(buf)))
def parse(log):
    ops=[]
    for ln in open(log):
        p=ln.rstrip('\n').split(' ')
        c=p[0]
        if c=='W': ops.append(('W',p[1],int(p[2]),bytes.fromhex(p[4]) if len(p)>4 else b''))
        elif c in('S','U','D','X'): ops.append((c,p[1]))
        elif c=='O': ops.append(('O',p[1],int(p[2])))
        elif c=='T': ops.append(('T',p[1],int(p[2])))
        elif c=='A': ops.append(('A',p[1],int(p[2]),int(p[3]),int(p[4])))
        elif c=='R': ops.append(('R',p[1],p[2]))
        elif c=='M': ops.append(('M',int(p[1])))
        elif c=='MMAPW': ops.append(('MMAPW',p[1]))
    return ops
def ns_apply(ns,o):
    if o[1]=='C': ns[o[2]]=o[3]
    elif o[1]=='R':
        if o[2] in ns: ns[o[3]]=ns.pop(o[2])
    elif o[1]=='U': ns.pop(o[2],None)
class Sim:
    def __init__(s,root):
        s.root=root; s.nid=0; s.vis={}; s.last={}; s.dirs={root}; s.seq=0; s.acked=0; s.mmapw=set()
        s.dur={}      # ino -> bytearray durable
        s.pend={}     # ino -> [ops]
        s.durJ={}; s.pendJ=[]; s.durS={}; s.pendS=[]; s.durF={}; s.pendF=[]; s.allns={}
    def res(s,p):
        if p.endswith(' (deleted)'): return s.last.get(p[:-10])
        return s.vis.get(p) or s.last.get(p)
    def nsop(s,o):
        s.pendJ.append(o); s.pendS.append(o); s.pendF.append(o); ns_apply(s.allns,o)
    def step(s,op):
        c=op[0]; s.seq+=1; q=s.seq
        if c=='D': s.dirs.add(op[1])
        elif c=='O':
            p=op[1]
            if p in s.dirs: return
            if p not in s.vis:
                s.nid+=1; i=s.nid; s.vis[p]=i; s.last[p]=i; s.dur[i]=bytearray(); s.pend[i]=[]; s.nsop((q,'C',p,i))
            elif op[2]: s.pend[s.vis[p]].append((q,'t',0))
        elif c=='W':
            i=s.res(op[1])
            if i: s.pend[i].append((q,'w',op[2],op[3]))
        elif c=='T':
            i=s.res(op[1])
            if i: s.pend[i].append((q,'t',op[2]))
        elif c=='A':
            i=s.res(op[1])
            if i and (op[2]&1)==0: s.pend[i].append((q,'x',op[3]+op[4]))
        elif c=='S':
            p=op[1]
            if p in s.dirs:
                keep=[]
                for o in s.pendS:
                    paths=[o[2]]+([o[3]] if o[1]=='R' else [])
                    if o[1]=='C': paths=[o[2]]
                    if any(os.path.dirname(x)==p for x in paths): ns_apply(s.durS,o)
                    else: keep.append(o)
                s.pendS=keep; keep=[]
                for o in s.pendF:
                    paths=[o[2]]+([o[3]] if o[1]=='R' else [])
                    if any(os.path.dirname(x)==p for x in paths): ns_apply(s.durF,o)
                    else: keep.append(o)
                s.pendF=keep
            else:
                i=s.res(p)
                if i:
                    for o in s.pend[i]: apply(s.dur[i],o)
                    s.pend[i]=[]
                    keep=[]
                    for o in s.pendF:
                        if o[1]=='C' and o[3]==i: ns_apply(s.durF,o)
                        else: keep.append(o)
                    s.pendF=keep
            for o in s.pendJ: ns_apply(s.durJ,o)
            s.pendJ=[]
        elif c=='R':
            a,b=op[1],op[2]
            if a in s.vis: i=s.vis.pop(a); s.vis[b]=i; s.last[b]=i; s.nsop((q,'R',a,b))
        elif c in('U','X'):
            if op[1] in s.vis: s.vis.pop(op[1]); s.nsop((q,'U',op[1]))
        elif c=='M': s.acked=op[1]
        elif c=='MMAPW': s.mmapw.add(op[1])
    def image(s,policy,regime,rng):
        # data survivors
        cand=[]  # (ino, op)
        for i,l in s.pend.items():
            for o in l: cand.append((o[0],i,o))
        cand.sort(key=lambda x:x[0])
        surv=[]
        if policy=='all': surv=cand
        elif policy=='dropall': surv=[]
        elif policy=='prefix':
            k=rng.randint(0,len(cand)); surv=cand[:k]
            if surv and surv[-1][2][1]=='w':
                q,i,o=surv[-1]; n=len(o[3]); sec=(n+SECT-1)//SECT; keep=rng.randint(0,sec)*SECT
                surv[-1]=(q,i,(o[0],'w',o[2],o[3][:min(keep,n)]))
        elif policy=='subset':
            for q,i,o in cand:
                if o[1]=='w':
                    off,d=o[2],o[3]; p0=off//PAGE; p1=(off+len(d)-1)//PAGE if d else p0-1
                    for pg in range(p0,p1+1):
                        if rng.random()<.5:
                            a=max(off,pg*PAGE); b=min(off+len(d),(pg+1)*PAGE)
                            surv.append((q,i,(q,'w',a,d[a-off:b-off])))
                elif rng.random()<.5: surv.append((q,i,o))
        # namespace
        if regime=='journal':
            ns=dict(s.durJ); k=rng.randint(0,len(s.pendJ))
            for o in s.pendJ[:k]: ns_apply(ns,o)
        elif regime=='fsfile':
            ns=dict(s.durF)
            for o in s.pendF:
                if rng.random()<.5: ns_apply(ns,o)
        elif regime=='full': ns=dict(s.allns)
        else:
            ns=dict(s.durS)
            for o in s.pendS:
                if rng.random()<.5: ns_apply(ns,o)
        data={i:bytearray(b) for i,b in s.dur.items()}
        for q,i,o in surv: apply(data[i],o)
        return {p:bytes(data[i]) for p,i in ns.items()}
def materialize(img,root,dst,dirs=()):
    os.makedirs(dst,exist_ok=True)
    for dd in dirs:
        if dd.startswith(root): os.makedirs(dst+dd[len(root):],exist_ok=True)
    for p,b in img.items():
        t=dst+p[len(root):]; os.makedirs(os.path.dirname(t),exist_ok=True); open(t,'wb').write(b)
def verify(store,cfg,d,acked):
    try:
        r=subprocess.run([WL,'verify',store,cfg,d,str(acked)],capture_output=True,timeout=60,text=True)
    except subprocess.TimeoutExpired: return 'timeout','hang'
    for ln in r.stdout.splitlines():
        if ln.startswith('RESULT '):
            body=ln[7:]; cls=body.split(' ')[0].split('|')[0]
            if cls=='ok' and 'INTEGRITY_FAIL' in body: cls='integrity_fail'
            if cls=='ok' and 'check_integrity=false' in body: cls='integrity_fail'
            return cls,body[:200]
    return ('crash_sig%d'%(-r.returncode) if r.returncode<0 else 'crash_rc%d'%r.returncode), (r.stderr.strip().splitlines() or [''])[-1][:160]
def job(a):
    store,cfg,d,acked,tag=a
    c,b=verify(store,cfg,d,acked)
    if acked==0 and c!='ok': c='init_'+c
    shutil.rmtree(d,ignore_errors=True); return tag,c,b
def main():
    store,cfg,N,cuts,seed=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),int(sys.argv[5])
    out=sys.argv[6] if len(sys.argv)>6 else None
    base=f'{HERE}/runs/{store}-{cfg}-{seed}'; shutil.rmtree(base,ignore_errors=True); os.makedirs(base+'/orig')
    log=base+'/trace.log'
    env=dict(os.environ,AEGIS_LOG=log,AEGIS_ROOT=base+'/orig',LD_PRELOAD=SHIM)
    r=subprocess.run([WL,'run',store,cfg,base+'/orig',str(N)],env=env,capture_output=True,text=True,timeout=600)
    if r.returncode!=0: print('RUN FAIL',r.stderr[-300:]); sys.exit(2)
    ops=parse(log); rng=random.Random(seed)
    cutset=set(rng.sample(range(1,len(ops)+1),min(cuts,len(ops)))); cutset.add(len(ops))
    sim=Sim(base+'/orig'); res=[]; t=time.time(); ex=cf.ThreadPoolExecutor(8)
    for k,op in enumerate(ops,1):
        sim.step(op)
        if k in cutset:
            jobs=[]
            for pol in('dropall','all','subset','prefix'):
                for reg in (('full',) if pol=='all' else ('journal','fsfile','strict')):
                    img=sim.image(pol,reg,rng); d=f'{base}/st{k}_{pol}_{reg}'
                    materialize(img,base+'/orig',d,sim.dirs); jobs.append((store,cfg,d,sim.acked,(k,pol,reg,sim.acked)))
            res+=list(ex.map(job,jobs))
    lag=collections.defaultdict(collections.Counter); tally=collections.defaultdict(collections.Counter); ex_=collections.defaultdict(list)
    for (k,pol,reg,ack),c,b in res:
        tally[(pol,reg)][c]+=1
        if c=='lost_ack':
            import re
            m=re.search(r'c=(\d+) acked=(\d+)',b)
            if m: lag[(pol,reg)][min(int(m.group(2))-int(m.group(1)),9)]+=1
        if c!='ok' and len(ex_[(pol,reg,c)])<2: ex_[(pol,reg,c)].append((k,ack,b))
    summ={'store':store,'cfg':cfg,'N':N,'seed':seed,'ops':len(ops),'cuts':len(cutset),'states':len(res),'mmapw':sorted(set(os.path.basename(x) for x in sim.mmapw)),
          'tally':{f'{p}/{r}':dict(c) for (p,r),c in tally.items()},'examples':{f'{p}/{r}/{c}':v for (p,r,c),v in ex_.items()},'lag':{f'{p}/{r}':dict(c) for (p,r),c in lag.items()},'secs':round(time.time()-t,1)}
    print(json.dumps(summ))
    if out: open(out,'a').write(json.dumps(summ)+'\n')
    shutil.rmtree(base,ignore_errors=True)
main()
