"""Fold a samply profile (+ .syms.json) into inclusive/self % per function."""
import gzip,json,sys,re,collections
path=sys.argv[1]; top=int(sys.argv[2]) if len(sys.argv)>2 else 40
p=json.load(gzip.open(path)); sy=json.load(open(path[:-3]+'.syms.json'))
st=sy['string_table']
bylib={}
for d in sy['data']:
    m={}
    for addr,i in d['known_addresses']:
        e=d['symbol_table'][i]
        frames=e.get('frames')
        m[addr]=[st[f['function']] if isinstance(f,dict) and 'function' in f else st[e['symbol']] for f in frames] if frames else [st[e['symbol']]]
    bylib[d['code_id'].upper()]=m
def short(n):
    n=re.sub(r'<[^<>]*>','',n); n=re.sub(r'<[^<>]*>','',n); n=re.sub(r'<[^<>]*>','',n)
    n=re.sub(r'::\{closure#\d+\}','::{cl}',n); n=re.sub(r'::h[0-9a-f]{16}$','',n)
    return n[:110]
inc=collections.Counter(); slf=collections.Counter(); total=0
for t in p['threads']:
    ft,stt,res,fu=t['frameTable'],t['stackTable'],t['resourceTable'],t['funcTable']
    libs=p['libs']
    def names(fr):
        a=ft['address'][fr]; f=ft['func'][fr]; r=fu['resource'][f]
        if r is None or r<0 or a<0: return ['?']
        lib=libs[res['lib'][r]]; m=bylib.get(lib['codeId'].upper(),{})
        n=m.get(a)
        if n: return [short(x) for x in n]
        return [lib['name']+'!?']
    cache={}
    def stack(s):
        if s in cache: return cache[s]
        out=[]
        while s is not None:
            out.append(names(stt['frame'][s])); s=stt['prefix'][s]
        cache[s]=out; return out
    for s in t['samples']['stack']:
        if s is None: continue
        total+=1
        fr=stack(s)
        leaf=fr[0][-1] if fr and fr[0] else '?'
        # inline frames: list ordered outer..inner? count all
        slf[fr[0][0] if fr[0] else '?']+=1
        seen=set(x for f in fr for x in f)
        for x in seen: inc[x]+=1
print(f"samples={total}")
print("--- inclusive ---")
for n,c in inc.most_common(top): print(f"{100*c/total:5.1f}%  {n}")
print("--- self ---")
for n,c in slf.most_common(15): print(f"{100*c/total:5.1f}%  {n}")
