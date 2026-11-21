"""Compare samply profiles of the contention runs: per-op time by leaf library/symbol and by
inclusive function, worker threads only. Usage: contend.py name:profile.json.gz:us_per_op ..."""
import gzip, json, sys, re, collections
INCL = ['resolve', 'encrypt_sizes', 'get_by_name', 'validate_operation', 'clone', 'drop_in_place',
        'fill_random', 'aead_seal', 'metadata::encode', 'try_read', 'read_unlock', 'agc_encrypt',
        'versioned::read', 'last_error', 'process::id']
def load(path):
    p = json.load(gzip.open(path)); sy = json.load(open(path[:-3] + '.syms.json')); st = sy['string_table']
    bylib = {}
    for d in sy['data']:
        m = {}
        for a, i in d['known_addresses']:
            e = d['symbol_table'][i]
            fr = e.get('frames')
            m[a] = [st[f['function']] for f in fr] if fr else [st[e['symbol']]]
        bylib[d['code_id'].upper()] = m
    return p, bylib
def run(path):
    p, bylib = load(path); libs = p['libs']
    leaf = collections.Counter(); inc = collections.Counter(); n = 0
    for t in p['threads']:
        ft, stt, res, fu = t['frameTable'], t['stackTable'], t['resourceTable'], t['funcTable']
        def names(fr):
            a = ft['address'][fr]; r = fu['resource'][ft['func'][fr]]
            if r is None or r < 0: return ('?', ['?'])
            lib = libs[res['lib'][r]]
            return (lib['name'], bylib.get(lib['codeId'].upper(), {}).get(a) or ['?'])
        for s in t['samples']['stack']:
            if s is None: continue
            chain = []
            while s is not None:
                chain.append(names(stt['frame'][s])); s = stt['prefix'][s]
            flat = [x for _, ns in chain for x in ns]
            if not any(re.search(r'\bwork\b', x) for x in flat): continue  # worker threads only
            n += 1
            lib, ns = chain[0]
            sym = ns[0] if ns[0] != '?' else ''
            leaf[(lib, re.sub(r'<[^>]*>', '', sym)[:70])] += 1
            for k in INCL:
                if any(k in x for x in flat): inc[k] += 1
    return n, leaf, inc
args = [a.split(':') for a in sys.argv[1:]]
res = {name: run(path) for name, path, _ in args}
us = {name: float(u) for name, _, u in args}
print('per-op µs by inclusive function (share × µs/op)')
print(f"{'':22}" + ''.join(f"{n:>16}" for n, _, _ in args))
for k in INCL:
    print(f"{k:22}" + ''.join(f"{100*res[n][2][k]/res[n][0]:6.1f}% {us[n]*res[n][2][k]/res[n][0]:6.2f}µs" for n, _, _ in args))
print('\ntop leaf (library, symbol): share and µs/op')
keys = collections.Counter()
for n, _, _ in args:
    for k, v in res[n][1].items(): keys[k] += v / res[n][0]
for k, _ in keys.most_common(22):
    print(f"{(k[0][:20] + ' ' + k[1])[:60]:60}" + ''.join(f"{100*res[n][1][k]/res[n][0]:6.1f}% {us[n]*res[n][1][k]/res[n][0]:5.2f}" for n, _, _ in args))
