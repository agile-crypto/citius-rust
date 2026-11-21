"""Per-crate code size of a Mach-O dylib: symbol sizes from address deltas
(llvm-nm -n), grouped by the first path segment of the demangled name."""
import subprocess, sys, re, collections
f = sys.argv[1]
out = subprocess.run(['xcrun', 'llvm-nm', '-n', '--demangle', '--defined-only', f], capture_output=True, text=True).stdout
# section bounds
sec = subprocess.run(['size', '-m', '-l', f], capture_output=True, text=True).stdout
bounds = {}
for m in re.finditer(r'Section (\S+): (\d+) \(addr 0x([0-9a-f]+)', sec):
    bounds.setdefault(m.group(1), []).append((int(m.group(3), 16), int(m.group(3), 16) + int(m.group(2))))
syms = []
for line in out.splitlines():
    parts = line.split(' ', 2)
    if len(parts) < 3: continue
    syms.append((int(parts[0], 16), parts[1], parts[2]))
def crate(name):
    n = name.lstrip('<&*').replace('dyn ', '').replace('mut ', '')
    n = re.sub(r'^\[|^\(', '', n)
    m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', n)
    c = m.group(1) if m else '?'
    if c.startswith('_'): c = 'C/runtime'
    return c
for secname in sys.argv[2:]:
    lo, hi = bounds[secname][0]
    inside = [s for s in syms if lo <= s[0] < hi]
    sizes = collections.Counter(); big = []
    for i, (a, t, n) in enumerate(inside):
        end = inside[i + 1][0] if i + 1 < len(inside) else hi
        sizes[crate(n)] += end - a; big.append((end - a, n))
    tot = hi - lo
    print(f"== {secname}: {tot/1024:.0f} KiB")
    for c, b in sizes.most_common(22): print(f"  {b/1024:8.1f} KiB {100*b/tot:5.1f}%  {c}")
    print("  largest symbols:")
    for b, n in sorted(big, reverse=True)[:8]: print(f"  {b/1024:8.1f} KiB  {n[:110]}")
