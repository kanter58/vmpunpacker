import sys, re, struct
sys.path.insert(0, 'tools')
from pe import read_pe

PATH = r'ref_vmpstatic.exe'
d, imagebase, secs = read_pe(PATH)


def off(va):
    rva = va - imagebase
    for x in secs:
        if x['vaddr'] <= rva < x['vaddr'] + max(x['vsize'], x['rawsize']):
            return x['rawptr'] + rva - x['vaddr']
    return None


def rd(va, n):
    o = off(va)
    return d[o:o + n]


def gostr(va):
    p, l = struct.unpack('<QQ', rd(va, 16))
    return rd(p, l).decode('utf-8', 'replace')


base = 0x14010f3a0
ref = []
for i in range(9):
    e = base + i * 48
    ref.append(tuple(gostr(e + k * 16) for k in range(3)))

src = open('src/detect.cpp', encoding='utf-8').read()
m = re.search(r'kEntryPointPatterns\[9\]\s*=\s*\{(.*?)\n    \};', src, re.S)
body = m.group(1)
entries = re.findall(r'\{\s*((?:"[^"]*"\s*)+),\s*((?:"[^"]*"\s*)+),\s*((?:"[^"]*"\s*)+)\}', body)
mine = []
for e in entries:
    parts = []
    for grp in e:
        parts.append(''.join(re.findall(r'"([^"]*)"', grp)))
    mine.append(tuple(parts))

ok = True
for i, (a, b) in enumerate(zip(ref, mine)):
    # the C++ source concatenates adjacent string literals, rejoin them
    if a != b:
        ok = False
        print('entry', i, 'MISMATCH')
        print('  ref :', a)
        print('  mine:', b)
print('total entries', len(mine), 'all match:', ok and len(mine) == 9)
