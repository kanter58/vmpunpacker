import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe import read_pe

src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', 'vmscan.cpp')).read()
m = re.search(r'kDosHeaderPattern\[\]\s*=\s*((?:\s*"[^"]*"\s*)+);', src)
lit = ''.join(re.findall(r'"([^"]*)"', m.group(1)))
print('cpp len', len(lit))

p = r'ref_vmpstatic.exe'
d, ib, secs = read_pe(p)


def off(va):
    rva = va - ib
    for s in secs:
        if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rawsize']):
            return s['rawptr'] + (rva - s['vaddr'])


fpat = d[off(0x1401092ff):off(0x1401092ff) + 230].decode()
print('file len', len(fpat))
print('equal', lit == fpat)
if lit != fpat:
    for i, (a, b) in enumerate(zip(lit, fpat)):
        if a != b:
            print('first diff at', i, repr(a), repr(b))
            print('cpp :', lit[max(0, i - 20):i + 20])
            print('file:', fpat[max(0, i - 20):i + 20])
            break
    print('cpp tokens', len(lit.split()), 'file tokens', len(fpat.split()))
