import sys, re
sys.path.insert(0, 'tools')
from dec import getstr

src = open('src/vmscan.cpp', encoding='utf-8').read()
m = re.search(r'kDosHeaderPattern\[\]\s*=\s*(.*?);', src, re.S)
lit = ''.join(re.findall(r'"([^"]*)"', m.group(1)))
ref = getstr(0x1401092ff, 230)
print('agent len', len(lit), 'ref len', len(ref))
print('equal:', lit == ref)
if lit != ref:
    for i, (a, b) in enumerate(zip(lit, ref)):
        if a != b:
            print('diff at', i)
            print('agent:', repr(lit[max(0, i-30):i+30]))
            print('ref  :', repr(ref[max(0, i-30):i+30]))
            break
