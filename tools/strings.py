import sys, os, struct, re
sys.path.insert(0, os.path.dirname(__file__))
from pe import read_pe

path = sys.argv[1]
out = sys.argv[2] if len(sys.argv) > 2 else 'strings.txt'
d, imagebase, secs = read_pe(path)

lines = []
for s in secs:
    if s['name'] not in ('.rdata', '.text', '.data'):
        continue
    raw = d[s['rawptr']:s['rawptr']+s['rawsize']]
    base = imagebase + s['vaddr']
    start = None
    for i, b in enumerate(raw):
        if 32 <= b < 127:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= 3:
                txt = raw[start:i].decode('ascii')
                lines.append('%016X %s' % (base+start, txt))
            start = None
    if start is not None and len(raw)-start >= 3:
        lines.append('%016X %s' % (base+start, raw[start:].decode('ascii')))

open(out, 'w', encoding='utf-8', errors='replace').write('\n'.join(lines))
print('wrote', len(lines), 'strings to', out)
