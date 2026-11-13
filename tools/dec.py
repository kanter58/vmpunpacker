import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from pe import read_pe

PATH = r'ref_vmpstatic.exe'
d, imagebase, secs = read_pe(PATH)

def va_to_off(va):
    rva = va - imagebase
    for s in secs:
        if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rawsize']):
            return s['rawptr'] + (rva - s['vaddr'])
    return None

def getstr(va, n):
    o = va_to_off(va)
    if o is None: return '<unmapped>'
    return d[o:o+n].decode('utf-8', 'replace')

if __name__ == '__main__':
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        va, n = line.split()
        print('%s %s => %r' % (va, n, getstr(int(va,16), int(n))))
