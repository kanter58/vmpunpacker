import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from pe import read_pe, decompress_zdebug
from dwarf import *

DW_TAG_inlined_subroutine = 0x1d
DW_AT_call_line = 0x57
DW_AT_call_file = 0x58
DW_AT_ranges = 0x55

path = sys.argv[1]
pkg = sys.argv[2] if len(sys.argv) > 2 else 'main'
d, imagebase, secs = read_pe(path)
info = decompress_zdebug(d, secs, '.zdebug_info')
abbrev = decompress_zdebug(d, secs, '.zdebug_abbrev')
di = DebugInfo(info, abbrev, b'\0', None, b'\0')

def walk(die, out):
    out.append(die)
    for c in die.children:
        walk(c, out)

for cu in di.cus:
    if cu.name() != pkg: continue
    dies = []
    walk(cu, dies)
    for die in dies:
        if die.tag != DW_TAG_inlined_subroutine:
            continue
        ao = die.ref(DW_AT_abstract_origin)
        ad = di.dies.get(ao)
        nm = ad.name() if ad is not None else '?'
        # find enclosing subprogram
        p = die.parent
        while p is not None and p.tag != DW_TAG_subprogram:
            p = p.parent
        pn = p.name() if p is not None else '?'
        lo = die.ref(DW_AT_low_pc)
        hi = die.ref(DW_AT_high_pc)
        print('INLINE %-45s in %-35s call_line=%s pc=%s..%s' % (
            nm, pn, die.ref(DW_AT_call_line),
            hex(lo) if lo is not None else '?', hex(hi) if hi is not None else '?'))
