import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from pe import read_pe, decompress_zdebug, section_data
from dwarf import *

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
    n = cu.name()
    if n != pkg: continue
    dies = []
    walk(cu, dies)
    print('### CU', n, 'stmt_list', cu.ref(DW_AT_stmt_list))
    for die in dies:
        if die.tag == DW_TAG_subprogram:
            params = []
            rt = die.ref(DW_AT_type)
            for c in die.children:
                if c.tag == DW_TAG_formal_parameter:
                    params.append('%s %s' % (di.type_name(c.ref(DW_AT_type)), c.name()))
                elif c.tag == DW_TAG_variable:
                    params.append('var %s %s' % (di.type_name(c.ref(DW_AT_type)), c.name()))
            print('FUNC %s @%s line=%s ret=%s (%s)' % (
                die.name(), hex(die.ref(DW_AT_low_pc) or 0), die.ref(DW_AT_decl_line),
                di.type_name(rt), ', '.join(params)))
