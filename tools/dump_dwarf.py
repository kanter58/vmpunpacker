import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from pe import read_pe, decompress_zdebug, section_data
from dwarf import *

path = sys.argv[1]
d, imagebase, secs = read_pe(path)
info = decompress_zdebug(d, secs, '.zdebug_info')
abbrev = decompress_zdebug(d, secs, '.zdebug_abbrev')
strs = section_data(d, secs, '.debug_str') or decompress_zdebug(d, secs, '.zdebug_str') or b'\0'
line_strs = section_data(d, secs, '.debug_line_str') or decompress_zdebug(d, secs, '.zdebug_line_str') or b'\0'
print('info len', len(info), 'abbrev len', len(abbrev) if abbrev else None, 'strs', len(strs), 'line_strs', len(line_strs))
print('unit_len', int.from_bytes(info[4:8],'little'), 'version', int.from_bytes(info[6:8],'little'))
di = DebugInfo(info, abbrev, strs, None, line_strs)
print('CUs', len(di.cus), 'DIEs', len(di.dies))

prefix = sys.argv[2] if len(sys.argv) > 2 else 'main'

def walk(die, out):
    out.append(die)
    for c in die.children:
        walk(c, out)

for cu in di.cus:
    dies = []
    walk(cu, dies)
    for die in dies:
        if die.tag == DW_TAG_structure_type or die.tag == DW_TAG_union_type:
            n = die.name() or ''
            if n.startswith(prefix) and die.ref(DW_AT_byte_size) is not None:
                print('=== %s %s size=%s' % ('struct' if die.tag==DW_TAG_structure_type else 'union', n, die.ref(DW_AT_byte_size)))
                for m in die.children:
                    if m.tag == DW_TAG_member:
                        print('    %-24s off=%-4s %s' % (m.name(), m.ref(DW_AT_data_member_location), di.type_name(m.ref(DW_AT_type))))
