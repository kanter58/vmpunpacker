import sys, os, struct
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
    if o is None:
        return '<unmapped>'
    return d[o:o+n].decode('utf-8', 'replace')

if __name__ == '__main__':
    # args: instr_va [strlen]
    va = int(sys.argv[1], 16)
    off = va_to_off(va)
    b = d[off:off+7]
    if b[0] == 0x48 and b[1] == 0x8D:
        modrm = b[2]
        if (modrm & 0xC7) == 0x05:  # [rip+disp32]
            disp = struct.unpack_from('<i', b, 3)[0]
            target = va + 7 + disp
            n = int(sys.argv[2]) if len(sys.argv) > 2 else 0
            print('instr @0x%x -> target 0x%x' % (va, target))
            if n:
                print('  len %d: %r' % (n, getstr(target, n)))
        else:
            print('modrm %02x not rip-relative' % modrm)
    else:
        print('not a lea: %s' % b.hex())
