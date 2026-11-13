import struct, sys, zlib

def read_pe(path):
    d = open(path,'rb').read()
    e_lfanew = struct.unpack_from('<I', d, 0x3c)[0]
    assert d[e_lfanew:e_lfanew+4] == b'PE\0\0'
    coff = e_lfanew+4
    nsec, = struct.unpack_from('<H', d, coff+2)
    optsize, = struct.unpack_from('<H', d, coff+16)
    opt = coff+20
    magic, = struct.unpack_from('<H', d, opt)
    pe32p = magic == 0x20b
    if pe32p:
        imagebase, = struct.unpack_from('<Q', d, opt+24)
        nrva_off = opt+108
    else:
        imagebase, = struct.unpack_from('<I', d, opt+28)
        nrva_off = opt+92
    nrva, = struct.unpack_from('<I', d, nrva_off)
    ddoff = nrva_off + 4 + nrva*8
    sec_off = opt + optsize
    # COFF string table for long section names
    symtab_ptr, = struct.unpack_from('<I', d, coff+8)
    nsyms, = struct.unpack_from('<I', d, coff+12)
    strtab_off = symtab_ptr + nsyms*18
    strtab_size, = struct.unpack_from('<I', d, strtab_off)
    strtab = d[strtab_off:strtab_off+strtab_size]
    secs = []
    for i in range(nsec):
        o = sec_off + i*40
        raw = d[o:o+8]
        if raw.startswith(b'/') and raw.rstrip(b'\0')[1:].isdigit():
            so = int(raw.rstrip(b'\0')[1:])
            e = strtab.index(b'\0', so)
            name = strtab[so:e].decode()
        else:
            name = raw.rstrip(b'\0').decode()
        vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', d, o+8)
        secs.append(dict(name=name, vsize=vsize, vaddr=vaddr, rawsize=rawsize, rawptr=rawptr))
    return d, imagebase, secs

def rva_to_off(secs, rva):
    for s in secs:
        if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rawsize']):
            return s['rawptr'] + (rva - s['vaddr'])
    return None

def section_data(d, secs, name):
    for s in secs:
        if s['name'] == name:
            return d[s['rawptr']:s['rawptr']+s['rawsize']]
    return None

def decompress_zdebug(d, secs, name):
    raw = section_data(d, secs, name)
    if raw is None:
        return None
    if raw[:4] == b'ZLIB':
        usize, = struct.unpack('>Q', raw[4:12])
        return zlib.decompress(raw[12:])
    return raw
