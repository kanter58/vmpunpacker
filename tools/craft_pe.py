"""Craft a minimal PE64 used to compare the C++ port against VMPStatic.exe."""
import struct
import sys


def craft(path, ep_bytes, n_sections=3, imports_kernel32=0):
    SECT = 0x200
    HDRS = 0x400

    dos = bytearray(0x80)
    dos[0:2] = b'MZ'
    dos[0x02] = 0x90
    dos[0x03] = 0x00
    dos[0x04] = 0x03
    dos[0x08] = 0x04
    dos[0x0A] = 0x00
    dos[0x0C] = 0xFF
    dos[0x0E] = 0x00
    dos[0x10] = 0xB8
    dos[0x18] = 0x40
    dos[0x1A] = 0x00
    struct.pack_into('<I', dos, 0x3C, 0x80)

    names = [b'.text\x00\x00\x00', b'.rdata\x00\x00', b'.rsrc\x00\x00\x00']
    secs = []
    rva = 0x1000
    raw = HDRS
    for i in range(n_sections):
        vsize = 0x1000
        rsize = SECT
        secs.append(dict(name=names[i], vsize=vsize, vaddr=rva, rsize=rsize, raw=raw,
                         chars=0x60000020 if i == 0 else 0x40000040))
        rva += (vsize + 0xFFF) & ~0xFFF
        raw += rsize

    # ---- imports ---------------------------------------------------------
    imp_rva = 0x3000
    imp_raw = None
    for s in secs:
        if s['vaddr'] <= imp_rva < s['vaddr'] + s['vsize']:
            imp_raw = s['raw'] + (imp_rva - s['vaddr'])
    # build import descriptors
    n_desc = imports_kernel32 + 1
    imp_size = n_desc * 0x14 + 0x40
    imp = bytearray(imp_size)
    k32_off = 0x100
    for i in range(imports_kernel32):
        off = i * 0x14
        struct.pack_into('<I', imp, off + 0x0C, imp_rva + k32_off + i * 0x40)
    struct.pack_into('<I', imp, (imports_kernel32) * 0x14 + 0x0C, 0)

    k32 = bytearray(0x40)
    k32[0:12] = b'KERNEL32.dll'
    k32[12:14] = b'\x00\x00'
    # second import (different name) so that both are KERNEL32.dll
    k32b = bytearray(0x40)
    k32b[0:12] = b'KERNEL32.dll'
    k32b[12:14] = b'\x00\x00'

    # ---- headers ---------------------------------------------------------
    coff = struct.pack('<HHIIIHH', 0x8664, n_sections, 0, 0, 0, 0xF0, 0x22)
    opt = bytearray(0xF0)
    struct.pack_into('<H', opt, 0, 0x20B)
    struct.pack_into('<B', opt, 2, 14)
    struct.pack_into('<Q', opt, 16, 0x140000000)
    struct.pack_into('<I', opt, 32, 0x1000)      # SectionAlignment
    struct.pack_into('<I', opt, 36, 0x200)       # FileAlignment
    struct.pack_into('<H', opt, 40, 6)           # MajorOS
    struct.pack_into('<H', opt, 46, 0)           # MajorImage
    struct.pack_into('<H', opt, 50, 3)           # MajorSubsystem (console)
    struct.pack_into('<I', opt, 56, 0x4000)      # SizeOfImage
    struct.pack_into('<I', opt, 60, HDRS)        # SizeOfHeaders
    struct.pack_into('<I', opt, 16, 0x1000)      # AddressOfEntryPoint
    struct.pack_into('<H', opt, 72, 3)           # Subsystem
    struct.pack_into('<I', opt, 108, 16)         # NumberOfRvaAndSizes
    struct.pack_into('<I', opt, 112 + 8, imp_rva)  # import dir RVA
    struct.pack_into('<I', opt, 112 + 16, 0x50)    # import dir size

    sectab = bytearray()
    for s in secs:
        sectab += s['name'][:8].ljust(8, b'\x00')
        sectab += struct.pack('<IIIIIIHHI', s['vsize'], s['vaddr'], s['rsize'], s['raw'],
                              0, 0, 0, 0, s['chars'])

    out = bytearray(HDRS)
    out[0:0x80] = dos
    out[0x80:0x80 + 4] = b'PE\x00\x00'
    out[0x84:0x84 + len(coff)] = coff
    out[0x98:0x98 + len(opt)] = opt
    out[0x98 + len(opt):0x98 + len(opt) + len(sectab)] = sectab

    # ---- sections -------------------------------------------------------
    body = bytearray()
    for i, s in enumerate(secs):
        data = bytearray(s['rsize'])
        if i == 0:
            code = (ep_bytes + b'\x00' * s['rsize'])[:s['rsize']]
            data[0:len(code)] = code
        elif s['vaddr'] == imp_rva:
            data[0:len(imp)] = imp
            data[k32_off:k32_off + len(k32)] = k32
            data[k32_off + 0x40:k32_off + 0x40 + len(k32b)] = k32b
        body += data
    out += body

    open(path, 'wb').write(bytes(out))
    return path


if __name__ == '__main__':
    # 20 VM ops (xor byte ptr [rax], al) followed by a ret
    code = b'\x30\xC0' * 20 + b'\xC3'
    craft(sys.argv[1] if len(sys.argv) > 1 else 'test.exe', code)
    print('written')
