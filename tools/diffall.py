"""Differential test: compare the C++ VMPStatic port against the original Go binary.

Generates a set of crafted PE files (including a VMProtect-like packed image
with a real LZMA stream) and compares stdout, stderr and the produced output
file byte for byte.
"""
import lzma
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ORIG = r'ref_vmpstatic.exe'
MINE = os.path.join(ROOT, 'build', 'Release', 'VMPStatic.exe')
TMP = os.path.join(ROOT, 'build', 'difftest')
os.makedirs(TMP, exist_ok=True)


def build_pe(sections, ep_rva, size_of_image, import_dir_rva=0, imports=(),
             data_dirs=None, size_of_headers=0x400, file_alignment=0x200,
             section_alignment=0x1000, dos_extra=b''):
    """sections: list of dicts(name, vsize, vaddr, rsize, raw, chars, data)"""
    out = bytearray(size_of_headers)
    dos = bytearray(0x80)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x80)
    out[0:0x80] = dos
    out[0x80:0x84] = b'PE\x00\x00'
    coff = struct.pack('<HHIIIHH', 0x8664, len(sections), 0, 0, 0, 0xF0, 0x22)
    opt = bytearray(0xF0)
    struct.pack_into('<H', opt, 0, 0x20B)
    struct.pack_into('<B', opt, 2, 14)
    struct.pack_into('<Q', opt, 16, 0x140000000)
    struct.pack_into('<I', opt, 32, section_alignment)
    struct.pack_into('<I', opt, 36, file_alignment)
    struct.pack_into('<I', opt, 56, size_of_image)
    struct.pack_into('<I', opt, 60, size_of_headers)
    struct.pack_into('<I', opt, 16, ep_rva)
    struct.pack_into('<H', opt, 72, 3)
    struct.pack_into('<I', opt, 108, 16)
    if import_dir_rva:
        struct.pack_into('<I', opt, 112 + 8, import_dir_rva)
        struct.pack_into('<I', opt, 112 + 16, 0x50)
    for idx, (va, sz) in (data_dirs or {}).items():
        struct.pack_into('<I', opt, 112 + idx * 8, va)
        struct.pack_into('<I', opt, 112 + idx * 8 + 4, sz)
    out[0x84:0x84 + len(coff)] = coff
    out[0x98:0x98 + len(opt)] = opt
    sectab = bytearray()
    for s in sections:
        sectab += s['name'][:8].ljust(8, b'\x00')
        sectab += struct.pack('<IIIIIIHHI', s['vsize'], s['vaddr'], s['rsize'],
                              s['raw'], 0, 0, 0, 0, s['chars'])
    out[0x98 + len(opt):0x98 + len(opt) + len(sectab)] = sectab

    body = bytearray()
    for s in sections:
        d = bytearray(s['rsize'])
        payload = s.get('data', b'')
        d[0:len(payload)] = payload
        body += d
    out += body
    return bytes(out)


def run(exe, inp, outp):
    if os.path.exists(outp):
        os.remove(outp)
    p = subprocess.run([exe, inp, outp], capture_output=True)
    data = None
    if os.path.exists(outp):
        data = open(outp, 'rb').read()
    return p.returncode, p.stdout, p.stderr, data


def compare(name, blob):
    inp = os.path.join(TMP, name + '.exe')
    outp = os.path.join(TMP, name + '.out.bin')
    open(inp, 'wb').write(blob)
    ra = run(ORIG, inp, outp)
    rb = run(MINE, inp, outp)
    ok = True
    msgs = []
    if ra[0] != rb[0]:
        ok = False
        msgs.append('exit %d vs %d' % (ra[0], rb[0]))
    if ra[1] != rb[1]:
        ok = False
        msgs.append('stdout differs')
    if ra[2] != rb[2]:
        ok = False
        msgs.append('stderr differs')
    if ra[3] != rb[3]:
        ok = False
        msgs.append('output file differs (%s vs %s bytes)' %
                    (len(ra[3]) if ra[3] is not None else None,
                     len(rb[3]) if rb[3] is not None else None))
    status = 'OK  ' if ok else 'FAIL'
    print('%s %-28s %s' % (status, name, '; '.join(msgs)))
    if not ok:
        print('  orig stdout:', ra[1].decode('utf-8', 'replace'))
        print('  mine stdout:', rb[1].decode('utf-8', 'replace'))
        if ra[2] or rb[2]:
            print('  orig stderr:', ra[2].decode('utf-8', 'replace'))
            print('  mine stderr:', rb[2].decode('utf-8', 'replace'))
    return ok


# ---------------------------------------------------------------------------
# 1. plain PE, entry point patterns
# ---------------------------------------------------------------------------
def plain_case(name, ep_bytes, n_sections=3, chars0=0x60000020, names=None,
               imports=1, ep_rva=0x1000):
    names = names or [b'.text\x00\x00\x00', b'.rdata\x00\x00', b'.rsrc\x00\x00\x00']
    while len(names) < n_sections:
        names.append(b'.sec%d\x00\x00' % len(names))
    SECT = 0x200
    HDRS = 0x400
    secs = []
    rva = 0x1000
    raw = HDRS
    for i in range(n_sections):
        vsize = 0x1000
        secs.append(dict(name=names[i], vsize=vsize, vaddr=rva, rsize=SECT, raw=raw,
                         chars=chars0 if i == 0 else 0x40000040, data=b''))
        rva += vsize
        raw += SECT
    imp_rva = 0x3000
    imp = bytearray(0x14 * (imports + 1) + 0x100)
    for i in range(imports):
        struct.pack_into('<I', imp, i * 0x14 + 0x0C, imp_rva + 0x40 + i * 0x40)
    struct.pack_into('<I', imp, imports * 0x14 + 0x0C, 0)
    for i in range(imports):
        off = 0x40 + i * 0x40
        imp[off:off + 12] = b'KERNEL32.dll'
    for s in secs:
        if s['vaddr'] == imp_rva:
            s['data'] = bytes(imp)
    secs[0]['data'] = ep_bytes
    blob = build_pe(secs, ep_rva, 0x4000 + 0x1000, import_dir_rva=imp_rva)
    return compare(name, blob)


# ---------------------------------------------------------------------------
# 2. VMProtect-like packed image with a real LZMA block
# ---------------------------------------------------------------------------
def packed_case(name, payload, vmp_va=0x4000, vmp_vsize=0x2000):
    HDRS = 0x400
    SECT = 0x400
    # .text holds the compressed stream, .vmp1 is the virtual only destination
    text_va = 0x1000
    vmp_raw = HDRS + SECT
    vmp_va = 0x3000
    size_of_image = 0x6000

    comp = lzma.compress(payload, format=lzma.FORMAT_ALONE,
                          filters=[{'id': lzma.FILTER_LZMA1, 'preset': 6}])
    props = comp[:5]
    stream = comp[13:]

    # section layout
    secs = []
    secs.append(dict(name=b'.text\x00\x00\x00', vsize=0x1000, vaddr=text_va,
                     rsize=SECT, raw=HDRS, chars=0x60000020, data=b''))
    secs.append(dict(name=b'.vmp1\x00\x00\x00', vsize=0x2000, vaddr=vmp_va,
                     rsize=0, raw=0, chars=0xC0000040, data=b''))
    secs.append(dict(name=b'.reloc\x00\x00', vsize=0x1000, vaddr=0x5000,
                     rsize=SECT, raw=vmp_raw, chars=0x42000040, data=b''))

    # the compressed stream lives in .text at RVA text_va
    src_rva = text_va

    # the PACKER_INFO table lives in the DOS stub area so that the pattern
    # (FF FF FF FF | DstRVA) is matched at a well defined offset:
    #   [RVA of props][Src RVA][Dst RVA]
    # the search pattern is FF FF FF FF | DstRVA, found at table+8
    props_rva = 0x5000 + 0x10
    table = bytearray(0x20)
    struct.pack_into('<I', table, 0x00, props_rva)   # RVA of the props
    struct.pack_into('<I', table, 0x08, src_rva)      # Src
    struct.pack_into('<I', table, 0x0C, vmp_va)       # Dst
    blob_sections = []
    for s in secs:
        d = bytearray(s['rsize'])
        if s['name'].startswith(b'.text'):
            d[0:len(stream)] = stream
        if s['name'].startswith(b'.reloc'):
            d[0x10:0x15] = props
        blob_sections.append(dict(s, data=bytes(d)))
    blob = bytearray(build_pe(blob_sections, text_va, size_of_image))
    blob[0x40:0x40 + len(table)] = table
    return compare(name, bytes(blob))


def v39_case(name, payloads):
    """Craft a VMProtect 3.9+ style image: the destination RVAs are stored
    obfuscated as Dst^key with the key rotated by 7 bits per entry."""
    HDRS = 0x400
    SECT = 0x400
    text_va = 0x1000
    vmp_va = 0x3000
    size_of_image = 0x6000

    streams = []
    for p in payloads:
        comp = lzma.compress(p, format=lzma.FORMAT_ALONE,
                              filters=[{'id': lzma.FILTER_LZMA1, 'preset': 6}])
        streams.append(comp[13:])

    dest_vas = [vmp_va + 0x1000 * i for i in range(len(payloads))]

    secs = []
    secs.append(dict(name=b'.text\x00\x00\x00', vsize=0x1000, vaddr=text_va,
                     rsize=SECT, raw=HDRS, chars=0x60000020, data=b''))
    for i, va in enumerate(dest_vas):
        secs.append(dict(name=b'.vmp%d\x00\x00' % (i + 1), vsize=0x1000, vaddr=va,
                         rsize=0, raw=0, chars=0xC0000040, data=b''))
    secs.append(dict(name=b'.reloc\x00\x00', vsize=0x1000, vaddr=0x6000,
                     rsize=SECT, raw=HDRS + SECT, chars=0x42000040, data=b''))

    # the compressed blocks live in .text, one after the other
    text = bytearray(SECT)
    src_rvas = []
    pos = 0
    for s in streams:
        src_rvas.append(text_va + pos)
        text[pos:pos + len(s)] = s
        pos += len(s) + 0x10

    key = 0x12345678
    stored = []
    for k, va in enumerate(dest_vas):
        rot = ((key << (7 * k)) | (key >> (32 - 7 * k))) & 0xFFFFFFFF if (7 * k) % 32 else key
        stored.append(va ^ rot)

    table = bytearray(8 * len(payloads))
    for k in range(len(payloads)):
        struct.pack_into('<I', table, k * 8 + 0, src_rvas[k])
        struct.pack_into('<I', table, k * 8 + 4, stored[k])

    blob_sections = []
    for s in secs:
        d = bytearray(s['rsize'])
        if s['name'].startswith(b'.text'):
            d[0:len(text)] = text
        blob_sections.append(dict(s, data=bytes(d)))
    blob = bytearray(build_pe(blob_sections, text_va, size_of_image))
    blob[0x40:0x40 + len(table)] = table
    return compare(name, bytes(blob))


def main():
    ok = True
    # entry point signature detection
    ok &= plain_case('ep_vmp0', b'\x60\x9c\x60\x9c')
    ok &= plain_case('ep_ret', b'\xc3' * 4)
    ok &= plain_case('ep_9ce9', b'\x9c\xe9' + b'\x00' * 8)
    ok &= plain_case('ep_9cff', b'\x9c\xff' + b'\x00' * 8)
    ok &= plain_case('ep_68e9', b'\x68\x11\x22\x33\x44\xe9' + b'\x00' * 8)
    # deep scan
    ok &= plain_case('deep_old', b'\x30\xc0' * 20 + b'\xc3')
    ok &= plain_case('deep_new', b'\x30\xc0' * 20 + b'\xff\x20')
    ok &= plain_case('deep_ds', b'\x9c' * 20 + b'\xc3')
    # two KERNEL32 imports -> packed variant
    ok &= plain_case('k32x2', b'\x60\x9c\x60\x9c', imports=2)
    # many sections -> vmp2 heuristic
    ok &= plain_case('many_sections', b'\xc3' * 4, n_sections=9)
    # VMProtect style section names
    ok &= plain_case('vmp_sections', b'\xc3' * 4,
                     names=[b'.vmp0\x00\x00\x00', b'.vmp1\x00\x00\x00', b'.text\x00\x00\x00'])
    ok &= plain_case('vmp_chars', b'\xc3' * 4, chars0=0x60000060,
                     names=[b'.vmp0\x00\x00\x00', b'.vmp1\x00\x00\x00', b'.text\x00\x00\x00'])
    # real LZMA unpacking (legacy PACKER_INFO)
    ok &= packed_case('lzma_block', b'hello VMProtect world!\x00' * 64)
    ok &= packed_case('lzma_big', bytes(range(256)) * 400)
    # VMProtect 3.9+ layout
    ok &= v39_case('v39_block', [b'3.9 block one\x00' * 32, b'3.9 block two\x00' * 32])
    # broken inputs
    ok &= compare('not_a_pe', b'hello world' * 100)
    ok &= compare('truncated', b'MZ' + b'\x00' * 30)
    ok &= compare('empty', b'')
    print('ALL OK' if ok else 'DIFFERENCES FOUND')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
