"""Temporary differential test for the detection functions in src/detect.cpp."""
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

GO = r'ref_vmpstatic.exe'
CPP = os.path.join(os.environ['TEMP'], 'dt.exe')

SECT = 0x200
HDRS = 0x400


def craft(path, names, chars=None, ep_bytes=b'\xC3' * 8, ep_rva=0x1000,
          empty=None, random_fill=False):
    """Minimal PE64 with the given section names / characteristics."""
    n_sections = len(names)
    if chars is None:
        chars = [0x60000020] + [0x40000040] * (n_sections - 1)
    if empty is None:
        empty = [False] * n_sections

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

    secs = []
    rva = 0x1000
    raw = HDRS
    for i in range(n_sections):
        vsize = 0x1000
        rsize = 0 if empty[i] else SECT
        secs.append(dict(name=names[i].encode(), vsize=vsize, vaddr=rva, rsize=rsize,
                         raw=0 if empty[i] else raw, chars=chars[i]))
        rva += (vsize + 0xFFF) & ~0xFFF
        raw += rsize

    imp_rva = 0x3000
    imp_raw = None
    for s in secs:
        if s['vaddr'] <= imp_rva < s['vaddr'] + s['vsize']:
            imp_raw = s['raw'] + (imp_rva - s['vaddr'])
    imp_size = 0x14 + 0x40
    imp = bytearray(imp_size)

    coff = struct.pack('<HHIIIHH', 0x8664, n_sections, 0, 0, 0, 0xF0, 0x22)
    opt = bytearray(0xF0)
    struct.pack_into('<H', opt, 0, 0x20B)
    struct.pack_into('<B', opt, 2, 14)
    struct.pack_into('<Q', opt, 16, 0x140000000)
    struct.pack_into('<I', opt, 32, 0x1000)
    struct.pack_into('<I', opt, 36, 0x200)
    struct.pack_into('<H', opt, 50, 3)
    struct.pack_into('<I', opt, 56, 0x4000)
    struct.pack_into('<I', opt, 60, HDRS)
    struct.pack_into('<I', opt, 16, ep_rva)
    struct.pack_into('<H', opt, 72, 3)
    struct.pack_into('<I', opt, 108, 16)

    sectab = bytearray()
    for s in secs:
        sectab += s['name'][:8].ljust(8, b'\x00')
        sectab += struct.pack('<IIIIIIHHI', s['vsize'], s['vaddr'], s['rsize'], s['raw'],
                              0, 0, 0, 0, s['chars'])

    out = bytearray(HDRS)
    out[0:0x80] = dos
    out[0x80:0x84] = b'PE\x00\x00'
    out[0x84:0x84 + len(coff)] = coff
    out[0x98:0x98 + len(opt)] = opt
    out[0x98 + len(opt):0x98 + len(opt) + len(sectab)] = sectab

    body = bytearray()
    for i, s in enumerate(secs):
        data = bytearray(s['rsize'])
        if random_fill:
            data[:] = os.urandom(len(data))
        elif i == 0:
            code = (ep_bytes + b'\x00' * s['rsize'])[:s['rsize']]
            data[0:len(code)] = code
        elif s['vaddr'] == imp_rva:
            data[0:len(imp)] = imp
        body += data
    out += body
    open(path, 'wb').write(bytes(out))
    return path


def run_go(path):
    out = os.path.join(os.environ['TEMP'], 'goout.exe')
    p = subprocess.run([GO, path, out], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.startswith('VMProtect'):
            return line
    return '<none>'


def run_cpp(path):
    p = subprocess.run([CPP, path], capture_output=True, text=True)
    return p.stdout.strip().replace('\n', ' | ')


CASES = [
    ('vmp0 last',            ['.text', '.rdata', '.vmp0'], None),
    ('vmp1 only',            ['.text', '.rdata', '.vmp1'], None),
    ('vmp0+vmp1',            ['.text', '.vmp0', '.vmp1'], None),
    ('vmp0+vmp1+vmp2',       ['.text', '.vmp0', '.vmp1', '.vmp2'], None),
    ('vmp0+vmp1+vmp2+vmp3',  ['.text', '.vmp0', '.vmp1', '.vmp2', '.vmp3'], None),
    ('abc0/abc1',            ['.text', 'abc0', 'abc1'], None),
    ('abc0/abc1/abc2',       ['.text', 'abc0', 'abc1', 'abc2'], None),
    ('abc1/abc2/abc0',       ['.text', 'abc1', 'abc2', 'abc0'], None),
    ('vmp0 magic chars',     ['.text', '.vmp0'], [0x60000020, 0x60000060]),
    ('vmp1 magic chars',     ['.text', '.vmp1'], [0x60000020, 0x60000060]),
    ('plain',                ['.text', '.rdata', '.data'], None),
    ('reloc last',           ['.text', '.rdata', '.reloc'], None),
    ('vmp0 then rsrc',       ['.text', '.vmp0', '.rsrc'], None),
    ('vmp0 first',           ['.vmp0', '.text', '.rdata'], None),
    ('vmp1 first',           ['.vmp1', '.text', '.rdata'], None),
    ('vmp2 first',           ['.vmp2', '.text', '.rdata'], None),
    ('sectChars 3sec',       ['.text', '.rdata', '.vmp1'],
     [0x60000020, 0x40000040, 0x60000060]),
    ('vmp310 empty x3',      ['.a', '.b', '.c', '.stub'], None),
]

tmp = os.environ['TEMP']
for name, names, chars in CASES:
    path = os.path.join(tmp, 'dtcase.exe')
    kwargs = {}
    if name == 'vmp310 empty x3':
        chars = [0x40000040, 0x40000040, 0x40000040, 0x60000020]
        kwargs = dict(ep_rva=0x4000, empty=[True, True, True, False],
                      random_fill=True)
    craft(path, names, chars, **kwargs)
    go = run_go(path)
    cpp = run_cpp(path)
    print('== %-22s go : %s' % (name, go))
    print('   %-24s cpp: %s' % ('', cpp))
