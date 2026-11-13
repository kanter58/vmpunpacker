"""Differential test for main.detectVMP2Heuristic."""
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import craft_pe

GO = r'ref_vmpstatic.exe'
HARNESS = os.path.join(os.environ['TEMP'], 'harness.exe')
TMP = os.environ['TEMP']


def build(path, vmp2, chars9=0x60000020, randomize=False):
    """10 sections; sections 5..7 virtual only; section 9 holds the entry point."""
    HDRS = 0x400
    SECT = 0x200
    dos = bytearray(0x80)
    dos[0:2] = b'MZ'
    dos[0x02] = 0x90
    struct.pack_into('<I', dos, 0x3C, 0x80)

    n = 10
    secs = []
    rva = 0x1000
    raw = HDRS
    for i in range(n):
        vsize = 0x1000
        if 5 <= i <= 7:
            rsize = 0
        else:
            rsize = SECT
        chars = 0x60000020 if i in (0, 9) else 0x40000040
        if i == 9:
            chars = chars9
        secs.append(dict(name=('.s%d' % i).encode().ljust(8, b'\x00'), vsize=vsize,
                         vaddr=rva, rsize=rsize, raw=raw if rsize else 0, chars=chars))
        rva += 0x1000
        raw += rsize

    coff = struct.pack('<HHIIIHH', 0x8664, n, 0, 0, 0, 0xF0, 0x22)
    opt = bytearray(0xF0)
    struct.pack_into('<H', opt, 0, 0x20B)
    struct.pack_into('<Q', opt, 16, 0x140000000)
    struct.pack_into('<I', opt, 32, 0x1000)
    struct.pack_into('<I', opt, 36, 0x200)
    struct.pack_into('<H', opt, 40, 6)
    struct.pack_into('<H', opt, 50, 3)
    struct.pack_into('<I', opt, 56, 0xB000)
    struct.pack_into('<I', opt, 60, HDRS)
    struct.pack_into('<I', opt, 16, 0xA000)       # entry point in section 9
    struct.pack_into('<H', opt, 72, 3)
    struct.pack_into('<I', opt, 108, 16)

    sectab = bytearray()
    for s in secs:
        sectab += s['name'][:8].ljust(8, b'\x00')
        sectab += struct.pack('<IIIIIIHHI', s['vsize'], s['vaddr'], s['rsize'],
                              s['raw'], 0, 0, 0, 0, s['chars'])

    out = bytearray(HDRS)
    out[0:0x80] = dos
    out[0x80:0x84] = b'PE\x00\x00'
    out[0x84:0x84 + len(coff)] = coff
    out[0x98:0x98 + len(opt)] = opt
    out[0x98 + len(opt):0x98 + len(opt) + len(sectab)] = sectab

    body = bytearray()
    for i, s in enumerate(secs):
        if s['rsize'] == 0:
            continue
        data = bytearray(s['rsize'])
        if i == 9:
            if randomize:
                data = bytearray(os.urandom(s['rsize']))
            if vmp2 >= 2:
                data[0x10:0x13] = b'\x9C\x8D\x64'
                data[0x40:0x43] = b'\x9C\x8D\x64'
            elif vmp2 == 1:
                data[0x10:0x13] = b'\x9C\x8D\x64'
            else:
                data[0x10:0x13] = b'\x90\x90\x90'
        body += data
    out += body
    open(path, 'wb').write(bytes(out))


def run_go(path):
    p = subprocess.run([GO, path, os.path.join(TMP, 'goout.exe')], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.startswith('VMProtect') or line.startswith('Warning: VMProtect'):
            return line
    return '<none>'


for vmp2, label in ((0, 'no vmp pattern'), (1, 'one vmp pattern'), (2, 'two vmp patterns')):
    path = os.path.join(TMP, 'vmp2.exe')
    build(path, vmp2)
    go = run_go(path)
    p = subprocess.run([HARNESS, path], capture_output=True, text=True)
    cpp = [l for l in p.stdout.splitlines() if 'VMP2' in l]
    print('== %s' % label)
    print('   go : %s' % go)
    print('   cpp: %s' % (cpp[0] if cpp else '?'))

# entropy branch: Characteristics == 0xE0000060 and random (high entropy) data
for rnd, label in ((False, 'chars E0000060, low entropy'), (True, 'chars E0000060, random data')):
    path = os.path.join(TMP, 'vmp2e.exe')
    build(path, 0, chars9=0xE0000060, randomize=rnd)
    go = run_go(path)
    p = subprocess.run([HARNESS, path], capture_output=True, text=True)
    cpp = [l for l in p.stdout.splitlines() if 'VMP2' in l]
    print('== %s' % label)
    print('   go : %s' % go)
    print('   cpp: %s' % (cpp[0] if cpp else '?'))
