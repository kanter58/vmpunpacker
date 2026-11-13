"""Differential test: VMPStatic.exe vs the C++ port (tools/harness.cpp)."""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import craft_pe

GO = r'ref_vmpstatic.exe'
HARNESS = os.path.join(os.environ['TEMP'], 'harness.exe')

# The DOS header pattern of the Go binary (offsets 0..76), wildcards -> 0x90.
PAT = ('4D 5A ?? 00 ?? 00 00 00 04 00 ?? 00 FF FF 00 00 B8 00 00 00 00 00 00 '
       '00 40 00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
       '00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 ?? ?? ?? 0E ?? '
       'B4 09 CD 21 B8 01 4C CD')
PT = PAT.split()


def make_dos():
    b = bytearray(0x80)
    for i, tok in enumerate(PT):
        if tok == '??':
            b[i] = 0x90
        else:
            b[i] = int(tok, 16)
    b[0x3C:0x40] = (0x80).to_bytes(4, 'little')
    return b


def patch_dos(path):
    d = bytearray(open(path, 'rb').read())
    d[0:0x80] = make_dos()
    open(path, 'wb').write(bytes(d))


def run_go(path):
    out = os.path.join(os.environ['TEMP'], 'goout.exe')
    p = subprocess.run([GO, path, out], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.startswith('VMProtect') or line.startswith('Warning: VMProtect'):
            return line
    return '<none> ' + p.stdout.strip().replace('\n', ' | ')[:120]


def run_cpp(path):
    p = subprocess.run([HARNESS, path], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        if line.startswith('detectByDeepScan') or line.startswith('checkPackedVariant'):
            pass
    deep = ''
    packed = ''
    for line in p.stdout.splitlines():
        if line.startswith('detectByDeepScan'):
            deep = line
        if line.startswith('checkPackedVariant'):
            packed = line
    return deep, packed


CASES = []

# --- deep scan ------------------------------------------------------------
CASES.append(('deep: 20 xor ops + ret', b'\x30\xC0' * 20 + b'\xC3', 0, False))
CASES.append(('deep: 20 xor ops + call r/m (old)', b'\x30\xC0' * 20 + b'\xFF\xD0', 0, False))
CASES.append(('deep: 20 xor ops + ff /4 (new)', b'\x30\xC0' * 20 + b'\xFF\xD4', 0, False))
CASES.append(('deep: 20 xor ops + mov/test (old)',
              b'\x30\xC0' * 20 + b'\x8B\x14\x85\x00\x00\x00\x00', 0, False))
CASES.append(('deep: 11 xor ops + ret', b'\x30\xC0' * 11 + b'\xC3', 0, False))
CASES.append(('deep: 10 xor ops + ret (too few)', b'\x30\xC0' * 10 + b'\xC3', 0, False))
CASES.append(('deep: 0x0f 0x31 prefix', b'\x0F\x31' * 20 + b'\xC3', 0, False))
CASES.append(('deep: 0x9c ops', b'\x9C' * 40 + b'\xC3', 0, False))
CASES.append(('deep: 0xf8 ops', b'\xF8' * 40 + b'\xC3', 0, False))
CASES.append(('deep: 0xcd ops (modrm sib)', b'\xCD\x60' * 20 + b'\xC3', 0, False))
CASES.append(('deep: 0xc8 ops', b'\xC8\x00' * 20 + b'\xC3', 0, False))
CASES.append(('deep: no ops at all', b'\x90' * 40, 0, False))
CASES.append(('deep: 300 ops -> too many instrs', b'\x30\xC0' * 300 + b'\xC3', 0, False))
CASES.append(('deep: 20 xor ops + ret, 2x kernel32', b'\x30\xC0' * 20 + b'\xC3', 2, False))
CASES.append(('packed: 2x kernel32 + dos pattern', b'\x30\xC0' * 20 + b'\xC3', 2, True))

tmp = os.environ['TEMP']
fails = 0
for name, code, nk32, dospat in CASES:
    path = os.path.join(tmp, 'case.exe')
    craft_pe.craft(path, code, imports_kernel32=nk32)
    if dospat:
        patch_dos(path)
    go = run_go(path)
    deep, packed = run_cpp(path)
    print('== %s' % name)
    print('   go : %s' % go)
    print('   cpp: %s' % deep)
    print('   cpp: %s' % packed)
