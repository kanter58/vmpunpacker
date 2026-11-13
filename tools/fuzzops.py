"""Randomised differential test of the VM opcode table (main.analyzeVMInstruction)."""
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import craft_pe

GO = r'ref_vmpstatic.exe'
HARNESS = os.path.join(os.environ['TEMP'], 'harness.exe')
TMP = os.environ['TEMP']

# opcodes / prefixes that main.analyzeVMInstruction recognises
PREFIXES = [0x0F]
SINGLES = [0x30, 0x31, 0x32, 0x33, 0x60, 0x61, 0x9C, 0x9D, 0xF5, 0xF8, 0xF9]
MODRMISH = list(range(0xCD, 0xD1))     # opcodes with a ModRM byte
SECOND = [0x31, 0xA3, 0xAB, 0xB3, 0xBB, 0xBC, 0xBD, 0xC8, 0xCF, 0x11, 0x22, 0xF6, 0xF7]
TERMINATORS = [b'\xC3', b'\xC2\x00\x00', b'\xFF\xD0', b'\xFF\xE0', b'\x8B\x14\x85\x00\x00\x00\x00']


def go_line(path):
    p = subprocess.run([GO, path, os.path.join(TMP, 'goout.exe')], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.startswith('VMProtect') or line.startswith('Warning: VMProtect'):
            return line
    return '<none>'


def deep_line(path):
    p = subprocess.run([HARNESS, path], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        if line.startswith('detectByDeepScan'):
            return line
    return '<none>'


def parse_deep(line):
    det = 'detected=1' in line
    ver = line.split("version='")[1].split("'")[0]
    return det, ver


def rand_instr(rnd):
    r = rnd.random()
    if r < 0.25:
        return bytes([rnd.choice(SINGLES)])
    if r < 0.45:
        return bytes([rnd.choice(MODRMISH), rnd.randrange(256)])
    if r < 0.65:
        return bytes([0x0F, rnd.choice(SECOND)])
    if r < 0.80:
        return bytes([0x0F, rnd.choice(SECOND), rnd.randrange(256)])
    if r < 0.90:
        return bytes([0xF6, rnd.randrange(256)])
    return bytes([rnd.randrange(256)])


rnd = random.Random(4242)
path = os.path.join(TMP, 'fuzz3.exe')
bad = 0
ndet = 0
N = 200
for i in range(N):
    n = rnd.randrange(11, 40)
    body = b''.join(rand_instr(rnd) for _ in range(n))
    code = body + rnd.choice(TERMINATORS)
    craft_pe.craft(path, code)
    g = go_line(path)
    det, ver = parse_deep(deep_line(path))
    if det:
        ndet += 1
        expect = 'VMProtect v%s [DS]' % ver
        if g != expect:
            bad += 1
            print('MISMATCH #%d code=%s' % (i, code.hex()))
            print('   go : %s' % g)
            print('   cpp: expected %s' % expect)
    else:
        if g.startswith('VMProtect vnew') or g.startswith('VMProtect vold'):
            bad += 1
            print('MISMATCH #%d code=%s' % (i, code.hex()))
            print('   go : %s' % g)
            print('   cpp: deep scan did not fire')
print('%d/%d mismatches, deep scan fired in %d cases' % (bad, N, ndet))
