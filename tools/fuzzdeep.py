"""Targeted randomised differential test of main.detectByDeepScan."""
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import craft_pe

GO = r'ref_vmpstatic.exe'
HARNESS = os.path.join(os.environ['TEMP'], 'harness.exe')
TMP = os.environ['TEMP']

VM_BYTES = ([0x30, 0x31, 0x32, 0x33, 0x60, 0x61, 0x9C, 0x9D, 0xF5, 0xF8, 0xF9] +
            list(range(0xCD, 0xD1)) + [0x0F, 0xA3, 0xAB, 0xB3, 0xBB, 0xBC, 0xBD, 0xC8])


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
    # detected=1 version='new' options='DS'
    det = 'detected=1' in line
    ver = line.split("version='")[1].split("'")[0]
    return det, ver


random.seed(99)
path = os.path.join(TMP, 'fuzz2.exe')
bad = 0
ndet = 0
N = 120
for i in range(N):
    n = random.randrange(4, 90)
    code = bytes(random.choice(VM_BYTES) if random.random() < 0.75 else random.randrange(256)
                  for _ in range(n))
    craft_pe.craft(path, code)
    g = go_line(path)
    det, ver = parse_deep(deep_line(path))
    if det:
        ndet += 1
    if det:
        # the deep scan fired -> Go must report exactly this version
        expect = 'VMProtect v%s [DS]' % ver
        if g != expect:
            bad += 1
            print('MISMATCH #%d code=%s' % (i, code.hex()))
            print('   go : %s' % g)
            print('   cpp: expected %s' % expect)
    else:
        # the deep scan did not fire -> Go must not report new/old
        if g.startswith('VMProtect vnew') or g.startswith('VMProtect vold'):
            bad += 1
            print('MISMATCH #%d code=%s' % (i, code.hex()))
            print('   go : %s' % g)
            print('   cpp: deep scan did not fire')
print('%d/%d mismatches' % (bad, N))
print('deep scan fired in %d/%d cases' % (ndet, N))
