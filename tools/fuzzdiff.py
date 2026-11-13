"""Randomised differential test of the complete detection chain."""
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import craft_pe

GO = r'ref_vmpstatic.exe'
CPP = os.path.join(os.environ['TEMP'], 'vmpbuild', 'vmpstatic.exe')
TMP = os.environ['TEMP']


def go_line(path):
    p = subprocess.run([GO, path, os.path.join(TMP, 'goout.exe')], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.startswith('VMProtect') or line.startswith('Warning: VMProtect'):
            return line
    return '<none>'


def cpp_line(path):
    p = subprocess.run([CPP, path, os.path.join(TMP, 'cppout.exe')], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.startswith('VMProtect') or line.startswith('Warning: VMProtect'):
            return line
    return '<none>'


random.seed(1234)
path = os.path.join(TMP, 'fuzz.exe')
bad = 0
N = 60
for i in range(N):
    n = random.choice([8, 16, 24, 32, 48, 64, 100, 150])
    code = bytes(random.randrange(256) for _ in range(n))
    craft_pe.craft(path, code)
    g = go_line(path)
    c = cpp_line(path)
    if g != c:
        bad += 1
        print('MISMATCH #%d code=%s' % (i, code.hex()))
        print('   go : %s' % g)
        print('   cpp: %s' % c)
print('%d/%d mismatches' % (bad, N))
