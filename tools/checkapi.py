import re, os, glob

hdr = open('src/vmp.h', encoding='utf-8').read()
decls = set()
for m in re.finditer(r'^\s*(?:MaybeErr|bool|int|double|void|std::vector<[^>]+>|std::string|VMPResult)\s+(\w+)\s*\(', hdr, re.M):
    decls.add(m.group(1))

src = ''
for f in glob.glob('src/*.cpp'):
    src += open(f, encoding='utf-8').read()

defined = set(re.findall(r'^\s*(?:MaybeErr|bool|int|double|void|std::vector<[^>]+>|std::string|VMPResult)\s+(\w+)\s*\(', src, re.M))

missing = sorted(d for d in decls if d not in defined)
print('declared:', len(decls))
print('missing definitions:', missing if missing else 'none')

# functions defined but not declared
extra = sorted(d for d in defined if d not in decls)
print('defined but not declared (internal helpers are expected):', extra)
