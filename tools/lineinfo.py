import sys, os, struct
sys.path.insert(0, os.path.dirname(__file__))
from pe import read_pe, decompress_zdebug, section_data
from dwarf import Reader, DW_FORM_string, DW_FORM_line_strp, DW_FORM_strp, DW_FORM_udata, DW_FORM_data1, DW_FORM_data2, DW_FORM_data16

def read_form(r, form, sec, strs):
    if form == DW_FORM_string: return r.cstr()
    if form == DW_FORM_line_strp:
        off = r.u32(); e = sec.index(b'\0', off); return sec[off:e].decode('utf-8','replace')
    if form == DW_FORM_strp:
        off = r.u32(); e = strs.index(b'\0', off); return strs[off:e].decode('utf-8','replace')
    if form == DW_FORM_udata: return r.uleb()
    if form == DW_FORM_data1: return r.u8()
    if form == DW_FORM_data2: return r.u16()
    if form == DW_FORM_data16: return r.bytes(16)
    if form == 0x02:  # block2
        n = r.u16(); return r.bytes(n)
    if form == 0x04:  # block4
        n = r.u32(); return r.bytes(n)
    if form == 0x05: return r.u16()
    if form == 0x06: return r.u32()
    if form == 0x07: return r.u64()
    if form == 0x0b: return r.u8()
    raise ValueError(hex(form))

def parse_line(data, sec_line_str=None, sec_str=None):
    r = Reader(data)
    unit_len, = struct.unpack_from('<I', data, r.o); r.o += 4
    end = r.o + unit_len
    ver, = struct.unpack_from('<H', data, r.o); r.o += 2
    addr_size = data[r.o]; r.o += 1
    if ver >= 5:
        seg_sel = data[r.o]; r.o += 1
    header_len, = struct.unpack_from('<I', data, r.o); r.o += 4
    after_hdr = r.o + header_len
    min_inst = r.u8(); max_ops = r.u8(); default_is_stmt = r.u8()
    line_base = struct.unpack_from('b', data, r.o)[0]; r.o += 1
    line_range = r.u8(); opcode_base = r.u8(); r.o += 1
    std_lens = [r.u8() for _ in range(opcode_base-1)]
    files = []
    dirs = []
    if ver >= 5:
        # directory table
        dfc = r.u8()
        dformats = [(r.uleb(), r.uleb()) for _ in range(dfc)]
        dcnt = r.uleb()
        for _ in range(dcnt):
            e = {}
            for ct, form in dformats:
                e[ct] = read_form(r, form, sec_line_str, sec_str)
            dirs.append(e.get(1, ''))
        ffc = r.u8()
        fformats = [(r.uleb(), r.uleb()) for _ in range(ffc)]
        fcnt = r.uleb()
        for _ in range(fcnt):
            e = {}
            for ct, form in fformats:
                e[ct] = read_form(r, form, sec_line_str, sec_str)
            files.append(e)
    else:
        incdirs = []
        while True:
            s = r.cstr()
            if not s: break
            incdirs.append(s)
        dirs = incdirs + ['']
        while True:
            n = r.cstr()
            if not n: break
            di = r.uleb(); mti = r.uleb(); ln = r.uleb()
            files.append({'name': n, 'dir_index': di, 'mtime': mti, 'length': ln})
    return dict(ver=ver, files=files, dirs=dirs)

if __name__ == '__main__':
    path = sys.argv[1]
    d, imagebase, secs = read_pe(path)
    data = decompress_zdebug(d, secs, '.zdebug_line')
    ls = section_data(d, secs, '.debug_line_str')
    st = section_data(d, secs, '.debug_str')
    r = Reader(data)
    off = 0
    n = 0
    while off < len(data):
        unit_len, = struct.unpack_from('<I', data, off)
        sub = data[off:off+4+unit_len]
        info = parse_line(sub, ls, st)
        print('== line program v%d, %d files' % (info['ver'], len(info['files'])))
        for i, f in enumerate(info['files'], 1):
            print('   %d: %s' % (i, f))
        off += 4 + unit_len
        n += 1
        if n > 200: break
