"""Minimal DWARF reader sufficient for Go binaries (DWARF 4/5)."""
import struct

# DWARF tags we care about
DW_TAG_array_type = 0x01
DW_TAG_class_type = 0x02
DW_TAG_enumeration_type = 0x04
DW_TAG_member = 0x0d
DW_TAG_pointer_type = 0x0f
DW_TAG_compile_unit = 0x11
DW_TAG_structure_type = 0x13
DW_TAG_subroutine_type = 0x15
DW_TAG_typedef = 0x16
DW_TAG_union_type = 0x17
DW_TAG_inheritance = 0x1c
DW_TAG_subrange_type = 0x21
DW_TAG_base_type = 0x24
DW_TAG_const_type = 0x26
DW_TAG_enumerator = 0x28
DW_TAG_subprogram = 0x2e
DW_TAG_variable = 0x34
DW_TAG_volatile_type = 0x35
DW_TAG_restrict_type = 0x37
DW_TAG_namespace = 0x39
DW_TAG_unspecified_type = 0x3b
DW_TAG_formal_parameter = 0x05
DW_TAG_lexical_block = 0x0b
DW_TAG_variant_part = 0x33

# attributes
DW_AT_location = 0x02
DW_AT_name = 0x03
DW_AT_byte_size = 0x0b
DW_AT_stmt_list = 0x10
DW_AT_low_pc = 0x11
DW_AT_high_pc = 0x12
DW_AT_language = 0x13
DW_AT_comp_dir = 0x1b
DW_AT_const_value = 0x1c
DW_AT_upper_bound = 0x2f
DW_AT_count = 0x37
DW_AT_decl_file = 0x3a
DW_AT_decl_line = 0x3b
DW_AT_declaration = 0x3c
DW_AT_encoding = 0x3e
DW_AT_external = 0x3f
DW_AT_frame_base = 0x40
DW_AT_type = 0x49
DW_AT_abstract_origin = 0x31
DW_AT_data_member_location = 0x38
DW_AT_external = 0x3f
DW_AT_sibling = 0x01
DW_AT_str_offsets_base = 0x72
DW_AT_addr_base = 0x73
DW_AT_rnglists_base = 0x74
DW_AT_loclists_base = 0x8c
DW_AT_linkage_name = 0x6e

DW_FORM_addr = 0x01
DW_FORM_block2 = 0x03
DW_FORM_block4 = 0x04
DW_FORM_data2 = 0x05
DW_FORM_data4 = 0x06
DW_FORM_data8 = 0x07
DW_FORM_string = 0x08
DW_FORM_block = 0x09
DW_FORM_block1 = 0x0a
DW_FORM_data1 = 0x0b
DW_FORM_flag = 0x0c
DW_FORM_sdata = 0x0d
DW_FORM_strp = 0x0e
DW_FORM_udata = 0x0f
DW_FORM_ref_addr = 0x10
DW_FORM_ref1 = 0x11
DW_FORM_ref2 = 0x12
DW_FORM_ref4 = 0x13
DW_FORM_ref8 = 0x14
DW_FORM_ref_udata = 0x15
DW_FORM_indirect = 0x16
DW_FORM_sec_offset = 0x17
DW_FORM_exprloc = 0x18
DW_FORM_flag_present = 0x19
DW_FORM_strx = 0x1a
DW_FORM_addrx = 0x1b
DW_FORM_ref_sup4 = 0x1c
DW_FORM_strp_sup = 0x1d
DW_FORM_data16 = 0x1e
DW_FORM_line_strp = 0x1f
DW_FORM_ref_sig8 = 0x20
DW_FORM_implicit_const = 0x21
DW_FORM_loclistx = 0x22
DW_FORM_rnglistx = 0x23
DW_FORM_ref_sup8 = 0x24
DW_FORM_strx1 = 0x25
DW_FORM_strx2 = 0x26
DW_FORM_strx3 = 0x27
DW_FORM_strx4 = 0x28
DW_FORM_addrx1 = 0x29
DW_FORM_addrx2 = 0x2a
DW_FORM_addrx3 = 0x2b
DW_FORM_addrx4 = 0x2c

class Reader:
    def __init__(self, data, off=0):
        self.d = data
        self.o = off
    def u8(self):
        v = self.d[self.o]; self.o += 1; return v
    def u16(self):
        v = struct.unpack_from('<H', self.d, self.o)[0]; self.o += 2; return v
    def u32(self):
        v = struct.unpack_from('<I', self.d, self.o)[0]; self.o += 4; return v
    def u64(self):
        v = struct.unpack_from('<Q', self.d, self.o)[0]; self.o += 8; return v
    def uleb(self):
        r = 0; s = 0
        while True:
            b = self.u8()
            r |= (b & 0x7f) << s
            if not (b & 0x80): break
            s += 7
        return r
    def sleb(self):
        r = 0; s = 0
        while True:
            b = self.u8()
            r |= (b & 0x7f) << s
            s += 7
            if not (b & 0x80):
                if b & 0x40: r |= -(1 << s)
                break
        return r
    def bytes(self, n):
        v = self.d[self.o:self.o+n]; self.o += n; return v
    def cstr(self):
        e = self.d.index(b'\0', self.o)
        v = self.d[self.o:e]; self.o = e+1
        return v.decode('utf-8', 'replace')

class Abbrev:
    def __init__(self, data):
        self.tables = {}
        r = Reader(data)
        while r.o < len(data):
            tbl_off = r.o
            tbl = {}
            while True:
                code = r.uleb()
                if code == 0:
                    break
                tag = r.uleb()
                has_children = r.u8()
                attrs = []
                while True:
                    at = r.uleb()
                    form = r.uleb()
                    if form == DW_FORM_implicit_const:
                        v = r.sleb()
                    else:
                        v = None
                    attrs.append((at, form, v))
                    if at == 0 and form == 0:
                        break
                tbl[code] = (tag, has_children, attrs)
            self.tables[tbl_off] = tbl

class DIE:
    __slots__ = ('off','tag','attrs','children','parent','cu')
    def __init__(self, off, tag, attrs):
        self.off = off; self.tag = tag; self.attrs = attrs
        self.children = []; self.parent = None; self.cu = None
    def name(self):
        return self.attrs.get(DW_AT_name)
    def ref(self, at):
        return self.attrs.get(at)
    def __repr__(self):
        return '<DIE tag=%x name=%r off=%x>' % (self.tag, self.name(), self.off)

class DebugInfo:
    def __init__(self, info, abbrev, strs=b'', str_offsets=None, line_strs=b'', addr_size=8, version=4):
        self.info = info
        self.abbrev = Abbrev(abbrev)
        self.strs = strs
        self.str_offsets = str_offsets
        self.line_strs = line_strs
        self.addr_size = addr_size
        self.version = version
        self.dies = {}
        self.cus = []
        self._parse()

    def _str(self, off):
        if self.str_offsets is not None:
            if off == 0: return ''
            p = self.str_offsets[off-4:off]
            e = self.strs.index(b'\0', p)
            return self.strs[p:e].decode('utf-8','replace')
        e = self.strs.index(b'\0', off)
        return self.strs[off:e].decode('utf-8','replace')

    def _parse(self):
        r = Reader(self.info)
        end = len(self.info)
        while r.o < end:
            cu_off = r.o
            unit_len, = struct.unpack_from('<I', self.info, r.o); r.o += 4
            if unit_len == 0xffffffff:
                unit_len, = struct.unpack_from('<Q', self.info, r.o); r.o += 8
                dwarf64 = True
            else:
                dwarf64 = False
            next_cu = r.o + unit_len
            ver, = struct.unpack_from('<H', self.info, r.o); r.o += 2
            if ver >= 5:
                unit_type = self.info[r.o]; r.o += 1
                addr_size = self.info[r.o]; r.o += 1
                abbrev_off = r.u32()
            else:
                abbrev_off = r.u32()
                addr_size = self.info[r.o]; r.o += 1
                unit_type = 1
            self.addr_size = addr_size
            tbl = self.abbrev.tables.get(abbrev_off)
            if tbl is None:
                r.o = next_cu; continue
            if ver >= 5:
                # skip extra CU headers
                if unit_type in (2, 4):  # type/split
                    r.o += 8  # type signature
                    r.o += 8  # type offset
                elif unit_type in (3, 5):  # split compile unit
                    r.o += 8
                elif unit_type == 1:
                    pass
            if ver >= 5 and unit_type in (2, 4, 6):
                r.o += 8  # dwo id
            # str_offsets_base etc: read DWARF5 header fields present in v5 CUs
            if ver >= 5:
                # after abbrev_off comes (for v5): we already read unit_type, addr_size
                pass
            cu_dies = []
            stack = []
            while r.o < next_cu:
                off = r.o
                code = r.uleb()
                if code == 0:
                    if stack:
                        stack.pop()
                    continue
                ent = tbl.get(code)
                if ent is None:
                    break
                tag, has_children, attrs = ent
                vals = {}
                for at, form, ic in attrs:
                    if at == 0 and form == 0:
                        break
                    vals[at] = self._form(r, form, ic)
                die = DIE(off, tag, vals)
                self.dies[off] = die
                if stack:
                    die.parent = stack[-1]
                    stack[-1].children.append(die)
                else:
                    cu_dies.append(die)
                if has_children:
                    stack.append(die)
            cu = cu_dies[0] if cu_dies else None
            for d in cu_dies:
                d.cu = cu
            if cu is not None:
                self.cus.append(cu)
            r.o = next_cu

    def _form(self, r, form, ic):
        if form == DW_FORM_addr:
            return r.u64() if self.addr_size == 8 else r.u32()
        if form == DW_FORM_block2:
            n = r.u16(); return r.bytes(n)
        if form == DW_FORM_block4:
            n = r.u32(); return r.bytes(n)
        if form == DW_FORM_data2: return r.u16()
        if form == DW_FORM_data4: return r.u32()
        if form == DW_FORM_data8: return r.u64()
        if form == DW_FORM_string: return r.cstr()
        if form == DW_FORM_block: n = r.uleb(); return r.bytes(n)
        if form == DW_FORM_block1: n = r.u8(); return r.bytes(n)
        if form == DW_FORM_data1: return r.u8()
        if form == DW_FORM_flag: return r.u8()
        if form == DW_FORM_sdata: return r.sleb()
        if form == DW_FORM_strp: return self._str(r.u32())
        if form == DW_FORM_udata: return r.uleb()
        if form == DW_FORM_ref_addr:
            return r.u32() if self.version < 5 else r.u64() if False else r.u32()
        if form == DW_FORM_ref1: return r.o + r.u8()
        if form == DW_FORM_ref2: return r.o + r.u16()
        if form == DW_FORM_ref4: return r.o + r.u32()
        if form == DW_FORM_ref8: return r.o + r.u64()
        if form == DW_FORM_ref_udata: return r.o + r.uleb()
        if form == DW_FORM_indirect:
            f2 = r.uleb(); return self._form(r, f2, None)
        if form == DW_FORM_sec_offset: return r.u32()
        if form == DW_FORM_exprloc:
            n = r.uleb(); return r.bytes(n)
        if form == DW_FORM_flag_present: return 1
        if form == DW_FORM_implicit_const: return ic
        if form == DW_FORM_line_strp: return self._linestr(r.u32())
        if form == DW_FORM_data16: return r.bytes(16)
        if form == DW_FORM_strx: return self._strx(r.uleb())
        if form == DW_FORM_strx1: return self._strx(r.u8())
        if form == DW_FORM_strx2: return self._strx(r.u16())
        if form == DW_FORM_strx3:
            v = int.from_bytes(r.bytes(3),'little'); return self._strx(v)
        if form == DW_FORM_strx4: return self._strx(r.u32())
        if form == DW_FORM_addrx: return r.uleb()
        if form == DW_FORM_addrx1: return r.u8()
        if form == DW_FORM_addrx2: return r.u16()
        if form == DW_FORM_addrx3:
            v = int.from_bytes(r.bytes(3),'little'); return v
        if form == DW_FORM_addrx4: return r.u32()
        if form == DW_FORM_ref_sup4: return r.u32()
        if form == DW_FORM_strp_sup: return r.u32()
        if form == DW_FORM_ref_sig8: return r.u64()
        if form == DW_FORM_loclistx: return r.uleb()
        if form == DW_FORM_rnglistx: return r.uleb()
        raise ValueError('form %#x' % form)

    def _strx(self, idx):
        if self.str_offsets is None: return ''
        p = self.str_offsets[idx*4:idx*4+4]
        o = int.from_bytes(p,'little')
        e = self.strs.index(b'\0', o)
        return self.strs[o:e].decode('utf-8','replace')

    def _linestr(self, off):
        e = self.line_strs.index(b'\0', off)
        return self.line_strs[off:e].decode('utf-8','replace')

    def type_name(self, die_off, depth=0):
        if die_off is None: return 'void'
        d = self.dies.get(die_off)
        if d is None: return '?'
        if depth > 12: return '...'
        t = d.tag
        if t == DW_TAG_base_type:
            return d.name() or 'int'
        if t == DW_TAG_typedef:
            return d.name() or 'typedef'
        if t == DW_TAG_structure_type:
            return 'struct ' + (d.name() or '{...}')
        if t == DW_TAG_union_type:
            return 'union ' + (d.name() or '{...}')
        if t == DW_TAG_enumeration_type:
            return 'enum ' + (d.name() or '{...}')
        if t == DW_TAG_pointer_type:
            return self.type_name(d.ref(DW_AT_type), depth+1) + ' *'
        if t == DW_TAG_const_type:
            return 'const ' + self.type_name(d.ref(DW_AT_type), depth+1)
        if t == DW_TAG_volatile_type:
            return 'volatile ' + self.type_name(d.ref(DW_AT_type), depth+1)
        if t == DW_TAG_array_type:
            n = ''
            for c in d.children:
                if c.tag == DW_TAG_subrange_type:
                    ub = c.ref(DW_AT_upper_bound)
                    if ub is not None: n = str(ub+1)
                    ct = c.ref(DW_AT_count)
                    if ct is not None: n = str(ct)
            return self.type_name(d.ref(DW_AT_type), depth+1) + '[' + n + ']'
        if t == DW_TAG_subroutine_type:
            return 'func'
        if t == DW_TAG_unspecified_type:
            return d.name() or 'void'
        return d.name() or '?'
