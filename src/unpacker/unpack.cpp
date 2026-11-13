#include "vmp.h"
#include "lzma.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <algorithm>

namespace vmp {

const std::uint8_t kDefaultLZMAProps[5] = { 0x5d, 0x00, 0x00, 0x00, 0x04 };

namespace {

inline std::uint16_t le16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}
inline std::uint32_t le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}
inline std::int64_t le64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return static_cast<std::int64_t>(v);
}

std::string hexU32(std::uint32_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%X", v);
    return buf;
}
std::string hexU64(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
    return buf;
}

std::string quoteName(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else out += c;
    }
    out += '"';
    return out;
}

std::string hexBytes(const std::vector<std::uint8_t>& b) {
    std::string out;
    for (const std::uint8_t v : b) {
        char tmp[4];
        std::snprintf(tmp, sizeof(tmp), "%02X", v);
        out += tmp;
    }
    return out;
}

std::uint32_t rol32(std::uint32_t v, unsigned n) {
    n &= 31u;
    if (n == 0) return v;
    return (v << n) | (v >> (32u - n));
}

long indexByte(const std::vector<std::uint8_t>& s, std::size_t from, std::uint8_t c) {
    for (std::size_t i = from; i < s.size(); ++i) {
        if (s[i] == c) return static_cast<long>(i - from);
    }
    return -1;
}

}

MaybeErr decompressLZMA(const std::vector<std::uint8_t>& props,
                        const std::vector<std::uint8_t>& compressed,
                        std::vector<std::uint8_t>* out) {
    if (props.size() != 5) {
        return "LZMA props must be 5 bytes, got " + std::to_string(props.size());
    }
    std::uint8_t header[13];
    std::memset(header, 0, sizeof(header));
    std::memcpy(header, props.data(), 5);
    for (int i = 5; i < 13; ++i) header[i] = 0xff;

    std::string err;
    out->clear();
    if (!lzma::decode(header, sizeof(header), header[0], 0, compressed.data(), compressed.size(),
                      out, &err)) {
        return err.empty() ? std::string("lzma: decompression failed") : err;
    }
    return noErr();
}

bool probeLZMA(const std::vector<std::uint8_t>& props,
               const std::vector<std::uint8_t>& compressed) {
    std::uint8_t header[13];
    std::memset(header, 0, sizeof(header));
    const std::size_t n = std::min<std::size_t>(5, props.size());
    if (n) std::memcpy(header, props.data(), n);
    for (int i = 5; i < 13; ++i) header[i] = 0xff;

    lzma::Options opts;
    opts.maxOutput = 512;

    std::vector<std::uint8_t> out;
    std::string err;
    const bool ok = lzma::decode(opts, header, sizeof(header), header[0], 0,
                                  compressed.data(), compressed.size(), &out, &err);
    if (!ok) {
        return false;
    }
    return !out.empty();
}

MaybeErr findPackerInfoLegacy(const PEFile& pe, const std::vector<SectionInfo>& dests,
                              std::int64_t* propsRawOff, std::vector<std::uint8_t>* props,
                              bool* ok) {
    *ok = false;
    props->clear();

    std::vector<std::uint8_t> pattern;
    pattern.reserve(dests.size() * 8);
    for (const SectionInfo& s : dests) {
        pattern.push_back(0xff);
        pattern.push_back(0xff);
        pattern.push_back(0xff);
        pattern.push_back(0xff);
        const std::uint32_t va = s.VirtualAddress;
        pattern.push_back(static_cast<std::uint8_t>(va & 0xff));
        pattern.push_back(static_cast<std::uint8_t>((va >> 8) & 0xff));
        pattern.push_back(static_cast<std::uint8_t>((va >> 16) & 0xff));
        pattern.push_back(static_cast<std::uint8_t>((va >> 24) & 0xff));
    }

    const int found = findPattern(pe.data, pattern);
    if (found < 8) return noErr();

    const std::size_t idx = static_cast<std::size_t>(found);
    const std::uint32_t rva = le32(&pe.data[idx - 8]);
    std::uint32_t raw = 0;
    if (rvaToRawOffset(pe, rva, &raw)) return noErr();
    if (pe.data.size() < static_cast<std::size_t>(raw) + 5) return noErr();

    *propsRawOff = static_cast<std::int64_t>(idx);
    props->assign(pe.data.begin() + raw, pe.data.begin() + raw + 5);
    *ok = true;
    return noErr();
}

MaybeErr findPackerInfoV39(const PEFile& pe, const std::vector<SectionInfo>& dests,
                           std::int64_t* piBase, std::vector<PackerInfo>* entries,
                           bool* ok) {
    *ok = false;
    *piBase = 0;
    entries->clear();

    if (dests.size() < 2) return noErr();

    std::set<std::uint32_t> isDest;
    for (const SectionInfo& s : dests) isDest.insert(s.VirtualAddress);

    const std::vector<std::uint8_t>& data = pe.data;
    const std::size_t n = dests.size();

    for (std::size_t off = 0; off + n * 8 <= data.size(); ++off) {
        bool valid = true;
        for (std::size_t i = 0; i < n; ++i) {
            if (off + i * 8 + 8 > data.size()) { valid = false; break; }
            const std::uint32_t src = le32(&data[off + i * 8]);
            std::uint32_t raw = 0;
            if (rvaToRawOffset(pe, src, &raw)) { valid = false; break; }
            if (raw >= data.size() || data[raw] != 0) { valid = false; break; }
        }
        if (!valid) continue;

        const std::uint32_t key = le32(&data[off + 4]);

        for (const SectionInfo& s : dests) {
            std::vector<PackerInfo> cand;
            std::set<std::uint32_t> seen;
            bool dup = false;
            for (std::size_t i = 0; i < n; ++i) {
                const std::uint32_t stored = le32(&data[off + i * 8 + 4]);
                const std::uint32_t dst = rol32(s.VirtualAddress ^ key,
                                               static_cast<unsigned>((i * 7) & 31u)) ^ stored;
                if (isDest.find(dst) == isDest.end()) { dup = true; break; }
                if (seen.find(dst) != seen.end()) { dup = true; break; }
                seen.insert(dst);
                PackerInfo pi;
                pi.Src = le32(&data[off + i * 8]);
                pi.Dst = dst;
                cand.push_back(pi);
            }
            if (dup) continue;

            bool good = true;
            for (std::size_t i = 0; i < n; ++i) {
                std::uint32_t raw = 0;
                if (rvaToRawOffset(pe, cand[i].Src, &raw)) { good = false; break; }
                if (raw >= data.size() || data[raw] != 0) { good = false; break; }
                std::vector<std::uint8_t> rest(data.begin() + raw, data.end());
                if (!probeLZMA(std::vector<std::uint8_t>(kDefaultLZMAProps,
                                                         kDefaultLZMAProps + 5), rest)) {
                    good = false;
                    break;
                }
            }
            if (!good) continue;

            *piBase = static_cast<std::int64_t>(off);
            *entries = cand;
            *ok = true;
            return noErr();
        }
    }
    return noErr();
}

MaybeErr locatePackerInfo(const PEFile& pe, const std::vector<SectionInfo>& dests,
                          PackerLocate* loc) {
    PackerLocate result;

    std::int64_t propsRawOff = 0;
    std::vector<std::uint8_t> props;
    bool ok = false;
    findPackerInfoLegacy(pe, dests, &propsRawOff, &props, &ok);
    if (ok) {
        result.legacy = true;
        result.piBase = propsRawOff;
        result.props = props;

        for (std::size_t i = 0; i < dests.size(); ++i) {
            const std::int64_t off = propsRawOff + static_cast<std::int64_t>(i) * 8;
            if (off < 0 || static_cast<std::size_t>(off) + 8 > pe.data.size()) {
                return "PACKER_INFO[" + std::to_string(i) + "] is out of file bounds";
            }
            PackerInfo pi;
            pi.Src = le32(&pe.data[static_cast<std::size_t>(off)]);
            pi.Dst = le32(&pe.data[static_cast<std::size_t>(off) + 4]);
            result.entries.push_back(pi);
        }
        *loc = result;
        return noErr();
    }

    std::int64_t piBase = 0;
    std::vector<PackerInfo> entries;
    bool ok39 = false;
    findPackerInfoV39(pe, dests, &piBase, &entries, &ok39);
    if (ok39) {
        result.v39 = true;
        result.piBase = piBase;
        result.props.assign(kDefaultLZMAProps, kDefaultLZMAProps + 5);
        result.entries = entries;
        *loc = result;
        return noErr();
    }

    return std::string("could not locate PACKER_INFO in packed PE");
}

VMPResult refineVersionByPackerLayout(const PEFile& pe, VMPResult result, const PackerLocate& loc) {
    if (!result.Detected) return result;
    if (!versionNeedsLayoutRefine(result.Version)) return result;
    if (!loc.v39) return result;

    const VMPResult r = detectVMP310(pe);
    if (r.Detected) {
        result.Version = r.Version;
    } else {
        result.Version = "3.9+";
    }
    return result;
}

MaybeErr unpackPEFile(const PEFile& pe, const PackerLocate* loc,
                      std::vector<std::uint8_t>* out) {
    out->assign(pe.sizeOfImage, 0);
    if (pe.sizeOfHeaders > pe.data.size()) {
        return "sizeOfHeaders (0x" + hexU32(pe.sizeOfHeaders) + ") exceeds file size";
    }
    if (pe.sizeOfHeaders > pe.sizeOfImage) {
        return std::string("sizeOfHeaders exceeds SizeOfImage");
    }
    if (pe.sizeOfHeaders) {
        std::memcpy(out->data(), pe.data.data(), pe.sizeOfHeaders);
    }

    for (const SectionInfo& s : pe.sections) {
        if (s.PointerToRawData == 0 || s.SizeOfRawData == 0) continue;
        const std::uint64_t rawEnd = static_cast<std::uint64_t>(s.SizeOfRawData) + s.PointerToRawData;
        const std::uint64_t imgEnd = static_cast<std::uint64_t>(s.VirtualAddress) + s.SizeOfRawData;
        if (pe.data.size() < rawEnd || pe.sizeOfImage < imgEnd) {
            std::printf("  Warning: section %s raw data out of bounds, skipping\n",
                        quoteName(s.Name).c_str());
            continue;
        }
        if (s.VirtualAddress + s.SizeOfRawData > out->size()) continue;
        std::memcpy(out->data() + s.VirtualAddress, pe.data.data() + s.PointerToRawData,
                    s.SizeOfRawData);
    }

    if (pe.sizeOfImage >= static_cast<std::uint64_t>(pe.ntHeadersOffset) + 0x16) {
        const std::uint32_t optSize = le16(&(*out)[pe.ntHeadersOffset + 0x14]);
        const std::uint64_t secTable = static_cast<std::uint64_t>(pe.ntHeadersOffset) + optSize;
        for (std::size_t i = 0; i < pe.sections.size(); ++i) {
            const std::uint64_t base = secTable + static_cast<std::uint64_t>(i) * 40;
            if (pe.sizeOfImage < base + 0x30) continue;
            const SectionInfo& s = pe.sections[i];
            std::uint32_t vsize = s.VirtualSize;
            std::uint32_t vaddr = s.VirtualAddress;
            std::memcpy(&(*out)[base + 0x2c], &vaddr, 4);
            if (vsize > 0) std::memcpy(&(*out)[base + 0x28], &vsize, 4);
        }
    }

    std::vector<SectionInfo> dests;
    for (const SectionInfo& s : pe.sections) {
        const bool isVirtualOnly = (s.SizeOfRawData == 0 && s.PointerToRawData == 0);
        const bool isNotUninit = (s.Characteristics & 0x80u) == 0;
        if (isVirtualOnly && isNotUninit) dests.push_back(s);
    }
    if (dests.empty()) {
        std::printf("  No virtual-only sections found; no LZMA blocks to decompress.\n");
        return noErr();
    }

    PackerLocate resolved;
    if (loc != nullptr) {
        resolved = *loc;
    } else {
        MaybeErr err = locatePackerInfo(pe, dests, &resolved);
        if (err) return err;
    }

    if (resolved.v39) {
        std::printf("PACKER_INFO at file offset 0x%X: %d {Src,Dst^key} entries, "
                    "implicit LZMA props %s (3.9+ layout)\n",
                    static_cast<unsigned>(static_cast<std::uint32_t>(resolved.piBase)),
                    static_cast<int>(resolved.entries.size()),
                    hexBytes(resolved.props).c_str());
    } else {
        std::printf("PACKER_INFO at file offset 0x%X: %d plaintext {Src,Dst} entries, "
                    "LZMA props %s\n",
                    static_cast<unsigned>(static_cast<std::uint32_t>(resolved.piBase)),
                    static_cast<int>(resolved.entries.size()),
                    hexBytes(resolved.props).c_str());
    }

    for (std::size_t i = 0; i < resolved.entries.size(); ++i) {
        const PackerInfo& e = resolved.entries[i];
        std::uint32_t srcRaw = 0;
        if (rvaToRawOffset(pe, e.Src, &srcRaw)) {
            return "block " + std::to_string(i) + ": failed to resolve compressed data RVA 0x" +
                   hexU32(e.Src) + ": RVA not found";
        }
        if (pe.sizeOfImage <= e.Dst) {
            return "block " + std::to_string(i) + ": destination RVA 0x" + hexU32(e.Dst) +
                   " is outside unpacked image";
        }
        if (srcRaw > pe.data.size()) {
            return "block " + std::to_string(i) + ": failed to resolve compressed data RVA 0x" +
                   hexU32(e.Src) + ": out of file bounds";
        }
        std::vector<std::uint8_t> compressed(pe.data.begin() + srcRaw, pe.data.end());
        std::vector<std::uint8_t> unpacked;
        MaybeErr err = decompressLZMA(resolved.props, compressed, &unpacked);
        if (err) {
            return "block " + std::to_string(i) + ": LZMA decompression failed: " + *err;
        }

        std::size_t n = unpacked.size();
        const std::size_t room = out->size() - e.Dst;
        if (n > room) n = room;
        if (e.Dst + n > out->size()) {
            return "block " + std::to_string(i) + ": destination RVA 0x" + hexU32(e.Dst) +
                   " is outside unpacked image";
        }
        if (n) std::memcpy(out->data() + e.Dst, unpacked.data(), n);

        std::string name = "?";
        for (const SectionInfo& s : pe.sections) {
            if (e.Dst >= s.VirtualAddress && e.Dst < s.VirtualAddress + s.VirtualSize) {
                name = s.Name;
                break;
            }
        }
        std::printf("  Block %d (%s): SrcRVA=0x%08X DstRVA=0x%08X DecompressedSize=%d\n",
                    static_cast<int>(i), name.c_str(), e.Src, e.Dst, static_cast<int>(n));
    }

    return noErr();
}

}
