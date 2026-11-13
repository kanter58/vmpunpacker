#include "vmp.h"

#include <cstdio>
#include <cstring>

namespace vmp {

namespace {

inline std::uint16_t le16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}
inline std::uint32_t le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

long indexByte(const std::vector<std::uint8_t>& s, std::size_t from, std::uint8_t c) {
    for (std::size_t i = from; i < s.size(); ++i) {
        if (s[i] == c) return static_cast<long>(i - from);
    }
    return -1;
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

std::string hexU32(std::uint32_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%X", v);
    return buf;
}

std::string hexSigned(std::int64_t v) {
    char buf[32];
    if (v < 0) {
        std::snprintf(buf, sizeof(buf), "-%llX",
                      static_cast<unsigned long long>(-(v + 1)) + 1ull);
    } else {
        std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
    }
    return buf;
}

}

MaybeErr parsePE(const std::vector<std::uint8_t>& data, PEFile* pe) {
    if (data.size() < 0x40) {
        return std::string("file too small to be a PE");
    }
    if (le16(data.data()) != 0x5A4D) {
        return std::string("invalid DOS signature");
    }
    const std::int64_t ntOff = static_cast<std::int32_t>(le32(&data[0x3c]));
    if (ntOff + 0x18 > static_cast<std::int64_t>(data.size())) {
        return "NT headers offset 0x" + hexSigned(ntOff) + " is out of file bounds";
    }
    if (le32(&data[static_cast<std::size_t>(ntOff)]) != 0x4550) {
        return std::string("invalid NT signature");
    }

    const std::size_t nt = static_cast<std::size_t>(ntOff);
    const std::size_t fhOff = nt + 4;
    const std::size_t ohOff = fhOff + 20;

    pe->data            = data;
    pe->ntHeadersOffset = ntOff;
    pe->entryPointRVA   = le32(&data[ohOff + 16]);
    pe->is64            = (le16(&data[ohOff]) == 0x20b);
    pe->sizeOfImage     = le32(&data[ohOff + 56]);
    pe->sizeOfHeaders   = le32(&data[ohOff + 60]);

    std::uint32_t numDirs = 0;
    std::size_t   dirBase = 0;
    if (pe->is64) {
        numDirs = le32(&data[ohOff + 108]);
        dirBase = ohOff + 112;
    } else {
        numDirs = le32(&data[ohOff + 92]);
        dirBase = ohOff + 96;
    }
    for (int i = 0; i < 16; ++i) {
        if (static_cast<std::uint32_t>(i) >= numDirs) break;
        const std::size_t off = dirBase + static_cast<std::size_t>(i) * 8;
        if (data.size() < off + 8) break;
        pe->dataDirectories[i].VirtualAddress = le32(&data[off]);
        pe->dataDirectories[i].Size           = le32(&data[off + 4]);
    }

    const int numSections = le16(&data[fhOff + 2]);
    const int optSize     = le16(&data[fhOff + 16]);
    if (data.size() < ohOff + 2) {
        return std::string("optional header is out of file bounds");
    }
    const std::size_t secTable = ohOff + static_cast<std::size_t>(optSize);

    pe->sections.resize(static_cast<std::size_t>(numSections));
    for (int i = 0; i < numSections; ++i) {
        const std::size_t off = secTable + static_cast<std::size_t>(i) * 40;
        if (data.size() < off + 0x28) {
            return "section header " + std::to_string(i) + " is out of file bounds";
        }
        long nameEnd = indexByte(data, off, 0);
        if (nameEnd < 0 || static_cast<std::size_t>(nameEnd) > 8) nameEnd = 8;
        SectionInfo& s = pe->sections[static_cast<std::size_t>(i)];
        s.Name             = std::string(reinterpret_cast<const char*>(&data[off]),
                                        static_cast<std::size_t>(nameEnd));
        s.VirtualSize      = le32(&data[off + 0x08]);
        s.VirtualAddress   = le32(&data[off + 0x0c]);
        s.SizeOfRawData    = le32(&data[off + 0x10]);
        s.PointerToRawData = le32(&data[off + 0x14]);
        s.Characteristics  = le32(&data[off + 0x24]);
    }

    MaybeErr err = parseImports(data, pe);
    if (err) return err;
    return noErr();
}

MaybeErr rvaToRawOffset(const PEFile& pe, std::uint32_t rva, std::uint32_t* out) {
    if (rva < pe.sizeOfHeaders) {
        if (rva >= pe.data.size()) {
            return "header RVA 0x" + hexU32(rva) + " is out of file bounds";
        }
        *out = rva;
        return noErr();
    }
    for (const SectionInfo& s : pe.sections) {
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize) {
            if (s.PointerToRawData == 0) {
                return "RVA 0x" + hexU32(rva) + " is in section " + quoteName(s.Name) +
                       " which has no raw data";
            }
            const std::uint32_t off = rva - s.VirtualAddress;
            if (off >= s.SizeOfRawData) {
                return "RVA 0x" + hexU32(rva) + " is in the virtual-only (BSS) part of section " +
                       quoteName(s.Name);
            }
            const std::uint32_t raw = s.PointerToRawData + off;
            if (raw >= pe.data.size()) {
                return "computed raw offset 0x" + hexU32(raw) + " for RVA 0x" + hexU32(rva) +
                       " is out of file bounds";
            }
            *out = raw;
            return noErr();
        }
    }
    return "RVA 0x" + hexU32(rva) + " was not found in any section";
}

MaybeErr parseImports(const std::vector<std::uint8_t>& data, PEFile* pe) {
    const std::uint32_t importDirRVA = pe->dataDirectories[1].VirtualAddress;
    if (importDirRVA == 0) return noErr();

    std::uint32_t importRawOff = 0;
    MaybeErr err = rvaToRawOffset(*pe, importDirRVA, &importRawOff);
    if (err) return err;

    pe->imports.clear();
    std::size_t off = importRawOff;
    while (off + 0x14 <= data.size()) {
        const std::uint32_t nameRVA = le32(&data[off + 0x0c]);
        if (nameRVA == 0) break;
        std::uint32_t nameRaw = 0;
        if (!rvaToRawOffset(*pe, nameRVA, &nameRaw)) {
            const long end = indexByte(data, nameRaw, 0);
            if (end >= 0) {
                ImportEntry e;
                e.LibraryName = std::string(reinterpret_cast<const char*>(&data[nameRaw]),
                                           static_cast<std::size_t>(end));
                pe->imports.push_back(e);
            }
        }
        off += 0x14;
    }
    return noErr();
}

}
