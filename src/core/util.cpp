#include "vmp.h"

#include <cmath>

namespace vmp {

namespace {

constexpr std::uint8_t kWildcard = 0xFF;

constexpr std::uint32_t kSectionCntUninitData = 0x00000080u;

bool goIsSpace(std::uint32_t r) {
    if (r <= 0xFFu) {
        switch (r) {
        case '\t': case '\n': case '\v': case '\f': case '\r':
        case ' ':  case 0x85u: case 0xA0u:
            return true;
        default:
            return false;
        }
    }
    return r == 0x1680u || (r >= 0x2000u && r <= 0x200Au) ||
           r == 0x2028u || r == 0x2029u || r == 0x202Fu ||
           r == 0x205Fu || r == 0x3000u;
}

std::uint32_t goDecodeRune(const std::string& s, std::size_t& i) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    if (c < 0x80u) {
        ++i;
        return c;
    }
    std::size_t   n;
    std::uint32_t r;
    if ((c & 0xE0u) == 0xC0u)      { n = 2; r = c & 0x1Fu; }
    else if ((c & 0xF0u) == 0xE0u) { n = 3; r = c & 0x0Fu; }
    else if ((c & 0xF8u) == 0xF0u) { n = 4; r = c & 0x07u; }
    else                           { ++i; return 0xFFFDu; }

    if (i + n > s.size()) { ++i; return 0xFFFDu; }
    for (std::size_t k = 1; k < n; ++k) {
        const unsigned char cc = static_cast<unsigned char>(s[i + k]);
        if ((cc & 0xC0u) != 0x80u) { ++i; return 0xFFFDu; }
        r = (r << 6) | (cc & 0x3Fu);
    }
    static const std::uint32_t kMin[5] = {0, 0, 0x80, 0x800, 0x10000};
    if (r < kMin[n] || r > 0x10FFFFu || (r >= 0xD800u && r <= 0xDFFFu)) {
        ++i;
        return 0xFFFDu;
    }
    i += n;
    return r;
}

std::vector<std::string> goFields(const std::string& s) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < s.size()) {
        std::size_t start = i;
        while (i < s.size()) {
            const std::size_t before = i;
            const std::uint32_t r = goDecodeRune(s, i);
            if (!goIsSpace(r)) {
                i = before;
                break;
            }
        }
        if (i > start) {
            continue;
        }
        start = i;
        while (i < s.size()) {
            const std::size_t before = i;
            const std::uint32_t r = goDecodeRune(s, i);
            if (goIsSpace(r)) {
                i = before;
                break;
            }
        }
        out.push_back(s.substr(start, i - start));
    }
    return out;
}

bool goHasSuffix(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

inline bool isHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline std::uint32_t hexValue(char c) {
    if (c >= '0' && c <= '9') return static_cast<std::uint32_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<std::uint32_t>(c - 'a' + 10);
    return static_cast<std::uint32_t>(c - 'A' + 10);
}

std::uint8_t goScanHexByte(const std::string& tok) {
    std::size_t n = 0;
    while (n < tok.size() && isHexDigit(tok[n])) ++n;

    if (n == 0)  return 0;
    if (n > 16)  return 0;

    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) {
        v = (v << 4) | hexValue(tok[i]);
    }
    return static_cast<std::uint8_t>(v & 0xFFu);
}

}

std::vector<std::uint8_t> parseHexPattern(const std::string& pattern) {
    const std::vector<std::string> parts = goFields(pattern);
    std::vector<std::uint8_t> result(parts.size(), 0);
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (parts[i] == "??") {
            result[i] = kWildcard;
        } else {
            result[i] = goScanHexByte(parts[i]);
        }
    }
    return result;
}

std::vector<std::uint8_t> parseHexPatternWithWildcard(const std::string& pattern) {
    const std::vector<std::string> parts = goFields(pattern);
    std::vector<std::uint8_t> result(parts.size(), 0);
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (parts[i] == "??" || parts[i] == "$$") {
            result[i] = kWildcard;
        } else {
            result[i] = goScanHexByte(parts[i]);
        }
    }
    return result;
}

bool matchesAtOffset(const std::vector<std::uint8_t>& data,
                     const std::vector<std::uint8_t>& pattern,
                     int offset) {
    if (offset < 0) return false;
    const std::int64_t end = static_cast<std::int64_t>(offset) +
                             static_cast<std::int64_t>(pattern.size());
    if (end > static_cast<std::int64_t>(data.size())) return false;

    for (std::size_t j = 0; j < pattern.size(); ++j) {
        const std::uint8_t pb = pattern[j];
        if (pb != kWildcard && data[static_cast<std::size_t>(offset) + j] != pb) {
            return false;
        }
    }
    return true;
}

int findPattern(const std::vector<std::uint8_t>& data,
                const std::vector<std::uint8_t>& pattern) {
    if (pattern.empty() || data.size() < pattern.size()) return -1;
    const std::size_t last = data.size() - pattern.size();
    for (std::size_t i = 0; i <= last; ++i) {
        if (matchesAtOffset(data, pattern, static_cast<int>(i))) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

std::vector<SectionInfo> packedSections(const PEFile& pe) {
    std::vector<SectionInfo> out;
    for (const SectionInfo& s : pe.sections) {
        const bool isVirtualOnly = (s.SizeOfRawData == 0 && s.PointerToRawData == 0);
        const bool isNotUninit   = (s.Characteristics & kSectionCntUninitData) == 0;
        if (isVirtualOnly && isNotUninit) {
            out.push_back(s);
        }
    }
    return out;
}

bool sectionNameAt(const PEFile& pe, std::uint32_t rva, SectionInfo* out) {
    for (const SectionInfo& s : pe.sections) {
        const std::uint32_t end = s.VirtualAddress + s.VirtualSize;
        if (rva >= s.VirtualAddress && rva < end) {
            if (out) *out = s;
            return true;
        }
    }
    return false;
}

bool isSectionNamePresent(const PEFile& pe, const std::string& name) {
    for (const SectionInfo& s : pe.sections) {
        if (s.Name == name) return true;
    }
    return false;
}

bool getSectionNameCollision(const PEFile& pe, const std::string& suffix1,
                             const std::string& suffix2, std::string* collision) {
    if (collision) collision->clear();
    for (const SectionInfo& s : pe.sections) {
        if (goHasSuffix(s.Name, suffix1)) {
            const std::string base = s.Name.substr(0, s.Name.size() - suffix1.size());
            if (isSectionNamePresent(pe, base + suffix2)) {
                if (collision) *collision = base;
                return true;
            }
        }
    }
    return false;
}

double calculateEntropy(const std::vector<std::uint8_t>& data) {
    if (data.empty()) return 0.0;

    std::uint64_t freq[256] = {};
    for (const std::uint8_t b : data) {
        ++freq[b];
    }

    double entropy  = 0.0;
    const double dataLen = static_cast<double>(data.size());
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        const double p = static_cast<double>(freq[i]) / dataLen;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

}
