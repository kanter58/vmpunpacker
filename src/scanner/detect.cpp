#include "vmp.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vmp {

namespace {

bool nameEndsWith(const std::string& name, char c) {
    return !name.empty() && name[name.size() - 1] == c;
}

const std::uint32_t kVmpCharacteristics[5] = {
    0x60000060u,
    0xe0000060u,
    0xe0000040u,
    0x68000060u,
    0xe2000060u,
};

}

bool isNetAssembly(const PEFile& pe) {
    return pe.dataDirectories[14].VirtualAddress != 0 && pe.dataDirectories[14].Size > 0;
}

bool getRelocsSection(const PEFile& pe, int* idx) {
    for (std::size_t i = 0; i < pe.sections.size(); ++i) {
        if (pe.sections[i].Name == ".reloc") {
            if (idx != nullptr) {
                *idx = static_cast<int>(i);
            }
            return true;
        }
    }

    const std::uint32_t rva = pe.dataDirectories[5].VirtualAddress;
    if (rva == 0) {
        if (idx != nullptr) {
            *idx = -1;
        }
        return false;
    }

    for (std::size_t i = 0; i < pe.sections.size(); ++i) {
        const SectionInfo& s = pe.sections[i];
        if (s.VirtualAddress <= rva && rva < s.VirtualAddress + s.VirtualSize) {
            if (idx != nullptr) {
                *idx = static_cast<int>(i);
            }
            return true;
        }
    }

    if (idx != nullptr) {
        *idx = -1;
    }
    return false;
}

bool getResourceSection(const PEFile& pe, int* idx) {
    for (std::size_t i = 0; i < pe.sections.size(); ++i) {
        if (pe.sections[i].Name == ".rsrc") {
            if (idx != nullptr) {
                *idx = static_cast<int>(i);
            }
            return true;
        }
    }

    const std::uint32_t rva = pe.dataDirectories[2].VirtualAddress;
    if (rva == 0) {
        if (idx != nullptr) {
            *idx = -1;
        }
        return false;
    }

    for (std::size_t i = 0; i < pe.sections.size(); ++i) {
        const SectionInfo& s = pe.sections[i];
        if (s.VirtualAddress <= rva && rva < s.VirtualAddress + s.VirtualSize) {
            if (idx != nullptr) {
                *idx = static_cast<int>(i);
            }
            return true;
        }
    }

    if (idx != nullptr) {
        *idx = -1;
    }
    return false;
}

bool getEntryPointSection(const PEFile& pe, std::uint32_t* ep, int* idx) {
    const std::uint32_t rva = pe.entryPointRVA;

    for (std::size_t i = 0; i < pe.sections.size(); ++i) {
        const SectionInfo& s = pe.sections[i];
        if (s.VirtualAddress <= rva && rva < s.VirtualAddress + s.VirtualSize) {
            if (ep != nullptr) {
                *ep = rva;
            }
            if (idx != nullptr) {
                *idx = static_cast<int>(i);
            }
            return true;
        }
    }

    if (ep != nullptr) {
        *ep = 0;
    }
    if (idx != nullptr) {
        *idx = -1;
    }
    return false;
}

bool versionNeedsLayoutRefine(const std::string& v) {
    if (v.empty()) {
        return true;
    }
    if (v.size() == 3) {
        return v == "2.X" || v == "new" || v == "old";
    }
    if (v.size() == 8) {
        return v == "1.X-3.XX";
    }
    if (v.size() == 9) {
        return v == "2.XX-3.XX";
    }
    return false;
}

VMPResult detectByVMPSections(const PEFile& pe) {
    VMPResult result;

    int relocIdx = -1;
    int resourceIdx = -1;
    getRelocsSection(pe, &relocIdx);
    getResourceSection(pe, &resourceIdx);

    std::string vmpSectionName;

    const int count = static_cast<int>(pe.sections.size());
    for (int i = count - 1; i >= 0; --i) {
        if (i == relocIdx || i == resourceIdx) {
            continue;
        }

        const std::string& name = pe.sections[static_cast<std::size_t>(i)].Name;
        if (name.empty()) {
            break;
        }
        vmpSectionName = name;

        if (i > 0 && name == ".vmp0") {
            result.Detected = true;
        } else if (i > 1 && nameEndsWith(name, '1')) {
            std::string collision;
            if (getSectionNameCollision(pe, "0", "1", &collision) && !collision.empty() &&
                isSectionNamePresent(pe, collision + "1")) {
                result.Detected = true;
            }
        } else if (i > 2 && nameEndsWith(name, '2')) {
            std::string collision;
            if (getSectionNameCollision(pe, "1", "2", &collision) && !collision.empty() &&
                isSectionNamePresent(pe, collision + "1") &&
                isSectionNamePresent(pe, collision + "0")) {
                result.Detected = true;
            }
        } else if (i > 3 && nameEndsWith(name, '3')) {
            std::string collision;
            if (getSectionNameCollision(pe, "2", "3", &collision) && !collision.empty() &&
                isSectionNamePresent(pe, collision + "2") &&
                isSectionNamePresent(pe, collision + "1") &&
                isSectionNamePresent(pe, collision + "0")) {
                result.Detected = true;
            }
        }

        break;
    }

    if (result.Detected) {
        result.Version = pe.is64 ? "2.XX-3.XX" : "1.X-3.XX";
        if (nameEndsWith(vmpSectionName, '0')) {
            result.Options = "Min protection";
        }
    }

    return result;
}

VMPResult detectBySectionCharacteristics(const PEFile& pe) {
    VMPResult result;

    for (const SectionInfo& s : pe.sections) {
        for (int j = 0; j < 5; ++j) {
            if (s.Characteristics == kVmpCharacteristics[j] && s.Name.size() >= 4 &&
                s.Name.compare(0, 4, ".vmp") == 0) {
                result.Detected = true;
                result.Version = "1.X-3.XX";
                return result;
            }
        }
    }

    std::string base;
    for (const SectionInfo& s : pe.sections) {
        if (!nameEndsWith(s.Name, '0')) {
            continue;
        }
        const std::string candidate = s.Name.substr(0, s.Name.size() - 1);
        if (isSectionNamePresent(pe, candidate + "1")) {
            base = candidate;
            break;
        }
    }

    if (!base.empty()) {
        for (int i = 0; i <= 2; ++i) {
            const std::string candidate = base + std::to_string(i);
            if (!isSectionNamePresent(pe, candidate)) {
                continue;
            }
            for (const SectionInfo& s : pe.sections) {
                if (s.Name != candidate) {
                    continue;
                }
                for (int j = 0; j < 5; ++j) {
                    if (s.Characteristics == kVmpCharacteristics[j]) {
                        result.Detected = true;
                        result.Version = "1.X-3.XX";
                        return result;
                    }
                }
            }
        }
    }

    return result;
}

VMPResult detectVMP310(const PEFile& pe) {
    VMPResult result;

    std::uint32_t ep = 0;
    int epIdx = -1;
    if (!getEntryPointSection(pe, &ep, &epIdx) || epIdx <= 0) {
        return result;
    }

    const SectionInfo& stub = pe.sections[static_cast<std::size_t>(epIdx)];

    if ((stub.Characteristics & 0x60000000u) != 0x60000000u) {
        return result;
    }
    if (stub.SizeOfRawData == 0) {
        return result;
    }

    int packed = 0;
    for (int i = 0; i < epIdx; ++i) {
        const SectionInfo& s = pe.sections[static_cast<std::size_t>(i)];
        if (s.SizeOfRawData == 0 && s.PointerToRawData == 0 &&
            (s.Characteristics & 0x80u) == 0) {
            ++packed;
        }
    }
    if (packed < 3) {
        return result;
    }

    const std::uint32_t end = stub.PointerToRawData + stub.SizeOfRawData;
    if (pe.data.size() < static_cast<std::size_t>(end)) {
        return result;
    }

    const std::size_t offset = stub.PointerToRawData;
    const std::size_t length = stub.SizeOfRawData;
    if (offset > pe.data.size() || length > pe.data.size() - offset) {
        return result;
    }

    const std::vector<std::uint8_t> chunk(pe.data.begin() + static_cast<std::ptrdiff_t>(offset),
                                           pe.data.begin() + static_cast<std::ptrdiff_t>(offset + length));
    const double entropy = calculateEntropy(chunk);
    if (entropy < 7.0) {
        return result;
    }

    result.Detected = true;
    result.Version = "3.10+";
    return result;
}

VMPResult detectByEntryPoint(const PEFile& pe) {
    struct EntryPointPattern {
        const char* pattern;
        const char* version;
        const char* options;
    };
    static const EntryPointPattern kEntryPointPatterns[9] = {
        { "68 ?? ?? ?? ?? E9",
          "1.60-2.05", "" },
        { "68 ?? ?? ?? ?? E8",
          "1.60-2.05", "" },
        { "54 C7 04 24 ?? ?? ?? ?? 9C 60 C7 44 24 ?? ?? ?? ?? ?? C6 44 24 ?? ?? 88 74 24 ?? 60",
          "2.06", "" },
        { "E8 $$ $$ $$ $$ E9 $$ $$ $$ $$ 88 04 24 88 1C 24 C7 04 24 ?? ?? ?? ?? 9C E8",
          "2.07", "" },
        { "9C E8 $$ $$ $$ $$ E8 $$ $$ $$ $$ C7 44 24 ?? ?? ?? ?? ?? E9 $$ $$ $$ $$ E8 $$ $$ $$ $$ "
          "C7 44 24 ?? ?? ?? ?? ?? 52 60 68",
          "2.12-2.13", "" },
        { "9C 9C C7 44 24 ?? ?? ?? ?? ?? 9C C7 44 24 ?? ?? ?? ?? ?? 9C 52 8D 64 24 ?? E9",
          "2.12-2.13", "" },
        { "68 ?? ?? ?? ?? E8 $$ $$ $$ $$ 41 57 41 50 44 8A C3 50 41 0F 96 C0 57 41 51 48 C7 C7",
          "3.0X", "" },
        { "9C E9",
          "2.X", "" },
        { "9C FF",
          "2.X", "" },
    };

    VMPResult result;

    std::uint32_t epOffset = 0;
    if (rvaToRawOffset(pe, pe.entryPointRVA, &epOffset)) {
        return result;
    }
    if (static_cast<std::size_t>(epOffset) + 20 > pe.data.size()) {
        return result;
    }

    for (const EntryPointPattern& p : kEntryPointPatterns) {
        const std::vector<std::uint8_t> pattern = parseHexPatternWithWildcard(p.pattern);
        if (matchesAtOffset(pe.data, pattern, static_cast<int>(epOffset))) {
            result.Detected = true;
            result.Version  = p.version;
            result.Options  = p.options;
            return result;
        }
    }

    return result;
}

VMPResult detectVMProtectPE(const PEFile& pe) {
    VMPResult result;

    if (isNetAssembly(pe)) {
        return result;
    }

    result = detectByVMPSections(pe);

    if (!result.Detected) {
        result = detectByEntryPoint(pe);
    }

    if (!result.Detected) {
        result = detectBySectionCharacteristics(pe);
    }

    if (!result.Detected && detectVMP2Heuristic(pe)) {
        result.Detected = true;
        result.Version  = "2.X";
    }

    if (!result.Detected) {
        result = detectVMP310(pe);
    }

    if (!result.Detected) {
        result = detectByDeepScan(pe);
    }

    result = checkPackedVariant(pe.data, pe, result);

    if (result.Detected && pe.sections.size() < 3) {
        result.Detected = false;
    }

    return result;
}

}
