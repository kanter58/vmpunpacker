#include "vmp.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vmp {

namespace {

const char kVersionOld[] = "old";
const char kVersionNew[] = "new";
const char kDeepScanOptions[] = "DS";
const char kKernel32[] = "KERNEL32.dll";
const char kSeparator[] = ", ";
const char kPacked[] = "Packed";

const char kDosHeaderPattern[] =
        "4D 5A ?? 00 ?? 00 00 00 04 00 ?? 00 FF FF 00 00 B8 00 00 00 00 00 00 "
    "00 40 00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 ?? ?? ?? 0E ?? "
    "B4 09 CD 21 B8 01 4C CD";

bool equalFoldAscii(const char* a, std::size_t alen, const char* b, std::size_t blen) {
    if (alen != blen) return false;
    for (std::size_t i = 0; i < alen; ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

long indexBytes(const std::uint8_t* hay, std::size_t hn,
                const std::uint8_t* needle, std::size_t nn) {
    if (nn == 0) return 0;
    if (hn < nn) return -1;
    for (std::size_t i = 0; i + nn <= hn; ++i) {
        std::size_t j = 0;
        while (j < nn && hay[i + j] == needle[j]) ++j;
        if (j == nn) return static_cast<long>(i);
    }
    return -1;
}

int getInstructionLengthCore(const std::uint8_t* d, std::size_t len) {
    if (len < 2) return 1;

    if (d[0] == 0x0F) {
        if ((d[1] & 0xC0) == 0xC0) return 2;
        return 3;
    }

    const std::uint8_t modrm = d[1];
    const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6) & 3);
    const std::uint8_t rm  = static_cast<std::uint8_t>(modrm & 7);

    switch (mod) {
        case 0:
            if (rm == 5) return 6;
            if (rm == 4) return 3;
            return 2;
        case 1:
            if (rm == 4) return 4;
            return 3;
        case 2:
            if (rm == 4) return 7;
            return 6;
        default:
            return 2;
    }
}

int analyzeVMInstructionCore(const std::uint8_t* d, std::size_t len, int* vmOpsCount) {
    if (len < 2) return 0;

    const std::uint8_t opcode = d[0];

    if (opcode <= 0x33) {
        if (opcode == 0x0F) {
            const std::uint8_t b = d[1];
            if (b > 0xAB) {
                if (b > 0xBB) {
                    if (b <= 0xBD) {
                        if (vmOpsCount) ++(*vmOpsCount);
                        return getInstructionLengthCore(d, len);
                    }
                    if (static_cast<std::uint8_t>(b + 0x38) <= 7) {
                        if (vmOpsCount) ++(*vmOpsCount);
                        return 2;
                    }
                    return 0;
                }
                if (b == 0xB3) {
                    if (vmOpsCount) ++(*vmOpsCount);
                    return getInstructionLengthCore(d, len);
                }
                if (b == 0xBB) {
                    if (vmOpsCount) ++(*vmOpsCount);
                    return getInstructionLengthCore(d, len);
                }
                return 0;
            }
            if (b == 0x31) {
                if (vmOpsCount) ++(*vmOpsCount);
                return 2;
            }
            if (b == 0xA3) {
                if (vmOpsCount) ++(*vmOpsCount);
                return getInstructionLengthCore(d, len);
            }
            if (b == 0xAB) {
                if (vmOpsCount) ++(*vmOpsCount);
                return getInstructionLengthCore(d, len);
            }
            return 0;
        }
        if (opcode >= 0x30) {
            if (vmOpsCount) ++(*vmOpsCount);
            return getInstructionLengthCore(d, len);
        }
        return 0;
    }

    if (opcode <= 0x9C) {
        if (opcode == 0x60) {
            if (vmOpsCount) ++(*vmOpsCount);
            return 1;
        }
        if (opcode == 0x61) {
            if (vmOpsCount) ++(*vmOpsCount);
            return 1;
        }
        if (opcode == 0x9C) {
            if (vmOpsCount) ++(*vmOpsCount);
            return 1;
        }
        return 0;
    }

    if (opcode <= 0xF5) {
        if (opcode == 0x9D) {
            if (vmOpsCount) ++(*vmOpsCount);
            return 1;
        }
        if (static_cast<std::uint8_t>(opcode + 0x30) <= 3) {
            if (vmOpsCount) ++(*vmOpsCount);
            return getInstructionLengthCore(d, len);
        }
        if (opcode == 0xF5) {
            if (vmOpsCount) ++(*vmOpsCount);
            return 1;
        }
        return 0;
    }

    if (opcode <= 0xF7) {
        if ((((static_cast<std::uint8_t>(d[1]) >> 3) & 7) | 1) == 3) {
            if (vmOpsCount) ++(*vmOpsCount);
        }
        return getInstructionLengthCore(d, len);
    }

    if (opcode == 0xF8) {
        if (vmOpsCount) ++(*vmOpsCount);
        return 1;
    }
    if (opcode == 0xF9) {
        if (vmOpsCount) ++(*vmOpsCount);
        return 1;
    }
    return 0;
}

}

int getInstructionLength(const std::vector<std::uint8_t>& data) {
    return getInstructionLengthCore(data.data(), data.size());
}

int analyzeVMInstruction(const std::vector<std::uint8_t>& data, int* vmOpsCount) {
    return analyzeVMInstructionCore(data.data(), data.size(), vmOpsCount);
}

VMPResult detectByDeepScan(const PEFile& pe) {
    VMPResult result;

    std::uint32_t epOffset = 0;
    if (rvaToRawOffset(pe, pe.entryPointRVA, &epOffset)) {
        return result;
    }

    const std::size_t len = pe.data.size();
    if (len < static_cast<std::size_t>(epOffset) + 0x3E8) {
        return result;
    }

    const std::uint8_t* data = pe.data.data();

    std::size_t offset  = epOffset;
    int         instructionCount = 0;
    int         vmOpsCount       = 0;
    bool        foundFreshExit   = false;

    while (instructionCount < 0x3E8) {
        if (len <= offset + 15) break;

        const std::uint8_t b = data[offset];

        if (len > offset + 6 && b == 0x8B && len > offset + 2) {
            const std::uint8_t modrm = data[offset + 1];
            if ((modrm == 0x14 || (modrm | 0x10) == 0x1C) && data[offset + 2] == 0x85) {
                foundFreshExit = false;
                break;
            }
        }

        if ((b | 1) == 0xC3) {
            foundFreshExit = (instructionCount < 0xC8);
            break;
        }

        if (b == 0xFF && len > offset + 1) {
            const std::uint8_t modrm = data[offset + 1];
            const std::uint8_t reg   = static_cast<std::uint8_t>((modrm >> 3) & 7);
            if (reg == 4 && (modrm & 0xC0) == 0xC0) {
                foundFreshExit = true;
                break;
            }
            if (reg == 2) {
                foundFreshExit = false;
                break;
            }
        }

        const int instrLen = analyzeVMInstructionCore(data + offset, len - offset, &vmOpsCount);
        offset += (instrLen > 0) ? static_cast<std::size_t>(instrLen) : 1u;
        ++instructionCount;
    }

    if (vmOpsCount <= 10 || instructionCount >= 0xC8) {
        return result;
    }

    result.Detected = true;
    result.Version  = foundFreshExit ? kVersionNew : kVersionOld;
    result.Options  = kDeepScanOptions;
    return result;
}

VMPResult checkPackedVariant(const std::vector<std::uint8_t>& data, const PEFile& pe,
                             VMPResult result) {
    int kernel32Count = 0;
    for (const ImportEntry& imp : pe.imports) {
        if (equalFoldAscii(kKernel32, sizeof(kKernel32) - 1,
                           imp.LibraryName.data(), imp.LibraryName.size())) {
            ++kernel32Count;
        }
        if (kernel32Count >= 2) break;
    }

    if (kernel32Count >= 2 && pe.is64) {
        const std::vector<std::uint8_t> pattern = parseHexPattern(kDosHeaderPattern);
        if (pattern.size() <= data.size()) {
            bool matched = true;
            for (std::size_t i = 0; i < pattern.size(); ++i) {
                if (pattern[i] != 0xFF && data[i] != pattern[i]) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                result.Detected = true;
                if (!result.Options.empty()) {
                    result.Options += kSeparator;
                }
                result.Options += kPacked;
            }
        }
    }

    return result;
}

bool detectVMP2Heuristic(const PEFile& pe) {
    const int numSections = static_cast<int>(pe.sections.size());
    if (numSections <= 7) return false;

    int resourceIdx = -1;
    for (int i = 0; i < numSections; ++i) {
        if (pe.sections[static_cast<std::size_t>(i)].Name == ".rsrc") {
            resourceIdx = i;
            break;
        }
    }
    if (resourceIdx == -1) {
        const std::uint32_t rva = pe.dataDirectories[2].VirtualAddress;
        if (rva != 0) {
            for (int i = 0; i < numSections; ++i) {
                const SectionInfo& s = pe.sections[static_cast<std::size_t>(i)];
                if (s.VirtualAddress <= rva && rva < s.VirtualAddress + s.VirtualSize) {
                    resourceIdx = i;
                    break;
                }
            }
        }
    }

    int relocIdx = -1;
    for (int i = 0; i < numSections; ++i) {
        if (pe.sections[static_cast<std::size_t>(i)].Name == ".reloc") {
            relocIdx = i;
            break;
        }
    }
    if (relocIdx == -1) {
        const std::uint32_t rva = pe.dataDirectories[5].VirtualAddress;
        if (rva != 0) {
            for (int i = 0; i < numSections; ++i) {
                const SectionInfo& s = pe.sections[static_cast<std::size_t>(i)];
                if (s.VirtualAddress <= rva && rva < s.VirtualAddress + s.VirtualSize) {
                    relocIdx = i;
                    break;
                }
            }
        }
    }

    int nCount = 5;
    if (resourceIdx > numSections - 5) nCount = 6;
    if (relocIdx > numSections - nCount) ++nCount;

    int  detectCount   = 0;
    int  lastVMPSection = -1;
    for (int i = numSections - nCount; i < numSections; ++i) {
        if (i == resourceIdx || i == relocIdx) continue;
        const SectionInfo& s = pe.sections[static_cast<std::size_t>(i)];
        if (s.SizeOfRawData == 0) {
            if (s.PointerToRawData == 0) ++detectCount;
        } else if (s.PointerToRawData != 0) {
            lastVMPSection = i;
        }
    }

    if (detectCount < 3 || lastVMPSection == -1) return false;

    int epIdx = -1;
    for (int i = 0; i < numSections; ++i) {
        const SectionInfo& s = pe.sections[static_cast<std::size_t>(i)];
        if (s.VirtualAddress <= pe.entryPointRVA &&
            pe.entryPointRVA < s.VirtualAddress + s.VirtualSize) {
            epIdx = i;
            break;
        }
    }
    if (epIdx != lastVMPSection) return false;

    const SectionInfo& s = pe.sections[static_cast<std::size_t>(lastVMPSection)];

    const std::uint32_t rawPtr = s.PointerToRawData;
    const std::uint32_t end    = rawPtr + s.SizeOfRawData;

    if (s.Characteristics == 0xE0000060u) {
        if (pe.data.size() >= static_cast<std::size_t>(end) && rawPtr <= end) {
            const std::vector<std::uint8_t> chunk(
                pe.data.begin() + static_cast<std::ptrdiff_t>(rawPtr),
                pe.data.begin() + static_cast<std::ptrdiff_t>(end));
            if (calculateEntropy(chunk) > 7.6) return true;
        }
    }

    if ((s.Characteristics & 0x20000000u) != 0) {
        if (pe.data.size() >= static_cast<std::size_t>(end) && rawPtr <= end) {
            static const std::uint8_t kVMPattern[3] = { 0x9C, 0x8D, 0x64 };
            const std::uint32_t size = s.SizeOfRawData;
            std::uint32_t off = 0;
            int          hits = 0;
            while (size >= off + 3) {
                const long idx = indexBytes(pe.data.data() + rawPtr + off,
                                            static_cast<std::size_t>(size - off),
                                            kVMPattern, sizeof(kVMPattern));
                if (idx < 0) break;
                if (hits + 1 >= 2) return true;
                off += static_cast<std::uint32_t>(idx) + 3;
                ++hits;
            }
        }
    }

    return false;
}

}
