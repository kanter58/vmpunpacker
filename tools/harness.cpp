// tools/harness.cpp - temporary test harness (not part of the shipped program).
#include "../src/vmp.h"

#include <cmath>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

namespace vmp {
// calculateEntropy comes from util.cpp
} // namespace vmp

int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: harness <file>\n"); return 1; }
    std::ifstream f(argv[1], std::ios::binary);
    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(f)),
                                   std::istreambuf_iterator<char>());
    vmp::PEFile pe;
    vmp::MaybeErr err = vmp::parsePE(data, &pe);
    if (err) { std::printf("parse error: %s\n", err->c_str()); return 1; }
    std::printf("is64=%d entryRVA=%08X sections=%zu imports=%zu dataLen=%zu\n",
                (int)pe.is64, pe.entryPointRVA, pe.sections.size(), pe.imports.size(),
                pe.data.size());
    for (const auto& s : pe.sections) {
        std::printf("  sec '%s' vs=%08X va=%08X rawsz=%08X rawptr=%08X chars=%08X\n",
                    s.Name.c_str(), s.VirtualSize, s.VirtualAddress, s.SizeOfRawData,
                    s.PointerToRawData, s.Characteristics);
    }
    for (const auto& i : pe.imports) {
        std::printf("  import '%s'\n", i.LibraryName.c_str());
    }

    vmp::VMPResult deep = vmp::detectByDeepScan(pe);
    std::printf("detectByDeepScan   : detected=%d version='%s' options='%s'\n",
                (int)deep.Detected, deep.Version.c_str(), deep.Options.c_str());

    vmp::VMPResult packed = vmp::checkPackedVariant(data, pe, deep);
    std::printf("checkPackedVariant : detected=%d version='%s' options='%s'\n",
                (int)packed.Detected, packed.Version.c_str(), packed.Options.c_str());

    std::printf("detectVMP2Heuristic: %d\n", (int)vmp::detectVMP2Heuristic(pe));
    return 0;
}
