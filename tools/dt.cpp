// tools/dt.cpp - temporary differential test driver for src/detect.cpp.
#include "../src/vmp.h"

#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: dt <file>\n"); return 1; }
    std::ifstream f(argv[1], std::ios::binary);
    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(f)),
                                   std::istreambuf_iterator<char>());
    vmp::PEFile pe;
    vmp::MaybeErr err = vmp::parsePE(data, &pe);
    if (err) { std::printf("parse error: %s\n", err->c_str()); return 1; }

    std::printf("epRVA=%08X dataLen=%zu sections=%zu\n", pe.entryPointRVA, pe.data.size(),
                pe.sections.size());
    for (const auto& s : pe.sections) {
        std::printf("  '%s' vs=%08X va=%08X rawsz=%08X rawptr=%08X chars=%08X\n",
                    s.Name.c_str(), s.VirtualSize, s.VirtualAddress, s.SizeOfRawData,
                    s.PointerToRawData, s.Characteristics);
    }
    vmp::VMPResult a = vmp::detectByVMPSections(pe);
    std::printf("vmpSections: %d '%s' '%s'\n", (int)a.Detected, a.Version.c_str(),
                a.Options.c_str());
    vmp::VMPResult b = vmp::detectBySectionCharacteristics(pe);
    std::printf("sectChars  : %d '%s' '%s'\n", (int)b.Detected, b.Version.c_str(),
                b.Options.c_str());
    vmp::VMPResult c = vmp::detectVMP310(pe);
    std::printf("vmp310     : %d '%s' '%s'\n", (int)c.Detected, c.Version.c_str(),
                c.Options.c_str());
    vmp::VMPResult d = vmp::detectVMProtectPE(pe);
    std::printf("full       : %d '%s' '%s'\n", (int)d.Detected, d.Version.c_str(),
                d.Options.c_str());
    return 0;
}
