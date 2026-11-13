#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <optional>

namespace vmp {

using MaybeErr = std::optional<std::string>;

inline MaybeErr noErr() { return std::nullopt; }

struct SectionInfo {
    std::string   Name;
    std::uint32_t VirtualSize       = 0;
    std::uint32_t VirtualAddress    = 0;
    std::uint32_t SizeOfRawData     = 0;
    std::uint32_t PointerToRawData  = 0;
    std::uint32_t Characteristics   = 0;
};

struct ImportEntry {
    std::string LibraryName;
};

struct DataDirectory {
    std::uint32_t VirtualAddress = 0;
    std::uint32_t Size          = 0;
};

struct PEFile {
    std::vector<std::uint8_t>   data;
    bool                        is64            = false;
    std::uint32_t               sizeOfImage     = 0;
    std::uint32_t               sizeOfHeaders   = 0;
    std::uint32_t               entryPointRVA   = 0;
    std::int64_t                ntHeadersOffset = 0;
    std::vector<SectionInfo>    sections;
    std::vector<ImportEntry>    imports;
    DataDirectory               dataDirectories[16]{};
};

struct VMPResult {
    bool        Detected = false;
    std::string Version;
    std::string Options;
};

struct PackerInfo {
    std::uint32_t Src = 0;
    std::uint32_t Dst = 0;
};

struct PackerLocate {
    bool                   legacy = false;
    bool                   v39    = false;
    std::int64_t           piBase = 0;
    std::vector<std::uint8_t> props;
    std::vector<PackerInfo>    entries;
};

MaybeErr parsePE(const std::vector<std::uint8_t>& data, PEFile* pe);
MaybeErr parseImports(const std::vector<std::uint8_t>& data, PEFile* pe);
MaybeErr rvaToRawOffset(const PEFile& pe, std::uint32_t rva, std::uint32_t* out);

bool isNetAssembly(const PEFile& pe);
bool getRelocsSection(const PEFile& pe, int* idx);
bool getResourceSection(const PEFile& pe, int* idx);
bool getEntryPointSection(const PEFile& pe, std::uint32_t* ep, int* idx);

VMPResult detectVMProtectPE(const PEFile& pe);
VMPResult detectByVMPSections(const PEFile& pe);
VMPResult detectBySectionCharacteristics(const PEFile& pe);
VMPResult detectVMP310(const PEFile& pe);
VMPResult detectByEntryPoint(const PEFile& pe);
VMPResult detectByDeepScan(const PEFile& pe);
VMPResult checkPackedVariant(const std::vector<std::uint8_t>& data, const PEFile& pe, VMPResult result);
bool       detectVMP2Heuristic(const PEFile& pe);
bool       versionNeedsLayoutRefine(const std::string& v);

int  analyzeVMInstruction(const std::vector<std::uint8_t>& data, int* vmOpsCount);
int  getInstructionLength(const std::vector<std::uint8_t>& data);

std::vector<std::uint8_t> parseHexPattern(const std::string& pattern);
std::vector<std::uint8_t> parseHexPatternWithWildcard(const std::string& pattern);
bool matchesAtOffset(const std::vector<std::uint8_t>& data,
                     const std::vector<std::uint8_t>& pattern,
                     int offset);
int  findPattern(const std::vector<std::uint8_t>& data,
                 const std::vector<std::uint8_t>& pattern);
std::vector<SectionInfo> packedSections(const PEFile& pe);
bool sectionNameAt(const PEFile& pe, std::uint32_t rva, SectionInfo* out);
bool isSectionNamePresent(const PEFile& pe, const std::string& name);
bool getSectionNameCollision(const PEFile& pe, const std::string& suffix1,
                             const std::string& suffix2, std::string* collision);

MaybeErr decompressLZMA(const std::vector<std::uint8_t>& props,
                        const std::vector<std::uint8_t>& compressed,
                        std::vector<std::uint8_t>* out);
bool probeLZMA(const std::vector<std::uint8_t>& props,
               const std::vector<std::uint8_t>& compressed);

MaybeErr findPackerInfoLegacy(const PEFile& pe, const std::vector<SectionInfo>& dests,
                              std::int64_t* propsRawOff, std::vector<std::uint8_t>* props,
                              bool* ok);
MaybeErr findPackerInfoV39(const PEFile& pe, const std::vector<SectionInfo>& dests,
                           std::int64_t* piBase, std::vector<PackerInfo>* entries,
                           bool* ok);
MaybeErr locatePackerInfo(const PEFile& pe, const std::vector<SectionInfo>& dests,
                          PackerLocate* loc);
VMPResult refineVersionByPackerLayout(const PEFile& pe, VMPResult result, const PackerLocate& loc);
MaybeErr unpackPEFile(const PEFile& pe, const PackerLocate* loc,
                      std::vector<std::uint8_t>* out);

double calculateEntropy(const std::vector<std::uint8_t>& data);

std::string vmpResultToString(const VMPResult& r);

extern const std::uint8_t kDefaultLZMAProps[5];

}
