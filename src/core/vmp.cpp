#include "vmp.h"

namespace vmp {

std::string vmpResultToString(const VMPResult& r) {
    if (!r.Detected) return "VMProtect: Not detected";
    std::string s = "VMProtect";
    if (!r.Version.empty()) s += " v" + r.Version;
    if (!r.Options.empty()) s += " [" + r.Options + "]";
    return s;
}

}
