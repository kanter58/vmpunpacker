// temporary stub for the not-yet-implemented LZMA decoder (test build only)
#include "lzma.h"

namespace vmp {
namespace lzma {

bool decode(const Options&, const std::uint8_t*, std::size_t, std::uint8_t, std::size_t,
            const std::uint8_t*, std::size_t, std::vector<std::uint8_t>*, std::string* err) {
    if (err) *err = "lzma stub";
    return false;
}

bool decode(const std::uint8_t*, std::size_t, std::uint8_t, std::size_t,
            const std::uint8_t*, std::size_t, std::vector<std::uint8_t>*, std::string* err) {
    if (err) *err = "lzma stub";
    return false;
}

} // namespace lzma
} // namespace vmp
