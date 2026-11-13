#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vmp {
namespace lzma {

struct Options {
    std::size_t dictionarySize = 0;
    std::size_t maxOutput = 0;
};

bool decode(const std::uint8_t* header, std::size_t headerLen,
            std::uint8_t propsByte, std::size_t dictSize,
            const std::uint8_t* in, std::size_t inLen,
            std::vector<std::uint8_t>* out,
            std::string* err);

bool decode(const Options& options,
            const std::uint8_t* header, std::size_t headerLen,
            std::uint8_t propsByte, std::size_t dictSize,
            const std::uint8_t* in, std::size_t inLen,
            std::vector<std::uint8_t>* out,
            std::string* err);

}
}
