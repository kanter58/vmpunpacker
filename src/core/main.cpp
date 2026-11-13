#include "vmp.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#  include <fcntl.h>
#  include <io.h>
#  include <windows.h>
#endif

namespace {

std::string quoteGo(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\a': out += "\\a";  break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        case '\v': out += "\\v";  break;
        default:
            if (c < 0x20 || c == 0x7f) {
                char tmp[8];
                std::snprintf(tmp, sizeof(tmp), "\\x%02x", c);
                out += tmp;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += '"';
    return out;
}

std::string utf16ToUtf8(const std::wstring& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        unsigned int c = static_cast<unsigned int>(s[i]);
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < s.size()) {
            const unsigned int lo = static_cast<unsigned int>(s[i + 1]);
            if (lo >= 0xDC00 && lo < 0xE000) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            }
        }
        if (c < 0x80) {
            out += static_cast<char>(c);
        } else if (c < 0x800) {
            out += static_cast<char>(0xC0 | (c >> 6));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            out += static_cast<char>(0xE0 | (c >> 12));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (c >> 18));
            out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        }
    }
    return out;
}

std::string pathError(const std::string& op, const std::string& path, unsigned long code) {
#if defined(_WIN32)
    wchar_t* buffer = nullptr;
    const DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                       FORMAT_MESSAGE_FROM_SYSTEM |
                                       FORMAT_MESSAGE_IGNORE_INSERTS,
                                   nullptr, static_cast<DWORD>(code),
                                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                   reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::string message;
    if (n != 0 && buffer != nullptr) {
        message = utf16ToUtf8(std::wstring(buffer, n));
        while (!message.empty() &&
               (message.back() == '\r' || message.back() == '\n' || message.back() == ' ')) {
            message.pop_back();
        }
    }
    if (buffer != nullptr) LocalFree(buffer);
    if (message.empty()) message = "unknown error";
#else
    (void)code;
    std::string message = "unknown error";
#endif
    return op + " " + path + ": " + message;
}

bool readFile(const std::string& path, std::vector<std::uint8_t>* out, std::string* err) {
#if defined(_WIN32)
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        *err = pathError("open", path, GetLastError());
        return false;
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size)) {
        const DWORD code = GetLastError();
        CloseHandle(h);
        *err = pathError("open", path, code);
        return false;
    }
    out->resize(static_cast<std::size_t>(size.QuadPart));
    std::size_t done = 0;
    while (done < out->size()) {
        DWORD chunk = static_cast<DWORD>(
            (out->size() - done) > 0x10000000u ? 0x10000000u : (out->size() - done));
        DWORD got = 0;
        if (!ReadFile(h, out->data() + done, chunk, &got, nullptr)) {
            const DWORD code = GetLastError();
            CloseHandle(h);
            *err = pathError("read", path, code);
            return false;
        }
        if (got == 0) break;
        done += got;
    }
    out->resize(done);
    CloseHandle(h);
    return true;
#else
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        *err = pathError("open", path, 0);
        return false;
    }
    f.seekg(0, std::ios::end);
    const std::streamoff size = f.tellg();
    f.seekg(0, std::ios::beg);
    out->resize(static_cast<std::size_t>(size));
    if (size > 0) f.read(reinterpret_cast<char*>(out->data()), size);
    if (!f) {
        *err = pathError("read", path, 0);
        return false;
    }
    return true;
#endif
}

bool writeFile(const std::string& path, const std::vector<std::uint8_t>& data, std::string* err) {
#if defined(_WIN32)
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        *err = pathError("open", path, GetLastError());
        return false;
    }
    std::size_t done = 0;
    while (done < data.size()) {
        DWORD chunk = static_cast<DWORD>(
            (data.size() - done) > 0x10000000u ? 0x10000000u : (data.size() - done));
        DWORD written = 0;
        if (!WriteFile(h, data.data() + done, chunk, &written, nullptr)) {
            const DWORD code = GetLastError();
            CloseHandle(h);
            *err = pathError("write", path, code);
            return false;
        }
        if (written == 0) break;
        done += written;
    }
    CloseHandle(h);
    return true;
#else
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        *err = pathError("open", path, 0);
        return false;
    }
    if (!data.empty()) {
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
    }
    f.close();
    if (!f) {
        *err = pathError("write", path, 0);
        return false;
    }
    return true;
#endif
}

}

int main(int argc, char** argv) {
#if defined(_WIN32)
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
#endif
    if (argc < 3) {
        std::fprintf(stderr, "Usage: %s <packed.exe> <output.exe>\n", argv[0]);
        return 1;
    }
    const std::string packedPath   = argv[1];
    const std::string unpackedPath = argv[2];

    std::vector<std::uint8_t> data;
    std::string err;
    if (!readFile(packedPath, &data, &err)) {
        std::fprintf(stderr, "Error reading input file: %s\n", err.c_str());
        return 1;
    }

    std::printf("Loaded %s \xE2\x80\x94 %d bytes\n\n", quoteGo(packedPath).c_str(),
                static_cast<int>(data.size()));

    vmp::PEFile pe;
    vmp::MaybeErr perr = vmp::parsePE(data, &pe);
    if (perr) {
        std::fprintf(stderr, "Error parsing pe file: %s\n", perr->c_str());
        return 1;
    }

    vmp::VMPResult result = vmp::detectVMProtectPE(pe);

    bool haveLoc = false;
    vmp::PackerLocate loc;
    {
        const std::vector<vmp::SectionInfo> dests = vmp::packedSections(pe);
        if (!dests.empty()) {
            vmp::MaybeErr lerr = vmp::locatePackerInfo(pe, dests, &loc);
            if (!lerr) {
                result = vmp::refineVersionByPackerLayout(pe, result, loc);
                haveLoc = true;
            }
        }
    }

    if (result.Detected) {
        std::printf("%s\n", vmp::vmpResultToString(result).c_str());
    } else {
        std::printf("Warning: VMProtect signature not found. The file may still be packed\n");
    }
    std::printf("\n");

    std::vector<std::uint8_t> unpacked;
    vmp::MaybeErr uerr = vmp::unpackPEFile(pe, haveLoc ? &loc : nullptr, &unpacked);
    if (uerr) {
        std::fprintf(stderr, "\nUnpacking failed: %s\n", uerr->c_str());
        return 1;
    }

    std::printf("\nUnpacked image size: %d bytes\n", static_cast<int>(unpacked.size()));

    if (!writeFile(unpackedPath, unpacked, &err)) {
        std::fprintf(stderr, "Error writing output file: %s\n", err.c_str());
        return 1;
    }

    std::printf("Unpacked file written to %s\n", quoteGo(unpackedPath).c_str());
    return 0;
}
