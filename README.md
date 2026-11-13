# VMPStatic

**VMPStatic** is a standalone, zero-dependency C++17 static **VMProtect** detector and packer-layer unpacker for Windows PE32 and PE32+ executables. It analyzes packed binaries purely on disk—without executing the target, injecting DLLs, or relying on external decompression libraries—by locating VMProtect's packer metadata and reconstructing the virtual image via a built-in LZMA decoder.

---

## Key Features

- **Pure Static Analysis**: Never runs target code; safe for inspecting untrusted or packed samples.
- **PE32 & PE32+ Support**: Handles both 32-bit (`0x10B`) and 64-bit (`0x20B`) Windows PE images, automatically skipping .NET assemblies (CLR Data Directory `14`).
- **Multi-Stage VMProtect Detection**:
  - `.vmp*` section names and paired numbered suffix collisions (`*0`, `*1`, `*2`, `*3`)
  - Masked entry-point byte signatures (`1.60-2.05`, `2.06`, `2.07`, `2.12-2.13`, `2.X`, `3.0X`)
  - Known VMProtect section characteristics (`0x60000060`, `0xE0000060`, `0xE0000040`, `0x68000060`, `0xE2000060`)
  - VMProtect `2.X` section-layout, high-entropy (`> 7.6`), and `9C 8D 64` stub heuristics
  - VMProtect `3.10+` stub entropy (`>= 7.0`) and virtual-section layout detection
  - Entry-point VM opcode deep scan (`DS`, distinguishing `new` vs. `old` exit stubs)
  - 64-bit `Packed` variant detection and `3.9+` / `3.10+` version refinement from packer metadata
- **Legacy & Modern `PACKER_INFO` Recovery**:
  - Supports plaintext `{SrcRVA, DstRVA}` tables with explicit 5-byte LZMA properties.
  - Supports **VMProtect 3.9+ / 3.10+** obfuscated `{SrcRVA, EncodedDst}` tables with key recovery and stream verification.
- **Zero External Dependencies**: Ships with an embedded, self-contained C++17 LZMA decoder (`src/lzma/lzma.cpp`) supporting large dictionaries (including VMProtect's 64 MB default).

---

## Scope & Limitations

`VMPStatic` targets **VMProtect's packing/compression layer**. Understanding what it does and does not handle will save analysis time:

- **Unpacks compressed sections**: Reconstructs virtual-only sections (`SizeOfRawData == 0`, `PointerToRawData == 0`, non-`IMAGE_SCN_CNT_UNINITIALIZED_DATA`) into a virtually mapped PE image (`PointerToRawData = VirtualAddress`, `SizeOfRawData = VirtualSize`).
- **Ready for static disassemblers**: Output binaries are laid out cleanly by `VirtualAddress` (`SizeOfImage` total bytes) for direct loading into IDA, Ghidra, or Binary Ninja.
- **Does not devirtualize VM bytecode**: Virtualized or mutated functions remain protected; only the outer packer compression is removed.
- **Does not rebuild imports or fix OEP**: Stripped/obfuscated import tables, stolen entry-point bytes, and dynamic runtime patches are not reconstructed.

---

## How It Works

1. **PE Parsing (`src/pe/pe.cpp`)**: Parses DOS/NT headers, optional header fields, data directories, section headers, and import descriptor library names, and provides RVA-to-raw-offset translation.
2. **Detection (`src/scanner/detect.cpp`, `src/scanner/vmscan.cpp`)**: Runs the detection pipeline (`detectVMProtectPE`) across section layout, entry-point patterns, section flags, entropy heuristics, and VM opcode frequency.
3. **Packer Metadata Discovery (`src/unpacker/unpack.cpp`)**:
   - **Legacy format (`findPackerInfoLegacy`)**: Searches for consecutive `0xFFFFFFFF` + `SectionVA` records matching all virtual-only destination sections and reads the 5-byte LZMA properties via the preceding RVA.
   - **VMProtect 3.9+ format (`findPackerInfoV39`)**: Scans for `N` consecutive 8-byte `{SrcRVA, StoredDst}` entries where every `SrcRVA` points to a valid raw byte `0x00` (LZMA range-decoder leading byte). Recovers the per-table key across candidate section VAs using:
     ```text
     DstRVA = rol32(SectionVA ^ key, (i * 7) & 31) ^ StoredDst
     ```
     Each candidate entry is confirmed with a 512-byte partial LZMA decode (`probeLZMA`) using VMProtect's implicit default properties (`5D 00 00 00 04`, i.e., `lc=3, lp=0, pb=2`, 64 MB dictionary).
4. **Image Reconstruction (`unpackPEFile`)**:
   - Allocates a zeroed buffer of `SizeOfImage` bytes and copies `SizeOfHeaders` plus all raw-backed sections to their `VirtualAddress`.
   - Rewrites section header `PointerToRawData` to `VirtualAddress` and `SizeOfRawData` to `VirtualSize` (when `VirtualSize > 0`).
   - Decompresses every `PACKER_INFO` entry from `SrcRVA` into `DstRVA` using `vmp::lzma::decode`.

---

## Project Structure

```text
vmpunpacker/
├── CMakeLists.txt              # CMake 3.16+ build configuration (C++17)
├── build.bat                   # Windows x64 Release build helper (vswhere + CMake)
├── VMPStatic.sln               # Visual Studio 2022 solution (x64 Debug/Release)
├── VMPStatic.vcxproj           # MSBuild project file (v143 toolset)
├── src/
│   ├── core/
│   │   ├── main.cpp            # CLI entry point and file I/O
│   │   ├── vmp.h               # Shared types, PE structures, and module APIs
│   │   ├── vmp.cpp             # Detection result formatting
│   │   └── util.cpp            # Pattern matching, section helpers, Shannon entropy
│   ├── pe/
│   │   └── pe.cpp              # PE32/PE32+ parser, import parser, RVA->raw mapping
│   ├── scanner/
│   │   ├── detect.cpp          # Section, entry-point, 3.10+, and pipeline detection
│   │   └── vmscan.cpp          # Deep VM opcode scan, 2.X heuristic, packed check
│   ├── unpacker/
│   │   └── unpack.cpp          # PACKER_INFO locator and PE image reconstructor
│   └── lzma/
│       ├── lzma.h              # Standalone LZMA decoder interface
│       └── lzma.cpp            # Self-contained LZMA range/match decoder
└── tools/                      # Porting reference (upstream_main.go) & dev/diff test scripts
```

---

## Building

### Prerequisites

- A **C++17** compiler:
  - **Windows**: Visual Studio 2022 (`v143` toolset / MSVC) or Build Tools for Visual Studio
  - **Linux / macOS**: GCC or Clang (with CMake 3.16+)
- **CMake 3.16+** (or MSBuild / Visual Studio IDE on Windows)
- No third-party libraries required.

### Option 1: Windows Automated Build (`build.bat`)

```bat
build.bat
```

Locates Visual Studio via `vswhere.exe`, initializes the x64 MSVC environment (`vcvars64.bat`), and compiles the Release binary at:

```text
build\Release\VMPStatic.exe
```

### Option 2: CMake CLI

**Windows (x64 Release):**
```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

**Linux / macOS:**
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Option 3: Visual Studio IDE

Open `VMPStatic.sln`, select **Release | x64** (or **Debug | x64**), and build the `VMPStatic` target. Output is placed in `build\Release\VMPStatic.exe` (or `build\Debug\VMPStatic.exe`).

---

## Usage

```text
VMPStatic.exe <packed.exe> <output.exe>
```

### Example

```powershell
.\build\Release\VMPStatic.exe packed_sample.exe unpacked_sample.exe
```

Sample output format:

```text
Loaded "packed_sample.exe" — 1048576 bytes

VMProtect v3.10+ [Min protection]

PACKER_INFO at file offset 0x1A400: 4 {Src,Dst^key} entries, implicit LZMA props 5D00000004 (3.9+ layout)
  Block 0 (.text): SrcRVA=0x00021000 DstRVA=0x00001000 DecompressedSize=524288
  Block 1 (.rdata): SrcRVA=0x00038000 DstRVA=0x00081000 DecompressedSize=131072
  ...

Unpacked image size: 1572864 bytes
Unpacked file written to "unpacked_sample.exe"
```

- **Exit code `0`**: Unpacking succeeded and `<output.exe>` was written.
- **Exit code `1`**: Invalid arguments, I/O error, malformed PE, unlocatable `PACKER_INFO`, or LZMA decompression failure (diagnostics printed to `stderr`).

---

## Development Tools (`tools/`)

The `tools/` directory contains development and verification artifacts used during the C++ port, including `upstream_main.go` (reference Go implementation) alongside Python/C++ differential test harnesses (`diffall.py`, `fuzzops.py`, `fuzzdeep.py`, `fuzzdiff.py`, `craft_pe.py`) and DWARF/PE inspection helpers (`dwarf.py`, `pe.py`). Note that several scripts in `tools/` are legacy porting helpers that expect an external reference binary (`ref_vmpstatic.exe`) or pre-reorganization source paths.

---

## Disclaimer

This tool is intended strictly for authorized reverse engineering, malware analysis, interoperability research, and security auditing. Ensure you have permission before analyzing third-party binaries.
