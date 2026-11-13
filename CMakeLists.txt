cmake_minimum_required(VERSION 3.16)
project(VMPStatic CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(VMPStatic
  src/core/main.cpp
  src/core/vmp.cpp
  src/core/util.cpp
  src/pe/pe.cpp
  src/scanner/detect.cpp
  src/scanner/vmscan.cpp
  src/unpacker/unpack.cpp
  src/lzma/lzma.cpp
)

target_include_directories(VMPStatic PRIVATE
  src/core
  src/pe
  src/scanner
  src/unpacker
  src/lzma
)
if(MSVC)
  target_compile_options(VMPStatic PRIVATE /W3 /permissive- /utf-8 /EHsc)
else()
  target_compile_options(VMPStatic PRIVATE -Wall -Wextra)
endif()
