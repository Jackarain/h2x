#
# fuzz/CMakeLists.txt
# ~~~~~~~~~~~~~~~~~~~~
#
# Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
#
# Distributed under the Boost Software License, Version 1.0. (See accompanying
# file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#

# Fuzz targets for h2x.
#
# Build with libFuzzer (Linux / Clang):
#   mkdir -p build/fuzz && cd build/fuzz
#   cmake -DENABLE_BUILD_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ ../..
#   make fuzz_frames fuzz_hpack
#
# Build in standalone mode (macOS / any compiler):
#   mkdir -p build/fuzz && cd build/fuzz
#   cmake -DENABLE_BUILD_FUZZ=ON -DSTANDALONE_FUZZER=ON ../..
#   make fuzz_frames fuzz_hpack
#
# Run:
#   ./bin/fuzz_frames fuzz/corpora/fuzz_frames

cmake_minimum_required(VERSION 3.16)

# The h2x target is already defined by the parent CMakeLists.txt.
# We only need the headers available.
set(H2X_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")

# Option: build without libFuzzer (standalone driver mode).
option(STANDALONE_FUZZER
    "Build with standalone fuzz driver (no libFuzzer dependency)" OFF)

# --- helper: define a fuzz executable ---
function(add_h2x_fuzz TARGET SOURCE)
    add_executable(${TARGET} ${SOURCE})

    target_include_directories(${TARGET} PRIVATE
        ${H2X_SOURCE_DIR}/h2x/include
        ${H2X_SOURCE_DIR}/third_party
    )

    if(STANDALONE_FUZZER)
        target_compile_definitions(${TARGET} PRIVATE STANDALONE_FUZZER)
        target_sources(${TARGET} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/fuzz_main.cc)
        target_link_libraries(${TARGET} PRIVATE h2x)
    else()
        # libFuzzer mode.
        target_compile_options(${TARGET} PRIVATE -fsanitize=fuzzer,address)
        target_link_options(${TARGET} PRIVATE -fsanitize=fuzzer,address)
        target_link_libraries(${TARGET} PRIVATE h2x)
    endif()

    set_target_properties(${TARGET} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endfunction()

# -------------------------------------------------------------------
# fuzz_frames — exercises every frame parser + HPACK free functions
# -------------------------------------------------------------------
add_h2x_fuzz(fuzz_frames fuzz_frames.cc)

# -------------------------------------------------------------------
# fuzz_hpack — targeted HPACK integer / string / Huffman decoder
# -------------------------------------------------------------------
add_h2x_fuzz(fuzz_hpack fuzz_hpack.cc)