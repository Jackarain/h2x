//
// fuzz_hpack.cc
// ~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Targeted fuzzer for HPACK integer/string/Huffman decoding routines.
//
// These functions return error codes (-1) on invalid input rather than
// throwing exceptions, making them ideal for fuzz-testing edge cases:
// overflow protection, truncated multi-byte integers, malformed Huffman
// padding, etc.
//
// Build:
//   clang++ -std=c++20 -fsanitize=fuzzer,address \
//     -I../h2x/include -I../third_party \
//     fuzz_hpack.cc -o fuzz_hpack
//
// Run:
//   ./fuzz_hpack -max_len=4096 corpus_hpack
//

#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <span>
#include <exception>
#include <stdexcept>

#include "h2x/h2_frame.hpp"

// -----------------------------------------------------------------------
//  Guard
// -----------------------------------------------------------------------
template <typename Fn>
static void try_invoke(Fn&& fn) noexcept {
    try {
        fn();
    } catch (const std::exception&) {
    } catch (...) {
    }
}

// -----------------------------------------------------------------------
//  HPACK integer decoding
// -----------------------------------------------------------------------
static void fuzz_hpack_integer(std::span<const uint8_t> data) {
    // Exercises every valid nbit value.
    for (uint8_t nbit = 1; nbit <= 8; ++nbit) {
        try_invoke([&] {
            uint64_t result = 0;
            h2x::hpack_unpack_integer(data, nbit, result);
        });
    }

    // Edge: nbit = 0 and nbit = 9 (both should return -1).
    try_invoke([&] {
        uint64_t result = 0;
        h2x::hpack_unpack_integer(data, 0, result);
    });
    try_invoke([&] {
        uint64_t result = 0;
        h2x::hpack_unpack_integer(data, 9, result);
    });

    // Round-trip: pack then unpack every byte-derived value.
    if (!data.empty()) {
        const uint64_t val = data[0];
        for (uint8_t nbit = 1; nbit <= 8; ++nbit) {
            try_invoke([&] {
                auto packed = h2x::hpack_pack_integer(val, nbit);
                uint64_t decoded = 0;
                int consumed = h2x::hpack_unpack_integer(
                    std::span<const uint8_t>(packed), nbit, decoded);
                // consumed should always be > 0 for our own output.
                (void)consumed;
            });
        }
    }

    // Edge: large-value packing + unpacking (triggers multi-byte extension).
    if (data.size() >= 2) {
        const uint64_t val =
            (static_cast<uint64_t>(data[0]) << 8) | data[1];
        for (uint8_t nbit = 1; nbit <= 8; ++nbit) {
            try_invoke([&] {
                auto packed = h2x::hpack_pack_integer(val, nbit);
                uint64_t decoded = 0;
                h2x::hpack_unpack_integer(
                    std::span<const uint8_t>(packed), nbit, decoded);
            });
        }
    }

    // Large value that may overflow.
    if (data.size() >= 8) {
        uint64_t big_val = 0;
        std::memcpy(&big_val, data.data(), 8);
        for (uint8_t nbit = 1; nbit <= 8; ++nbit) {
            try_invoke([&] {
                auto packed = h2x::hpack_pack_integer(big_val, nbit);
                uint64_t decoded = 0;
                h2x::hpack_unpack_integer(
                    std::span<const uint8_t>(packed), nbit, decoded);
            });
        }
    }
}

// -----------------------------------------------------------------------
//  HPACK string decoding (length-prefixed, optional Huffman)
// -----------------------------------------------------------------------
static void fuzz_hpack_string(std::span<const uint8_t> data) {
    // hpack_unpack decodes the length prefix then the string body.
    try_invoke([&] {
        std::vector<uint8_t> result;
        h2x::hpack_unpack(data, result);
    });

    // Round-trip: pack arbitrary data and decode it back.
    try_invoke([&] {
        auto packed = h2x::hpack_pack(data);
        std::vector<uint8_t> result;
        int consumed = h2x::hpack_unpack(
            std::span<const uint8_t>(packed), result);
        (void)consumed;
    });
}

// -----------------------------------------------------------------------
//  Raw Huffman decode
// -----------------------------------------------------------------------
static void fuzz_huffman(std::span<const uint8_t> data) {
    // Decode arbitrary bytes as Huffman.
    try_invoke([&] {
        auto result = h2x::huffman_decode(data);
        (void)result.size();
    });

    // Encode then decode round-trip.
    try_invoke([&] {
        std::vector<uint8_t> enc;
        if (h2x::huffman_encode(data, enc)) {
            auto dec = h2x::huffman_decode(std::span<const uint8_t>(enc));
            (void)dec.size();
        }
    });

    // huffman_encode_size is a simple length estimator.
    try_invoke([&] {
        (void)h2x::huffman_encode_size(data);
    });
}

// -----------------------------------------------------------------------
//  HPACK index lookup
// -----------------------------------------------------------------------
static void fuzz_hpack_index(std::span<const uint8_t> data) {
    if (data.empty())
        return;

    // Static table indices: 1-61
    uint32_t idx = (data[0] % 128) + 1;  // 1..128
    try_invoke([&] { (void)h2x::hpack_index_to_frame(idx); });

    // Out of range: above dynamic table.
    try_invoke([&] { (void)h2x::hpack_index_to_frame(2000u); });
    try_invoke([&] { (void)h2x::hpack_index_to_frame(9999u); });

    // Zero and near-zero.
    try_invoke([&] { (void)h2x::hpack_index_to_frame(0u); });
    try_invoke([&] { (void)h2x::hpack_index_to_frame(61u); });
    try_invoke([&] { (void)h2x::hpack_index_to_frame(62u); });
}

// -----------------------------------------------------------------------
//  Fuzzer entry point
// -----------------------------------------------------------------------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const auto span = std::span<const uint8_t>(data, size);

    fuzz_hpack_integer(span);
    fuzz_hpack_string(span);
    fuzz_huffman(span);
    fuzz_hpack_index(span);

    return 0;
}