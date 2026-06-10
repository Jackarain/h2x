//
// fuzz_frames.cc
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Fuzz harness for h2x HTTP/2 frame parsing.
//
// Exercises every frame parser (DATA, HEADERS, PRIORITY, RST_STREAM,
// SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION)
// as well as the HPACK free functions (integer decode, string decode,
// Huffman decode) on fuzzer-supplied payloads.
//
// Build:
//   clang++ -std=c++20 -fsanitize=fuzzer,address \
//     -I../h2x/include -I../third_party \
//     fuzz_frames.cc -o fuzz_frames
//
// Run:
//   ./fuzz_frames -max_len=16384 corpus_frames
//

#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <exception>
#include <stdexcept>
#include <span>

#include "h2x/h2_frame.hpp"

// -----------------------------------------------------------------------
//  Guard — wrap every frame/HPACK call so no exception escapes the fuzzer.
// -----------------------------------------------------------------------
template <typename Fn>
static void try_invoke(Fn&& fn) noexcept {
    try {
        fn();
    } catch (const std::exception&) {
        // All frame parsers throw std::runtime_error on invalid input;
        // that is expected behaviour, not a crash.
    } catch (...) {
        // Unknown exception type — still not a crash.
    }
}

// -----------------------------------------------------------------------
//  Frame parser fuzzing
// -----------------------------------------------------------------------
static void fuzz_frame_codec(std::span<const uint8_t> data) {
    if (data.size() < 9)
        return;

    // We need mutable buffers because frame_codec also has setters.
    // Make a writable copy for each parser attempt.
    auto buf = std::vector<uint8_t>(data.begin(), data.end());
    uint8_t* const raw = buf.data();
    const size_t len = buf.size();

    // ----- base frame_codec -----
    try_invoke([&] {
        h2x::frame_codec fc(raw, len);
        (void)fc.type();
        (void)fc.flags();
        (void)fc.stream_id();
        (void)fc.payload_size();
        (void)fc.frame_size();
        (void)fc.payload();            // just pointer arithmetic
    });

    // ----- DATA frame -----
    try_invoke([&] {
        auto cpy = buf;
        cpy[3] = static_cast<uint8_t>(h2x::frame_type::DATA);
        h2x::data_frame f(cpy.data(), cpy.size());
        (void)f.get_data();
        (void)f.is_end_stream();
        (void)f.get_pad_length();
    });

    // ----- HEADERS frame (most complex — includes HPACK) -----
    try_invoke([&] {
        auto cpy = buf;
        cpy[3] = static_cast<uint8_t>(h2x::frame_type::HEADERS);
        h2x::headers_frame f(cpy.data(), cpy.size());
    });

    // ----- PRIORITY frame -----
    try_invoke([&] {
        auto cpy = buf;
        cpy[3] = static_cast<uint8_t>(h2x::frame_type::PRIORITY);
        h2x::priority_frame f(cpy.data(), cpy.size());
        (void)f.get_depends_on();
        (void)f.get_weight();
        (void)f.is_exclusive();
    });

    // ----- RST_STREAM frame -----
    try_invoke([&] {
        auto cpy = buf;
        cpy[3] = static_cast<uint8_t>(h2x::frame_type::RST_STREAM);
        h2x::rst_stream_frame f(cpy.data(), cpy.size());
        (void)f.get_error_code();
    });

    // ----- SETTINGS frame -----
    try_invoke([&] {
        auto cpy = buf;
        cpy[3] = static_cast<uint8_t>(h2x::frame_type::SETTINGS);
        h2x::settings_frame f(cpy.data(), cpy.size());
        (void)f.ack_;
        (void)f.entries_.size();
    });

    // ----- PUSH_PROMISE frame -----
    try_invoke([&] {
        auto cpy = buf;
        cpy[3] = static_cast<uint8_t>(h2x::frame_type::PUSH_PROMISE);
        h2x::push_promise_frame f(cpy.data(), cpy.size());
        (void)f.get_promised_stream_id();
        (void)f.get_header_block_fragment();
        (void)f.is_end_headers();
        (void)f.get_pad_length();
    });

    // ----- PING frame -----
    try_invoke([&] {
        auto cpy = buf;
        cpy[3] = static_cast<uint8_t>(h2x::frame_type::PING);
        h2x::ping_frame f(cpy.data(), cpy.size());
        (void)f.get_opaque_data();
        (void)f.is_ack();
    });

    // ----- GOAWAY frame -----
    try_invoke([&] {
        auto cpy = buf;
        cpy[3] = static_cast<uint8_t>(h2x::frame_type::GOAWAY);
        h2x::goaway_frame f(cpy.data(), cpy.size());
        (void)f.get_last_stream_id();
        (void)f.get_error_code();
        (void)f.get_debug_data();
    });

    // ----- WINDOW_UPDATE frame -----
    try_invoke([&] {
        auto cpy = buf;
        cpy[3] = static_cast<uint8_t>(h2x::frame_type::WINDOW_UPDATE);
        h2x::window_update_frame f(cpy.data(), cpy.size());
        (void)f.get_window_increment();
    });

    // ----- CONTINUATION frame -----
    try_invoke([&] {
        auto cpy = buf;
        cpy[3] = static_cast<uint8_t>(h2x::frame_type::CONTINUATION);
        h2x::continuation_frame f(cpy.data(), cpy.size());
        (void)f.get_header_block_fragment();
        (void)f.is_end_headers();
    });

    // ----- Frame-level validation helpers -----
    try_invoke([&] {
        h2x::frame_codec::check_stream_id(
            (static_cast<uint32_t>(raw[5] & 0x7F) << 24) |
            (static_cast<uint32_t>(raw[6]) << 16) |
            (static_cast<uint32_t>(raw[7]) << 8) |
            static_cast<uint32_t>(raw[8]));
    });
    try_invoke([&] {
        h2x::frame_codec::check_frame_length(
            (static_cast<uint32_t>(raw[0]) << 16) |
            (static_cast<uint32_t>(raw[1]) << 8) |
            static_cast<uint32_t>(raw[2]));
    });
}

// -----------------------------------------------------------------------
//  HPACK free-function fuzzing
// -----------------------------------------------------------------------
static void fuzz_hpack_free_functions(std::span<const uint8_t> data) {
    // ---- hpack_unpack_integer with all valid nbit values ----
    for (uint8_t nbit = 1; nbit <= 8; ++nbit) {
        try_invoke([&] {
            uint64_t result = 0;
            h2x::hpack_unpack_integer(data, nbit, result);
        });
    }

    // ---- hpack_unpack (string decode, includes Huffman) ----
    try_invoke([&] {
        std::vector<uint8_t> result;
        h2x::hpack_unpack(data, result);
    });

    // ---- huffman_decode on arbitrary bytes ----
    try_invoke([&] {
        auto result = h2x::huffman_decode(data);
        (void)result.size();
    });

    // ---- hpack_index_to_frame on various indices derived from data ----
    if (!data.empty()) {
        uint32_t idx = data[0];
        try_invoke([&] { (void)h2x::hpack_index_to_frame(idx); });

        // Also try some larger indices near the dynamic-table boundary.
        try_invoke([&] { (void)h2x::hpack_index_to_frame(62u); });
        try_invoke([&] { (void)h2x::hpack_index_to_frame(100u); });
        try_invoke([&] { (void)h2x::hpack_index_to_frame(2000u); });
    }

    // ---- hpack_pack / hpack_pack_integer round-trip ----
    try_invoke([&] {
        auto packed = h2x::hpack_pack(data);
        // Decode what we just packed (should always succeed).
        std::vector<uint8_t> decoded;
        h2x::hpack_unpack(std::span<const uint8_t>(packed), decoded);
    });

    // ---- hpack_pack_integer with various values from fuzz data ----
    if (data.size() >= 4) {
        uint64_t val = 0;
        for (int i = 0; i < 4 && i < (int)data.size(); ++i)
            val = (val << 8) | data[i];

        for (uint8_t nbit = 1; nbit <= 8; ++nbit) {
            try_invoke([&] {
                auto packed = h2x::hpack_pack_integer(val, nbit);
                uint64_t decoded = 0;
                h2x::hpack_unpack_integer(
                    std::span<const uint8_t>(packed), nbit, decoded);
            });
        }
    }

    // ---- huffman_encode_size / huffman_encode ----
    try_invoke([&] {
        (void)h2x::huffman_encode_size(data);
    });
    try_invoke([&] {
        std::vector<uint8_t> enc;
        h2x::huffman_encode(data, enc);
    });
}

// -----------------------------------------------------------------------
//  Fuzzer entry point
// -----------------------------------------------------------------------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const auto span = std::span<const uint8_t>(data, size);

    fuzz_frame_codec(span);
    fuzz_hpack_free_functions(span);

    return 0;  // Non-zero return values are reserved by libFuzzer.
}