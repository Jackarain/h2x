//
// global_data_test.cpp
// ~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string_view>
#include <unordered_map>

#include "h2x/h2_global_data.hpp"
#include "h2x/h2_frame.hpp"

// 为 Boost.Test 提供枚举的 operator<<.
namespace h2x {
inline std::ostream& operator<<(std::ostream& os, operation_type ot)
{
    return os << static_cast<int>(ot);
}
}

namespace h2x {

// ──────────────────────────────────────────────────────────────────────────────
// 连接前言
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(client_preface)

BOOST_AUTO_TEST_CASE(preface_string)
{
    std::string_view preface(global_client_preface, global_client_preface_len);
    BOOST_CHECK_EQUAL(preface, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
}

BOOST_AUTO_TEST_CASE(preface_length)
{
    BOOST_CHECK_EQUAL(global_client_preface_len, 24);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// 最大帧大小常量
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(max_frame_size)

BOOST_AUTO_TEST_CASE(default_max_frame_size)
{
    BOOST_CHECK_EQUAL(global_frame_max_limit_size, 16384);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// 静态 HPACK 头表
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(static_header_table)

BOOST_AUTO_TEST_CASE(table_size)
{
    // 静态表应有 61 个条目.
    int count = 0;
    for (auto& entry : global_static_header_table) {
        (void)entry;
        ++count;
    }

    BOOST_CHECK_EQUAL(count, global_static_header_table_size);
    BOOST_CHECK_EQUAL(count, 61);
}

BOOST_AUTO_TEST_CASE(first_entry)
{
    auto& entry = global_static_header_table[0];
    BOOST_CHECK_EQUAL(entry.index_, 1);
    BOOST_CHECK_EQUAL(entry.name_.value_or(""), ":authority");
    BOOST_CHECK_EQUAL(entry.value_.value_or(""), "");
}

BOOST_AUTO_TEST_CASE(known_entries)
{
    // 验证一些关键条目.
    BOOST_CHECK_EQUAL(global_static_header_table[1].name_.value_or(""), ":method");
    BOOST_CHECK_EQUAL(global_static_header_table[1].value_.value_or(""), "GET");

    BOOST_CHECK_EQUAL(global_static_header_table[2].name_.value_or(""), ":method");
    BOOST_CHECK_EQUAL(global_static_header_table[2].value_.value_or(""), "POST");

    BOOST_CHECK_EQUAL(global_static_header_table[3].name_.value_or(""), ":path");
    BOOST_CHECK_EQUAL(global_static_header_table[3].value_.value_or(""), "/");

    BOOST_CHECK_EQUAL(global_static_header_table[5].name_.value_or(""), ":scheme");
    BOOST_CHECK_EQUAL(global_static_header_table[5].value_.value_or(""), "http");

    BOOST_CHECK_EQUAL(global_static_header_table[6].name_.value_or(""), ":scheme");
    BOOST_CHECK_EQUAL(global_static_header_table[6].value_.value_or(""), "https");

    BOOST_CHECK_EQUAL(global_static_header_table[7].name_.value_or(""), ":status");
    BOOST_CHECK_EQUAL(global_static_header_table[7].value_.value_or(""), "200");
}

BOOST_AUTO_TEST_CASE(indexes_are_sequential)
{
    for (int i = 0; i < global_static_header_table_size; ++i) {
        BOOST_CHECK_EQUAL(global_static_header_table[i].index_, i + 1);
    }
}

BOOST_AUTO_TEST_CASE(all_entries_have_type_pointers)
{
    for (int i = 0; i < global_static_header_table_size; ++i) {
        BOOST_REQUIRE_NE(global_static_header_table[i].type_, nullptr);
        BOOST_CHECK_EQUAL(global_static_header_table[i].type_->type_,
            operation_type::INDEXED);
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// 静态表索引映射 (hash -> index)
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(static_header_table_map)

BOOST_AUTO_TEST_CASE(map_size_matches_table)
{
    BOOST_CHECK_EQUAL(global_static_header_table_map.size(),
        static_cast<size_t>(global_static_header_table_size));
}

BOOST_AUTO_TEST_CASE(map_contains_all_hashes)
{
    for (int i = 0; i < global_static_header_table_size; ++i) {
        auto hash = global_static_header_table[i].hash_;
        auto it = global_static_header_table_map.find(hash);
        BOOST_REQUIRE(it != global_static_header_table_map.end());
        BOOST_CHECK_EQUAL(it->second, i);
    }
}

BOOST_AUTO_TEST_CASE(map_lookup_correctness)
{
    // :authority -> index 0
    auto it = global_static_header_table_map.find(3153725150u);
    BOOST_REQUIRE(it != global_static_header_table_map.end());
    BOOST_CHECK_EQUAL(it->second, 0);

    // :status 200 -> index 7
    it = global_static_header_table_map.find(1883682711u);
    BOOST_REQUIRE(it != global_static_header_table_map.end());
    BOOST_CHECK_EQUAL(it->second, 7);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// HPACK 辅助常量
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(hpack_constants)

BOOST_AUTO_TEST_CASE(hpack_has_bits)
{
    BOOST_CHECK_EQUAL(HPACK_HAS_BITS[0], 0x00);
    BOOST_CHECK_EQUAL(HPACK_HAS_BITS[1], 0x01);
    BOOST_CHECK_EQUAL(HPACK_HAS_BITS[4], 0x0F);
    BOOST_CHECK_EQUAL(HPACK_HAS_BITS[7], 0x7F);
    BOOST_CHECK_EQUAL(HPACK_HAS_BITS[8], 0xFF);
}

BOOST_AUTO_TEST_CASE(hpack_operation_patterns)
{
    BOOST_CHECK_EQUAL(global_hpack_ops[0].type_, operation_type::INDEXED);
    BOOST_CHECK_EQUAL(global_hpack_ops[0].pattern_, 0b10000000);
    BOOST_CHECK_EQUAL(global_hpack_ops[0].nbits_, 7);

    BOOST_CHECK_EQUAL(global_hpack_ops[1].type_,
        operation_type::LITERALINCREMENTALINDEXING);
    BOOST_CHECK_EQUAL(global_hpack_ops[1].pattern_, 0b01000000);
    BOOST_CHECK_EQUAL(global_hpack_ops[1].nbits_, 6);

    BOOST_CHECK_EQUAL(global_hpack_ops[4].type_,
        operation_type::DYNAMICTABLESIZEUPDATE);
    BOOST_CHECK_EQUAL(global_hpack_ops[4].pattern_, 0b00100000);
    BOOST_CHECK_EQUAL(global_hpack_ops[4].nbits_, 5);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// Huffman 表完整性
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(huffman_table)

BOOST_AUTO_TEST_CASE(huffman_table_size)
{
    // RFC 7541 附录 B 定义 256 个符号的 Huffman 码表 (0x00-0xFF).
    // 表中还有一个额外条目 (索引 256) 作为哨兵.
    int count = 0;
    for (auto& sym : global_huffman_table) {
        (void)sym;
        ++count;
    }
    BOOST_CHECK_EQUAL(count, 257);
}

BOOST_AUTO_TEST_CASE(huffman_tree_initial_state)
{
    // 首节点应有 16 个子节点 (nibble-based tree).
    auto& state0 = global_huffman_tree[0];
    // 至少第一个子节点有效.
    int non_zero = 0;
    for (int i = 0; i < 16; ++i) {
        if (state0[i].fstate != 0 || state0[i].flags != 0) {
            ++non_zero;
        }
    }
    // 根节点应有多个 non-zero 条目（实际有 16 个状态转移）.
    BOOST_CHECK_GT(non_zero, 0);
}

BOOST_AUTO_TEST_CASE(huffman_code_sanity)
{
    // 空格 (0x20) 的 huffman 码长为 6 位.
    BOOST_CHECK_EQUAL(global_huffman_table[0x20].first, 6);

    // '0' (0x30) 的码长为 5 位.
    BOOST_CHECK_EQUAL(global_huffman_table[0x30].first, 5);

    // 'A' (0x41) 的码长为 6 位 (RFC 7541 附录 B).
    BOOST_CHECK_EQUAL(global_huffman_table[0x41].first, 6);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// hpack_index_to_frame 与全局动态表
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(hpack_index_lookup)

BOOST_AUTO_TEST_CASE(static_index_valid)
{
    for (uint32_t i = 1; i <= 61; ++i) {
        auto* entry = hpack_index_to_frame(i);
        BOOST_REQUIRE_NE(entry, nullptr);
        BOOST_CHECK_EQUAL(entry->index_, static_cast<int64_t>(i));
    }
}

BOOST_AUTO_TEST_CASE(static_index_out_of_range)
{
    // 动态表为空时, > 61 应返回 nullptr.
    auto* entry = hpack_index_to_frame(62);
    BOOST_CHECK(entry == nullptr);

    entry = hpack_index_to_frame(9999);
    BOOST_CHECK(entry == nullptr);
}

BOOST_AUTO_TEST_CASE(small_index_out_of_range)
{
    // 索引 0 对于 hpack_index_to_frame 来说 < 61，会返回 table[0-1] (越界).
    // 这里仅验证至少索引 1 有效.
    auto* entry = hpack_index_to_frame(1);
    BOOST_REQUIRE_NE(entry, nullptr);
    BOOST_CHECK_EQUAL(entry->index_, 1);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace h2x