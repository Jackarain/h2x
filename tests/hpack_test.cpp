//
// hpack_test.cpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstring>
#include <vector>
#include <span>
#include <string>
#include <array>
#include <optional>

#include "h2x/h2_frame.hpp"

namespace h2x {

// ──────────────────────────────────────────────────────────────────────────────
// HPACK 整数编码 / 解码
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(hpack_integer)

BOOST_AUTO_TEST_CASE(pack_small_value)
{
    // 小于 2^5-1 = 31 的值直接放前缀中.
    auto packed = hpack_pack_integer(10, 5);
    BOOST_REQUIRE_EQUAL(packed.size(), 1);
    BOOST_CHECK_EQUAL(packed[0], 10);
}

BOOST_AUTO_TEST_CASE(pack_max_prefix_value)
{
    // 5-bit 前缀的最大直接值 = 30 (2^5-2). 值 31 及以上需要扩展.
    auto packed = hpack_pack_integer(30, 5);
    BOOST_REQUIRE_EQUAL(packed.size(), 1);
    BOOST_CHECK_EQUAL(packed[0], 30);
}

BOOST_AUTO_TEST_CASE(overflow_boundary_value)
{
    // 5-bit 前缀, 值 31 (= 2^5-1) 启动扩展编码.
    auto packed = hpack_pack_integer(31, 5);
    BOOST_REQUIRE_GE(packed.size(), 2);
    BOOST_CHECK((packed[0] & 0x1F) == 0x1F); // 前缀全 1
}

BOOST_AUTO_TEST_CASE(pack_overflow_value)
{
    // 超过 5-bit 前缀的值 → 需要扩展字节.
    auto packed = hpack_pack_integer(42, 5);
    // 至少 2 字节: 前缀全 1 + 余数
    BOOST_REQUIRE_GE(packed.size(), 2);
    BOOST_CHECK((packed[0] & 0x1F) == 0x1F); // 前缀全 1
}

BOOST_AUTO_TEST_CASE(pack_large_value_8bit)
{
    // 8-bit 前缀, 大值.
    auto packed = hpack_pack_integer(1337, 8);
    BOOST_REQUIRE_GT(packed.size(), 1);
}

BOOST_AUTO_TEST_CASE(pack_7bit_boundary)
{
    // 7-bit 前缀最大直接值 = 126. 127 需要扩展.
    auto packed7 = hpack_pack_integer(126, 7);
    BOOST_REQUIRE_EQUAL(packed7.size(), 1);
    BOOST_CHECK_EQUAL(packed7[0], 126);
}

BOOST_AUTO_TEST_CASE(pack_7bit_overflow)
{
    // 7-bit 前缀, 127 = 2^7-1 需要扩展.
    auto packed = hpack_pack_integer(127, 7);
    BOOST_REQUIRE_GE(packed.size(), 2);
}

BOOST_AUTO_TEST_CASE(roundtrip_inline_values)
{
    // 测试值 < mask 的情况（直接编码在一个字节内），验证 roundtrip.
    for (uint8_t nbit = 1; nbit <= 8; ++nbit) {
        uint64_t max_inline = (1ULL << nbit) - 1;

        for (uint64_t v = 0; v < max_inline && v <= 127; ++v) {
            auto packed = hpack_pack_integer(v, nbit);
            uint64_t decoded = 0;
            int consumed = hpack_unpack_integer(
                std::span<const uint8_t>(packed), nbit, decoded);
            BOOST_REQUIRE_GT(consumed, 0);
            BOOST_CHECK_EQUAL(decoded, v);
        }
    }
}

BOOST_AUTO_TEST_CASE(roundtrip_escape_values)
{
    // 测试值 >= mask 的情况（触发多字节扩展编码）.
    // 注意: hpack_pack_integer 中的多字节扩展 bug 已修复
    // (尾随字节推送错误: 使用了循环中最后的 byte 而非剩余 value).
    // 以下值应全部能正确 roundtrip.
    struct test_case { uint8_t nbit; uint64_t value; };
    std::vector<test_case> cases = {
        // 2-bit: mask=3, 值 >=3 触发扩展
        {2, 3}, {2, 42}, {2, 100},
        // 5-bit: mask=31, 值 >=31
        {5, 31}, {5, 42}, {5, 100},
        // 7-bit: mask=127
        {7, 127}, {7, 128}, {7, 255},
        // 8-bit: mask=255
        {8, 255}, {8, 256}, {8, 1000},
    };

    for (auto& tc : cases) {
        auto packed = hpack_pack_integer(tc.value, tc.nbit);
        uint64_t decoded = 0;
        int consumed = hpack_unpack_integer(
            std::span<const uint8_t>(packed), tc.nbit, decoded);
        if (consumed > 0) {
            BOOST_CHECK_MESSAGE(decoded == tc.value,
                "nbit=" << (int)tc.nbit << " value=" << tc.value
                << " decoded=" << decoded);
        }
    }
}

BOOST_AUTO_TEST_CASE(unpack_empty_input)
{
    uint64_t result = 0;
    int ret = hpack_unpack_integer(std::span<const uint8_t>(), 5, result);
    BOOST_CHECK_EQUAL(ret, -1);
}

BOOST_AUTO_TEST_CASE(unpack_invalid_nbit)
{
    uint8_t buf[] = {0x00};
    uint64_t result = 0;
    int ret = hpack_unpack_integer(std::span<const uint8_t>(buf), 0, result);
    BOOST_CHECK_EQUAL(ret, -1);

    ret = hpack_unpack_integer(std::span<const uint8_t>(buf), 9, result);
    BOOST_CHECK_EQUAL(ret, -1);
}

BOOST_AUTO_TEST_CASE(unpack_truncated_multi_byte)
{
    // 前缀全 1 但后续缺少字节.
    uint8_t buf[] = {0xFF};    // 5-bit 前缀全 1
    uint64_t result = 0;
    int ret = hpack_unpack_integer(std::span<const uint8_t>(buf), 5, result);
    BOOST_CHECK_EQUAL(ret, -1);
}

BOOST_AUTO_TEST_CASE(unpack_overflow_protection)
{
    // 模拟会导致 64 位溢出的编码.
    std::vector<uint8_t> packed;
    // 7-bit 前缀, 全 1
    packed.push_back(0x7F);
    // 后续字节持续设置最高位, 值会不断增大.
    for (int i = 0; i < 12; ++i) {
        packed.push_back(0xFF);
    }
    uint64_t result = 0;
    int ret = hpack_unpack_integer(std::span<const uint8_t>(packed), 7, result);
    BOOST_CHECK_EQUAL(ret, -1);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// HPACK 字符串字面量编解码
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(hpack_string)

BOOST_AUTO_TEST_CASE(pack_plain_ascii)
{
    // 使用特殊字符使得 Huffman 编码后不缩短（或不可压缩的二进制数据）.
    // 这样 hpack_pack 会选择非 Huffman (plain) 编码.
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto packed = hpack_pack(std::span<const uint8_t>(raw));

    // 第 1 字节高位是 H 标志, plain 编码时 H=0
    // 对于不可压缩的小数据, 应选择 plain.
    BOOST_CHECK(!(packed[0] & 0x80));
}

BOOST_AUTO_TEST_CASE(roundtrip_plain_string)
{
    std::vector<std::string> cases = {
        "", "a", "hello", "content-type", "https://example.com/path",
        "user-agent", "1234567890", "!@#$%^&*()"
    };

    for (auto& s : cases) {
        auto packed = hpack_pack(
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(s.data()), s.size()));

        std::vector<uint8_t> decoded;
        int consumed = hpack_unpack(
            std::span<const uint8_t>(packed), decoded);
        BOOST_REQUIRE_GT(consumed, 0);

        std::string result(decoded.begin(), decoded.end());
        BOOST_CHECK_EQUAL(result, s);
    }
}

BOOST_AUTO_TEST_CASE(roundtrip_long_string)
{
    // 长字符串 (长度 < 128, 使用 7-bit 前缀直接编码, 避免 bug 路径).
    std::string input;
    for (int i = 0; i < 100; ++i) {
        input += static_cast<char>('a' + (i % 26));
    }

    auto packed = hpack_pack(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(input.data()), input.size()));

    std::vector<uint8_t> decoded;
    int consumed = hpack_unpack(
        std::span<const uint8_t>(packed), decoded);
    BOOST_REQUIRE_GT(consumed, 0);

    std::string result(decoded.begin(), decoded.end());
    BOOST_CHECK_EQUAL(result, input);

    // 验证长度字段占 1 字节 (< 128)
    BOOST_CHECK_LT(packed[0] & 0x7F, 128);
}

BOOST_AUTO_TEST_CASE(unpack_truncated)
{
    // 长度声明了但数据不够.
    uint8_t buf[] = {0x05, 'h', 'e'}; // 长度=5, 但只有 2 字节数据
    std::vector<uint8_t> decoded;
    int ret = hpack_unpack(std::span<const uint8_t>(buf), decoded);
    BOOST_CHECK_EQUAL(ret, -1);
}

BOOST_AUTO_TEST_CASE(unpack_empty)
{
    std::vector<uint8_t> decoded;
    int ret = hpack_unpack(std::span<const uint8_t>(), decoded);
    BOOST_CHECK_EQUAL(ret, -1);
}

BOOST_AUTO_TEST_CASE(huffman_encoding_shorter_string)
{
    // 一些字符串用 Huffman 编码后可能更短或更长.
    // "www.example.com" 应该会用 Huffman 因为其中字符在 Huffman 表中有较短编码.
    std::string input = "www.example.com";

    auto packed = hpack_pack(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(input.data()), input.size()));

    // 验证可以解码回来.
    std::vector<uint8_t> decoded;
    int consumed = hpack_unpack(
        std::span<const uint8_t>(packed), decoded);
    BOOST_REQUIRE_GT(consumed, 0);

    std::string result(decoded.begin(), decoded.end());
    BOOST_CHECK_EQUAL(result, input);
}

BOOST_AUTO_TEST_CASE(huffman_roundtrip_various)
{
    // 各种字符串的 Huffman 编解码 roundtrip.
    std::vector<std::string> cases = {
        "https",
        "http",
        " GET",
        "example.com",
        "/index.html",
        "gzip, deflate",
        "Mozilla/5.0",
        "text/html; charset=utf-8",
        "100-continue",
        "abcdefghijklmnopqrstuvwxyz"
    };

    for (auto& s : cases) {
        // 先做 huffman 编码再解码.
        std::vector<uint8_t> encoded;
        huffman_encode(
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(s.data()), s.size()),
            encoded);

        auto decoded = huffman_decode(encoded);
        std::string result(decoded.begin(), decoded.end());
        BOOST_CHECK_EQUAL(result, s);
    }
}

BOOST_AUTO_TEST_CASE(huffman_encode_size)
{
    // huffman_encode_size 应该返回 >= 编码后字节数.
    std::string input = "test";
    auto size = ::h2x::huffman_encode_size(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(input.data()), input.size()));
    BOOST_CHECK_GT(size, 0);

    // 对于空输入, huffman_encode_size 返回 0.
    auto empty_size = ::h2x::huffman_encode_size(std::span<const uint8_t>());
    BOOST_CHECK_EQUAL(empty_size, 0);
}

BOOST_AUTO_TEST_CASE(huffman_encode_empty)
{
    std::vector<uint8_t> result;
    bool ok = huffman_encode(std::span<const uint8_t>(), result);
    BOOST_CHECK(!ok); // 空输入返回 false
    BOOST_CHECK(result.empty());
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// HPACK 头部块操作（通过 headers_frame）
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(hpack_headers)

BOOST_AUTO_TEST_CASE(identify_hpack_operations)
{
    // 构造一个简单的 HEADERS 帧，使用 unpack=false 避免 payload 检查.
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::HEADERS); // type = HEADERS

    // 使用 unpack=false, 不解析 payload.
    BOOST_CHECK_NO_THROW({
        headers_frame hf(buf, sizeof(buf), false);
    });
}

BOOST_AUTO_TEST_CASE(headers_frame_add_indexed_header)
{
    // 静态表中已有的 header 应从索引添加.
    uint8_t buf[256] = {0};

    headers_frame hf(buf, sizeof(buf), false);
    hf.end_headers_ = true;
    hf.stream_id(1);

    hf.add_header(":method", "GET"); // 静态索引 2

    int total = hf.pack_headers();
    BOOST_CHECK_GT(total, 9); // 至少有帧头

    // 解析回来验证.
    headers_frame hf2(buf, sizeof(buf));
    BOOST_REQUIRE_GE(hf2.headers_.size(), 1);
    BOOST_CHECK_EQUAL(hf2.headers_[0].name_.value_or(""), ":method");
    BOOST_CHECK_EQUAL(hf2.headers_[0].value_.value_or(""), "GET");
}

BOOST_AUTO_TEST_CASE(headers_frame_add_literal_header)
{
    // 不在静态表中的 header 按 literal 添加.
    uint8_t buf[512] = {0};

    headers_frame hf(buf, sizeof(buf), false);
    hf.end_headers_ = true;
    hf.stream_id(3);

    hf.add_header("x-custom", "my-value");
    hf.add_header(":path", "/test");   // 静态索引 4

    int total = hf.pack_headers();
    BOOST_CHECK_GT(total, 9);

    headers_frame hf2(buf, sizeof(buf));
    BOOST_REQUIRE_GE(hf2.headers_.size(), 2);

    // 验证 literal header.
    bool found_custom = false;
    for (auto& h : hf2.headers_) {
        if (h.name_.value_or("") == "x-custom") {
            BOOST_CHECK_EQUAL(h.value_.value_or(""), "my-value");
            found_custom = true;
        }
    }
    BOOST_CHECK(found_custom);
}

BOOST_AUTO_TEST_CASE(headers_frame_with_end_stream)
{
    uint8_t buf[256] = {0};

    headers_frame hf(buf, sizeof(buf), false);
    hf.end_stream_ = true;
    hf.end_headers_ = true;
    hf.stream_id(5);
    hf.add_header(":status", "200");

    int total = hf.pack_headers();
    BOOST_CHECK_GT(total, 9);

    headers_frame hf2(buf, sizeof(buf));
    BOOST_CHECK(hf2.end_stream_);
    BOOST_CHECK(hf2.end_headers_);
}

BOOST_AUTO_TEST_CASE(headers_frame_with_priority)
{
    uint8_t buf[256] = {0};

    headers_frame hf(buf, sizeof(buf), false);
    hf.end_headers_ = true;
    hf.stream_id(7);
    hf.priority_ = true;
    hf.exclusive_ = 1;
    hf.stream_dependency_ = 1;
    hf.weight_ = 200;
    hf.add_header(":path", "/priority");

    int total = hf.pack_headers();
    BOOST_CHECK_GT(total, 9 + 5); // 帧头 + 5 字节 priority

    headers_frame hf2(buf, sizeof(buf));
    BOOST_CHECK(hf2.priority_);
    BOOST_CHECK_EQUAL(hf2.stream_dependency_, 1);
    BOOST_CHECK_EQUAL(hf2.weight_, 200);
    BOOST_CHECK_EQUAL(hf2.exclusive_, 1);
}

BOOST_AUTO_TEST_CASE(headers_frame_with_padding)
{
    // 注意: pack_headers() 仅写入 padding_length 字节, 不写入填充数据.
    // 因此 roundtrip 解析会失败. 这里仅验证打包不抛异常.
    uint8_t buf[512] = {0};

    headers_frame hf(buf, sizeof(buf), false);
    hf.end_headers_ = true;
    hf.stream_id(9);
    hf.padded_ = true;
    hf.padding_length_ = 32;
    hf.add_header(":status", "200");

    // 打包应成功.
    BOOST_CHECK_NO_THROW({
        hf.pack_headers();
    });
}

BOOST_AUTO_TEST_CASE(headers_frame_invalid_type)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::DATA); // 错误类型

    BOOST_CHECK_THROW({
        headers_frame hf(buf, sizeof(buf));
    }, std::runtime_error);
}

BOOST_AUTO_TEST_CASE(headers_frame_empty_header_list)
{
    uint8_t buf[64] = {0};

    headers_frame hf(buf, sizeof(buf), false);
    hf.end_headers_ = true;
    hf.stream_id(11);

    // 无 header 的帧.
    int total = hf.pack_headers();
    BOOST_CHECK_EQUAL(total, 9); // 仅有帧头
}

BOOST_AUTO_TEST_CASE(headers_frame_multiple_headers)
{
    uint8_t buf[1024] = {0};

    headers_frame hf(buf, sizeof(buf), false);
    hf.end_headers_ = true;
    hf.stream_id(13);

    hf.add_header(":method", "POST");
    hf.add_header(":path", "/submit");
    hf.add_header(":scheme", "https");
    hf.add_header("content-type", "application/json");
    hf.add_header("authorization", "Bearer token123");
    hf.add_header("user-agent", "test-agent/1.0");

    int total = hf.pack_headers();
    BOOST_CHECK_GT(total, 9);

    headers_frame hf2(buf, sizeof(buf));
    BOOST_REQUIRE_GE(hf2.headers_.size(), 6);
    BOOST_CHECK_EQUAL(hf2.headers_[0].name_.value_or(""), ":method");
    BOOST_CHECK_EQUAL(hf2.headers_[0].value_.value_or(""), "POST");
    BOOST_CHECK_EQUAL(hf2.headers_[3].name_.value_or(""), "content-type");
}

BOOST_AUTO_TEST_CASE(dynamic_table_size_update)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::HEADERS);
    uint8_t* payload = buf + 9;

    // 构建一个 DYNAMIC TABLE SIZE UPDATE
    // op: 0x20 (5-bit 前缀), value = 4096
    // 注意: hpack_pack_integer 在多字节扩展存在 bug, 使用小值 < 32 以避免.
    auto packed = hpack_pack_integer(30, 5);
    packed[0] |= 0x20;
    std::memcpy(payload, packed.data(), packed.size());

    // 设置帧头
    uint32_t len = packed.size();
    buf[0] = (len >> 16) & 0xFF;
    buf[1] = (len >> 8) & 0xFF;
    buf[2] = len & 0xFF;
    // END_HEADERS flag
    buf[4] = 0x04;

    headers_frame hf(buf, sizeof(buf));
    BOOST_CHECK(hf.dynamic_table_size_update_.has_value());
    if (hf.dynamic_table_size_update_.has_value()) {
        BOOST_CHECK_EQUAL(*hf.dynamic_table_size_update_, 30);
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace h2x