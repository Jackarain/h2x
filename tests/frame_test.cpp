//
// frame_test.cpp
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
#include <string>
#include <stdexcept>

#include "h2x/h2_frame.hpp"

// 为 Boost.Test 提供枚举的 operator<< 以支持 BOOST_CHECK_EQUAL 输出.
namespace h2x {
inline std::ostream& operator<<(std::ostream& os, frame_type ft)
{
    return os << static_cast<int>(ft);
}
inline std::ostream& operator<<(std::ostream& os, rst_stream_error_code ec)
{
    return os << static_cast<int>(ec);
}
inline std::ostream& operator<<(std::ostream& os, goaway_error_code ec)
{
    return os << static_cast<int>(ec);
}
}

namespace h2x {

// ──────────────────────────────────────────────────────────────────────────────
// 基础帧编解码 (frame_codec)
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(frame_codec_basic)

BOOST_AUTO_TEST_CASE(construct_minimum_buffer)
{
    uint8_t buf[9] = {0};
    BOOST_CHECK_NO_THROW({
        frame_codec fc(buf, 9);
    });
}

BOOST_AUTO_TEST_CASE(construct_too_small_buffer)
{
    uint8_t buf[8] = {0};
    BOOST_CHECK_THROW({
        frame_codec fc(buf, 8);
    }, std::runtime_error);
}

BOOST_AUTO_TEST_CASE(read_write_type)
{
    uint8_t buf[64] = {0};
    frame_codec fc(buf, sizeof(buf));

    fc.type(frame_type::SETTINGS);
    BOOST_CHECK_EQUAL(fc.type(), frame_type::SETTINGS);

    fc.type(frame_type::HEADERS);
    BOOST_CHECK_EQUAL(fc.type(), frame_type::HEADERS);

    fc.type(frame_type::DATA);
    BOOST_CHECK_EQUAL(fc.type(), frame_type::DATA);

    fc.type(frame_type::GOAWAY);
    BOOST_CHECK_EQUAL(fc.type(), frame_type::GOAWAY);
}

BOOST_AUTO_TEST_CASE(read_write_stream_id)
{
    uint8_t buf[64] = {0};
    frame_codec fc(buf, sizeof(buf));

    fc.stream_id(0);
    BOOST_CHECK_EQUAL(fc.stream_id(), 0u);

    fc.stream_id(1);
    BOOST_CHECK_EQUAL(fc.stream_id(), 1u);

    fc.stream_id(0x7FFFFFFF);
    BOOST_CHECK_EQUAL(fc.stream_id(), 0x7FFFFFFFu);
}

BOOST_AUTO_TEST_CASE(read_write_flags)
{
    uint8_t buf[64] = {0};
    frame_codec fc(buf, sizeof(buf));

    fc.flags(0x00);
    BOOST_CHECK_EQUAL(fc.flags(), 0x00);

    fc.flags(0x01); // END_STREAM
    BOOST_CHECK_EQUAL(fc.flags(), 0x01);

    fc.flags(0x05); // END_STREAM | END_HEADERS
    BOOST_CHECK_EQUAL(fc.flags(), 0x05);
}

BOOST_AUTO_TEST_CASE(read_write_payload_size)
{
    uint8_t buf[64] = {0};
    frame_codec fc(buf, sizeof(buf));

    fc.payload_size(0);
    BOOST_CHECK_EQUAL(fc.payload_size(), 0u);

    fc.payload_size(100);
    BOOST_CHECK_EQUAL(fc.payload_size(), 100u);

    fc.payload_size(16384);
    BOOST_CHECK_EQUAL(fc.payload_size(), 16384u);
}

BOOST_AUTO_TEST_CASE(frame_size_calculation)
{
    uint8_t buf[64] = {0};
    frame_codec fc(buf, sizeof(buf));

    fc.payload_size(0);
    BOOST_CHECK_EQUAL(fc.frame_size(), 9u);

    fc.payload_size(100);
    BOOST_CHECK_EQUAL(fc.frame_size(), 109u);
}

BOOST_AUTO_TEST_CASE(payload_pointer)
{
    uint8_t buf[64] = {0};
    frame_codec fc(buf, sizeof(buf));

    uint8_t* p = fc.payload();
    BOOST_CHECK_EQUAL(p, buf + 9);
}

BOOST_AUTO_TEST_CASE(check_stream_id_valid)
{
    BOOST_CHECK(frame_codec::check_stream_id(0));
    BOOST_CHECK(frame_codec::check_stream_id(1));
    BOOST_CHECK(frame_codec::check_stream_id(0x7FFFFFFF));
}

BOOST_AUTO_TEST_CASE(check_stream_id_invalid)
{
    BOOST_CHECK(!frame_codec::check_stream_id(0x80000000));
    BOOST_CHECK(!frame_codec::check_stream_id(0xFFFFFFFF));
}

BOOST_AUTO_TEST_CASE(check_frame_length_valid)
{
    BOOST_CHECK(frame_codec::check_frame_length(0));
    BOOST_CHECK(frame_codec::check_frame_length(16384));
    BOOST_CHECK(frame_codec::check_frame_length(16384, 16384));
}

BOOST_AUTO_TEST_CASE(check_frame_length_invalid)
{
    BOOST_CHECK(!frame_codec::check_frame_length(16385, 16384));
    BOOST_CHECK(!frame_codec::check_frame_length(999999));
}

BOOST_AUTO_TEST_CASE(payload_read_write)
{
    uint8_t buf[64] = {0};
    frame_codec fc(buf, sizeof(buf));

    fc.payload_size(4);
    uint8_t test_data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    fc.payload(test_data, 4);

    uint8_t* p = fc.payload();
    BOOST_CHECK_EQUAL(p[0], 0xDE);
    BOOST_CHECK_EQUAL(p[1], 0xAD);
    BOOST_CHECK_EQUAL(p[2], 0xBE);
    BOOST_CHECK_EQUAL(p[3], 0xEF);
}

BOOST_AUTO_TEST_CASE(payload_write_overflow)
{
    uint8_t buf[64] = {0};
    frame_codec fc(buf, sizeof(buf));

    fc.payload_size(4);
    uint8_t large_data[10] = {0};
    BOOST_CHECK_THROW({
        fc.payload(large_data, 10);
    }, std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// DATA 帧
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(data_frame_tests)

BOOST_AUTO_TEST_CASE(pack_unpack_basic)
{
    uint8_t buf[128] = {0};

    data_frame df(buf, sizeof(buf), false);
    df.stream_id(1);
    df.type(frame_type::DATA);

    std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o'};
    df.set_data(payload);
    df.set_end_stream(true);

    int total = df.pack_payload();
    BOOST_CHECK_GT(total, 9);

    data_frame df2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(df2.stream_id(), 1u);
    BOOST_CHECK(df2.is_end_stream());

    auto data = df2.get_data();
    BOOST_REQUIRE_EQUAL(data.size(), 5);
    BOOST_CHECK_EQUAL(data[0], 'H');
    BOOST_CHECK_EQUAL(data[4], 'o');
}

BOOST_AUTO_TEST_CASE(pack_unpack_with_padding)
{
    uint8_t buf[256] = {0};

    data_frame df(buf, sizeof(buf), false);
    df.stream_id(3);
    df.type(frame_type::DATA);

    std::vector<uint8_t> payload = {'d', 'a', 't', 'a'};
    df.set_data(payload);
    df.set_pad_length(16);

    int total = df.pack_payload();
    BOOST_CHECK_GT(total, 9);

    data_frame df2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(df2.get_pad_length(), 16);
    auto data = df2.get_data();
    BOOST_CHECK_EQUAL(data.size(), 4);
}

BOOST_AUTO_TEST_CASE(end_stream_flag)
{
    uint8_t buf[64] = {0};

    data_frame df(buf, sizeof(buf), false);
    df.stream_id(5);
    df.type(frame_type::DATA);
    df.set_data(std::vector<uint8_t>{'x'});
    df.set_end_stream(true);

    int total = df.pack_payload();
    BOOST_CHECK_GT(total, 9);

    data_frame df2(buf, sizeof(buf));
    BOOST_CHECK(df2.is_end_stream());
}

BOOST_AUTO_TEST_CASE(empty_data)
{
    uint8_t buf[64] = {0};

    data_frame df(buf, sizeof(buf), false);
    df.stream_id(7);
    df.type(frame_type::DATA);

    int total = df.pack_payload();
    BOOST_CHECK_EQUAL(total, 9);

    data_frame df2(buf, sizeof(buf));
    BOOST_CHECK(df2.get_data().empty());
}

BOOST_AUTO_TEST_CASE(large_data)
{
    uint8_t buf[1024] = {0};

    data_frame df(buf, sizeof(buf), false);
    df.stream_id(9);
    df.type(frame_type::DATA);

    std::vector<uint8_t> payload(512, 'A');
    df.set_data(payload);

    int total = df.pack_payload();
    BOOST_CHECK_GT(total, 9);

    data_frame df2(buf, sizeof(buf));
    auto data = df2.get_data();
    BOOST_REQUIRE_EQUAL(data.size(), 512);
    BOOST_CHECK_EQUAL(data[0], 'A');
    BOOST_CHECK_EQUAL(data[511], 'A');
}

BOOST_AUTO_TEST_CASE(invalid_type)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::HEADERS);

    BOOST_CHECK_THROW({
        data_frame df(buf, sizeof(buf));
    }, std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// SETTINGS 帧
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(settings_frame_tests)

BOOST_AUTO_TEST_CASE(pack_unpack_settings)
{
    uint8_t buf[128] = {0};

    settings_frame sf(buf, sizeof(buf), false);
    sf.entries_.emplace_back(settings_id::SETTINGS_HEADER_TABLE_SIZE, 4096);
    sf.entries_.emplace_back(settings_id::SETTINGS_ENABLE_PUSH, 1);
    sf.entries_.emplace_back(settings_id::SETTINGS_MAX_CONCURRENT_STREAMS, 100);
    sf.entries_.emplace_back(settings_id::SETTINGS_INITIAL_WINDOW_SIZE, 65535);
    sf.entries_.emplace_back(settings_id::SETTINGS_MAX_FRAME_SIZE, 16384);

    int total = sf.pack_settings();
    BOOST_CHECK_GT(total, 9);

    settings_frame sf2(buf, sizeof(buf));
    BOOST_REQUIRE_EQUAL(sf2.entries_.size(), 5);
    BOOST_CHECK_EQUAL(sf2.entries_[0].identifier_,
        static_cast<uint16_t>(settings_id::SETTINGS_HEADER_TABLE_SIZE));
    BOOST_CHECK_EQUAL(sf2.entries_[0].value_, 4096u);
    BOOST_CHECK_EQUAL(sf2.entries_[4].identifier_,
        static_cast<uint16_t>(settings_id::SETTINGS_MAX_FRAME_SIZE));
    BOOST_CHECK_EQUAL(sf2.entries_[4].value_, 16384u);
}

BOOST_AUTO_TEST_CASE(ack_frame)
{
    uint8_t buf[64] = {0};

    settings_frame sf(buf, sizeof(buf), false);
    sf.ack_ = true;
    int total = sf.pack_settings();
    BOOST_CHECK_EQUAL(total, 9);

    settings_frame sf2(buf, sizeof(buf));
    BOOST_CHECK(sf2.ack_);
    BOOST_CHECK(sf2.entries_.empty());
}

BOOST_AUTO_TEST_CASE(invalid_type)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::DATA);

    BOOST_CHECK_THROW({
        settings_frame sf(buf, sizeof(buf));
    }, std::runtime_error);
}

BOOST_AUTO_TEST_CASE(empty_entries)
{
    uint8_t buf[64] = {0};

    settings_frame sf(buf, sizeof(buf), false);
    int total = sf.pack_settings();
    BOOST_CHECK_EQUAL(total, 9);

    settings_frame sf2(buf, sizeof(buf));
    BOOST_CHECK(sf2.entries_.empty());
}

BOOST_AUTO_TEST_CASE(settings_max_frame_size)
{
    uint8_t buf[128] = {0};

    settings_frame sf(buf, sizeof(buf), false);
    sf.entries_.emplace_back(settings_id::SETTINGS_MAX_FRAME_SIZE, 65536);
    int total = sf.pack_settings();
    BOOST_CHECK_GT(total, 9);

    settings_frame sf2(buf, sizeof(buf));
    BOOST_REQUIRE_EQUAL(sf2.entries_.size(), 1);
    BOOST_CHECK_EQUAL(sf2.entries_[0].value_, 65536u);
}

BOOST_AUTO_TEST_CASE(settings_id_to_string_values)
{
    BOOST_CHECK_EQUAL(::h2x::settings_id_to_string(settings_id::SETTINGS_HEADER_TABLE_SIZE),
        "SETTINGS_HEADER_TABLE_SIZE");
    BOOST_CHECK_EQUAL(::h2x::settings_id_to_string(settings_id::SETTINGS_ENABLE_PUSH),
        "SETTINGS_ENABLE_PUSH");
    BOOST_CHECK_EQUAL(::h2x::settings_id_to_string(settings_id::SETTINGS_MAX_FRAME_SIZE),
        "SETTINGS_MAX_FRAME_SIZE");
    BOOST_CHECK_EQUAL(::h2x::settings_id_to_string(static_cast<settings_id>(0xFF)),
        "UNKNOWN");
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// RST_STREAM 帧
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(rst_stream_frame_tests)

BOOST_AUTO_TEST_CASE(pack_unpack_rst_stream)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::RST_STREAM);

    rst_stream_frame rf(buf, sizeof(buf), false);
    rf.set_error_code(rst_stream_error_code::CANCEL);
    rf.stream_id(1);

    int total = rf.pack_payload();
    BOOST_CHECK_EQUAL(total, 13); // 9 + 4

    rst_stream_frame rf2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(rf2.stream_id(), 1u);
    BOOST_CHECK_EQUAL(rf2.get_error_code(), rst_stream_error_code::CANCEL);
}

BOOST_AUTO_TEST_CASE(all_error_codes)
{
    std::vector<rst_stream_error_code> codes = {
        rst_stream_error_code::NO_ERROR,
        rst_stream_error_code::PROTOCOL_ERROR,
        rst_stream_error_code::INTERNAL_ERROR,
        rst_stream_error_code::FLOW_CONTROL_ERROR,
        rst_stream_error_code::SETTINGS_TIMEOUT,
        rst_stream_error_code::STREAM_CLOSED,
        rst_stream_error_code::FRAME_SIZE_ERROR,
        rst_stream_error_code::REFUSED_STREAM,
        rst_stream_error_code::CANCEL,
        rst_stream_error_code::COMPRESSION_ERROR,
        rst_stream_error_code::CONNECT_ERROR,
        rst_stream_error_code::ENHANCE_YOUR_CALM,
        rst_stream_error_code::INADEQUATE_SECURITY,
        rst_stream_error_code::HTTP_1_1_REQUIRED,
    };

    for (auto code : codes) {
        uint8_t buf[64] = {0};
        buf[3] = static_cast<uint8_t>(frame_type::RST_STREAM);

        rst_stream_frame rf(buf, sizeof(buf), false);
        rf.set_error_code(code);
        rf.stream_id(1);

        rf.pack_payload();

        rst_stream_frame rf2(buf, sizeof(buf));
        BOOST_CHECK_EQUAL(rf2.get_error_code(), code);
    }
}

BOOST_AUTO_TEST_CASE(invalid_type)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::PING);

    BOOST_CHECK_THROW({
        rst_stream_frame rf(buf, sizeof(buf));
    }, std::runtime_error);
}

BOOST_AUTO_TEST_CASE(error_code_to_string)
{
    BOOST_CHECK_EQUAL(rst_stream_error_code_to_string(rst_stream_error_code::NO_ERROR),
        "NO_ERROR");
    BOOST_CHECK_EQUAL(rst_stream_error_code_to_string(rst_stream_error_code::CANCEL),
        "CANCEL");
    BOOST_CHECK_EQUAL(rst_stream_error_code_to_string(rst_stream_error_code::PROTOCOL_ERROR),
        "PROTOCOL_ERROR");
    BOOST_CHECK_EQUAL(rst_stream_error_code_to_string(
        static_cast<rst_stream_error_code>(0xFF)), "UNKNOWN");
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// PING 帧
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(ping_frame_tests)

BOOST_AUTO_TEST_CASE(pack_unpack_ping)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::PING);

    ping_frame pf(buf, sizeof(buf), false);
    pf.stream_id(0);

    uint8_t opaque[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    pf.set_opaque_data(opaque);

    int total = pf.pack_payload();
    BOOST_CHECK_EQUAL(total, 17); // 9 + 8

    ping_frame pf2(buf, sizeof(buf));
    BOOST_CHECK(!pf2.is_ack());

    const uint8_t* data = pf2.get_opaque_data();
    BOOST_CHECK_EQUAL(data[0], 0x01);
    BOOST_CHECK_EQUAL(data[7], 0x08);
}

BOOST_AUTO_TEST_CASE(ping_ack)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::PING);

    ping_frame pf(buf, sizeof(buf), false);
    pf.stream_id(0);
    pf.set_ack(true);

    pf.pack_payload();

    ping_frame pf2(buf, sizeof(buf));
    BOOST_CHECK(pf2.is_ack());
}

BOOST_AUTO_TEST_CASE(ping_zero_opaque)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::PING);

    ping_frame pf(buf, sizeof(buf), false);
    pf.stream_id(0);
    pf.set_opaque_data(nullptr); // 全零

    pf.pack_payload();

    ping_frame pf2(buf, sizeof(buf));
    const uint8_t* data = pf2.get_opaque_data();
    for (int i = 0; i < 8; ++i) {
        BOOST_CHECK_EQUAL(data[i], 0);
    }
}

BOOST_AUTO_TEST_CASE(invalid_type)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::GOAWAY);

    BOOST_CHECK_THROW({
        ping_frame pf(buf, sizeof(buf));
    }, std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// GOAWAY 帧
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(goaway_frame_tests)

BOOST_AUTO_TEST_CASE(pack_unpack_goaway)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::GOAWAY);

    goaway_frame gf(buf, sizeof(buf), false);
    gf.stream_id(0);
    gf.set_last_stream_id(100);
    gf.set_error_code(goaway_error_code::NO_ERROR);

    int total = gf.pack_payload();
    BOOST_CHECK_EQUAL(total, 17); // 9 + 8

    goaway_frame gf2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(gf2.get_last_stream_id(), 100u);
    BOOST_CHECK_EQUAL(gf2.get_error_code(), goaway_error_code::NO_ERROR);
}

BOOST_AUTO_TEST_CASE(goaway_with_debug_data)
{
    uint8_t buf[128] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::GOAWAY);

    goaway_frame gf(buf, sizeof(buf), false);
    gf.stream_id(0);
    gf.set_last_stream_id(0);
    gf.set_error_code(goaway_error_code::INTERNAL_ERROR);

    std::vector<uint8_t> debug = {'d', 'e', 'b', 'u', 'g'};
    gf.set_debug_data(debug);

    int total = gf.pack_payload();
    BOOST_CHECK_EQUAL(total, 22); // 9 + 8 + 5

    goaway_frame gf2(buf, sizeof(buf));
    auto debug2 = gf2.get_debug_data();
    BOOST_REQUIRE_EQUAL(debug2.size(), 5);
    BOOST_CHECK_EQUAL(debug2[0], 'd');
}

BOOST_AUTO_TEST_CASE(all_error_codes)
{
    std::vector<goaway_error_code> codes = {
        goaway_error_code::NO_ERROR,
        goaway_error_code::PROTOCOL_ERROR,
        goaway_error_code::INTERNAL_ERROR,
        goaway_error_code::FLOW_CONTROL_ERROR,
        goaway_error_code::SETTINGS_TIMEOUT,
        goaway_error_code::STREAM_CLOSED,
        goaway_error_code::FRAME_SIZE_ERROR,
        goaway_error_code::REFUSED_STREAM,
        goaway_error_code::CANCEL,
        goaway_error_code::COMPRESSION_ERROR,
        goaway_error_code::CONNECT_ERROR,
        goaway_error_code::ENHANCE_YOUR_CALM,
        goaway_error_code::INADEQUATE_SECURITY,
        goaway_error_code::HTTP_1_1_REQUIRED,
    };

    for (auto code : codes) {
        uint8_t buf[64] = {0};
        buf[3] = static_cast<uint8_t>(frame_type::GOAWAY);

        goaway_frame gf(buf, sizeof(buf), false);
        gf.stream_id(0);
        gf.set_last_stream_id(0);
        gf.set_error_code(code);
        gf.pack_payload();

        goaway_frame gf2(buf, sizeof(buf));
        BOOST_CHECK_EQUAL(gf2.get_error_code(), code);
    }
}

BOOST_AUTO_TEST_CASE(error_code_to_string)
{
    BOOST_CHECK_EQUAL(goaway_error_code_to_string(goaway_error_code::NO_ERROR),
        "NO_ERROR");
    BOOST_CHECK_EQUAL(goaway_error_code_to_string(goaway_error_code::PROTOCOL_ERROR),
        "PROTOCOL_ERROR");
    BOOST_CHECK_EQUAL(goaway_error_code_to_string(
        static_cast<goaway_error_code>(0xFF)), "UNKNOWN");
}

BOOST_AUTO_TEST_CASE(invalid_type)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::DATA);

    BOOST_CHECK_THROW({
        goaway_frame gf(buf, sizeof(buf));
    }, std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// WINDOW_UPDATE 帧
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(window_update_frame_tests)

BOOST_AUTO_TEST_CASE(pack_unpack_window_update)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::WINDOW_UPDATE);

    window_update_frame wuf(buf, sizeof(buf), false);
    wuf.stream_id(0);
    wuf.set_window_increment(100);

    int total = wuf.pack_payload();
    BOOST_CHECK_EQUAL(total, 13); // 9 + 4

    window_update_frame wuf2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(wuf2.get_window_increment(), 100u);
}

BOOST_AUTO_TEST_CASE(stream_level_window_update)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::WINDOW_UPDATE);

    window_update_frame wuf(buf, sizeof(buf), false);
    wuf.stream_id(3);
    wuf.set_window_increment(65535);

    wuf.pack_payload();

    window_update_frame wuf2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(wuf2.stream_id(), 3u);
    BOOST_CHECK_EQUAL(wuf2.get_window_increment(), 65535u);
}

BOOST_AUTO_TEST_CASE(zero_increment_throws)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::WINDOW_UPDATE);

    window_update_frame wuf(buf, sizeof(buf), false);
    wuf.stream_id(0);

    BOOST_CHECK_THROW({
        wuf.set_window_increment(0);
    }, std::runtime_error);
}

BOOST_AUTO_TEST_CASE(overflow_increment_throws)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::WINDOW_UPDATE);

    window_update_frame wuf(buf, sizeof(buf), false);
    wuf.stream_id(0);

    BOOST_CHECK_THROW({
        wuf.set_window_increment(0x80000000);
    }, std::runtime_error);
}

BOOST_AUTO_TEST_CASE(max_increment)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::WINDOW_UPDATE);

    window_update_frame wuf(buf, sizeof(buf), false);
    wuf.stream_id(0);
    wuf.set_window_increment(0x7FFFFFFF);

    BOOST_CHECK_NO_THROW(wuf.pack_payload());

    window_update_frame wuf2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(wuf2.get_window_increment(), 0x7FFFFFFFu);
}

BOOST_AUTO_TEST_CASE(invalid_type)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::PRIORITY);

    BOOST_CHECK_THROW({
        window_update_frame wuf(buf, sizeof(buf));
    }, std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// PRIORITY 帧
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(priority_frame_tests)

BOOST_AUTO_TEST_CASE(pack_unpack_priority)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::PRIORITY);

    priority_frame pf(buf, sizeof(buf), false);
    pf.stream_id(1);
    pf.set_depends_on(0);
    pf.set_weight(200);
    pf.set_exclusive(false);

    int total = pf.pack_payload();
    BOOST_CHECK_EQUAL(total, 14); // 9 + 5

    priority_frame pf2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(pf2.get_depends_on(), 0u);
    BOOST_CHECK_EQUAL(pf2.get_weight(), 200);
    BOOST_CHECK(!pf2.is_exclusive());
}

BOOST_AUTO_TEST_CASE(exclusive_priority)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::PRIORITY);

    priority_frame pf(buf, sizeof(buf), false);
    pf.stream_id(3);
    pf.set_depends_on(1);
    pf.set_weight(16);
    pf.set_exclusive(true);

    pf.pack_payload();

    priority_frame pf2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(pf2.get_depends_on(), 1u);
    BOOST_CHECK(pf2.is_exclusive());
    BOOST_CHECK_EQUAL(pf2.get_weight(), 16);
}

BOOST_AUTO_TEST_CASE(all_weights)
{
    for (int w = 0; w <= 255; ++w) {
        uint8_t buf[64] = {0};
        buf[3] = static_cast<uint8_t>(frame_type::PRIORITY);

        priority_frame pf(buf, sizeof(buf), false);
        pf.stream_id(5);
        pf.set_depends_on(0);
        pf.set_weight(static_cast<uint8_t>(w));
        pf.pack_payload();

        priority_frame pf2(buf, sizeof(buf));
        BOOST_CHECK_EQUAL(pf2.get_weight(), static_cast<uint8_t>(w));
    }
}

BOOST_AUTO_TEST_CASE(invalid_type)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::RST_STREAM);

    BOOST_CHECK_THROW({
        priority_frame pf(buf, sizeof(buf));
    }, std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// PUSH_PROMISE 帧
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(push_promise_frame_tests)

BOOST_AUTO_TEST_CASE(pack_unpack_push_promise)
{
    uint8_t buf[128] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::PUSH_PROMISE);

    push_promise_frame ppf(buf, sizeof(buf), false);
    ppf.stream_id(1);
    ppf.set_promised_stream_id(2);
    ppf.set_end_headers(true);

    std::vector<uint8_t> fragment = {'h', 'e', 'a', 'd', 'e', 'r'};
    ppf.set_header_block_fragment(fragment);

    int total = ppf.pack_payload();
    BOOST_CHECK_GT(total, 9);

    push_promise_frame ppf2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(ppf2.get_promised_stream_id(), 2u);
    BOOST_CHECK(ppf2.is_end_headers());

    auto frag = ppf2.get_header_block_fragment();
    BOOST_REQUIRE_EQUAL(frag.size(), 6);
    BOOST_CHECK_EQUAL(frag[0], 'h');
}

BOOST_AUTO_TEST_CASE(push_promise_with_padding)
{
    uint8_t buf[256] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::PUSH_PROMISE);

    push_promise_frame ppf(buf, sizeof(buf), false);
    ppf.stream_id(1);
    ppf.set_promised_stream_id(4);
    ppf.set_end_headers(true);
    ppf.set_pad_length(8);

    ppf.pack_payload();

    push_promise_frame ppf2(buf, sizeof(buf));
    BOOST_CHECK_EQUAL(ppf2.get_promised_stream_id(), 4u);
    BOOST_CHECK_EQUAL(ppf2.get_pad_length(), 8);
}

BOOST_AUTO_TEST_CASE(invalid_type)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::DATA);

    BOOST_CHECK_THROW({
        push_promise_frame ppf(buf, sizeof(buf));
    }, std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// CONTINUATION 帧
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(continuation_frame_tests)

BOOST_AUTO_TEST_CASE(pack_unpack_continuation)
{
    uint8_t buf[128] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::CONTINUATION);

    continuation_frame cf(buf, sizeof(buf), false);
    cf.stream_id(1);
    cf.set_end_headers(true);

    std::vector<uint8_t> fragment = {'f', 'r', 'a', 'g'};
    cf.set_header_block_fragment(fragment);

    int total = cf.pack_payload();
    BOOST_CHECK_EQUAL(total, 13); // 9 + 4

    continuation_frame cf2(buf, sizeof(buf));
    BOOST_CHECK(cf2.is_end_headers());

    auto frag = cf2.get_header_block_fragment();
    BOOST_REQUIRE_EQUAL(frag.size(), 4);
    BOOST_CHECK_EQUAL(frag[0], 'f');
}

BOOST_AUTO_TEST_CASE(continuation_not_end_headers)
{
    uint8_t buf[128] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::CONTINUATION);

    continuation_frame cf(buf, sizeof(buf), false);
    cf.stream_id(1);
    cf.set_end_headers(false);

    std::vector<uint8_t> fragment = {'d', 'a', 't', 'a'};
    cf.set_header_block_fragment(fragment);

    cf.pack_payload();

    continuation_frame cf2(buf, sizeof(buf));
    BOOST_CHECK(!cf2.is_end_headers());
    BOOST_CHECK_EQUAL(cf2.get_header_block_fragment().size(), 4);
}

BOOST_AUTO_TEST_CASE(append_fragment)
{
    uint8_t buf[128] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::CONTINUATION);

    continuation_frame cf(buf, sizeof(buf), false);
    cf.stream_id(1);

    cf.append_header_block_fragment(
        reinterpret_cast<const uint8_t*>("part1"), 5);
    cf.append_header_block_fragment(
        reinterpret_cast<const uint8_t*>("part2"), 5);
    cf.set_end_headers(true);
    cf.pack_payload();

    continuation_frame cf2(buf, sizeof(buf));
    auto frag = cf2.get_header_block_fragment();
    BOOST_REQUIRE_EQUAL(frag.size(), 10);
}

BOOST_AUTO_TEST_CASE(invalid_type)
{
    uint8_t buf[64] = {0};
    buf[3] = static_cast<uint8_t>(frame_type::HEADERS);

    BOOST_CHECK_THROW({
        continuation_frame cf(buf, sizeof(buf));
    }, std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// 帧标志枚举 (frame_flag)
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(frame_flag_tests)

BOOST_AUTO_TEST_CASE(bit_values)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_flag::FLAG_NONE), 0x00);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_flag::END_STREAM), 0x01);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_flag::FLAG_ACK), 0x01);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_flag::END_HEADERS), 0x04);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_flag::PADDED), 0x08);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_flag::PRIORITY), 0x20);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// 帧类型枚举 (frame_type)
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(frame_type_tests)

BOOST_AUTO_TEST_CASE(type_values)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::DATA), 0x00);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::HEADERS), 0x01);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::PRIORITY), 0x02);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::RST_STREAM), 0x03);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::SETTINGS), 0x04);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::PUSH_PROMISE), 0x05);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::PING), 0x06);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::GOAWAY), 0x07);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::WINDOW_UPDATE), 0x08);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::CONTINUATION), 0x09);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::ALTSVC), 0x0a);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::ORIGIN), 0x0c);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(frame_type::PRIORITY_UPDATE), 0x10);
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// 帧哈希函数 (frame_header_hash)
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(frame_header_hash_tests)

BOOST_AUTO_TEST_CASE(fnv1a_known_values)
{
    // 与静态表中的值对应验证.
    header_entry h1{0, ":authority", "", 3153725150, nullptr};
    auto hash1 = frame_header_hash(h1);
    BOOST_CHECK_EQUAL(hash1, 3153725150u);

    header_entry h2{0, ":method", "GET", 1312632084, nullptr};
    auto hash2 = frame_header_hash(h2);
    BOOST_CHECK_EQUAL(hash2, 1312632084u);

    header_entry h3{0, ":path", "/", 4184852371, nullptr};
    auto hash3 = frame_header_hash(h3);
    BOOST_CHECK_EQUAL(hash3, 4184852371u);
}

BOOST_AUTO_TEST_CASE(empty_optional_handling)
{
    // name_ 和 value_ 都是 std::nullopt.
    header_entry h{0, std::nullopt, std::nullopt, 0, nullptr};
    // 此时 hash 应返回 2166136261u (FNV-1a 初始值).
    auto hash = frame_header_hash(h);
    BOOST_CHECK_EQUAL(hash, 2166136261u);
}

BOOST_AUTO_TEST_CASE(different_values_different_hashes)
{
    header_entry h1{0, "name", "value1", 0, nullptr};
    header_entry h2{0, "name", "value2", 0, nullptr};

    auto hash1 = frame_header_hash(h1);
    auto hash2 = frame_header_hash(h2);

    BOOST_CHECK_NE(hash1, hash2);
}

BOOST_AUTO_TEST_CASE(different_names_different_hashes)
{
    header_entry h1{0, "name1", "value", 0, nullptr};
    header_entry h2{0, "name2", "value", 0, nullptr};

    auto hash1 = frame_header_hash(h1);
    auto hash2 = frame_header_hash(h2);

    BOOST_CHECK_NE(hash1, hash2);
}

BOOST_AUTO_TEST_CASE(same_headers_same_hashes)
{
    header_entry h1{0, "cache-control", "max-age=3600", 0, nullptr};
    header_entry h2{0, "cache-control", "max-age=3600", 0, nullptr};

    auto hash1 = frame_header_hash(h1);
    auto hash2 = frame_header_hash(h2);

    BOOST_CHECK_EQUAL(hash1, hash2);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace h2x