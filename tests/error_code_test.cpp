//
// error_code_test.cpp
// ~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/test/unit_test.hpp>
#include <boost/system/error_code.hpp>

#include "h2x/h2_error_code.hpp"

namespace h2x {

// ──────────────────────────────────────────────────────────────────────────────
// 错误分类 (error_category)
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(error_category_tests)

BOOST_AUTO_TEST_CASE(category_name)
{
    auto& cat = error_category();
    BOOST_CHECK_EQUAL(cat.name(), "HTTP/2");
}

BOOST_AUTO_TEST_CASE(error_messages)
{
    auto& cat = error_category();

    BOOST_CHECK_EQUAL(cat.message(0), "Success");
    BOOST_CHECK_EQUAL(cat.message(1), "Stream not found");
    BOOST_CHECK_EQUAL(cat.message(2), "Stream already exists");
    BOOST_CHECK_EQUAL(cat.message(3), "Connection error");
    BOOST_CHECK_EQUAL(cat.message(4), "Flow control error");
    BOOST_CHECK_EQUAL(cat.message(5), "Protocol error");
    BOOST_CHECK_EQUAL(cat.message(6), "Frame size error");
    BOOST_CHECK_EQUAL(cat.message(7), "Stream closed");
    BOOST_CHECK_EQUAL(cat.message(8), "NextLayer is not open");
    BOOST_CHECK_EQUAL(cat.message(999), "Unknown error");
}

BOOST_AUTO_TEST_CASE(default_error_condition)
{
    auto& cat = error_category();
    auto cond = cat.default_error_condition(0);
    // 默认情况下, error_condition 与 error_code 等价.
    BOOST_CHECK_EQUAL(cond.category().name(), "HTTP/2");
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// errc 枚举与 error_code 集成
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(errc_integration)

BOOST_AUTO_TEST_CASE(make_error_code)
{
    auto ec = errc::make_error_code(errc::stream_not_found);
    BOOST_CHECK_EQUAL(ec.value(), 1);
    BOOST_CHECK_EQUAL(ec.category().name(), "HTTP/2");
    BOOST_CHECK_EQUAL(ec.message(), "Stream not found");
}

BOOST_AUTO_TEST_CASE(error_code_comparison)
{
    auto ec1 = errc::make_error_code(errc::stream_not_found);
    auto ec2 = errc::make_error_code(errc::stream_not_found);
    auto ec3 = errc::make_error_code(errc::protocol_error);

    BOOST_CHECK(ec1 == ec2);
    BOOST_CHECK(ec1 != ec3);
}

BOOST_AUTO_TEST_CASE(all_errc_values)
{
    // 验证所有 errc 值都能转换为 error_code.
    auto ec0 = errc::make_error_code(errc::success);
    BOOST_CHECK_EQUAL(ec0.value(), static_cast<int>(errc::success));

    auto ec1 = errc::make_error_code(errc::stream_not_found);
    BOOST_CHECK_EQUAL(ec1.value(), static_cast<int>(errc::stream_not_found));

    auto ec2 = errc::make_error_code(errc::stream_already_exists);
    BOOST_CHECK_EQUAL(ec2.value(), static_cast<int>(errc::stream_already_exists));

    auto ec3 = errc::make_error_code(errc::connection_error);
    BOOST_CHECK_EQUAL(ec3.value(), static_cast<int>(errc::connection_error));

    auto ec4 = errc::make_error_code(errc::flow_control_error);
    BOOST_CHECK_EQUAL(ec4.value(), static_cast<int>(errc::flow_control_error));

    auto ec5 = errc::make_error_code(errc::protocol_error);
    BOOST_CHECK_EQUAL(ec5.value(), static_cast<int>(errc::protocol_error));

    auto ec6 = errc::make_error_code(errc::frame_size_error);
    BOOST_CHECK_EQUAL(ec6.value(), static_cast<int>(errc::frame_size_error));

    auto ec7 = errc::make_error_code(errc::stream_closed);
    BOOST_CHECK_EQUAL(ec7.value(), static_cast<int>(errc::stream_closed));

    auto ec8 = errc::make_error_code(errc::next_layer_not_open);
    BOOST_CHECK_EQUAL(ec8.value(), static_cast<int>(errc::next_layer_not_open));
}

BOOST_AUTO_TEST_CASE(error_code_bool_conversion)
{
    auto ec_success = errc::make_error_code(errc::success);
    BOOST_CHECK(!ec_success); // 0 表示无错误

    auto ec_error = errc::make_error_code(errc::protocol_error);
    BOOST_CHECK(static_cast<bool>(ec_error)); // 非零表示错误
}

BOOST_AUTO_TEST_SUITE_END()

// ──────────────────────────────────────────────────────────────────────────────
// is_error_code_enum trait
// ──────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(error_code_enum_trait)

BOOST_AUTO_TEST_CASE(trait_value)
{
    bool is_specialized =
        boost::system::is_error_code_enum<errc::errc_t>::value;
    BOOST_CHECK(is_specialized);
}

BOOST_AUTO_TEST_CASE(implicit_conversion)
{
    // is_error_code_enum 特化允许 errc_t 隐式转换为 error_code.
    boost::system::error_code ec = errc::protocol_error;
    BOOST_CHECK_EQUAL(ec.value(), static_cast<int>(errc::protocol_error));
    BOOST_CHECK_EQUAL(ec.category().name(), "HTTP/2");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace h2x