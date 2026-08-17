//
// connection_test.cpp
// ~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <h2x/h2.hpp>

namespace net = boost::asio;
using namespace h2x;
using namespace std::chrono_literals;

namespace h2x {

// 协程间共享的测试状态.
struct connection_test_state {
    std::string error;        // 非空表示测试过程出错.
    bool headers_ok = false;  // 收到 :status 301.
    bool clean_eof = false;   // body 读取干净结束 (无错误).
    size_t body_bytes = 0;    // 读取到的 body 字节数.
};

// ── 帧构建辅助 (模拟服务端) ──

// 构建 SETTINGS 帧 (空设置项, 可选 ACK).
static std::vector<uint8_t> build_settings_frame(bool ack)
{
    std::vector<uint8_t> buf(64, 0);
    settings_frame sf(buf.data(), buf.size(), false);
    sf.ack_ = ack;
    sf.entries_.clear();
    int total = sf.pack_settings();
    buf.resize(static_cast<size_t>(total));
    return buf;
}

// 构建 HEADERS 帧 (单帧, END_HEADERS; end_stream 控制 END_STREAM 标志).
static std::vector<uint8_t> build_headers_frame(
    uint32_t sid,
    const std::vector<std::pair<std::string, std::string>>& headers,
    bool end_stream)
{
    std::vector<uint8_t> buf(1024, 0);
    headers_frame hf(buf.data(), buf.size(), false);
    hf.stream_id(sid);
    hf.end_stream_ = end_stream;
    hf.end_headers_ = true;
    for (auto& [name, value] : headers) {
        hf.add_header(name, value);
    }
    int total = hf.pack_headers();
    BOOST_REQUIRE(total > 0);
    buf.resize(static_cast<size_t>(total));
    return buf;
}

// 构建 DATA 帧.
static std::vector<uint8_t> build_data_frame(
    uint32_t sid, const std::string& payload, bool end_stream)
{
    std::vector<uint8_t> buf(payload.size() + 9, 0);
    data_frame df(buf.data(), buf.size(), false);
    df.stream_id(sid);
    df.type(frame_type::DATA);
    df.set_data(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
    df.set_end_stream(end_stream);
    df.pack_payload();
    buf.resize(df.frame_size());
    return buf;
}

// 从 socket 读取一个完整的 HTTP/2 帧 (9 字节头 + payload).
// 失败时返回空 vector.
static net::awaitable<std::vector<uint8_t>> read_frame(net::ip::tcp::socket& sock)
{
    boost::system::error_code ec;
    std::vector<uint8_t> hdr(9);
    co_await net::async_read(sock, net::buffer(hdr), net_awaitable[ec]);
    if (ec) {
        co_return std::vector<uint8_t>{};
    }

    uint32_t len = (static_cast<uint32_t>(hdr[0]) << 16)
                 | (static_cast<uint32_t>(hdr[1]) << 8)
                 | static_cast<uint32_t>(hdr[2]);
    std::vector<uint8_t> frame(9 + len);
    std::memcpy(frame.data(), hdr.data(), 9);
    if (len > 0) {
        co_await net::async_read(sock, net::buffer(frame.data() + 9, len), net_awaitable[ec]);
        if (ec) {
            co_return std::vector<uint8_t>{};
        }
    }
    co_return frame;
}

// ── 模拟服务端: 完成握手后发送 HEADERS(301) → DATA → 空 DATA(END_STREAM) ──

// 模拟 google.com 301 场景: 响应体之后还跟一个空的 DATA + END_STREAM 帧.
// 客户端在读取完 body 后会再次挂起等待 EOF, 此时该终止帧触发流释放路径;
// 若释放先于挂起协程恢复, 将导致 use-after-free.
static net::awaitable<void> run_mock_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    // 客户端连接前言 (24 字节).
    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) {
        st.error = "server: read preface: " + ec.message();
        co_return;
    }

    // 客户端 SETTINGS 帧.
    if ((co_await read_frame(sock)).empty()) {
        st.error = "server: read client settings failed";
        co_return;
    }

    // 服务端 SETTINGS 帧.
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if (ec) {
        st.error = "server: write settings: " + ec.message();
        co_return;
    }

    // 客户端 SETTINGS ACK.
    if ((co_await read_frame(sock)).empty()) {
        st.error = "server: read client settings ack failed";
        co_return;
    }

    // 服务端 SETTINGS ACK.
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);
    if (ec) {
        st.error = "server: write settings ack: " + ec.message();
        co_return;
    }

    // 客户端请求 HEADERS (流 1).
    if ((co_await read_frame(sock)).empty()) {
        st.error = "server: read request failed";
        co_return;
    }

    // 响应 HEADERS: 301.
    auto hf = build_headers_frame(1, {
        {":status", "301"},
        {"content-type", "text/html"},
        {"content-length", "220"},
    }, false);
    co_await net::async_write(sock, net::buffer(hf), net_awaitable[ec]);
    if (ec) {
        st.error = "server: write response headers: " + ec.message();
        co_return;
    }

    // 响应 body (220 字节), 不带 END_STREAM.
    std::string body(220, 'x');
    auto df = build_data_frame(1, body, false);
    co_await net::async_write(sock, net::buffer(df), net_awaitable[ec]);
    if (ec) {
        st.error = "server: write response body: " + ec.message();
        co_return;
    }

    // 等待客户端消费完 body 并重新挂起等待 EOF.
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(150ms);
    co_await timer.async_wait(net_awaitable[ec]);

    // 空 DATA + END_STREAM (终止帧, 无 body 数据).
    auto tf = build_data_frame(1, "", true);
    co_await net::async_write(sock, net::buffer(tf), net_awaitable[ec]);
    if (ec) {
        st.error = "server: write end stream frame: " + ec.message();
        co_return;
    }

    sock.close();
}

// ── 模拟客户端: 发起请求并读取 301 响应 ──

static net::awaitable<void> run_mock_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    auto s = std::make_shared<settings>();
    s->header_table_size = 4096;
    s->max_concurrent_streams = 1;
    s->initial_window_size = 65535;
    s->max_frame_size = 16384;

    co_await conn->async_handshake(role::client, *s, ec);
    if (ec) {
        st.error = "client: handshake: " + ec.message();
        co_return;
    }

    auto req_result = co_await conn->async_request();
    if (!req_result.has_value()) {
        st.error = "client: async_request: " + req_result.error().message();
        co_return;
    }
    auto stream = std::move(req_result.value());

    std::vector<std::pair<std::string, std::string>> headers = {
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "https"},
        {":authority", "test.local"},
        {"user-agent", "h2x-test"},
        {"accept", "*/*"},
    };
    ec = co_await stream.async_write_headers(headers, true);
    if (ec) {
        st.error = "client: write headers: " + ec.message();
        co_return;
    }

    auto hdr = co_await stream.async_read_headers();
    if (!hdr.has_value()) {
        st.error = "client: read headers: " + hdr.error().message();
        co_return;
    }
    for (auto& h : hdr.value()) {
        if (h.name_ && *h.name_ == ":status" && h.value_ && *h.value_ == "301") {
            st.headers_ok = true;
        }
    }

    // 读取 body 直到 EOF.
    while (!stream.is_done()) {
        auto data = co_await stream.async_read_data();
        if (!data.has_value()) {
            if (data.error() == make_error_code(errc::stream_closed)) {
                break;
            }
            st.error = "client: read data: " + data.error().message();
            co_return;
        }

        auto& chunk = data.value();
        if (chunk.empty()) {
            break;
        }
        st.body_bytes += chunk.size();
    }
    st.clean_eof = true;

    conn->close();
    co_await conn->async_wait_pump(3s);
}

BOOST_AUTO_TEST_SUITE(connection_lifecycle)

// 回归测试: 响应以空 DATA + END_STREAM 结束时, 流释放不得早于
// 挂起协程恢复, 否则读取协程恢复后访问已释放的流状态导致
// use-after-free (修复见 wake_waiter 槽位清理时机).
BOOST_AUTO_TEST_CASE(stream_release_after_empty_data_end_stream)
{
    net::io_context ioc(1);
    connection_test_state st;

    net::ip::tcp::acceptor acceptor(
        ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    auto port = acceptor.local_endpoint().port();

    // 看门狗: 回归发生时 (无 ASAN 环境) 测试可能挂起, 超时后失败退出.
    net::steady_timer watchdog(ioc);
    watchdog.expires_after(10s);
    watchdog.async_wait([&](boost::system::error_code ec) {
        if (!ec) {
            st.error = "test timeout";
            ioc.stop();
        }
    });

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        auto sock = co_await acceptor.async_accept(net_awaitable[ec]);
        if (ec) {
            st.error = "accept: " + ec.message();
            ioc.stop();
            co_return;
        }
        co_await run_mock_server(std::move(sock), st);
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) {
            st.error = "connect: " + ec.message();
            ioc.stop();
            co_return;
        }
        co_await run_mock_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK(st.headers_ok);
    BOOST_CHECK_EQUAL(st.body_bytes, 220u);
    BOOST_CHECK(st.clean_eof);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace h2x
