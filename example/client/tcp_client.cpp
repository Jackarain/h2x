//
// tcp_client.cpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// 简单的基于 TCP 的 HTTP/2 客户端示例（不使用 TLS）

#include <iostream>
#include <string>
#include <vector>
#include <memory>

#include <boost/system/error_code.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <h2x/h2.hpp>

namespace net = boost::asio;
using namespace h2x;
using namespace std::chrono_literals;

// 执行一个简单的 HTTP/2 GET 请求（纯 TCP，适用于测试本地 server 示例）。
net::awaitable<void> do_request(const std::string& host, const std::string& port)
{
    boost::system::error_code ec;

    net::ip::tcp::resolver resolver(co_await net::this_coro::executor);
    auto endpoints = co_await resolver.async_resolve(host, port, net_awaitable[ec]);
    if (ec) {
        std::cerr << "Resolve error: " << ec.message() << std::endl;
        co_return;
    }

    // 使用裸 TCP socket
    net::ip::tcp::socket sock(co_await net::this_coro::executor);
    co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
    if (ec) {
        std::cerr << "Connect error: " << ec.message() << std::endl;
        co_return;
    }

    std::cout << "Connected to " << host << ":" << port << " (TCP)" << std::endl;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    auto s = std::make_shared<settings>();
    s->header_table_size = 4096;
    s->max_concurrent_streams = 1;
    s->initial_window_size = 65535;
    s->max_frame_size = 16384;

    // 执行 HTTP/2 握手，握手完成后 pump 协程在后台自动运行.
    boost::system::error_code hs_ec;
    co_await conn->async_handshake(role::client, *s, hs_ec);
    if (hs_ec) {
        std::cerr << "Handshake error: " << hs_ec.message() << std::endl;
        co_return;
    }

    // 创建请求流
    auto req_result = co_await conn->async_request();
    if (!req_result.has_value()) {
        std::cerr << "Failed to create request stream: "
                  << req_result.error().message() << std::endl;
        co_return;
    }
    auto stream = std::move(req_result.value());

    std::vector<std::pair<std::string, std::string>> headers = {
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "http"},
        {":authority", host},
        {"user-agent", "h2x-tcp-client/1.0"},
    };

    // 先发 HEADERS，不关闭流（end_stream=false），后面还有 DATA 要发送
    ec = co_await stream.async_write_headers(headers, false);
    if (ec) {
        std::cerr << "Write headers error: " << ec.message() << std::endl;
        co_return;
    }

    // 发送请求体数据，然后关闭流（end_stream=true）
    std::string test_data = "Hello from TCP client!";
    ec = co_await stream.async_write_data(test_data, true);
    if (ec) {
        std::cerr << "Write test data error: " << ec.message() << std::endl;
        co_return;
    }

    std::cout << "Request sent, waiting for response..." << std::endl;

    auto hdr_result = co_await stream.async_read_headers();
    if (!hdr_result.has_value()) {
        std::cerr << "Read headers error: " << hdr_result.error().message() << std::endl;
        co_return;
    }

    std::cout << "\n=== Response headers ===" << std::endl;
    for (auto& h : hdr_result.value()) {
        if (h.name_ && h.value_) {
            std::cout << "  " << *h.name_ << ": " << *h.value_ << std::endl;
        }
    }

    std::cout << "\n=== Response body ===" << std::endl;
    bool has_data = false;
    while (!stream.is_done()) {
        auto data_result = co_await stream.async_read_data();
        if (!data_result.has_value()) {
            auto err = data_result.error();
            if (err == make_error_code(errc::stream_closed)) break;
            std::cerr << "Read data error: " << err.message() << std::endl;
            co_return;
        }

        auto& data = data_result.value();
        if (data.empty()) break;

        has_data = true;
        std::cout.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
    if (has_data) std::cout << std::endl;

    std::cout << "\n=== Request completed ===" << std::endl;

    conn->close();

    // 等待 pump 协程完全退出（超时 3 秒）.
    if (!co_await conn->async_wait_pump(3s)) {
        std::cerr << "Warning: pump did not exit within timeout" << std::endl;
    }
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cerr << "Usage: tcp_client <host> <port>\n";
        return EXIT_FAILURE;
    }

    std::string host = argv[1];
    std::string port = argv[2];

    net::io_context ioc{1};
    net::co_spawn(ioc, do_request(host, port), net::detached);
    ioc.run();
    return 0;
}
