//
// tcp_server.cpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// 简单的基于 TCP 的 HTTP/2 服务器示例（不使用 TLS）

#include <iostream>
#include <cstdlib>
#include <string>
#include <chrono>
#include <memory>
#include <vector>

#include <boost/system/error_code.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <h2x/h2.hpp>

namespace net = boost::asio;
using namespace h2x;
using namespace std::chrono_literals;

using conn_type = connection<net::ip::tcp::socket>;
using stream_type = conn_type::stream_type;

// 处理单个 HTTP/2 请求
net::awaitable<void> handle_http_request(stream_type stream)
{
    boost::system::error_code ec;

    auto hdr_result = co_await stream.async_read_headers();
    if (!hdr_result.has_value()) {
        std::cerr << "Read headers error: " << hdr_result.error().message() << std::endl;
        co_return;
    }

    auto& headers = hdr_result.value();

    std::string method, path, scheme, authority;
    for (auto& h : headers) {
        if (!h.name_ || !h.value_) continue;
        if (*h.name_ == ":method") method = *h.value_;
        else if (*h.name_ == ":path") path = *h.value_;
        else if (*h.name_ == ":scheme") scheme = *h.value_;
        else if (*h.name_ == ":authority") authority = *h.value_;
    }

    std::cout << "Request: " << method << " " << path
              << " (" << (authority.empty() ? "unknown" : authority) << ")"
              << std::endl;

    std::vector<std::pair<std::string, std::string>> resp_headers = {
        {":status", "200"},
        {"content-type", "application/json"},
        {"server", "h2x-tcp-server"},
    };

    ec = co_await stream.async_write_headers(resp_headers, false);
    if (ec) {
        std::cerr << "Write headers error: " << ec.message() << std::endl;
        co_return;
    }

    std::string body = R"({"message": "Hello HTTP/2 (TCP)!", "method": ")" + method + R"(", "path": ")" + path + R"("})";

    ec = co_await stream.async_write_data(body, true);
    if (ec) {
        std::cerr << "Write data error: " << ec.message() << std::endl;
        co_return;
    }

    std::cout << "=== Response body ===" << std::endl;
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

    std::cout << "=== Request completed ===" << std::endl;

    co_return;
}

// 处理单个会话：握手后循环接受流
net::awaitable<void> server_session(net::ip::tcp::socket sock)
{
    auto executor = sock.get_executor();

    auto conn = std::make_shared<conn_type>(std::move(sock));
    auto s = std::make_shared<settings>();
    s->header_table_size = 4096;
    s->max_concurrent_streams = 100;
    s->initial_window_size = 65535;
    s->max_frame_size = 16384;

    // 执行 HTTP/2 握手，握手完成后协程 pump 在后台自动运行。
    boost::system::error_code hs_ec;
    co_await conn->async_handshake(role::server, *s, hs_ec);
    if (hs_ec) {
        std::cerr << "Session handshake error: " << hs_ec.message() << std::endl;
        co_return;
    }

    while (true) {
        auto res = co_await conn->async_accept_stream();
        if (!res) break;

        stream_type stream = std::move(res.value());

        net::co_spawn(executor,
            handle_http_request(std::move(stream)),
            net::detached);
    }

    // 清理：关闭连接并等待 pump 协程退出.
    conn->close();
    if (!co_await conn->async_wait_pump(3s)) {
        std::cerr << "Warning: pump did not exit within timeout" << std::endl;
    }
}

// 监听并接受 TCP 连接
net::awaitable<void> listener(net::ip::tcp::acceptor& acceptor)
{
    for (;;) {
        boost::system::error_code ec;
        auto socket = co_await acceptor.async_accept(net_awaitable[ec]);
        if (ec) {
            std::cerr << "Accept error: " << ec.message() << std::endl;
            co_return;
        }

        std::cout << "New connection from " << socket.remote_endpoint() << std::endl;

        net::co_spawn(socket.get_executor(),
            [s = std::move(socket)]() mutable -> net::awaitable<void> {
                co_await server_session(std::move(s));
            },
            net::detached);
    }
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cerr << "Usage: tcp_server <address> <port>\n"
                  << "Example: tcp_server 0.0.0.0 8080\n";
        return EXIT_FAILURE;
    }

    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));

    net::io_context ioc{1};

    net::ip::tcp::acceptor acceptor(ioc, {address, port});
    acceptor.set_option(net::ip::tcp::acceptor::reuse_address(true));

    std::cout << "HTTP/2 TCP server listening on " << address << ":" << port << std::endl;

    net::co_spawn(ioc,
        [&acceptor]() -> net::awaitable<void> {
            co_await listener(acceptor);
        },
        net::detached);

    ioc.run();
    return 0;
}
