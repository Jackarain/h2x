//
// server.cpp
// ~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

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

#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>

#include <h2x/h2.hpp>

namespace net = boost::asio;
using namespace h2x;
using namespace std::chrono_literals;

namespace ssl = boost::asio::ssl;
using ssl_stream = ssl::stream<net::ip::tcp::socket>;
using conn_type = connection<ssl_stream>;
using stream_type = conn_type::stream_type;

// ============================================================================
// 处理单个 HTTP/2 请求
// ============================================================================
net::awaitable<void> handle_http_request(stream_type stream)
{
    boost::system::error_code ec;

    // 1. 接收请求头
    auto hdr_result = co_await stream.async_read_headers();
    if (!hdr_result.has_value()) {
        std::cerr << "Read headers error: " << hdr_result.error().message() << std::endl;
        co_return;
    }

    auto& headers = hdr_result.value();

    // 2. 解析伪头
    std::string method, path, scheme, authority;
    for (auto& h : headers) {
        if (!h.name_ || !h.value_) continue;
        if (*h.name_ == ":method")    method = *h.value_;
        else if (*h.name_ == ":path") path = *h.value_;
        else if (*h.name_ == ":scheme") scheme = *h.value_;
        else if (*h.name_ == ":authority") authority = *h.value_;
    }

    std::cout << "Request: " << method << " " << path
              << " (" << (authority.empty() ? "unknown" : authority) << ")"
              << std::endl;

    // 3. 发送响应头
    std::vector<std::pair<std::string, std::string>> resp_headers = {
        {":status", "200"},
        {"content-type", "application/json"},
        {"server", "h2x-server"},
    };

    ec = co_await stream.async_write_headers(resp_headers, false);
    if (ec) {
        std::cerr << "Write headers error: " << ec.message() << std::endl;
        co_return;
    }

    // 4. 发送响应体
    std::string body = R"({"message": "Hello HTTP/2!", "method": ")"
                     + method + R"(", "path": ")" + path + R"("})";

    ec = co_await stream.async_write_data(body, true);  // end_stream = true
    if (ec) {
        std::cerr << "Write data error: " << ec.message() << std::endl;
        co_return;
    }

    // 读取请求体（如果有）并打印，直到流结束.
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

// ============================================================================
// 处理单个 TLS 会话：握手后循环接受流
// ============================================================================
net::awaitable<void> server_session(ssl_stream ssl_sock)
{
    auto executor = ssl_sock.get_executor();

    // 使用 shared_ptr 管理连接与设置的生命周期。
    auto conn = std::make_shared<conn_type>(std::move(ssl_sock));
    auto s = std::make_shared<settings>();
    s->header_table_size = 4096;
    s->max_concurrent_streams = 100;
    s->initial_window_size = 65535;
    s->max_frame_size = 16384;

    // 执行 HTTP/2 握手，握手完成后 pump 协程在后台自动运行。
    boost::system::error_code hs_ec;
    co_await conn->async_handshake(role::server, *s, hs_ec);
    if (hs_ec) {
        std::cerr << "Session handshake error: " << hs_ec.message() << std::endl;
        co_return;
    }

    // 循环接受新请求（新 Stream）。
    while (true) {
        auto res = co_await conn->async_accept_stream();
        if (!res) {
            // 连接已关闭或出错。
            break;
        }

        stream_type stream = std::move(res.value());

        // 为每个请求启动独立协程处理。
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

// ============================================================================
// 异步监听并接受 TLS 连接
// ============================================================================
net::awaitable<void> listener(net::ip::tcp::acceptor& acceptor, ssl::context& ssl_ctx)
{
    for (;;) {
        boost::system::error_code ec;
        auto socket = co_await acceptor.async_accept(net_awaitable[ec]);
        if (ec) {
            std::cerr << "Accept error: " << ec.message() << std::endl;
            co_return;
        }

        std::cout << "New connection from "
                  << socket.remote_endpoint() << std::endl;

        // 将原始 socket 包装为 SSL 流并在后台完成握手，然后交给 server_session。
        ssl_stream ssl_sock(std::move(socket), ssl_ctx);

        net::co_spawn(
            ssl_sock.get_executor(),
            [s = std::move(ssl_sock)]() mutable -> net::awaitable<void> {
                boost::system::error_code ec;

                // 完成 TLS 握手（服务器模式）。
                co_await s.async_handshake(ssl::stream_base::server, net_awaitable[ec]);
                if (ec) {
                    std::cerr << "TLS handshake error: " << ec.message() << std::endl;
                    co_return;
                }

                // 检查 ALPN 协商结果。
                const unsigned char* alpn_data = nullptr;
                unsigned int alpn_len = 0;
                SSL_get0_alpn_selected(s.native_handle(), &alpn_data, &alpn_len);
                if (alpn_data && alpn_len > 0) {
                    std::string alpn_proto(reinterpret_cast<const char*>(alpn_data), alpn_len);
                    std::cout << "ALPN negotiated: " << alpn_proto << std::endl;
                    if (alpn_proto != "h2") {
                        std::cerr << "Client did not negotiate h2, got: " << alpn_proto << std::endl;
                        boost::system::error_code close_ec;
                        s.lowest_layer().shutdown(net::ip::tcp::socket::shutdown_both, close_ec);
                        s.lowest_layer().close(close_ec);
                        co_return;
                    }
                }

                // 启动 HTTP/2 会话处理。
                co_await server_session(std::move(s));
            },
            net::detached);
    }
}

// ============================================================================
// ALPN 选择回调：只支持 h2
// ============================================================================
int alpn_select_cb(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                   const unsigned char* in, unsigned int inlen, void* /*arg*/)
{
    // 从客户端 ALPN 列表中手动查找 h2，out 指向客户端列表确保生命周期有效。
    for (unsigned int i = 0; i < inlen; ) {
        unsigned char proto_len = in[i];
        if (i + 1 + proto_len > inlen) break;
        if (proto_len == 2 && in[i + 1] == 'h' && in[i + 2] == '2') {
            *out = in + i + 1;   // 指向客户端列表中协议名称.
            *outlen = 2;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + proto_len;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

// ============================================================================
// 入口
// ============================================================================
int main(int argc, char* argv[])
{
    if (argc != 5) {
        std::cerr <<
            "Usage: server <address> <port> <cert.pem> <key.pem>\n"
            "Example:\n"
            "    server 0.0.0.0 8443 server.crt server.key\n";
        return EXIT_FAILURE;
    }

    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    std::string cert_file = argv[3];
    std::string key_file = argv[4];

    net::io_context ioc{1};

    // 配置 SSL 上下文（服务器）。
    ssl::context ssl_ctx(ssl::context::tlsv12_server);
    ssl_ctx.set_options(ssl::context::default_workarounds |
                        ssl::context::no_sslv2 |
                        ssl::context::no_sslv3 |
                        ssl::context::single_dh_use);

    try {
        ssl_ctx.use_certificate_chain_file(cert_file);
        ssl_ctx.use_private_key_file(key_file, ssl::context::pem);
    } catch (std::exception& e) {
        std::cerr << "Failed to load cert/key: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    // 设置 ALPN 回调，选择 h2。
    SSL_CTX_set_alpn_select_cb(ssl_ctx.native_handle(), alpn_select_cb, nullptr);

    net::ip::tcp::acceptor acceptor(ioc, {address, port});
    acceptor.set_option(net::ip::tcp::acceptor::reuse_address(true));

    std::cout << "HTTP/2 TLS server listening on " << address << ":" << port << std::endl;

    net::co_spawn(ioc,
        [&acceptor, &ssl_ctx]() -> net::awaitable<void> {
            co_await listener(acceptor, ssl_ctx);
        },
        net::detached);

    ioc.run();

    return 0;
}
