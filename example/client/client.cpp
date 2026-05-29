//
// client.cpp
// ~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

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
#include <boost/asio/ssl.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <h2x/h2.hpp>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using namespace h2x;
using namespace std::chrono_literals;

// 执行一个简单的 HTTP/2 GET 请求（TLS）.
net::awaitable<void> do_request(const std::string& host, const std::string& port, bool insecure)
{
    boost::system::error_code ec;

    // 创建 SSL 上下文，配置 TLS.
    ssl::context ssl_ctx(ssl::context::tlsv12_client);

    if (insecure) {
        // 跳过证书验证（仅用于本地测试）.
        ssl_ctx.set_verify_mode(ssl::verify_none);
    } else {
        // macOS 上需要显式加载 CA 证书文件.
        ssl_ctx.load_verify_file("/etc/ssl/cert.pem");
        ssl_ctx.set_verify_mode(ssl::verify_peer);
    }

    // 设置 ALPN 协议为 h2（HTTP/2 over TLS 必须）.
    SSL_CTX_set_alpn_protos(ssl_ctx.native_handle(),
        reinterpret_cast<const unsigned char*>("\x02h2"), 3);

    // 连接到服务器.
    net::ip::tcp::resolver resolver(co_await net::this_coro::executor);
    auto endpoints = co_await resolver.async_resolve(host, port, net_awaitable[ec]);
    if (ec) {
        std::cerr << "Resolve error: " << ec.message() << std::endl;
        co_return;
    }

    // 创建 SSL 流.
    using ssl_stream = ssl::stream<net::ip::tcp::socket>;
    ssl_stream ssl_sock(co_await net::this_coro::executor, ssl_ctx);

    // 设置 SNI（Server Name Indication）.
    if (!SSL_set_tlsext_host_name(ssl_sock.native_handle(), host.c_str())) {
        std::cerr << "SNI setup failed" << std::endl;
        co_return;
    }

    // TCP 连接.
    co_await net::async_connect(ssl_sock.lowest_layer(), endpoints, net_awaitable[ec]);
    if (ec) {
        std::cerr << "Connect error: " << ec.message() << std::endl;
        co_return;
    }

    // TLS 握手.
    co_await ssl_sock.async_handshake(ssl::stream_base::client, net_awaitable[ec]);
    if (ec) {
        std::cerr << "TLS handshake error: " << ec.message() << std::endl;
        co_return;
    }

    // 验证 ALPN 协商结果.
    const unsigned char* alpn_data = nullptr;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl_sock.native_handle(), &alpn_data, &alpn_len);
    if (alpn_data && alpn_len > 0) {
        std::string alpn_proto(reinterpret_cast<const char*>(alpn_data), alpn_len);
        std::cout << "ALPN negotiated: " << alpn_proto << std::endl;
        if (alpn_proto != "h2") {
            std::cerr << "Server did not negotiate h2, got: " << alpn_proto << std::endl;
            co_return;
        }
    } else {
        std::cerr << "No ALPN negotiated" << std::endl;
        co_return;
    }

    std::cout << "Connected to " << host << ":" << port << " (TLS)" << std::endl;

    // 使用 shared_ptr 管理连接生命周期，防止 pump 协程访问已销毁对象.
    using conn_type = connection<ssl_stream>;
    auto conn = std::make_shared<conn_type>(std::move(ssl_sock));

    // 配置客户端设置.
    auto s = std::make_shared<settings>();
    s->header_table_size = 4096;
    s->max_concurrent_streams = 1;
    s->initial_window_size = 65535;
    s->max_frame_size = 16384;

    // 执行 HTTP/2 握手，握手完成后泵送协程在后台自动运行.
    {
        boost::system::error_code hs_ec;
        co_await conn->async_handshake(role::client, *s, hs_ec);
        if (hs_ec) {
            std::cerr << "Handshake error: " << hs_ec.message() << std::endl;
            co_return;
        }
    }

    // 创建请求流.
    auto req_result = co_await conn->async_request();
    if (!req_result.has_value()) {
        std::cerr << "Failed to create request stream: "
                  << req_result.error().message() << std::endl;
        co_return;
    }
    auto stream = std::move(req_result.value());

    // 发送请求头.
    std::vector<std::pair<std::string, std::string>> headers = {
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "https"},
        {":authority", host},
        {"user-agent", "h2x/1.0"},
        {"accept", "*/*"},
    };

    ec = co_await stream.async_write_headers(headers, true);
    if (ec) {
        std::cerr << "Write headers error: " << ec.message() << std::endl;
        co_return;
    }

    std::cout << "Request sent, waiting for response..." << std::endl;

    // 读取响应头.
    auto hdr_result = co_await stream.async_read_headers();
    if (!hdr_result.has_value()) {
        std::cerr << "Read headers error: "
                  << hdr_result.error().message() << std::endl;
        co_return;
    }

    std::cout << "\n=== Response headers ===" << std::endl;
    for (auto& h : hdr_result.value()) {
        if (h.name_ && h.value_) {
            std::cout << "  " << *h.name_ << ": " << *h.value_ << std::endl;
        }
    }

    // 读取响应体.
    std::cout << "\n=== Response body ===" << std::endl;
    bool has_data = false;
    while (!stream.is_done()) {
        auto data_result = co_await stream.async_read_data();
        if (!data_result.has_value()) {
            auto err = data_result.error();
            if (err == make_error_code(errc::stream_closed)) {
                break;
            }
            std::cerr << "Read data error: " << err.message() << std::endl;
            co_return;
        }

        auto& data = data_result.value();
        if (data.empty()) {
            break;
        }

        has_data = true;
        std::cout.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
    if (has_data) std::cout << std::endl;

    std::cout << "\n=== Request completed ===" << std::endl;

    // 优雅关闭：先关闭连接，再等待 pump 退出.
    conn->close();

    // 等待 pump 协程完全退出（超时 3 秒）.
    if (!co_await conn->async_wait_pump(3s)) {
        std::cerr << "Warning: pump did not exit within timeout" << std::endl;
    }
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cerr << "Usage: client <host> <port> [--insecure]\n"
                  << "Example:\n"
                  << "    client nghttp2.org 443\n"
                  << "    client localhost 8443 --insecure\n";
        return EXIT_FAILURE;
    }

    std::string host = argv[1], port = argv[2];
    bool insecure = (argc >= 4 && std::string(argv[3]) == "--insecure");

    net::io_context ioc{1};

    net::co_spawn(ioc, do_request(host, port, insecure), net::detached);

    ioc.run();

    return 0;
}
