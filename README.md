
# h2x — HTTP/2 实现（C++20）

h2x 是一个使用现代 C++（C++20）与 Boost.Asio 协程支持实现的轻量 HTTP/2 库。

## h2x 简介

h2x 库主要提供一套现代 C++ API 设计的 HTTP2 库，是一个轻量级的 H2 协议库，通过非常现代的分层设计理念实现协议与传输的解耦，让你感受到从未有过如此轻松就能驾驭 HTTP2 的 C++ 开发相关的工作。

开发 h2x 的初衷是因为主流开源的 HTTP2 库的使用极为复杂，往往需要了解非常复杂的 API 设计，以及十分繁琐易错的各种细节设定，还需要编写大量与业务无关的代码才能够勉强使用，并且还常常因为其设计流程会导致业务本身嵌入十分困难和割裂，显得喧宾夺主。

## 快速上手

``` text
编译环境依赖：CMake、ninja（可选）、编译器支持 C++20 协程
```

从仓库根目录示例构建：

```bash
cmake -S . -B build -G Ninja
cmake --build build -j
```

## 用法示例

### TLS 客户端 — 发送 HTTP/2 GET 请求

以下代码展示如何使用 h2x 库通过 TLS 发起 HTTP/2 请求（完整代码见 `example/client/client.cpp`）。

``` cpp
#include <h2x/h2.hpp>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using namespace h2x;

net::awaitable<void> do_request(const std::string& host,
                                const std::string& port)
{
    boost::system::error_code ec;

    // 1. 创建 SSL 上下文并设置 ALPN 为 h2.
    ssl::context ssl_ctx(ssl::context::tlsv12_client);
    ssl_ctx.load_verify_file("/etc/ssl/cert.pem");
    ssl_ctx.set_verify_mode(ssl::verify_peer);
    SSL_CTX_set_alpn_protos(ssl_ctx.native_handle(),
        reinterpret_cast<const unsigned char*>("\x02h2"), 3);

    // 2. TCP 连接 + TLS 握手.
    net::ip::tcp::resolver resolver(co_await net::this_coro::executor);
    auto endpoints = co_await resolver.async_resolve(host, port, net_awaitable[ec]);

    using ssl_stream = ssl::stream<net::ip::tcp::socket>;
    ssl_stream ssl_sock(co_await net::this_coro::executor, ssl_ctx);
    co_await net::async_connect(ssl_sock.lowest_layer(), endpoints, net_awaitable[ec]);
    co_await ssl_sock.async_handshake(ssl::stream_base::client, net_awaitable[ec]);

    // 3. 创建 connection<ssl_stream> 并执行 HTTP/2 握手.
    using conn_type = connection<ssl_stream>;
    auto conn = std::make_shared<conn_type>(std::move(ssl_sock));

    auto s = std::make_shared<settings>();
    s->header_table_size = 4096;
    s->max_concurrent_streams = 1;
    s->initial_window_size = 65535;

    co_await conn->async_handshake(role::client, *s, ec);
    // 握手完成后，pump 协程在后台自动收发帧, 关闭这个 conn 时需要等待 pump 协程退出.

    // 4. 创建请求流并发送请求头.
    auto req_result = co_await conn->async_request();
    auto stream = std::move(req_result.value());

    std::vector<std::pair<std::string, std::string>> headers = {
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "https"},
        {":authority", host},
        {"user-agent", "h2x/1.0"},
    };
    co_await stream.async_write_headers(headers, true);  // end_stream = true

    // 5. 读取响应头.
    auto hdr_result = co_await stream.async_read_headers();
    for (auto& h : hdr_result.value()) {
        if (h.name_ && h.value_)
            std::cout << *h.name_ << ": " << *h.value_ << std::endl;
    }

    // 6. 读取响应体.
    while (!stream.is_done()) {
        auto data_result = co_await stream.async_read_data();
        if (!data_result.has_value()) break;
        auto& data = data_result.value();
        if (data.empty()) break;
        std::cout.write(
            reinterpret_cast<const char*>(data.data()), data.size());
    }

    // 7. 清理.
    conn->close();
    // 8. 等待 connection 的 pump 协程退出.
    co_await conn->async_wait_pump(3s);
}
```

### TLS 服务器 — 接收 HTTP/2 请求

以下代码展示如何使用 h2x 库搭建 TLS HTTP/2 服务器（完整代码见 `example/server/server.cpp`）。

``` cpp
#include <h2x/h2.hpp>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using namespace h2x;

using ssl_stream = ssl::stream<net::ip::tcp::socket>;
using conn_type = connection<ssl_stream>;
using stream_type = conn_type::stream_type;

// 处理单个 HTTP/2 请求.
net::awaitable<void> handle_http_request(stream_type stream)
{
    // 1. 读取请求头.
    auto hdr_result = co_await stream.async_read_headers();
    auto& headers = hdr_result.value();

    // 2. 解析伪头并打印.
    for (auto& h : headers) {
        if (h.name_ && h.value_)
            std::cout << *h.name_ << ": " << *h.value_ << std::endl;
    }

    // 3. 发送响应头.
    std::vector<std::pair<std::string, std::string>> resp_headers = {
        {":status", "200"},
        {"content-type", "application/json"},
        {"server", "h2x-server"},
    };
    co_await stream.async_write_headers(resp_headers, false);

    // 4. 发送响应体并关闭流.
    std::string body = R"({"message": "Hello HTTP/2!"})";
    co_await stream.async_write_data(body, true);  // end_stream = true

    // 您要做的其它业务...略
}

// 处理一个 TLS 会话.
net::awaitable<void> server_session(ssl_stream ssl_sock)
{
    // 1. 创建 connection 并握手.
    auto conn = std::make_shared<conn_type>(std::move(ssl_sock));
    auto s = std::make_shared<settings>();
    s->header_table_size = 4096;
    s->max_concurrent_streams = 100;
    s->initial_window_size = 65535;

    boost::system::error_code hs_ec;
    co_await conn->async_handshake(role::server, *s, hs_ec);
    // 握手完成后 pump 协程在后台自动运行, 关闭这个 conn 时需要等待 pump 协程退出.

    // 2. 循环接受新的请求流.
    while (true) {
        auto res = co_await conn->async_accept_stream();
        if (!res) break;  // 连接关闭或出错

        // 为每个请求启动独立协程.
        net::co_spawn(co_await net::this_coro::executor,
            handle_http_request(std::move(res.value())),
            net::detached);
    }

    // 3. 清理.
    conn->close();
    // 4. 等待 connection 的 pump 协程退出.
    co_await conn->async_wait_pump(3s);
}
```

### 纯 TCP 模式

h2x 的 `connection<NextLayer>` 是基于分层设计的模板化实现，只需将 `NextLayer` 替换为 `net::ip::tcp::socket` 即可用于纯 TCP 场景（无需 TLS）。

详细代码见 `example/server/tcp_server.cpp` 和 `example/client/tcp_client.cpp`。

```cpp
// TCP 服务端 —— 只需要替换模板参数.
using conn_type = connection<net::ip::tcp::socket>;
using stream_type = conn_type::stream_type;

// TCP 客户端 —— 不需要 SSL 上下文和 ALPN.
net::ip::tcp::socket sock(co_await net::this_coro::executor);
co_await net::async_connect(sock, endpoints, net_awaitable[ec]);

using conn_type = connection<net::ip::tcp::socket>;
auto conn = std::make_shared<conn_type>(std::move(sock));
co_await conn->async_handshake(role::client, *s, hs_ec);
// 后续 API 用法与 TLS 版本完全一致.
```

纯 TCP 模式采用 HTTP/2 prior-knowledge（不使用 ALPN），适合在受控环境或本地测试使用。

## 贡献与沟通

- 欢迎通过 issue / pull request 贡献，提交 PR 时请附带可复现的用例和说明。

## 许可证

- 本项目采用 Boost Software License 1.0（详见仓库中的 `LICENSE` 文件）。
