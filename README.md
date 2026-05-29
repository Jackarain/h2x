
# h2x — HTTP/2 实现（C++20）

h2x 是一个使用现代 C++（C++20）与 Boost.Asio 协程风格实现的轻量 HTTP/2 库。
它实现了 HTTP/2 的核心功能（帧处理、HPACK、流与窗口管理），并提供可插拔的传输层模板 `connection<NextLayer>`，使得同一套实现可在 TLS（`ssl::stream<tcp::socket>`）或裸 TCP 上复用。

主要特性

- HTTP/2 帧的编码与解码（HEADERS/DATA/SETTINGS/PRIORITY/PING/GOAWAY 等）。
- HPACK 编解码（包含静态表与 Huffman 支持）。
- 基于 `boost::asio` 的 awaitable 协程接口，使用 `co_await` / `co_spawn` 编写异步逻辑。
- 模板化的 `connection<NextLayer>` 与 `stream` 设计，NextLayer 可选 TLS 或 TCP。
- 提供示例：TLS client/server 与纯 TCP client/server（见 `example/`）。

目录结构（摘要）

- `include/h2x/`：库头文件，公共入口 `include/h2x/h2.hpp`。
- `example/`：示例程序：`client`/`server`（TLS），`tcp_client`/`tcp_server`（纯 TCP）。
- `third_party/`：部分第三方依赖（OpenSSL、Boost 等）。

快速上手

依赖：CMake、ninja（可选）、编译器支持 C++20、OpenSSL 与 Boost（仓库包含部分第三方以便构建）。

从仓库根目录示例构建：

```bash
cmake -S . -B build -G Ninja
cmake --build build -j
```

运行示例

- TLS server（需要证书和私钥）：

```bash
./build/bin/server 0.0.0.0 8443 /path/to/server.crt /path/to/server.key
```

- TLS client（示例：请求 nghttp2.org）：

```bash
./build/bin/client nghttp2.org 443
```

- 纯 TCP server（用于本地测试 HTTP/2 prior-knowledge）：

```bash
./build/bin/tcp_server 0.0.0.0 8080
```

- 纯 TCP client（连接本地 `tcp_server`）：

```bash
./build/bin/tcp_client localhost 8080
```

测试说明

- TLS 示例已在本地与 `nghttp2.org` 做过互通测试，ALPN 协商为 `h2`。
- 纯 TCP 示例采用 HTTP/2 prior-knowledge（不使用 ALPN），适合在受控环境或本地测试使用。

开发者指南

- 核心头文件：
  - `include/h2x/h2_connection.hpp`：`connection<NextLayer>` 的实现（帧收发、流管理、pump 协程）。
  - `include/h2x/h2_stream.hpp`：`stream` 的声明与对 `connection` 的外联实现。
  - `include/h2x/h2_frame.hpp`：帧与 HPACK 编解码实现。
- 推荐阅读示例：`example/server/server.cpp` 与 `example/client/client.cpp`。

贡献与沟通

- 欢迎通过 issue / pull request 贡献。提交 PR 时请附带可复现的用例和说明。

许可证

- 本项目采用 Boost Software License 1.0（详见仓库中的 `LICENSE` 文件）。
