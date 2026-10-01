//
// fuzz_connection.cc
// ~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Connection/session-level fuzz harness for h2x.
//
// Mirrors nghttp2's fuzz/fuzz_target.cc and fuzz/fuzz_target_fdp.cc: instead of
// feeding bytes to the individual frame parsers, arbitrary bytes are injected
// as the *peer* side of a real HTTP/2 connection and the whole state machine
// (handshake, SETTINGS negotiation, frame dispatch, stream lifecycle, HPACK
// encode/decode, flow control) is driven to completion.
//
// The peer side is a connected AF_UNIX socket pair, so no network and no extra
// thread are needed; one io_context drives a single iteration.
//
// Build (see fuzz/CMakeLists.txt and fuzz/README.md):
//   cmake -DCMAKE_CXX_COMPILER=clang++ -DENABLE_BUILD_FUZZ=ON ../..
//   make fuzz_connection
//
// Run:
//   ./bin/fuzz_connection -max_len=16384 fuzz/corpora/fuzz_connection
//

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/connect_pair.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include "h2x/h2.hpp"

namespace net = boost::asio;
using namespace h2x;
using namespace std::chrono_literals;

namespace {

using sock_t = net::local::stream_protocol::socket;
using conn_t = connection<sock_t>;
using conn_ptr = std::shared_ptr<conn_t>;

constexpr std::chrono::milliseconds kWatchdog{2000};

// -----------------------------------------------------------------------
//  从 fuzz 数据合成对端报文
// -----------------------------------------------------------------------

uint8_t pick(const uint8_t* data, size_t size, size_t idx, uint8_t fallback)
{
    return size > 0 ? data[idx % size] : fallback;
}

std::vector<uint8_t> pack_settings(
    const std::vector<std::pair<uint16_t, uint32_t>>& entries, bool ack)
{
    std::vector<uint8_t> buf(64 + entries.size() * 6, 0);
    settings_frame sf(buf.data(), buf.size(), false);
    sf.ack_ = ack;
    sf.entries_.clear();
    for (auto& [id, value] : entries)
        sf.entries_.emplace_back(static_cast<settings_id>(id), value);
    buf.resize(static_cast<size_t>(sf.pack_settings()));
    return buf;
}

// 本端 settings: 取值保持在合法范围内, 避免掩盖协议逻辑路径.
settings make_settings(const uint8_t* data, size_t size)
{
    static const uint32_t table_sizes[] = {0, 64, 4096, 8192, 65536};
    static const uint32_t windows[] = {0, 1, 1024, 65535, 1u << 20};
    static const uint32_t frames[] = {16384, 32768, 65536, 1u << 20};

    settings s;
    s.header_table_size = table_sizes[pick(data, size, 0, 0) % 5];
    s.enable_push = (pick(data, size, 1, 0) & 1) != 0;
    s.max_concurrent_streams = pick(data, size, 2, 0) % 101;
    s.initial_window_size = windows[pick(data, size, 3, 0) % 5];
    s.max_frame_size = frames[pick(data, size, 4, 0) % 4];
    s.max_header_list_size = (pick(data, size, 5, 0) & 1) ? (1u << 20) : 0;
    s.no_rfc7540_priorities = (pick(data, size, 6, 0) & 1) != 0;
    s.enable_connect_protocol = (pick(data, size, 7, 0) & 1) != 0;
    return s;
}

// 对端 SETTINGS 项: 覆盖合法边界、非法取值与未知标识, 以 fuzz 设置校验逻辑.
std::vector<std::pair<uint16_t, uint32_t>> make_settings_entries(
    const uint8_t* data, size_t size, size_t offset)
{
    static const uint16_t ids[] = {
        0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x8, 0x9, 0xA0, 0x1009,
    };
    static const uint32_t values[] = {
        0, 1, 2, 3, 100, 16383, 16384, 16385, 65535, 65536,
        0x7FFFFFFFu, 0x7FFFFFFFu + 1u, 0xFFFFFFu, 0xFFFFFFu + 1u, 0xFFFFFFFFu,
    };

    std::vector<std::pair<uint16_t, uint32_t>> out;
    size_t n = 1 + (pick(data, size, offset, 0) % 8);
    for (size_t i = 0; i < n; ++i) {
        uint16_t id = ids[pick(data, size, offset + 1 + i * 2, 0) % 10];
        uint32_t value = values[pick(data, size, offset + 2 + i * 2, 0) % 15];
        out.emplace_back(id, value);
    }
    return out;
}

// -----------------------------------------------------------------------
//  对端与本地应用协程
// -----------------------------------------------------------------------

// 对端: 写出注入字节 -> 半关闭发送方向 -> 读走 h2x 的全部输出.
net::awaitable<void> feed(sock_t& peer, std::vector<uint8_t> input)
{
    boost::system::error_code ec;

    if (!input.empty()) {
        co_await net::async_write(peer, net::buffer(input), net_awaitable[ec]);
        if (ec)
            co_return;
    }

    // 半关闭: 使 h2x 的 pump_in 读到 EOF 并退出, 保证本轮迭代收敛.
    peer.shutdown(net::socket_base::shutdown_send, ec);

    std::vector<uint8_t> sink(4096);
    for (;;) {
        auto n = co_await peer.async_read_some(net::buffer(sink), net_awaitable[ec]);
        if (ec || n == 0)
            break;
    }
    co_return;
}

// 服务端应用侧: 接受流, 读请求, 回响应, 直到连接结束.
net::awaitable<void> serve(conn_ptr conn)
{
    boost::system::error_code ec;

    for (;;) {
        auto accepted = co_await conn->async_accept_stream();
        if (!accepted.has_value())
            break;

        auto stream = std::move(accepted.value());

        auto headers = co_await stream.async_read_headers();
        if (headers.has_value()) {
            (void)co_await stream.async_write_headers(
                {{":status", "200"}, {"server", "h2x-fuzz"}}, false);
        }

        for (;;) {
            auto chunk = co_await stream.async_read_data();
            if (!chunk.has_value() || chunk.value().empty())
                break;
        }

        (void)co_await stream.async_write_data("ok", true);
    }

    co_return;
}

// 客户端应用侧: 发起若干请求并读完响应.
net::awaitable<void> request(conn_ptr conn, size_t count)
{
    boost::system::error_code ec;

    for (size_t i = 0; i < count; ++i) {
        auto created = co_await conn->async_request();
        if (!created.has_value())
            break;

        auto stream = std::move(created.value());

        ec = co_await stream.async_write_headers({
            {":method", "GET"},
            {":path", "/"},
            {":scheme", "https"},
            {":authority", "fuzz.local"},
        }, true);
        if (ec)
            break;

        auto headers = co_await stream.async_read_headers();
        if (!headers.has_value())
            break;

        for (;;) {
            auto chunk = co_await stream.async_read_data();
            if (!chunk.has_value() || chunk.value().empty())
                break;
        }
    }

    co_return;
}

net::awaitable<void> drive(conn_ptr conn, settings local, role r, size_t requests)
{
    boost::system::error_code ec;

    co_await conn->async_handshake(r, local, ec);
    if (!ec) {
        if (r == role::server)
            co_await serve(conn);
        else
            co_await request(conn, requests);
    }

    conn->close();
    co_await conn->async_wait_pump(500ms);
    co_return;
}

// -----------------------------------------------------------------------
//  单次迭代
// -----------------------------------------------------------------------

void run_iteration(const uint8_t* data, size_t size)
{
    net::io_context ioc(1);

    sock_t a(ioc), b(ioc);
    net::local::connect_pair(a, b);

    auto conn = std::make_shared<conn_t>(std::move(a));

    const uint8_t mode = pick(data, size, 0, 0) % 3;
    const bool as_client = (pick(data, size, 1, 0) & 0x80) != 0;
    const settings local = make_settings(data, size);

    // 模式 0: 原始字节, 直接 fuzz 握手; 模式 1/2: 合成合法握手前缀后 fuzz pump.
    std::vector<uint8_t> input;
    if (mode != 0) {
        auto entries = (mode == 2)
            ? make_settings_entries(data, size, 8)
            : std::vector<std::pair<uint16_t, uint32_t>>{};

        if (!as_client) {
            input.insert(input.end(), global_client_preface,
                global_client_preface + global_client_preface_len);
        }
        auto settings_bytes = pack_settings(entries, false);
        input.insert(input.end(), settings_bytes.begin(), settings_bytes.end());

        auto ack_bytes = pack_settings({}, true);
        input.insert(input.end(), ack_bytes.begin(), ack_bytes.end());
    }
    input.insert(input.end(), data, data + size);

    net::steady_timer watchdog(ioc);
    watchdog.expires_after(kWatchdog);
    watchdog.async_wait([&](boost::system::error_code ec) {
        if (ec)
            return;
        conn->close();
        boost::system::error_code ignored;
        b.close(ignored);
    });

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        co_await feed(b, std::move(input));
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        co_await drive(conn, local, as_client ? role::client : role::server,
            1 + mode);
        boost::system::error_code ignored;
        b.close(ignored);
        watchdog.cancel();
    }, net::detached);

    ioc.run();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
        return 0;

    try {
        run_iteration(data, size);
    } catch (const std::exception&) {
    } catch (...) {
    }

    return 0;
}
