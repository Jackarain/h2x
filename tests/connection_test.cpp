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
    int dup_headers = 0;      // 同一头部块内自引用动态表索引解出的条数.
    uint8_t observed_frame_type = 0;   // 服务端观测到的客户端回帧类型.
    uint32_t observed_error_code = 0;  // 上述回帧携带的错误码 (RST/GOAWAY).
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

// ── 构造原始帧并模拟"带 PADDED/PRIORITY 前缀的分片响应头"服务端 ──

// 组装一个裸帧 (9 字节头 + payload).
static std::vector<uint8_t> build_raw_frame(uint32_t sid, uint8_t type,
    uint8_t flags, const uint8_t* payload, size_t len)
{
    std::vector<uint8_t> f(9 + len, 0);
    f[0] = (len >> 16) & 0xFF;
    f[1] = (len >> 8) & 0xFF;
    f[2] = len & 0xFF;
    f[3] = type;
    f[4] = flags;
    f[5] = (sid >> 24) & 0x7F;
    f[6] = (sid >> 16) & 0xFF;
    f[7] = (sid >> 8) & 0xFF;
    f[8] = sid & 0xFF;
    if (len) {
        std::memcpy(f.data() + 9, payload, len);
    }
    return f;
}

// 服务端: 握手后把响应 HEADERS 拆成 "HEADERS(PADDED|PRIORITY, END_HEADERS 未置位)
// + CONTINUATION". 回归: 前缀+padding 的偏移计算必须正确, 否则会构造反向区间.
static net::awaitable<void> run_fragmented_headers_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) { st.error = "server: read preface: " + ec.message(); co_return; }

    if ((co_await read_frame(sock)).empty()) {
        st.error = "server: read client settings failed"; co_return;
    }
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if (ec) { st.error = "server: write settings: " + ec.message(); co_return; }

    if ((co_await read_frame(sock)).empty()) {
        st.error = "server: read client settings ack failed"; co_return;
    }
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);
    if (ec) { st.error = "server: write settings ack: " + ec.message(); co_return; }

    if ((co_await read_frame(sock)).empty()) {
        st.error = "server: read request failed"; co_return;
    }

    // 响应头块 (:status: 200).
    auto hb_frame = build_headers_frame(1, { {":status", "200"} }, false);
    std::vector<uint8_t> block(hb_frame.begin() + 9, hb_frame.end());
    const size_t split = block.size() / 2;

    // HEADERS payload: [pad_len][priority(5字节)][header_block 前半][padding].
    const uint8_t pad = 3;
    std::vector<uint8_t> p1;
    p1.push_back(pad);
    for (int i = 0; i < 5; ++i) p1.push_back(0);
    p1.insert(p1.end(), block.begin(), block.begin() + split);
    for (int i = 0; i < pad; ++i) p1.push_back(0);

    const uint8_t flags1 = static_cast<uint8_t>(frame_flag::PADDED)
        | static_cast<uint8_t>(frame_flag::PRIORITY);
    auto f1 = build_raw_frame(1, static_cast<uint8_t>(frame_type::HEADERS),
        flags1, p1.data(), p1.size());

    auto f2 = build_raw_frame(1, static_cast<uint8_t>(frame_type::CONTINUATION),
        static_cast<uint8_t>(frame_flag::END_HEADERS),
        block.data() + split, block.size() - split);

    co_await net::async_write(sock, net::buffer(f1), net_awaitable[ec]);
    if (ec) { st.error = "server: write headers: " + ec.message(); co_return; }
    co_await net::async_write(sock, net::buffer(f2), net_awaitable[ec]);
    if (ec) { st.error = "server: write continuation: " + ec.message(); co_return; }

    // 空 DATA + END_STREAM 结束响应.
    auto endf = build_data_frame(1, "", true);
    co_await net::async_write(sock, net::buffer(endf), net_awaitable[ec]);
    if (ec) { st.error = "server: write end: " + ec.message(); co_return; }

    // 让客户端读完后自然关闭.
    std::vector<uint8_t> ignore(1);
    co_await net::async_read(sock, net::buffer(ignore), net_awaitable[ec]);
}

// 客户端: 发请求并校验能从分片头部块中解出 :status 200, 且读到干净 EOF.
static net::awaitable<void> run_fragmented_headers_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (!req.has_value()) {
        st.error = "client: async_request: " + req.error().message(); co_return;
    }
    auto stream = std::move(req.value());

    ec = co_await stream.async_write_headers({
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, true);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    auto hdr = co_await stream.async_read_headers();
    if (!hdr.has_value()) {
        st.error = "client: read headers: " + hdr.error().message(); co_return;
    }
    for (auto& h : hdr.value()) {
        if (h.name_ && *h.name_ == ":status" && h.value_ && *h.value_ == "200") {
            st.headers_ok = true;
        }
    }

    auto data = co_await stream.async_read_data();
    if (!data.has_value()) {
        st.error = "client: read data: " + data.error().message(); co_return;
    }
    st.clean_eof = data.value().empty();

    conn->close();
    co_await conn->async_wait_pump(3s);
}

// 服务端: 接收一个大头部块 (会被拆成 HEADERS + CONTINUATION) 且带
// END_STREAM 的请求, 校验能读到干净的流结束.
static net::awaitable<void> run_large_headers_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::server, s, ec);
    if (ec) { st.error = "server: handshake: " + ec.message(); co_return; }

    auto res = co_await conn->async_accept_stream();
    if (!res.has_value()) {
        st.error = "server: accept: " + res.error().message(); co_return;
    }
    auto stream = std::move(res.value());

    auto hdr = co_await stream.async_read_headers();
    if (!hdr.has_value()) {
        st.error = "server: read headers: " + hdr.error().message(); co_return;
    }
    st.headers_ok = true;

    auto data = co_await stream.async_read_data();
    if (!data.has_value()) {
        st.error = "server: read data: " + data.error().message(); co_return;
    }
    st.clean_eof = data.value().empty();

    conn->close();
    co_await conn->async_wait_pump(3s);
}

// 客户端: 发送一个超过默认帧长的请求头且 end_stream=true.
static net::awaitable<void> run_large_headers_client(
    net::ip::tcp::socket sock)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) co_return;

    auto req = co_await conn->async_request();
    if (!req.has_value()) co_return;
    auto stream = std::move(req.value());

    std::string big(40000, 'x');
    ec = co_await stream.async_write_headers({
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"}, {"x-big", big},
    }, true);
    (void)ec;

    // 等待服务端判定结束并停止 io_context.
}

// 构造只含一个设置项的 SETTINGS 帧.
static std::vector<uint8_t> build_settings_entry(uint16_t id, uint32_t value)
{
    std::vector<uint8_t> buf(64, 0);
    settings_frame sf(buf.data(), buf.size(), false);
    sf.entries_.clear();
    sf.entries_.emplace_back(static_cast<settings_id>(id), value);
    int total = sf.pack_settings();
    buf.resize(static_cast<size_t>(total));
    return buf;
}

// 服务端: 发送 MAX_FRAME_SIZE=0 的非法 SETTINGS.
static net::awaitable<void> run_bad_settings_server(net::ip::tcp::socket sock)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) co_return;

    (void)co_await read_frame(sock);   // 客户端 SETTINGS.

    auto bad = build_settings_entry(
        static_cast<uint16_t>(settings_id::SETTINGS_MAX_FRAME_SIZE), 0);
    co_await net::async_write(sock, net::buffer(bad), net_awaitable[ec]);

    // 若客户端错误地接受了非法设置, 会回 SETTINGS ACK 并等待本端 ACK;
    // 这里补发 ACK, 使"未修复"路径能完成握手 (从而暴露问题).
    (void)co_await read_frame(sock);
    auto ack = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(ack), net_awaitable[ec]);
}

// 客户端: 非法 SETTINGS 必须导致握手失败.
static net::awaitable<void> run_bad_settings_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (!ec) {
        st.error = "handshake unexpectedly succeeded with MAX_FRAME_SIZE=0";
        conn->close();
        co_return;
    }
    conn->close();
}


// 服务端: 响应头块内部先以增量索引加入 "x-a: b", 再引用索引 62 (刚加入的
// 表项). 解码器必须按顺序在解析过程中更新动态表, 否则索引 62 无法解析.
static net::awaitable<void> run_self_reference_server(net::ip::tcp::socket sock)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) co_return;

    if ((co_await read_frame(sock)).empty()) co_return;
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if (ec) co_return;

    if ((co_await read_frame(sock)).empty()) co_return;
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);
    if (ec) co_return;

    if ((co_await read_frame(sock)).empty()) co_return;

    // HPACK: 0x88 (:status 200)
    //       0x40 0x03 "x-a" 0x01 "b"  -> 增量索引加入, 成为索引 62
    //       0xBE                       -> 引用索引 62
    const std::vector<uint8_t> block = {
        0x88,
        0x40, 0x03, 'x', '-', 'a', 0x01, 'b',
        0xBE,
    };
    auto hf = build_raw_frame(1, static_cast<uint8_t>(frame_type::HEADERS),
        static_cast<uint8_t>(frame_flag::END_HEADERS), block.data(), block.size());
    co_await net::async_write(sock, net::buffer(hf), net_awaitable[ec]);
    if (ec) co_return;

    auto endf = build_data_frame(1, "", true);
    co_await net::async_write(sock, net::buffer(endf), net_awaitable[ec]);

    std::vector<uint8_t> ignore(1);
    co_await net::async_read(sock, net::buffer(ignore), net_awaitable[ec]);
}

// 客户端: 校验同一头部块内的动态表自引用能被正确解析.
static net::awaitable<void> run_self_reference_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (!req.has_value()) {
        st.error = "client: async_request: " + req.error().message(); co_return;
    }
    auto stream = std::move(req.value());

    ec = co_await stream.async_write_headers({
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, true);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    auto hdr = co_await stream.async_read_headers();
    if (!hdr.has_value()) {
        st.error = "client: read headers: " + hdr.error().message(); co_return;
    }
    for (auto& h : hdr.value()) {
        if (h.name_ && *h.name_ == ":status" && h.value_ && *h.value_ == "200") {
            st.headers_ok = true;
        }
        if (h.name_ && *h.name_ == "x-a" && h.value_ && *h.value_ == "b") {
            ++st.dup_headers;
        }
    }

    auto data = co_await stream.async_read_data();
    if (!data.has_value()) {
        st.error = "client: read data: " + data.error().message(); co_return;
    }
    st.clean_eof = data.value().empty();

    conn->close();
    co_await conn->async_wait_pump(3s);
}


// 服务端: 收到请求后发送一个必然溢出流级窗口的 WINDOW_UPDATE,
// 并记录客户端回送的帧类型与错误码.
static net::awaitable<void> run_window_overflow_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) co_return;

    if ((co_await read_frame(sock)).empty()) co_return;
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if (ec) co_return;

    if ((co_await read_frame(sock)).empty()) co_return;
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);
    if (ec) co_return;

    if ((co_await read_frame(sock)).empty()) co_return;

    // WINDOW_UPDATE(stream 1, 2^31-1): 65535 + (2^31-1) 超过 2^31-1.
    std::vector<uint8_t> wu(13, 0);
    window_update_frame wuf(wu.data(), wu.size(), false);
    wuf.stream_id(1);
    wuf.type(frame_type::WINDOW_UPDATE);
    wuf.set_window_increment(0x7FFFFFFF);
    wuf.pack_payload();
    co_await net::async_write(sock, net::buffer(wu), net_awaitable[ec]);
    if (ec) co_return;

    auto resp = co_await read_frame(sock);
    if (resp.size() >= 9) {
        st.observed_frame_type = resp[3];
        st.observed_error_code = (static_cast<uint32_t>(resp[9]) << 24)
            | (static_cast<uint32_t>(resp[10]) << 16)
            | (static_cast<uint32_t>(resp[11]) << 8)
            | static_cast<uint32_t>(resp[12]);
    }

    sock.close();
}

// 客户端: 打开一条流后等待, 由服务端的越界 WINDOW_UPDATE 触发流错误.
static net::awaitable<void> run_window_overflow_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (!req.has_value()) {
        st.error = "client: async_request: " + req.error().message(); co_return;
    }
    auto stream = std::move(req.value());

    ec = co_await stream.async_write_headers({
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, true);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    // 让 pump 处理 WINDOW_UPDATE (越界只应重置该流).
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(300ms);
    co_await timer.async_wait(net_awaitable[ec]);

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

// 回归: CONTINUATION 分片累积时 padding 与前缀偏移必须匹配,
// 否则会以反向区间 insert (未定义行为).
BOOST_AUTO_TEST_CASE(fragmented_headers_padding_priority)
{
    net::io_context ioc(1);
    connection_test_state st;

    net::ip::tcp::acceptor acceptor(
        ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    auto port = acceptor.local_endpoint().port();

    net::steady_timer watchdog(ioc);
    watchdog.expires_after(10s);
    watchdog.async_wait([&](boost::system::error_code ec) {
        if (!ec) { st.error = "test timeout"; ioc.stop(); }
    });

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        auto sock = co_await acceptor.async_accept(net_awaitable[ec]);
        if (ec) { st.error = "accept: " + ec.message(); ioc.stop(); co_return; }
        co_await run_fragmented_headers_server(std::move(sock), st);
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_fragmented_headers_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK(st.headers_ok);
    BOOST_CHECK(st.clean_eof);
}

// 回归: HEADERS 头部块超过帧长上限被拆成 CONTINUATION 时, END_STREAM
// 必须由首帧 HEADERS 携带 (CONTINUATION 无该标志), 否则对端永远读不到结束.
BOOST_AUTO_TEST_CASE(large_headers_end_stream_over_continuation)
{
    net::io_context ioc(1);
    connection_test_state st;

    net::ip::tcp::acceptor acceptor(
        ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    auto port = acceptor.local_endpoint().port();

    net::steady_timer watchdog(ioc);
    watchdog.expires_after(10s);
    watchdog.async_wait([&](boost::system::error_code ec) {
        if (!ec) { st.error = "test timeout"; ioc.stop(); }
    });

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        auto sock = co_await acceptor.async_accept(net_awaitable[ec]);
        if (ec) { st.error = "accept: " + ec.message(); ioc.stop(); co_return; }
        co_await run_large_headers_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_large_headers_client(std::move(sock));
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK(st.headers_ok);
    BOOST_CHECK(st.clean_eof);
}

// 回归: 对端 SETTINGS_MAX_FRAME_SIZE 非法 (0) 时必须作为连接错误拒绝,
// 不能被接受 (否则后续发送会因 max_payload=0 空转).
BOOST_AUTO_TEST_CASE(peer_settings_invalid_max_frame_size)
{
    net::io_context ioc(1);
    connection_test_state st;

    net::ip::tcp::acceptor acceptor(
        ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    auto port = acceptor.local_endpoint().port();

    net::steady_timer watchdog(ioc);
    watchdog.expires_after(10s);
    watchdog.async_wait([&](boost::system::error_code ec) {
        if (!ec) { st.error = "test timeout"; ioc.stop(); }
    });

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        auto sock = co_await acceptor.async_accept(net_awaitable[ec]);
        if (ec) { st.error = "accept: " + ec.message(); ioc.stop(); co_return; }
        co_await run_bad_settings_server(std::move(sock));
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_bad_settings_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
}

// 回归: 同一头部块内先用增量索引加入表项, 再引用该表项 (索引 62),
// 解码器必须边解析边更新动态表; 否则索引越界触发 COMPRESSION_ERROR.
BOOST_AUTO_TEST_CASE(hpack_self_reference_within_block)
{
    net::io_context ioc(1);
    connection_test_state st;

    net::ip::tcp::acceptor acceptor(
        ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    auto port = acceptor.local_endpoint().port();

    net::steady_timer watchdog(ioc);
    watchdog.expires_after(10s);
    watchdog.async_wait([&](boost::system::error_code ec) {
        if (!ec) { st.error = "test timeout"; ioc.stop(); }
    });

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        auto sock = co_await acceptor.async_accept(net_awaitable[ec]);
        if (ec) { st.error = "accept: " + ec.message(); ioc.stop(); co_return; }
        co_await run_self_reference_server(std::move(sock));
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_self_reference_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK(st.headers_ok);
    BOOST_CHECK_EQUAL(st.dup_headers, 2);
    BOOST_CHECK(st.clean_eof);
}
// 回归: 流级 WINDOW_UPDATE 使流窗口超过 2^31-1 时, 必须只重置该流
// (RST_STREAM FLOW_CONTROL_ERROR), 不能以 GOAWAY 中断整条连接.
BOOST_AUTO_TEST_CASE(stream_window_update_overflow_rst_stream)
{
    net::io_context ioc(1);
    connection_test_state st;

    net::ip::tcp::acceptor acceptor(
        ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    auto port = acceptor.local_endpoint().port();

    net::steady_timer watchdog(ioc);
    watchdog.expires_after(10s);
    watchdog.async_wait([&](boost::system::error_code ec) {
        if (!ec) { st.error = "test timeout"; ioc.stop(); }
    });

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        auto sock = co_await acceptor.async_accept(net_awaitable[ec]);
        if (ec) { st.error = "accept: " + ec.message(); ioc.stop(); co_return; }
        co_await run_window_overflow_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_window_overflow_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::RST_STREAM));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::FLOW_CONTROL_ERROR));
}
BOOST_AUTO_TEST_SUITE_END()

} // namespace h2x
