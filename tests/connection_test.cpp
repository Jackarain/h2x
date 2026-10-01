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
    size_t streams_left = 0;           // 客户端空闲后仍被跟踪的流数量.
    bool handshake_failed = false;     // 握手是否按预期失败.
    int handshake_errc = 0;            // 握手失败时的 error_code 数值.
    std::vector<uint8_t> header_prefix; // 客户端发出的首个头部块前缀.
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
    st.streams_left = conn->stream_count();

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

// 服务端: 发送一项指定取值的 SETTINGS, 用于校验对端设置合法性.
static net::awaitable<void> run_bad_settings_server(
    net::ip::tcp::socket sock, uint16_t id, uint32_t value)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) co_return;

    (void)co_await read_frame(sock);   // 客户端 SETTINGS.

    auto bad = build_settings_entry(id, value);
    co_await net::async_write(sock, net::buffer(bad), net_awaitable[ec]);

    // 若客户端错误地接受了非法设置, 会回 SETTINGS ACK 并等待本端 ACK;
    // 这里补发 ACK, 使"未修复"路径能完成握手 (从而暴露问题).
    (void)co_await read_frame(sock);
    auto ack = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(ack), net_awaitable[ec]);
}

// 客户端: 非法 SETTINGS 必须导致握手失败, 并记录 error_code.
static net::awaitable<void> run_bad_settings_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (!ec) {
        st.error = "handshake unexpectedly succeeded with invalid settings";
        conn->close();
        co_return;
    }
    st.handshake_errc = ec.value();
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


// 服务端: 收到请求后发送一个"实际数据小于窗口、但总负载(含 padding)
// 超过窗口"的 DATA 帧. 流控必须计入 Pad Length 与 Padding (RFC 7540 §6.9.1).
static net::awaitable<void> run_padded_data_server(
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

    // 90 字节数据 + 1 字节 pad length + 20 字节 padding = 111 > 窗口 100.
    std::vector<uint8_t> buf(9 + 1 + 90 + 20, 0);
    data_frame df(buf.data(), buf.size(), false);
    df.stream_id(1);
    df.type(frame_type::DATA);
    df.set_data(std::vector<uint8_t>(90, 'z'));
    df.set_pad_length(20);
    df.pack_payload();
    buf.resize(df.frame_size());
    co_await net::async_write(sock, net::buffer(buf), net_awaitable[ec]);
    if (ec) co_return;

    auto resp = co_await read_frame(sock);
    if (resp.size() >= 13) {
        st.observed_frame_type = resp[3];
        st.observed_error_code = (static_cast<uint32_t>(resp[9]) << 24)
            | (static_cast<uint32_t>(resp[10]) << 16)
            | (static_cast<uint32_t>(resp[11]) << 8)
            | static_cast<uint32_t>(resp[12]);
    }

    sock.close();
}

// 客户端: 声明较小的初始窗口 (100), 使带 padding 的 DATA 超限.
static net::awaitable<void> run_padded_data_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    s.initial_window_size = 100;
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
    }, false);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(300ms);
    co_await timer.async_wait(net_awaitable[ec]);

    conn->close();
    co_await conn->async_wait_pump(3s);
}


// 服务端: 在 SETTINGS 中声明 MAX_CONCURRENT_STREAMS=0.
static net::awaitable<void> run_zero_concurrency_server(net::ip::tcp::socket sock)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) co_return;

    if ((co_await read_frame(sock)).empty()) co_return;
    auto sf = build_settings_entry(
        static_cast<uint16_t>(settings_id::SETTINGS_MAX_CONCURRENT_STREAMS), 0);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if (ec) co_return;

    if ((co_await read_frame(sock)).empty()) co_return;
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);

    std::vector<uint8_t> ignore(1);
    co_await net::async_read(sock, net::buffer(ignore), net_awaitable[ec]);
}

// 客户端: 对端 MAX_CONCURRENT_STREAMS=0 时 async_request 必须失败.
static net::awaitable<void> run_zero_concurrency_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (req.has_value()) {
        st.error = "async_request unexpectedly succeeded with peer limit 0";
        st.observed_error_code = 0;
    } else {
        st.observed_error_code =
            static_cast<uint32_t>(req.error().value());
    }

    conn->close();
    co_await conn->async_wait_pump(3s);
}


// 服务端: 以 max_concurrent_streams=0 完成握手. 客户端把请求 HEADERS
// 紧跟在 SETTINGS 之后流水线发送, 这些帧在握手期间就会被处理.
static net::awaitable<void> run_pipelined_headers_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    s.max_concurrent_streams = 0;
    co_await conn->async_handshake(role::server, s, ec);
    if (ec) { st.error = "server: handshake: " + ec.message(); co_return; }

    // 等待 pump 把握手期间排队的 RST_STREAM 发出.
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(300ms);
    co_await timer.async_wait(net_awaitable[ec]);

    conn->close();
    co_await conn->async_wait_pump(3s);
}

// 裸客户端: preface + SETTINGS + 立即流水线 HEADERS.
static net::awaitable<void> run_pipelined_headers_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    co_await net::async_write(sock,
        net::buffer(global_client_preface, global_client_preface_len), net_awaitable[ec]);
    if (ec) { st.error = "client: write preface: " + ec.message(); co_return; }

    auto cs = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(cs), net_awaitable[ec]);

    auto hf = build_headers_frame(1, {
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, true);
    co_await net::async_write(sock, net::buffer(hf), net_awaitable[ec]);

    for (int i = 0; i < 8; ++i) {
        auto f = co_await read_frame(sock);
        if (f.size() < 9) break;
        if (f.size() >= 13
            && f[3] == static_cast<uint8_t>(frame_type::RST_STREAM)) {
            st.observed_frame_type = f[3];
            st.observed_error_code = (static_cast<uint32_t>(f[9]) << 24)
                | (static_cast<uint32_t>(f[10]) << 16)
                | (static_cast<uint32_t>(f[11]) << 8)
                | static_cast<uint32_t>(f[12]);
            break;
        }
        if (f[3] == static_cast<uint8_t>(frame_type::SETTINGS)
            && !(f[4] & static_cast<uint8_t>(frame_flag::FLAG_ACK))) {
            auto ack = build_settings_frame(true);
            co_await net::async_write(sock, net::buffer(ack), net_awaitable[ec]);
        }
    }
    sock.close();
}


// 服务端: 收到请求后发送增量非法 (0) 的 WINDOW_UPDATE.
static net::awaitable<void> run_zero_window_update_server(
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

    // 手工构造 WINDOW_UPDATE(sid=1, increment=0); set_window_increment 会拒绝 0.
    const uint8_t payload[4] = { 0, 0, 0, 0 };
    auto wu = build_raw_frame(1, static_cast<uint8_t>(frame_type::WINDOW_UPDATE),
        0, payload, sizeof(payload));
    co_await net::async_write(sock, net::buffer(wu), net_awaitable[ec]);
    if (ec) co_return;

    auto resp = co_await read_frame(sock);
    if (resp.size() >= 13) {
        st.observed_frame_type = resp[3];
        st.observed_error_code = (static_cast<uint32_t>(resp[9]) << 24)
            | (static_cast<uint32_t>(resp[10]) << 16)
            | (static_cast<uint32_t>(resp[11]) << 8)
            | static_cast<uint32_t>(resp[12]);
    }

    sock.close();
}

// 客户端: 增量 0 的 WINDOW_UPDATE 应触发流错误 PROTOCOL_ERROR, 且连接存活.
static net::awaitable<void> run_zero_window_update_client(
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

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(300ms);
    co_await timer.async_wait(net_awaitable[ec]);

    // 连接未被中止: 仍可发起新流 (不会被 abort_ 挡住).
    if (conn->stream_count() == 0) {
        st.error = "client: connection appears to have been torn down";
    }

    conn->close();
    co_await conn->async_wait_pump(3s);
}


// 服务端: 正常握手后, 由客户端发来的非法 SETTINGS 触发连接错误 GOAWAY.
static net::awaitable<void> run_goaway_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::server, s, ec);
    if (ec) { st.error = "server: handshake: " + ec.message(); co_return; }

    // 等待 pump 处理客户端随后的非法 SETTINGS 并发出 GOAWAY.
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(500ms);
    co_await timer.async_wait(net_awaitable[ec]);

    conn->close();
    co_await conn->async_wait_pump(3s);
}

// 裸客户端: 完成握手后发送非法 SETTINGS, 期望收到 GOAWAY(FRAME_SIZE_ERROR).
static net::awaitable<void> run_goaway_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    co_await net::async_write(sock,
        net::buffer(global_client_preface, global_client_preface_len), net_awaitable[ec]);
    if (ec) { st.error = "client: write preface: " + ec.message(); co_return; }

    auto cs = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(cs), net_awaitable[ec]);

    // 读取服务端 SETTINGS 并回 ACK.
    for (int i = 0; i < 4; ++i) {
        auto f = co_await read_frame(sock);
        if (f.size() < 9) break;
        if (f[3] == static_cast<uint8_t>(frame_type::SETTINGS)
            && !(f[4] & static_cast<uint8_t>(frame_flag::FLAG_ACK))) {
            auto ack = build_settings_frame(true);
            co_await net::async_write(sock, net::buffer(ack), net_awaitable[ec]);
        } else if (f[3] == static_cast<uint8_t>(frame_type::SETTINGS)) {
            break;   // 服务端 SETTINGS ACK → 握手完成.
        }
    }

    // 非法 SETTINGS: MAX_FRAME_SIZE=0 → 服务端应 GOAWAY(PROTOCOL_ERROR).
    auto bad = build_settings_entry(
        static_cast<uint16_t>(settings_id::SETTINGS_MAX_FRAME_SIZE), 0);
    co_await net::async_write(sock, net::buffer(bad), net_awaitable[ec]);
    if (ec) co_return;

    for (int i = 0; i < 4; ++i) {
        auto f = co_await read_frame(sock);
        if (f.size() < 17) break;
        if (f[3] == static_cast<uint8_t>(frame_type::GOAWAY)) {
            st.observed_frame_type = f[3];
            // GOAWAY 负载: [last_stream_id(4)][error_code(4)].
            st.observed_error_code = (static_cast<uint32_t>(f[13]) << 24)
                | (static_cast<uint32_t>(f[14]) << 16)
                | (static_cast<uint32_t>(f[15]) << 8)
                | static_cast<uint32_t>(f[16]);
            break;
        }
    }
    sock.close();
}


// 裸服务端: 握手后发送 stream id 为 0 的 HEADERS (非法).
static net::awaitable<void> run_stream_zero_server(
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

    const uint8_t block[1] = { 0x88 };   // :status: 200
    auto hf = build_raw_frame(0, static_cast<uint8_t>(frame_type::HEADERS),
        static_cast<uint8_t>(frame_flag::END_HEADERS), block, sizeof(block));
    co_await net::async_write(sock, net::buffer(hf), net_awaitable[ec]);
    if (ec) co_return;

    for (int i = 0; i < 4; ++i) {
        auto f = co_await read_frame(sock);
        if (f.size() < 17) break;
        if (f[3] == static_cast<uint8_t>(frame_type::GOAWAY)) {
            st.observed_frame_type = f[3];
            st.observed_error_code = (static_cast<uint32_t>(f[13]) << 24)
                | (static_cast<uint32_t>(f[14]) << 16)
                | (static_cast<uint32_t>(f[15]) << 8)
                | static_cast<uint32_t>(f[16]);
            break;
        }
    }
    sock.close();
}

// 客户端: 收到 stream 0 的 HEADERS 必须作为连接错误拒绝.
static net::awaitable<void> run_stream_zero_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(300ms);
    co_await timer.async_wait(net_awaitable[ec]);

    // 不得为非法帧创建流 0.
    if (conn->stream_count() != 0) {
        st.error = "client: stream 0 was created";
    }

    conn->close();
    co_await conn->async_wait_pump(3s);
}


// 裸服务端: 握手后发送 stream id 非 0 的 SETTINGS (非法).
static net::awaitable<void> run_settings_nonzero_sid_server(
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

    std::vector<uint8_t> buf(64, 0);
    settings_frame bad(buf.data(), buf.size(), false);
    bad.entries_.clear();
    int total = bad.pack_settings();
    buf.resize(static_cast<size_t>(total));
    // pack_settings 会强制 stream id 为 0, 手工篡改为 1 以构造非法帧.
    buf[5] = 0; buf[6] = 0; buf[7] = 0; buf[8] = 1;
    co_await net::async_write(sock, net::buffer(buf), net_awaitable[ec]);
    if (ec) co_return;

    for (int i = 0; i < 4; ++i) {
        auto f = co_await read_frame(sock);
        if (f.size() < 17) break;
        if (f[3] == static_cast<uint8_t>(frame_type::GOAWAY)) {
            st.observed_frame_type = f[3];
            st.observed_error_code = (static_cast<uint32_t>(f[13]) << 24)
                | (static_cast<uint32_t>(f[14]) << 16)
                | (static_cast<uint32_t>(f[15]) << 8)
                | static_cast<uint32_t>(f[16]);
            break;
        }
    }
    sock.close();
}

// 客户端: 仅完成握手并等待处理非法帧.
static net::awaitable<void> run_settings_nonzero_sid_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

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
    BOOST_CHECK_EQUAL(st.streams_left, 0u);
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

// 运行一个"握手期非法 SETTINGS"场景: 服务端发送单项设置, 断言客户端
// 以 PROTOCOL_ERROR 拒绝握手.
static void run_settings_rejection_case(uint16_t id, uint32_t value)
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
        co_await run_bad_settings_server(std::move(sock), id, value);
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
    BOOST_CHECK_EQUAL(st.handshake_errc,
        make_error_code(errc::protocol_error).value());
}

// 回归: 对端 SETTINGS_MAX_FRAME_SIZE 非法 (0) 时必须作为连接错误拒绝,
// 且错误类型必须是 PROTOCOL_ERROR (RFC 9113 §6.5.2), 不能被接受
// (否则后续发送会因 max_payload=0 空转).
BOOST_AUTO_TEST_CASE(peer_settings_invalid_max_frame_size)
{
    run_settings_rejection_case(
        static_cast<uint16_t>(settings_id::SETTINGS_MAX_FRAME_SIZE), 0);
}

// 回归: 服务端不得把 SETTINGS_ENABLE_PUSH 显式设为 1, 客户端收到后必须
// 作为连接错误 PROTOCOL_ERROR 处理 (RFC 9113 §6.5.2).
BOOST_AUTO_TEST_CASE(server_enable_push_rejected)
{
    run_settings_rejection_case(
        static_cast<uint16_t>(settings_id::SETTINGS_ENABLE_PUSH), 1);
}

// 回归: SETTINGS_ENABLE_PUSH 取值超出 0/1 属连接错误 PROTOCOL_ERROR
// (RFC 9113 §6.5.2).
BOOST_AUTO_TEST_CASE(enable_push_out_of_range_rejected)
{
    run_settings_rejection_case(
        static_cast<uint16_t>(settings_id::SETTINGS_ENABLE_PUSH), 2);
}

// 回归: SETTINGS_ENABLE_CONNECT_PROTOCOL 取值必须是 0 或 1
// (RFC 8441 §3), 其它取值属连接错误 PROTOCOL_ERROR.
BOOST_AUTO_TEST_CASE(enable_connect_protocol_out_of_range_rejected)
{
    run_settings_rejection_case(
        static_cast<uint16_t>(settings_id::SETTINGS_ENABLE_CONNECT_PROTOCOL), 2);
}

// 回归: SETTINGS_NO_RFC7540_PRIORITIES 取值必须是 0 或 1
// (RFC 9218 §2.1), 其它取值属连接错误 PROTOCOL_ERROR.
BOOST_AUTO_TEST_CASE(no_rfc7540_priorities_out_of_range_rejected)
{
    run_settings_rejection_case(
        static_cast<uint16_t>(settings_id::SETTINGS_NO_RFC7540_PRIORITIES), 2);
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
// 回归: DATA 帧流控必须计入整个 payload (含 Pad Length 与 Padding),
// 否则 padding 膨胀可绕过流控窗口.
BOOST_AUTO_TEST_CASE(data_flow_control_counts_padding)
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
        co_await run_padded_data_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_padded_data_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::RST_STREAM));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::FLOW_CONTROL_ERROR));
}
// 回归: 不得超出对端 SETTINGS_MAX_CONCURRENT_STREAMS 发起新流 (RFC 7540 §5.1.2).
BOOST_AUTO_TEST_CASE(peer_max_concurrent_streams_enforced)
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
        co_await run_zero_concurrency_server(std::move(sock));
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_zero_concurrency_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(errc::too_many_streams));
}
// 回归: 握手期间收到的流水线帧必须使用调用方传入的 settings, 而不是
// 默认值; 否则 MAX_CONCURRENT_STREAMS 等限制对该窗口内的流失效.
BOOST_AUTO_TEST_CASE(pipelined_headers_use_configured_settings)
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
        co_await run_pipelined_headers_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_pipelined_headers_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::RST_STREAM));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::REFUSED_STREAM));
}
// 回归: 流级 WINDOW_UPDATE 增量为 0 是流错误 PROTOCOL_ERROR (RFC 7540 §6.9),
// 必须回 RST_STREAM 而非静默中断连接.
BOOST_AUTO_TEST_CASE(zero_increment_window_update_stream_error)
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
        co_await run_zero_window_update_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_zero_window_update_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::RST_STREAM));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::PROTOCOL_ERROR));
}
// 回归: 连接错误时排队的 GOAWAY 必须在关闭前真正发出, 否则对端只看到
// TCP 连接被重置 (无法区分错误原因).
BOOST_AUTO_TEST_CASE(connection_error_goaway_is_delivered)
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
        co_await run_goaway_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_goaway_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::GOAWAY));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::PROTOCOL_ERROR));
}
// 回归: HEADERS 的 stream id 为 0 是连接错误 (RFC 7540 §6.2), 客户端
// 不得把它当新流处理.
BOOST_AUTO_TEST_CASE(headers_on_stream_zero_rejected)
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
        co_await run_stream_zero_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_stream_zero_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::GOAWAY));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::PROTOCOL_ERROR));
}
// 回归: SETTINGS 的 stream id 必须为 0 (RFC 7540 §6.5), 否则连接错误.
BOOST_AUTO_TEST_CASE(settings_nonzero_stream_id_rejected)
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
        co_await run_settings_nonzero_sid_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_settings_nonzero_sid_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::GOAWAY));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::PROTOCOL_ERROR));
}

// 服务端: 已发送 END_STREAM 后仍发送 DATA, 观察客户端回帧.
static net::awaitable<void> run_data_after_end_stream_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) { st.error = "server: read preface: " + ec.message(); co_return; }
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings"; co_return; }
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings ack"; co_return; }
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no request"; co_return; }

    // 响应头带 END_STREAM, 随后非法再发一个 DATA.
    auto hf = build_headers_frame(1, {{":status", "200"}}, true);
    co_await net::async_write(sock, net::buffer(hf), net_awaitable[ec]);
    auto df = build_data_frame(1, "XYZ", false);
    co_await net::async_write(sock, net::buffer(df), net_awaitable[ec]);

    auto f = co_await read_frame(sock);
    if (f.size() >= 13) {
        st.observed_frame_type = f[3];
        st.observed_error_code = (uint32_t(f[9]) << 24) | (uint32_t(f[10]) << 16)
            | (uint32_t(f[11]) << 8) | f[12];
    }
    sock.close();
}

static net::awaitable<void> run_data_after_end_stream_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (!req.has_value()) { st.error = "client: async_request failed"; co_return; }
    auto stream = std::move(req.value());

    ec = co_await stream.async_write_headers({
        {":method", "POST"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, false);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    auto hdr = co_await stream.async_read_headers();
    if (!hdr.has_value()) { st.error = "client: read headers failed"; co_return; }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(200ms);
    co_await timer.async_wait(net_awaitable[ec]);

    auto d = co_await stream.async_read_data();
    st.body_bytes = d.has_value() ? d.value().size() : 0;

    conn->close();
    co_await conn->async_wait_pump(3s);
}

// 回归: 对端在 END_STREAM 之后发送的 DATA 必须以 RST_STREAM(STREAM_CLOSED) 拒绝,
// 且不得把该 DATA 交给应用 (RFC 9113 §6.1).
BOOST_AUTO_TEST_CASE(data_after_remote_end_stream_rejected)
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
        co_await run_data_after_end_stream_server(std::move(sock), st);
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_data_after_end_stream_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::RST_STREAM));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::STREAM_CLOSED));
    BOOST_CHECK_EQUAL(st.body_bytes, 0u);
}

// 服务端: 发送未置 END_HEADERS 的 HEADERS 后插入 PING, 观察客户端回帧.
static net::awaitable<void> run_interleaved_frame_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) { st.error = "server: read preface: " + ec.message(); co_return; }
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings"; co_return; }
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings ack"; co_return; }
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no request"; co_return; }

    // 响应头未置 END_HEADERS, 头部块在途期间插入一个合法 PING 帧.
    auto hf = build_headers_frame(1, {{":status", "200"}}, false);
    hf[4] = static_cast<uint8_t>(hf[4]
        & ~static_cast<uint8_t>(frame_flag::END_HEADERS));
    co_await net::async_write(sock, net::buffer(hf), net_awaitable[ec]);

    uint8_t ping_payload[8] = {0, 0, 0, 0, 0, 0, 0, 1};
    auto ping = build_raw_frame(0, static_cast<uint8_t>(frame_type::PING),
        0, ping_payload, sizeof(ping_payload));
    co_await net::async_write(sock, net::buffer(ping), net_awaitable[ec]);

    auto f = co_await read_frame(sock);
    if (f.size() >= 9) {
        st.observed_frame_type = f[3];
        if (f.size() >= 17) {
            st.observed_error_code = (static_cast<uint32_t>(f[13]) << 24)
                | (static_cast<uint32_t>(f[14]) << 16)
                | (static_cast<uint32_t>(f[15]) << 8)
                | static_cast<uint32_t>(f[16]);
        }
    }
    sock.close();
}

static net::awaitable<void> run_interleaved_frame_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (!req.has_value()) { st.error = "client: async_request failed"; co_return; }
    auto stream = std::move(req.value());

    ec = co_await stream.async_write_headers({
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, true);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(300ms);
    co_await timer.async_wait(net_awaitable[ec]);

    conn->close();
    co_await conn->async_wait_pump(3s);
}

// 回归: 头部块 (未置 END_HEADERS) 在途期间出现非 CONTINUATION 帧属于连接错误,
// 必须回 GOAWAY(PROTOCOL_ERROR) (RFC 9113 §6.10).
BOOST_AUTO_TEST_CASE(interleaved_frame_during_header_block_rejected)
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
        co_await run_interleaved_frame_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_interleaved_frame_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::GOAWAY));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::PROTOCOL_ERROR));
}

// 服务端: 握手后对从未开启的空闲流 bad_sid 发送 RST_STREAM, 观察客户端回帧.
static net::awaitable<void> run_idle_rst_server(
    net::ip::tcp::socket sock, connection_test_state& st, uint32_t bad_sid)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) { st.error = "server: read preface: " + ec.message(); co_return; }
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings"; co_return; }
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings ack"; co_return; }
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no request"; co_return; }

    uint8_t code[4] = {0, 0, 0, static_cast<uint8_t>(http2_error_code::CANCEL)};
    auto rst = build_raw_frame(bad_sid,
        static_cast<uint8_t>(frame_type::RST_STREAM), 0, code, sizeof(code));
    co_await net::async_write(sock, net::buffer(rst), net_awaitable[ec]);

    auto f = co_await read_frame(sock);
    if (f.size() >= 9) {
        st.observed_frame_type = f[3];
        if (f.size() >= 17) {
            st.observed_error_code = (static_cast<uint32_t>(f[13]) << 24)
                | (static_cast<uint32_t>(f[14]) << 16)
                | (static_cast<uint32_t>(f[15]) << 8)
                | static_cast<uint32_t>(f[16]);
        }
    }
    sock.close();
}

static net::awaitable<void> run_idle_rst_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (!req.has_value()) { st.error = "client: async_request failed"; co_return; }
    auto stream = std::move(req.value());

    ec = co_await stream.async_write_headers({
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, true);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(300ms);
    co_await timer.async_wait(net_awaitable[ec]);

    conn->close();
    co_await conn->async_wait_pump(3s);
}

// 运行一个"空闲流 RST_STREAM"场景, 断言客户端回 GOAWAY(PROTOCOL_ERROR).
static void run_idle_rst_case(uint32_t bad_sid)
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
        co_await run_idle_rst_server(std::move(sock), st, bad_sid);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_idle_rst_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::GOAWAY));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::PROTOCOL_ERROR));
}

// 回归: 对从未开启的本端流 (奇数) 发送 RST_STREAM 是连接错误 (RFC 9113 §6.4).
BOOST_AUTO_TEST_CASE(rst_stream_on_idle_local_stream_rejected)
{
    run_idle_rst_case(5);
}

// 回归: 对从未开启的对端流 (偶数) 发送 RST_STREAM 也是连接错误.
BOOST_AUTO_TEST_CASE(rst_stream_on_idle_peer_stream_rejected)
{
    run_idle_rst_case(2);
}

// 服务端: 握手后发送一个畸形帧, 观察客户端是否回错误帧而非静默断连.
static net::awaitable<void> run_bad_frame_server(
    net::ip::tcp::socket sock, connection_test_state& st,
    std::vector<uint8_t> bad_frame)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) { st.error = "server: read preface: " + ec.message(); co_return; }
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings"; co_return; }
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings ack"; co_return; }
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);

    co_await net::async_write(sock, net::buffer(bad_frame), net_awaitable[ec]);

    // 客户端可能先发出请求 HEADERS, 因此持续读取直到看到 GOAWAY.
    for (int i = 0; i < 6; ++i) {
        auto f = co_await read_frame(sock);
        if (f.size() < 9) break;
        if (f[3] == static_cast<uint8_t>(frame_type::GOAWAY) && f.size() >= 17) {
            st.observed_frame_type = f[3];
            st.observed_error_code = (static_cast<uint32_t>(f[13]) << 24)
                | (static_cast<uint32_t>(f[14]) << 16)
                | (static_cast<uint32_t>(f[15]) << 8)
                | static_cast<uint32_t>(f[16]);
            break;
        }
    }
    sock.close();
}

static net::awaitable<void> run_bad_frame_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (!req.has_value()) { st.error = "client: async_request failed"; co_return; }
    auto stream = std::move(req.value());
    ec = co_await stream.async_write_headers({
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, true);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(300ms);
    co_await timer.async_wait(net_awaitable[ec]);

    conn->close();
    co_await conn->async_wait_pump(3s);
}

// 运行一个"畸形帧"场景, 断言客户端回 GOAWAY 且错误码为 expected.
static void run_bad_frame_case(
    std::vector<uint8_t> bad_frame, http2_error_code expected)
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
        co_await run_bad_frame_server(std::move(sock), st, std::move(bad_frame));
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_bad_frame_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::GOAWAY));
    BOOST_CHECK_EQUAL(st.observed_error_code, static_cast<uint32_t>(expected));
}

// 回归: 长度非法的帧必须回错误帧而非静默断连 (RFC 9113 §4.2/§6.5).
BOOST_AUTO_TEST_CASE(malformed_ping_length_returns_frame_size_error)
{
    uint8_t p4[4] = {1, 2, 3, 4};
    run_bad_frame_case(
        build_raw_frame(0, static_cast<uint8_t>(frame_type::PING), 0, p4, sizeof(p4)),
        http2_error_code::FRAME_SIZE_ERROR);
}

// 回归: DATA 的 padding 非法属连接错误, 必须回 GOAWAY(PROTOCOL_ERROR)
// (RFC 9113 §6.1).
BOOST_AUTO_TEST_CASE(malformed_data_padding_returns_protocol_error)
{
    uint8_t pad[1] = {5};  // pad length 5 >= payload size 1
    run_bad_frame_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::DATA),
            static_cast<uint8_t>(frame_flag::PADDED), pad, sizeof(pad)),
        http2_error_code::PROTOCOL_ERROR);
}

// 回归: 带 payload 的 SETTINGS ACK 属连接错误 FRAME_SIZE_ERROR (RFC 9113 §6.5).
BOOST_AUTO_TEST_CASE(settings_ack_with_payload_rejected)
{
    uint8_t ack_payload[6] = {0, 1, 0, 0, 0x10, 0};
    run_bad_frame_case(
        build_raw_frame(0, static_cast<uint8_t>(frame_type::SETTINGS),
            static_cast<uint8_t>(frame_flag::FLAG_ACK), ack_payload, sizeof(ack_payload)),
        http2_error_code::FRAME_SIZE_ERROR);
}

// 服务端: 握手期间对客户端 SETTINGS 回带 payload 的 ACK (非法).
static net::awaitable<void> run_handshake_bad_ack_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) { st.error = "server: read preface: " + ec.message(); co_return; }
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings"; co_return; }
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings ack"; co_return; }

    uint8_t ack_payload[6] = {0, 1, 0, 0, 0x10, 0};
    auto bad = build_raw_frame(0, static_cast<uint8_t>(frame_type::SETTINGS),
        static_cast<uint8_t>(frame_flag::FLAG_ACK), ack_payload, sizeof(ack_payload));
    co_await net::async_write(sock, net::buffer(bad), net_awaitable[ec]);

    for (int i = 0; i < 6; ++i) {
        auto f = co_await read_frame(sock);
        if (f.size() < 9) break;
        if (f[3] == static_cast<uint8_t>(frame_type::GOAWAY) && f.size() >= 17) {
            st.observed_frame_type = f[3];
            st.observed_error_code = (static_cast<uint32_t>(f[13]) << 24)
                | (static_cast<uint32_t>(f[14]) << 16)
                | (static_cast<uint32_t>(f[15]) << 8)
                | static_cast<uint32_t>(f[16]);
            break;
        }
    }
    sock.close();
}

static net::awaitable<void> run_handshake_bad_ack_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    st.handshake_failed = static_cast<bool>(ec) &&
        (ec == make_error_code(errc::frame_size_error));

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(200ms);
    boost::system::error_code ignored;
    co_await timer.async_wait(net_awaitable[ignored]);
}

// 回归: 握手期间收到带 payload 的 SETTINGS ACK 必须立即回 GOAWAY(FRAME_SIZE_ERROR)
// 并使握手失败 (RFC 9113 §6.5).
BOOST_AUTO_TEST_CASE(handshake_settings_ack_with_payload_rejected)
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
        co_await run_handshake_bad_ack_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_handshake_bad_ack_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_MESSAGE(st.handshake_failed, "handshake should fail with frame_size_error");
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::GOAWAY));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::FRAME_SIZE_ERROR));
}

// 服务端: 通告 HEADER_TABLE_SIZE=0, 检查客户端下一个头部块是否以其开头.
static net::awaitable<void> run_table_size_update_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) { st.error = "server: read preface: " + ec.message(); co_return; }
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings"; co_return; }

    auto sf = build_settings_entry(
        static_cast<uint16_t>(settings_id::SETTINGS_HEADER_TABLE_SIZE), 0);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings ack"; co_return; }
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);

    for (int i = 0; i < 6; ++i) {
        auto f = co_await read_frame(sock);
        if (f.size() < 10) break;
        if (f[3] == static_cast<uint8_t>(frame_type::HEADERS)) {
            // 头部块首字节应为动态表大小更新 (0x20).
            st.header_prefix.push_back(f[9]);
            break;
        }
    }
    sock.close();
}

static net::awaitable<void> run_table_size_update_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (!req.has_value()) { st.error = "client: async_request failed"; co_return; }
    auto stream = std::move(req.value());
    ec = co_await stream.async_write_headers({
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, true);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(300ms);
    co_await timer.async_wait(net_awaitable[ec]);

    conn->close();
    co_await conn->async_wait_pump(3s);
}

// 回归: 对端修改 SETTINGS_HEADER_TABLE_SIZE 后, 编码端必须在下一个头部块
// 开头发出动态表大小更新 (RFC 7541 §4.2/§6.3), 否则对端解码表会失步.
BOOST_AUTO_TEST_CASE(encoder_emits_dynamic_table_size_update)
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
        co_await run_table_size_update_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_table_size_update_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_REQUIRE(!st.header_prefix.empty());
    // 0b00100000 = 动态表大小更新, 值 0 (RFC 7541 §6.3).
    BOOST_CHECK_EQUAL(static_cast<int>(st.header_prefix[0]), 0x20);
}

// 回归: 头部块中非法 Huffman 填充/码字属解码错误, 必须回
// GOAWAY(COMPRESSION_ERROR) (RFC 9113 §4.3, RFC 7541 §5.2).
BOOST_AUTO_TEST_CASE(invalid_huffman_header_block_returns_compression_error)
{
    // 0x88 = :status 200 (静态索引 8);
    // 0x01 = 无索引字面量, 名字索引 1 (:authority);
    // 0x81 0x18 = H=1 长度 1 的 Huffman 字符串, 填充非法.
    uint8_t block[4] = {0x88, 0x01, 0x81, 0x18};
    run_bad_frame_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::HEADERS),
            static_cast<uint8_t>(frame_flag::END_HEADERS), block, sizeof(block)),
        http2_error_code::COMPRESSION_ERROR);
}


// ── 帧校验矩阵 (对照 nghttp2_frame_test.c 的 iv_check) ──
// RFC 9113 §4.2/§6: 各帧类型的载荷长度与流标识符约束, 违反者属连接错误.
// 参考 nghttp2 的 fuzz_target 与 session 校验路径, 这些分支此前没有连接级测试.

BOOST_AUTO_TEST_CASE(rst_stream_bad_length_returns_frame_size_error)
{
    // RST_STREAM 载荷必须恰为 4 字节 (RFC 9113 §6.4).
    uint8_t payload[3] = {0, 0, 0};
    run_bad_frame_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::RST_STREAM), 0,
            payload, sizeof(payload)),
        http2_error_code::FRAME_SIZE_ERROR);
}

BOOST_AUTO_TEST_CASE(priority_bad_length_returns_frame_size_error)
{
    // PRIORITY 载荷必须恰为 5 字节 (RFC 9113 §6.3).
    uint8_t payload[4] = {0, 0, 0, 0};
    run_bad_frame_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::PRIORITY), 0,
            payload, sizeof(payload)),
        http2_error_code::FRAME_SIZE_ERROR);
}

BOOST_AUTO_TEST_CASE(goaway_bad_length_returns_frame_size_error)
{
    // GOAWAY 载荷至少 8 字节 (RFC 9113 §6.8).
    uint8_t payload[7] = {0};
    run_bad_frame_case(
        build_raw_frame(0, static_cast<uint8_t>(frame_type::GOAWAY), 0,
            payload, sizeof(payload)),
        http2_error_code::FRAME_SIZE_ERROR);
}

BOOST_AUTO_TEST_CASE(push_promise_bad_length_returns_frame_size_error)
{
    // PUSH_PROMISE 载荷至少 4 字节 (RFC 9113 §6.6).
    uint8_t payload[3] = {0, 0, 0};
    run_bad_frame_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::PUSH_PROMISE),
            static_cast<uint8_t>(frame_flag::END_HEADERS), payload, sizeof(payload)),
        http2_error_code::FRAME_SIZE_ERROR);
}

BOOST_AUTO_TEST_CASE(window_update_bad_length_returns_frame_size_error)
{
    // WINDOW_UPDATE 载荷必须恰为 4 字节 (RFC 9113 §6.9).
    uint8_t payload[3] = {0, 0, 1};
    run_bad_frame_case(
        build_raw_frame(0, static_cast<uint8_t>(frame_type::WINDOW_UPDATE), 0,
            payload, sizeof(payload)),
        http2_error_code::FRAME_SIZE_ERROR);
}

BOOST_AUTO_TEST_CASE(settings_bad_length_returns_frame_size_error)
{
    // SETTINGS 载荷长度必须是 6 的整数倍 (RFC 9113 §6.5).
    uint8_t payload[7] = {0};
    run_bad_frame_case(
        build_raw_frame(0, static_cast<uint8_t>(frame_type::SETTINGS), 0,
            payload, sizeof(payload)),
        http2_error_code::FRAME_SIZE_ERROR);
}

BOOST_AUTO_TEST_CASE(rst_stream_on_stream_zero_rejected)
{
    // RST_STREAM 必须关联到具体流 (RFC 9113 §6.4).
    uint8_t payload[4] = {0, 0, 0, 0};
    run_bad_frame_case(
        build_raw_frame(0, static_cast<uint8_t>(frame_type::RST_STREAM), 0,
            payload, sizeof(payload)),
        http2_error_code::PROTOCOL_ERROR);
}

BOOST_AUTO_TEST_CASE(priority_on_stream_zero_rejected)
{
    // PRIORITY 必须关联到具体流 (RFC 9113 §6.3).
    uint8_t payload[5] = {0, 0, 0, 0, 16};
    run_bad_frame_case(
        build_raw_frame(0, static_cast<uint8_t>(frame_type::PRIORITY), 0,
            payload, sizeof(payload)),
        http2_error_code::PROTOCOL_ERROR);
}

BOOST_AUTO_TEST_CASE(ping_nonzero_stream_id_rejected)
{
    // PING 只作用于连接, 流标识符必须为 0 (RFC 9113 §6.7).
    uint8_t payload[8] = {0};
    run_bad_frame_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::PING), 0,
            payload, sizeof(payload)),
        http2_error_code::PROTOCOL_ERROR);
}

BOOST_AUTO_TEST_CASE(connection_window_update_zero_increment_rejected)
{
    // 连接级 WINDOW_UPDATE 增量为 0 是连接错误 (RFC 9113 §6.9).
    uint8_t payload[4] = {0, 0, 0, 0};
    run_bad_frame_case(
        build_raw_frame(0, static_cast<uint8_t>(frame_type::WINDOW_UPDATE), 0,
            payload, sizeof(payload)),
        http2_error_code::PROTOCOL_ERROR);
}


// 回归: 没有在途头部块 (HEADERS/PUSH_PROMISE 未置 END_HEADERS) 时收到
// CONTINUATION 属连接错误 PROTOCOL_ERROR (RFC 9113 §6.10).
BOOST_AUTO_TEST_CASE(continuation_on_stream_zero_without_header_block_rejected)
{
    run_bad_frame_case(
        build_raw_frame(0, static_cast<uint8_t>(frame_type::CONTINUATION),
            static_cast<uint8_t>(frame_flag::END_HEADERS), nullptr, 0),
        http2_error_code::PROTOCOL_ERROR);
}

// 回归: 已存在的流上, 若没有在途的头部块, CONTINUATION 同样是连接错误.
BOOST_AUTO_TEST_CASE(continuation_without_header_block_on_stream_rejected)
{
    run_bad_frame_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::CONTINUATION),
            static_cast<uint8_t>(frame_flag::END_HEADERS), nullptr, 0),
        http2_error_code::PROTOCOL_ERROR);
}


// ── 空闲流 / 流标识符 / 推送校验 (RFC 9113 §5.1, §5.1.1, §6.6) ──
// 对照 nghttp2 session_on_data_received_fail_fast /
// session_on_stream_window_update_received / on_request_headers_received /
// on_push_promise_received 的校验路径.

// 回归: 空闲流上收到 DATA 属连接错误 PROTOCOL_ERROR (RFC 9113 §5.1).
BOOST_AUTO_TEST_CASE(data_on_idle_stream_rejected)
{
    run_bad_frame_case(
        build_raw_frame(2, static_cast<uint8_t>(frame_type::DATA), 0,
            nullptr, 0),
        http2_error_code::PROTOCOL_ERROR);
}

// 回归: 空闲流上收到 WINDOW_UPDATE 属连接错误 PROTOCOL_ERROR
// (RFC 9113 §5.1; nghttp2 "WINDOW_UPDATE to idle stream").
BOOST_AUTO_TEST_CASE(window_update_on_idle_stream_rejected)
{
    uint8_t inc[4] = {0, 0, 0, 1};
    run_bad_frame_case(
        build_raw_frame(2, static_cast<uint8_t>(frame_type::WINDOW_UPDATE), 0,
            inc, sizeof(inc)),
        http2_error_code::PROTOCOL_ERROR);
}

// 回归: 客户端收到服务端在空闲流上直接发起的 HEADERS (未经 PUSH_PROMISE)
// 属连接错误 PROTOCOL_ERROR (RFC 9113 §5.1).
BOOST_AUTO_TEST_CASE(headers_on_idle_server_initiated_stream_rejected)
{
    run_bad_frame_case(
        build_raw_frame(2, static_cast<uint8_t>(frame_type::HEADERS),
            static_cast<uint8_t>(frame_flag::END_HEADERS), nullptr, 0),
        http2_error_code::PROTOCOL_ERROR);
}

// 回归: 客户端已禁用推送 (SETTINGS_ENABLE_PUSH=0) 时收到 PUSH_PROMISE
// 属连接错误 PROTOCOL_ERROR (RFC 9113 §6.6).
BOOST_AUTO_TEST_CASE(push_promise_when_push_disabled_rejected)
{
    uint8_t payload[4] = {0, 0, 0, 2};  // promised stream id = 2
    run_bad_frame_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::PUSH_PROMISE),
            static_cast<uint8_t>(frame_flag::END_HEADERS), payload, sizeof(payload)),
        http2_error_code::PROTOCOL_ERROR);
}

// 回归: PUSH_PROMISE 的流标识符为 0 属连接错误 PROTOCOL_ERROR
// (RFC 9113 §6.6).
BOOST_AUTO_TEST_CASE(push_promise_on_stream_zero_rejected)
{
    uint8_t payload[4] = {0, 0, 0, 2};
    run_bad_frame_case(
        build_raw_frame(0, static_cast<uint8_t>(frame_type::PUSH_PROMISE),
            static_cast<uint8_t>(frame_flag::END_HEADERS), payload, sizeof(payload)),
        http2_error_code::PROTOCOL_ERROR);
}


// 服务端: 响应头带 END_STREAM 关闭远端方向后, 再发一个 HEADERS (非法).
static net::awaitable<void> run_headers_after_end_stream_server(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) { st.error = "server: read preface: " + ec.message(); co_return; }
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings"; co_return; }
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings ack"; co_return; }
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no request"; co_return; }

    // 响应头带 END_STREAM: 远端方向关闭, 流进入 half-closed(remote).
    auto hf = build_headers_frame(1, {{":status", "200"}}, true);
    co_await net::async_write(sock, net::buffer(hf), net_awaitable[ec]);

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(50ms);
    co_await timer.async_wait(net_awaitable[ec]);

    // 之后再发 HEADERS 属流错误 STREAM_CLOSED (RFC 9113 §5.1).
    auto hf2 = build_headers_frame(1, {{"x-trailer", "1"}}, true);
    co_await net::async_write(sock, net::buffer(hf2), net_awaitable[ec]);

    auto f = co_await read_frame(sock);
    if (f.size() >= 13) {
        st.observed_frame_type = f[3];
        st.observed_error_code = (uint32_t(f[9]) << 24) | (uint32_t(f[10]) << 16)
            | (uint32_t(f[11]) << 8) | f[12];
    }
    sock.close();
}

static net::awaitable<void> run_headers_after_end_stream_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    settings s;
    co_await conn->async_handshake(role::client, s, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (!req.has_value()) { st.error = "client: async_request failed"; co_return; }
    auto stream = std::move(req.value());

    // 不带 END_STREAM: 本端方向保持打开, 响应 END_STREAM 后流停留在
    // half-closed(remote), 不会被回收.
    ec = co_await stream.async_write_headers({
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, false);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    auto hdr = co_await stream.async_read_headers();
    if (!hdr.has_value()) { st.error = "client: read headers failed"; co_return; }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(150ms);
    co_await timer.async_wait(net_awaitable[ec]);

    conn->close();
    co_await conn->async_wait_pump(3s);
}

// 回归: 远端已发送 END_STREAM 后再收到 HEADERS 必须回 RST_STREAM
// (STREAM_CLOSED) 且不得交付字段 (RFC 9113 §5.1).
BOOST_AUTO_TEST_CASE(headers_after_remote_end_stream_rejected)
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
        co_await run_headers_after_end_stream_server(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_headers_after_end_stream_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::RST_STREAM));
    BOOST_CHECK_EQUAL(st.observed_error_code,
        static_cast<uint32_t>(http2_error_code::STREAM_CLOSED));
}


// ── HEADERS 前缀 / GOAWAY 流标识符校验 (RFC 9113 §4.2, §6.2, §6.8) ──

// 服务端: 握手并在收到客户端请求后, 发送一个畸形响应 HEADERS.
static net::awaitable<void> run_malformed_response_server(
    net::ip::tcp::socket sock, connection_test_state& st,
    std::vector<uint8_t> frame)
{
    boost::system::error_code ec;

    std::vector<uint8_t> preface(24);
    co_await net::async_read(sock, net::buffer(preface), net_awaitable[ec]);
    if (ec) { st.error = "server: read preface: " + ec.message(); co_return; }
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings"; co_return; }
    auto sf = build_settings_frame(false);
    co_await net::async_write(sock, net::buffer(sf), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no settings ack"; co_return; }
    auto sa = build_settings_frame(true);
    co_await net::async_write(sock, net::buffer(sa), net_awaitable[ec]);
    if ((co_await read_frame(sock)).empty()) { st.error = "server: no request"; co_return; }

    co_await net::async_write(sock, net::buffer(frame), net_awaitable[ec]);

    for (int i = 0; i < 6; ++i) {
        auto f = co_await read_frame(sock);
        if (f.size() < 9) break;
        if (f[3] == static_cast<uint8_t>(frame_type::GOAWAY) && f.size() >= 17) {
            st.observed_frame_type = f[3];
            st.observed_error_code = (static_cast<uint32_t>(f[13]) << 24)
                | (static_cast<uint32_t>(f[14]) << 16)
                | (static_cast<uint32_t>(f[15]) << 8)
                | static_cast<uint32_t>(f[16]);
            break;
        }
    }
    sock.close();
}

static net::awaitable<void> run_malformed_response_client(
    net::ip::tcp::socket sock, connection_test_state& st)
{
    boost::system::error_code ec;

    using conn_type = connection<net::ip::tcp::socket>;
    auto conn = std::make_shared<conn_type>(std::move(sock));

    co_await conn->async_handshake(role::client, settings{}, ec);
    if (ec) { st.error = "client: handshake: " + ec.message(); co_return; }

    auto req = co_await conn->async_request();
    if (!req.has_value()) { st.error = "client: async_request failed"; co_return; }
    auto stream = std::move(req.value());
    ec = co_await stream.async_write_headers({
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"},
        {":authority", "test.local"},
    }, false);
    if (ec) { st.error = "client: write headers: " + ec.message(); co_return; }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(200ms);
    co_await timer.async_wait(net_awaitable[ec]);

    conn->close();
    co_await conn->async_wait_pump(3s);
}

static void run_malformed_response_case(
    std::vector<uint8_t> frame, http2_error_code expected)
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
        co_await run_malformed_response_server(std::move(sock), st, std::move(frame));
        ioc.stop();
    }, net::detached);

    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        boost::system::error_code ec;
        net::ip::tcp::socket sock(ioc);
        std::vector<net::ip::tcp::endpoint> endpoints{
            net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port)};
        co_await net::async_connect(sock, endpoints, net_awaitable[ec]);
        if (ec) { st.error = "connect: " + ec.message(); ioc.stop(); co_return; }
        co_await run_malformed_response_client(std::move(sock), st);
        ioc.stop();
    }, net::detached);

    ioc.run();

    BOOST_CHECK_MESSAGE(st.error.empty(), st.error);
    BOOST_CHECK_EQUAL(static_cast<int>(st.observed_frame_type),
        static_cast<int>(frame_type::GOAWAY));
    BOOST_CHECK_EQUAL(st.observed_error_code, static_cast<uint32_t>(expected));
}

// 回归: HEADERS 的 padding 长度 >= 载荷长度属连接错误 PROTOCOL_ERROR
// (RFC 9113 §6.2), 而不是 COMPRESSION_ERROR.
BOOST_AUTO_TEST_CASE(headers_invalid_padding_returns_protocol_error)
{
    uint8_t pad[1] = {5};  // pad length 5 >= 载荷长度 1
    run_malformed_response_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::HEADERS),
            static_cast<uint8_t>(frame_flag::PADDED), pad, sizeof(pad)),
        http2_error_code::PROTOCOL_ERROR);
}

// 回归: PADDED 置位但缺少 Pad Length 字段属连接错误 FRAME_SIZE_ERROR
// (RFC 9113 §4.2).
BOOST_AUTO_TEST_CASE(headers_missing_pad_length_returns_frame_size_error)
{
    run_malformed_response_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::HEADERS),
            static_cast<uint8_t>(frame_flag::PADDED), nullptr, 0),
        http2_error_code::FRAME_SIZE_ERROR);
}

// 回归: PRIORITY 置位但不足 5 字节前缀属连接错误 FRAME_SIZE_ERROR
// (RFC 9113 §4.2).
BOOST_AUTO_TEST_CASE(headers_priority_too_short_returns_frame_size_error)
{
    uint8_t p[3] = {0, 0, 0};
    run_malformed_response_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::HEADERS),
            static_cast<uint8_t>(frame_flag::PRIORITY), p, sizeof(p)),
        http2_error_code::FRAME_SIZE_ERROR);
}

// 同上, 但置位 END_HEADERS 走完整解码路径: 结果必须一致而非 COMPRESSION_ERROR.
BOOST_AUTO_TEST_CASE(headers_full_missing_pad_length_returns_frame_size_error)
{
    run_malformed_response_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::HEADERS),
            static_cast<uint8_t>(frame_flag::PADDED)
                | static_cast<uint8_t>(frame_flag::END_HEADERS),
            nullptr, 0),
        http2_error_code::FRAME_SIZE_ERROR);
}

BOOST_AUTO_TEST_CASE(headers_full_priority_too_short_returns_frame_size_error)
{
    uint8_t p[3] = {0, 0, 0};
    run_malformed_response_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::HEADERS),
            static_cast<uint8_t>(frame_flag::PRIORITY)
                | static_cast<uint8_t>(frame_flag::END_HEADERS),
            p, sizeof(p)),
        http2_error_code::FRAME_SIZE_ERROR);
}

BOOST_AUTO_TEST_CASE(headers_full_invalid_padding_returns_protocol_error)
{
    uint8_t pad[1] = {5};
    run_malformed_response_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::HEADERS),
            static_cast<uint8_t>(frame_flag::PADDED)
                | static_cast<uint8_t>(frame_flag::END_HEADERS),
            pad, sizeof(pad)),
        http2_error_code::PROTOCOL_ERROR);
}

// 回归: GOAWAY 的流标识符必须为 0 (RFC 9113 §6.8).
BOOST_AUTO_TEST_CASE(goaway_nonzero_stream_id_rejected)
{
    uint8_t payload[8] = {0};
    run_bad_frame_case(
        build_raw_frame(1, static_cast<uint8_t>(frame_type::GOAWAY), 0,
            payload, sizeof(payload)),
        http2_error_code::PROTOCOL_ERROR);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace h2x
