//
// h2_connection.hpp
// ~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef H2X_H2_CONNECTION_HPP
#define H2X_H2_CONNECTION_HPP


#include <type_traits>
#include <deque>
#include <map>
#include <queue>
#include <set>
#include <functional>
#include <atomic>
#include <optional>

#include <boost/asio/strand.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <boost/system/result.hpp>

#include "use_awaitable.hpp"

#include "h2_frame.hpp"
#include "h2_error_code.hpp"

/*
客户端                 服务端
  │                      │
  │─ PRI * HTTP/2.0... ─►│  ← 连接前言（不是帧）
  │─ SETTINGS ──────────►│
  │◄─ SETTINGS ──────────│
  │◄─ SETTINGS(ACK) ─────│
  │─ SETTINGS(ACK) ─────►│
  │                      │
  │─ HEADERS (stream1) ─►│  ← 开始真正的HTTP请求
  │─ DATA* (如果有body) ─►│
  │                      │
  │◄─ HEADERS (stream1) ─│  ← 响应头
  │◄─ DATA* ─────────────│  ← 响应体
  │◄─ (可能有Trailer) ────│

*/

namespace h2x {

    ////////////////////////////////////////////////////////////////////////////////

    namespace net = boost::asio;

    // 表示 HTTP/2 连接的角色.
    enum class role : uint8_t {
        client,
        server,
    };

    // 表示 HTTP/2 连接设置.
    struct settings {
        uint32_t header_table_size = 4096;
        bool enable_push = false;
        uint32_t max_concurrent_streams = 100;
        uint32_t initial_window_size = 65535;
        uint32_t max_frame_size = 16384;
        uint32_t max_header_list_size = 0;
        bool no_rfc7540_priorities = true;
        bool enable_connect_protocol = false;
    };

    // 表示流的生命周期状态.
    enum class stream_state : uint8_t {
        idle,           // 流尚未打开
        reserved_local, // 已保留（PUSH_PROMISE）
        reserved_remote,// 已保留（PUSH_PROMISE 远端）
        open,           // 流已打开，双向通信
        half_closed_local,   // 本地已关闭（发送了 END_STREAM）
        half_closed_remote,  // 远端已关闭（收到了 END_STREAM）
        closed,         // 流已完全关闭
    };

    template <class T>
    using result = boost::system::result<T>;

    template <class Connection>
    class stream;

    /**
     * @brief 表示一个 HTTP/2 连接的核心类模板。
     *
     * 模板参数:
     * - NextLayer: 底层 I/O 层类型（例如 `boost::asio::ssl::stream<tcp::socket>` 或 `tcp::socket`）。
     *
     * 该类负责帧的收发、流管理、HPACK 动态表维护以及连接级别的流控与设置协商。
     * 所有异步操作基于 Boost.Asio 协程 (`awaitable`) 实现。
     */
    template <class NextLayer>
    class connection
    {
    public:
        using next_layer_type = std::remove_reference_t<NextLayer>;
        using lowest_layer_type = typename next_layer_type::lowest_layer_type;
        using executor_type = typename lowest_layer_type::executor_type;

        // 表示 HTTP/2 流.
        using stream_type = stream<connection<NextLayer>>;

        // stream_type 你是我的好朋友, 我会对你敞开我的一切.
        friend stream_type;

        ////////////////////////////////////////////////////////////////////////////////

        template <typename Arg>
        connection(Arg&& next_layer)
            : next_layer_(static_cast<Arg&&>(next_layer))
            , out_notifier_(next_layer_.get_executor())
            , strand_(next_layer_.get_executor())
            , dynamic_table_map_(global_static_header_table_map)
        {}

        connection(connection&& other)
            : next_layer_(std::move(other.next_layer_))
            , out_notifier_(std::move(other.out_notifier_))
            , strand_(std::move(other.strand_))
            , settings_(std::move(other.settings_))
            , dynamic_table_map_(std::move(other.dynamic_table_map_))
            , dynamic_table_(std::move(other.dynamic_table_))
            , streams_(std::move(other.streams_))
        {}

        connection& operator=(connection&& other)
        {
            if (this != &other) {
                next_layer_ = static_cast<NextLayer&&>(other.next_layer_);
                out_notifier_ = std::move(other.out_notifier_);
                strand_ = std::move(other.strand_);
                settings_ = std::move(other.settings_);
                dynamic_table_map_ = std::move(other.dynamic_table_map_);
                dynamic_table_ = std::move(other.dynamic_table_);
                streams_ = std::move(other.streams_);
            }
            return *this;
        }

        ~connection() = default;

        ////////////////////////////////////////////////////////////////////////////////

        executor_type get_executor() noexcept
        {
            return next_layer_.lowest_layer().get_executor();
        }

        const next_layer_type& next_layer() const
        {
            return next_layer_;
        }

        next_layer_type& next_layer()
        {
            return next_layer_;
        }

        lowest_layer_type& lowest_layer()
        {
            return next_layer_.lowest_layer();
        }

        const lowest_layer_type& lowest_layer() const
        {
            return next_layer_.lowest_layer();
        }

        ////////////////////////////////////////////////////////////////////////////////

        /**
         * @brief 执行 HTTP/2 连接握手。
         *
         * 该函数负责发送/接收连接前言与 SETTINGS，协商设置。
         * 握手完成后，内部的输入/输出 pump（`pump_in` 与 `pump_out`）
         * 会在后台独立运行，`async_handshake` 将正常返回。
         * 泵送协程在调用 `close()` 设置 `abort_` 标志后自动退出。
         *
         * @param r 本端角色（client 或 server）。
         * @param s 要发送/协商的本端 `settings`。
         * @param ec 输出的错误码（通过引用返回）。
         * @return awaitable<void>
         */
        net::awaitable<void> async_handshake(role r, settings& s, boost::system::error_code& ec)
        {
            role_ = r;

            try {
                // 检查底层对象是否打开.
                if (!next_layer_.lowest_layer().is_open()) {
                    ec = make_error_code(errc::next_layer_not_open);
                    co_return;
                }

                // 客户端发送连接前言.
                if (r == role::client) {
                    co_await net::async_write(next_layer_,
                        net::buffer(global_client_preface, global_client_preface_len),
                        net_awaitable[ec]);
                    if (ec) {
                        co_return;
                    }
                } else if (r == role::server) {
                    // 服务端接收连接前言.
                    std::vector<uint8_t> client_preface(global_client_preface_len);
                    co_await net::async_read(next_layer_,
                        net::buffer(client_preface, global_client_preface_len),
                        net_awaitable[ec]);
                    if (ec) {
                        co_return;
                    }
                    // 验证服务端连接前言是否正确.
                    if (std::string_view(
                            reinterpret_cast<const char*>(client_preface.data()),
                            client_preface.size())
                        != std::string_view(global_client_preface, global_client_preface_len)) {
                        ec = make_error_code(errc::protocol_error);
                        co_return;
                    }
                }

                // 发送连接设置帧.
                uint8_t bufs[64] = {0};

                settings_frame sf(bufs, sizeof(bufs), false);

                sf.entries_.emplace_back(settings_id::SETTINGS_HEADER_TABLE_SIZE, s.header_table_size);
                sf.entries_.emplace_back(settings_id::SETTINGS_ENABLE_PUSH, s.enable_push);
                sf.entries_.emplace_back(settings_id::SETTINGS_MAX_CONCURRENT_STREAMS, s.max_concurrent_streams);
                sf.entries_.emplace_back(settings_id::SETTINGS_INITIAL_WINDOW_SIZE, s.initial_window_size);
                sf.entries_.emplace_back(settings_id::SETTINGS_MAX_FRAME_SIZE, s.max_frame_size);
                sf.entries_.emplace_back(settings_id::SETTINGS_MAX_HEADER_LIST_SIZE, s.max_header_list_size);
                sf.entries_.emplace_back(settings_id::SETTINGS_NO_RFC7540_PRIORITIES, s.no_rfc7540_priorities);
                sf.entries_.emplace_back(settings_id::SETTINGS_ENABLE_CONNECT_PROTOCOL, s.enable_connect_protocol);

                sf.pack_settings();

                // 发送连接设置帧.
                co_await async_write_frame(sf, ec);
                if (ec) {
                    co_return;
                }

                // 接收对方的连接设置帧.
                co_await async_read_frame(sf, ec);
                if (ec) {
                    co_return;
                }

                // 解析对方的连接设置帧, 更新本地配置.
                apply_peer_settings(sf.entries_);

                // 发送连接设置帧 ACK.
                sf.ack_ = true;
                sf.entries_.clear();
                sf.pack_settings();

                // 发送连接设置帧 ACK.
                co_await async_write_frame(sf, ec);
                if (ec) {
                    co_return;
                }

                // 接收对方的连接设置帧 ACK.
                co_await async_read_frame(sf, ec);
                if (ec) {
                    co_return;
                }

                // 更新协商后的配置.
                settings_ = s;

                // 在后台启动输入/输出泵送协程，async_handshake 将正常返回.
                auto exit_flag = pump_done_;
                net::co_spawn(strand_,
                    [this, exit_flag]() -> net::awaitable<void> {
                        using namespace net::experimental::awaitable_operators;
                        co_await (pump_in() && pump_out());
                        *exit_flag = true;
                    },
                    net::detached);

            } catch (std::exception&) {
                ec = make_error_code(errc::protocol_error);
            }

            co_return;
        }

        ////////////////////////////////////////////////////////////////////////////////

        /**
         * @brief 为本端发起一个新的流并返回对应的 `stream` 对象（可写入 HEADERS/DATA）。
         *
         * 注意：此方法在 `h2_stream.hpp` 中实现（需要 `stream` 的完整定义）。
         */
        net::awaitable<result<stream_type>> async_request();

        /**
         * @brief 与 `async_accept()` 等效的别名，用于 API 可读性。
         */
        net::awaitable<result<stream_type>> async_accept_stream();

        /**
         * @brief 主动关闭/中止连接。
         *
         * 设置内部 `abort_` 标志、取消等待者，并关闭底层 socket。
         * 关闭 socket 会使待决的 async_read/async_write 立即失败，
         * 确保 pump_in/pump_out 协程快速退出，避免 use-after-free。
         */
        void close()
        {
            abort_ = true;
            out_notifier_.cancel();
            boost::system::error_code ec;
            next_layer_.lowest_layer().close(ec);
        }

        /**
         * @brief 异步等待泵送协程完全退出。
         *
         * 内部泵送协程（pump_in() && pump_out()）退出时，此函数返回 true。
         * 若在指定的 timeout 时间内泵送协程仍未退出，返回 false。
         * 通常在调用 close() 后调用此函数，确保连接对象可安全销毁。
         *
         * @tparam Rep 时间精度的算术类型。
         * @tparam Period 时间单位的 std::ratio 类型。
         * @param timeout 最长等待时间。
         * @return awaitable<bool> 超时返回 false，泵送协程正常退出返回 true。
         */
        template <typename Rep, typename Period>
        net::awaitable<bool> async_wait_pump(
            std::chrono::duration<Rep, Period> timeout) noexcept
        {
            auto exit_flag = pump_done_;
            boost::system::error_code ec;

            using clock = net::steady_timer::clock_type;
            auto deadline = clock::now() + timeout;

            while (!*exit_flag) {
                auto now = clock::now();
                if (now >= deadline)
                    co_return false;

                auto remain = std::chrono::duration_cast<
                    net::steady_timer::duration>(deadline - now);
                auto wait_time = std::min<net::steady_timer::duration>(
                    remain, std::chrono::milliseconds(100));

                net::steady_timer timer(co_await net::this_coro::executor);
                timer.expires_after(wait_time);
                co_await timer.async_wait(net_awaitable[ec]);
            }

            co_return true;
        }

        ////////////////////////////////////////////////////////////////////////////////

        /** @brief 获取协商后的连接设置（只读）。 */
        const settings& get_settings() const noexcept { return settings_; }
        /** @brief 返回本端角色（client/server）。 */
        role get_role() const noexcept { return role_; }

        ////////////////////////////////////////////////////////////////////////////////

        /**
         * @brief 将给定的已打包帧写入底层 NextLayer（awaitable）。
         *
         * @param fc 已准备好的帧编码对象（包含 data_ 与 size_）。
         * @param ec 输出错误码引用。
         * @return awaitable 返回写入的字节数。
         */
        net::awaitable<size_t> async_write_frame(frame_codec& fc, boost::system::error_code& ec)
        {
            auto total = fc.frame_size();
            co_await net::async_write(next_layer_,
                net::buffer(fc.data_, total), net_awaitable[ec]);
            co_return total;
        }

        /**
         * @brief 从底层读取帧头与负载到 `frame_codec` 的缓冲区并返回读取的字节数。
         *
         * @param fc 目标帧编码对象，必须包含足够的缓冲区大小。
         * @param ec 输出错误码引用。
         * @return awaitable 返回读取的字节数（payload 部分）。
         */
        net::awaitable<size_t> async_read_frame(frame_codec& fc, boost::system::error_code& ec)
        {
            // 读取帧头.
            auto size = co_await net::async_read(next_layer_,
                net::buffer(fc.data_, 9), net_awaitable[ec]);
            if (ec) {
                co_return 0;
            }

            // 检查帧大小是否超过最大帧大小.
            auto want_size = fc.payload_size() + 9;
            if ((want_size > settings_.max_frame_size) ||
                (want_size > fc.size_)) {
                ec = make_error_code(errc::frame_size_error);
                co_return 0;
            }

            // 读取帧数据.
            size = co_await net::async_read(next_layer_,
                net::buffer(fc.data_ + 9, fc.payload_size()), net_awaitable[ec]);
            if (ec) {
                co_return 0;
            }

            co_return size;
        }

        /**
         * @brief 将已序列化的帧数据入队，等待 `pump_out` 将其写出。
         *
         * 线程安全（通过 strand 分发），供内部帧构建逻辑调用。
         */
        void write_frame_data(std::vector<uint8_t>&& data)
        {
            net::dispatch(strand_,
                [this, data = std::move(data)]() mutable {
                try {
                    out_queue_.emplace_back(std::move(data));
                    out_notifier_.cancel();
                } catch (const std::exception&) {
                }
            });
        }

    private:
        // 从对端 SETTINGS 更新本地配置.
        void apply_peer_settings(const std::vector<settings_entry>& entries)
        {
            for (auto& e : entries) {
                switch (static_cast<settings_id>(e.identifier_)) {
                case settings_id::SETTINGS_HEADER_TABLE_SIZE:
                    peer_header_table_size_ = e.value_;
                    break;
                case settings_id::SETTINGS_MAX_CONCURRENT_STREAMS:
                    peer_max_concurrent_streams_ = e.value_;
                    break;
                case settings_id::SETTINGS_INITIAL_WINDOW_SIZE:
                {
                    int32_t delta = static_cast<int32_t>(e.value_)
                                  - static_cast<int32_t>(peer_initial_window_size_);
                    peer_initial_window_size_ = e.value_;
                    // 更新所有已存在流的远端窗口.
                    for (auto& [id, sd] : streams_) {
                        sd.remote_window += delta;
                    }
                    break;
                }
                case settings_id::SETTINGS_MAX_FRAME_SIZE:
                    peer_max_frame_size_ = e.value_;
                    break;
                default:
                    break;
                }
            }
        }

        // 分配流 ID：客户端使用奇数，服务端使用偶数.
        uint32_t allocate_stream_id()
        {
            uint32_t id = next_stream_id_;
            if (role_ == role::client) {
                if (id % 2 == 0) id++; // 确保奇数
                next_stream_id_ = id + 2;
            } else {
                if (id % 2 == 1) id++; // 确保偶数
                next_stream_id_ = id + 2;
            }
            return id;
        }

        // 处理接收到的各个类型帧.
        net::awaitable<void> handle_frame(frame_codec& fc)
        {
            auto type = fc.type();
            auto sid = fc.stream_id();
            auto flags = fc.flags();

            switch (type) {
            case frame_type::DATA:
                co_await handle_data_frame(fc);
                break;
            case frame_type::HEADERS:
                co_await handle_headers_frame(fc);
                break;
            case frame_type::PRIORITY:
                co_await handle_priority_frame(fc);
                break;
            case frame_type::RST_STREAM:
                co_await handle_rst_stream_frame(fc);
                break;
            case frame_type::SETTINGS:
                co_await handle_settings_frame(fc);
                break;
            case frame_type::PUSH_PROMISE:
                co_await handle_push_promise_frame(fc);
                break;
            case frame_type::PING:
                co_await handle_ping_frame(fc);
                break;
            case frame_type::GOAWAY:
                co_await handle_goaway_frame(fc);
                break;
            case frame_type::WINDOW_UPDATE:
                co_await handle_window_update_frame(fc);
                break;
            case frame_type::CONTINUATION:
                co_await handle_continuation_frame(fc);
                break;
            default:
                // 忽略未知帧类型.
                break;
            }
            co_return;
        }

        // ── 各帧处理 ──

        net::awaitable<void> handle_data_frame(frame_codec& fc)
        {
            auto sid = fc.stream_id();
            auto it = streams_.find(sid);
            if (it == streams_.end()) {
                // 流不存在，发送 RST_STREAM.
                co_await send_rst_stream(sid, rst_stream_error_code::STREAM_CLOSED);
                co_return;
            }

            auto& sd = it->second;

            // 如果流已关闭或收到重置，忽略 DATA 帧.
            if (sd.state == stream_state::closed || sd.reset_received) {
                co_return;
            }
            data_frame df(fc.data_, fc.size_);

            // 更新流控窗口.
            size_t data_len = df.get_data().size();
            if (data_len > sd.local_window) {
                co_await send_rst_stream(sid, rst_stream_error_code::FLOW_CONTROL_ERROR);
                co_return;
            }
            sd.local_window -= data_len;

            // 检查是否需要更新流级窗口.
            if (sd.local_window < settings_.initial_window_size / 2) {
                uint32_t increment = settings_.initial_window_size - sd.local_window;
                co_await send_window_update(sid, increment);
                sd.local_window = settings_.initial_window_size;
            }

            // 检查是否需要更新连接级窗口.
            conn_local_window_ -= data_len;
            if (conn_local_window_ < settings_.initial_window_size / 2) {
                uint32_t increment = settings_.initial_window_size - conn_local_window_;
                co_await send_window_update(0, increment);
                conn_local_window_ = settings_.initial_window_size;
            }

            // 推送数据到流的读取队列.
            if (!df.get_data().empty()) {
                sd.read_buffer.insert(sd.read_buffer.end(),
                    df.get_data().begin(), df.get_data().end());
            }

            // 通知等待的读取者.
            if (sd.read_waiter) {
                sd.read_waiter();
                sd.read_waiter = nullptr;
            }

            if (df.is_end_stream()) {
                // 仅在流已被 async_accept 拾取后（非 idle）才更新状态.
                if (sd.state != stream_state::idle) {
                    sd.state = (sd.state == stream_state::half_closed_local)
                        ? stream_state::closed
                        : stream_state::half_closed_remote;
                }
                sd.remote_end_stream = true;
            }

            co_return;
        }

        net::awaitable<void> handle_headers_frame(frame_codec& fc)
        {
            auto sid = fc.stream_id();
            auto it = streams_.find(sid);

            // 如果是新流 ID（服务端收到客户端请求）.
            if (it == streams_.end()) {
                // 角色感知的流 ID 检查:
                // - 服务端只能收到客户端发起的奇数流 ID
                // - 客户端只能收到服务端发起的偶数流 ID (推送流)
                if ((role_ == role::server && sid % 2 == 0) ||
                    (role_ == role::client && sid % 2 == 1 && sid != 0)) {
                    // 违反 HTTP/2 协议，发送 GOAWAY PROTOCOL_ERROR
                    co_await send_goaway(sid, goaway_error_code::PROTOCOL_ERROR);
                    co_return;
                }

                auto [new_it, ok] = streams_.emplace(sid, stream_state_data{});
                if (!ok) co_return;
                it = new_it;
                it->second.stream_id = sid;
                it->second.state = stream_state::idle;  // 等待 async_accept 拾取
                it->second.is_remote_initiated = true;
                it->second.local_window = settings_.initial_window_size;
                it->second.remote_window = peer_initial_window_size_;
            }

            auto& sd = it->second;

            headers_frame hf(fc.data_, fc.size_);

            // 存储头部到流.
            for (auto& h : hf.headers_) {
                sd.headers.emplace_back(h);
            }

            if (hf.end_stream_) {
                // 仅在流已被 async_accept 拾取后（非 idle）才更新状态.
                if (sd.state != stream_state::idle) {
                    sd.state = (sd.state == stream_state::half_closed_local)
                        ? stream_state::closed
                        : stream_state::half_closed_remote;
                }
                sd.remote_end_stream = true;
            }

            // 通知等待的读取者.
            if (sd.read_waiter) {
                sd.read_waiter();
                sd.read_waiter = nullptr;
            }

            // 通知 async_accept 有新流到达.
            if (accept_waiter_) {
                accept_waiter_();
                accept_waiter_ = nullptr;
            }

            co_return;
        }

        net::awaitable<void> handle_priority_frame(frame_codec& fc)
        {
            // PRIORITY 帧在 RFC 7540 中可接收但不必须做任何事.
            co_return;
        }

        net::awaitable<void> handle_rst_stream_frame(frame_codec& fc)
        {
            auto sid = fc.stream_id();
            rst_stream_frame rf(fc.data_, fc.size_);

            auto it = streams_.find(sid);
            if (it != streams_.end()) {
                it->second.state = stream_state::closed;
                it->second.reset_received = true;
            }
            co_return;
        }

        net::awaitable<void> handle_settings_frame(frame_codec& fc)
        {
            settings_frame sf(fc.data_, fc.size_);

            // 如果是 ACK，不需要处理.
            if (sf.ack_) {
                co_return;
            }

            // 更新对端设置.
            apply_peer_settings(sf.entries_);

            // 发送 SETTINGS ACK.
            sf.ack_ = true;
            sf.entries_.clear();
            sf.pack_settings();

            std::vector<uint8_t> buf(sf.frame_size());
            std::memcpy(buf.data(), sf.data_, sf.frame_size());
            write_frame_data(std::move(buf));

            co_return;
        }

        net::awaitable<void> handle_push_promise_frame(frame_codec& fc)
        {
            push_promise_frame ppf(fc.data_, fc.size_);
            auto promised_id = ppf.get_promised_stream_id();

            // 创建预留流.
            auto [it, ok] = streams_.emplace(promised_id, stream_state_data{});
            if (ok) {
                it->second.stream_id = promised_id;
                it->second.state = stream_state::reserved_remote;
                it->second.is_remote_initiated = true;
            }
            co_return;
        }

        net::awaitable<void> handle_ping_frame(frame_codec& fc)
        {
            ping_frame pf(fc.data_, fc.size_);

            if (!pf.is_ack()) {
                // 收到 PING，发送 PING ACK.
                pf.set_ack(true);
                pf.pack_payload();

                std::vector<uint8_t> buf(pf.frame_size());
                std::memcpy(buf.data(), pf.data_, pf.frame_size());
                write_frame_data(std::move(buf));
            }
            co_return;
        }

        net::awaitable<void> handle_goaway_frame(frame_codec& fc)
        {
            goaway_frame gf(fc.data_, fc.size_);

            // 记录 GOAWAY 信息并关闭连接.
            last_stream_id_ = gf.get_last_stream_id();
            abort_ = true;
            co_return;
        }

        net::awaitable<void> handle_window_update_frame(frame_codec& fc)
        {
            auto sid = fc.stream_id();
            window_update_frame wuf(fc.data_, fc.size_);
            uint32_t increment = wuf.get_window_increment();

            if (sid == 0) {
                // 连接级窗口更新.
                conn_remote_window_ += increment;
                // 通知所有等待发送的写入者（连接级窗口影响所有流）.
                for (auto& [id, sd] : streams_) {
                    if (sd.write_waiter) {
                        sd.write_waiter();
                        sd.write_waiter = nullptr;
                    }
                }
            } else {
                // 流级窗口更新.
                auto it = streams_.find(sid);
                if (it != streams_.end()) {
                    it->second.remote_window += increment;
                    // 通知等待发送的写入者.
                    if (it->second.write_waiter) {
                        it->second.write_waiter();
                        it->second.write_waiter = nullptr;
                    }
                }
            }
            co_return;
        }

        net::awaitable<void> handle_continuation_frame(frame_codec& fc)
        {
            auto sid = fc.stream_id();
            continuation_frame cf(fc.data_, fc.size_);

            auto it = streams_.find(sid);
            if (it != streams_.end()) {
                // 累积 CONTINUATION 的头部数据.
                auto& frag = cf.get_header_block_fragment();
                it->second.pending_header_block.insert(
                    it->second.pending_header_block.end(),
                    frag.begin(), frag.end());
            }
            co_return;
        }

        // ── 帧发送辅助 ──

        net::awaitable<void> send_rst_stream(uint32_t sid, rst_stream_error_code code)
        {
            uint8_t buf[64] = {0};
            rst_stream_frame rf(buf, sizeof(buf), false);
            rf.stream_id(sid);
            rf.type(frame_type::RST_STREAM);
            rf.set_error_code(code);
            rf.pack_payload();

            std::vector<uint8_t> data(rf.frame_size());
            std::memcpy(data.data(), rf.data_, rf.frame_size());
            write_frame_data(std::move(data));
            co_return;
        }

        net::awaitable<void> send_window_update(uint32_t sid, uint32_t increment)
        {
            uint8_t buf[64] = {0};
            window_update_frame wuf(buf, sizeof(buf), false);
            wuf.stream_id(sid);
            wuf.type(frame_type::WINDOW_UPDATE);
            wuf.set_window_increment(increment);
            wuf.pack_payload();

            std::vector<uint8_t> data(wuf.frame_size());
            std::memcpy(data.data(), wuf.data_, wuf.frame_size());
            write_frame_data(std::move(data));
            co_return;
        }

        net::awaitable<void> send_goaway(uint32_t last_sid, goaway_error_code code)
        {
            uint8_t buf[64] = {0};
            goaway_frame gf(buf, sizeof(buf), false);
            gf.stream_id(0);
            gf.type(frame_type::GOAWAY);
            gf.set_last_stream_id(last_sid);
            gf.set_error_code(code);
            gf.pack_payload();

            std::vector<uint8_t> data(gf.frame_size());
            std::memcpy(data.data(), gf.data_, gf.frame_size());
            write_frame_data(std::move(data));
            co_return;
        }

        // ── 动态 HPACK 表操作 ──

        // 在动态表中查找 entry 的索引.
        int find_dynamic_index(uint32_t hash) const
        {
            auto it = dynamic_table_map_.find(hash);
            if (it != dynamic_table_map_.end()) {
                return it->second + 62; // 动态表索引从 62 开始.
            }
            return 0;
        }

        // 向动态表添加 entry.
        void add_to_dynamic_table(const header_entry& entry)
        {
            size_t max_size = settings_.header_table_size;

            // 如果动态表满了，移除最旧的条目.
            while (!dynamic_table_.empty() &&
                   dynamic_table_.size() >= max_size / 32) {
                auto& old = dynamic_table_.back();
                dynamic_table_map_.erase(old.hash_);
                dynamic_table_.pop_back();
            }

            dynamic_table_.insert(dynamic_table_.begin(), entry);
            dynamic_table_map_[entry.hash_] = 0;

            // 重新索引.
            for (size_t i = 0; i < dynamic_table_.size(); ++i) {
                dynamic_table_map_[dynamic_table_[i].hash_] = static_cast<int>(i);
            }
        }

        // 用于发送数据的处理泵.
        net::awaitable<void> pump_out() noexcept
        {
            boost::system::error_code ec;

            while (!abort_) {
                while (out_queue_.empty()) {
                    if (abort_) co_return;
                    // 输出队列为空时, 等待.
                    out_notifier_.expires_after(net::chrono::milliseconds(100));
                    co_await out_notifier_.async_wait(net_awaitable[ec]);
                }
                // 从输出队列中取出数据.
                auto data = std::move(out_queue_.front());
                out_queue_.pop_front();
                // 异步发送数据.
                co_await net::async_write(next_layer_, net::buffer(data), net_awaitable[ec]);
                if (ec) {
                    co_return;
                }
            }

            co_return;
        }

        // 用于接收数据的处理泵.
        net::awaitable<void> pump_in()
        {
            boost::system::error_code ec;

            while (!abort_) {
                // 分配帧缓冲区.
                auto frame_buf = std::make_unique<uint8_t[]>(settings_.max_frame_size + 9);
                frame_codec fc(frame_buf.get(), settings_.max_frame_size + 9);

                // 异步读取帧.
                co_await async_read_frame(fc, ec);
                if (ec) {
                    if (!abort_) {
                        abort_ = true;
                    }
                    co_return;
                }

                // 分派帧处理.
                co_await handle_frame(fc);
            }

            co_return;
        }


    private:
        // 下一层协议栈.
        NextLayer next_layer_;

    private:
        // 输出队列, 用于存储待发送的数据.
        std::deque<std::vector<uint8_t>> out_queue_;

        // 用于通知输出处理泵发送数据的定时器.
        net::steady_timer out_notifier_;

        // 用于保护并发访问的 strand.
        net::strand<executor_type> strand_;

        // 协商的连接设置.
        settings settings_;

        // 对端设置.
        uint32_t peer_header_table_size_ = 4096;
        uint32_t peer_max_concurrent_streams_ = 100;
        uint32_t peer_initial_window_size_ = 65535;
        uint32_t peer_max_frame_size_ = 16384;

        // 连接角色.
        role role_{role::client};

        // 流管理.
        uint32_t next_stream_id_ = 1; // 客户端从 1 开始，服务端从 2 开始.

        // 连接级流控窗口（初始化后在 async_handshake 中通过 SETTINGS 协商更新）.
        int64_t conn_local_window_ = 65535;   // 本地可接收窗口.
        int64_t conn_remote_window_ = 65535;  // 远端允许发送窗口.

        // 最后一个流 ID（GOAWAY 用）.
        uint32_t last_stream_id_ = 0;

        // hash 表, 用于快速查找动态表中的索引.
        std::unordered_map<uint32_t, int> dynamic_table_map_;
        std::vector<header_entry> dynamic_table_;

        // 用于标记是否需要中止连接.
        std::atomic_bool abort_{false};

        // 泵送协程退出标志（pump_in/pump_out 完成时设为 true）.
        std::shared_ptr<std::atomic<bool>> pump_done_{
            std::make_shared<std::atomic<bool>>(false)};

        // 用于通知 async_accept 有新流到达.
        std::function<void()> accept_waiter_;

        // ── 流状态数据结构 ──

        struct stream_state_data {
            uint32_t stream_id = 0;
            stream_state state = stream_state::idle;
            bool is_remote_initiated = false;
            bool remote_end_stream = false;
            bool reset_received = false;

            // 流控窗口.
            int64_t local_window = 65535;
            int64_t remote_window = 65535;

            // 头部数据.
            std::vector<header_entry> headers;
            std::vector<uint8_t> pending_header_block;

            // 数据读取缓冲区.
            std::vector<uint8_t> read_buffer;

            // 等待者回调（用于通知等待读/写的协程）.
            std::function<void()> read_waiter;
            std::function<void()> write_waiter;
        };

        // 流容器.
        std::map<uint32_t, stream_state_data> streams_;
    };
} // namespace h2x

#endif // H2X_H2_CONNECTION_HPP