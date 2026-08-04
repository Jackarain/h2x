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
#include <memory>

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

#include "h2x/use_awaitable.hpp"

#include "h2x/h2_frame.hpp"
#include "h2x/h2_error_code.hpp"

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
        : public std::enable_shared_from_this<connection<NextLayer>>
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

        // 禁止移动: 连接一旦开始异步运行 (pump 协程捕获内部状态, 可能已有
        // stream 持有其引用), 移动会遗漏窗口/流 ID/pump 退出标志等成员, 导致
        // async_wait_pump 挂起或 use-after-free. 请使用 shared_ptr 管理.
        connection(connection&&) = delete;
        connection& operator=(connection&&) = delete;

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
         * pump 协程在调用 `close()` 设置 `abort_` 标志后自动退出。
         *
         * @param r 本端角色（client 或 server）。
         * @param s 要发送/协商的本端 `settings`。
         * @param ec 输出的错误码（通过引用返回）。
         * @return awaitable<void>
         */
        net::awaitable<void> async_handshake(role r, const settings& s, boost::system::error_code& ec)
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
                uint8_t bufs[256] = {0};

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

                // 接收对方 SETTINGS. 握手期间可能收到其它帧 (如客户端在
                // SETTINGS 后立即流水线化的请求 HEADERS), 一律派发到
                // handle_frame 处理, 而不是吞掉丢弃.
                bool got_settings = false;
                while (!got_settings) {
                    if (!co_await async_read_frame_timed(sf,
                            std::chrono::seconds(30), ec)) {
                        co_return;
                    }
                    if (sf.type() == frame_type::SETTINGS &&
                        !(sf.flags() & static_cast<uint8_t>(frame_flag::FLAG_ACK))) {
                        got_settings = true;
                    } else {
                        co_await handle_frame(sf);
                    }
                }

                // 解析对方的连接设置帧, 更新本地配置.
                sf.entries_.clear();
                sf.unpack_settings();
                if (!apply_peer_settings(sf.entries_)) {
                    ec = make_error_code(errc::flow_control_error);
                    co_return;
                }

                // 发送连接设置帧 ACK.
                sf.ack_ = true;
                sf.entries_.clear();
                sf.pack_settings();

                // 发送连接设置帧 ACK.
                co_await async_write_frame(sf, ec);
                if (ec) {
                    co_return;
                }

                // 等待对方 ACK 我们的 SETTINGS. 期间其它帧照常派发,
                // 并校验收到的确实是 SETTINGS ACK.
                bool got_ack = false;
                while (!got_ack) {
                    if (!co_await async_read_frame_timed(sf,
                            std::chrono::seconds(30), ec)) {
                        co_return;
                    }
                    if (sf.type() == frame_type::SETTINGS &&
                        (sf.flags() & static_cast<uint8_t>(frame_flag::FLAG_ACK))) {
                        got_ack = true;
                    } else {
                        co_await handle_frame(sf);
                    }
                }

                // 更新协商后的配置.
                settings_ = s;

                // 初始化 pump 缓冲区（持久分配，避免每帧分配）.
                // 值初始化 (()) 防止帧头读入前被误读时读到未初始化数据.
                pump_buf_.reset(new uint8_t[settings_.max_frame_size + 9]());

                // 在后台启动输入/输出 pump 协程，async_handshake 将正常返回.
                // 捕获 self (shared_from_this) 保持连接存活, 防止调用方在
                // pump 退出前释放连接导致 use-after-free.
                // 注意: connection 需由 shared_ptr 管理 (见 README 示例).
                auto self = this->shared_from_this();
                auto exit_flag = pump_done_;
                net::co_spawn(strand_,
                    [self, exit_flag]() -> net::awaitable<void> {
                        using namespace net::experimental::awaitable_operators;
                        co_await (self->pump_in() && self->pump_out());
                        *exit_flag = true;
                        // pump 退出后, 标记所有流为已重置并唤醒等待者,
                        // 确保任何阻塞在 wait_until 的协程能被唤醒并退出.
                        for (auto& [id, sd] : self->streams_) {
                            sd.reset_received = true;
                            if (sd.read_waiter) { sd.read_waiter(); sd.read_waiter = nullptr; }
                            if (sd.write_waiter) { sd.write_waiter(); sd.write_waiter = nullptr; }
                        }
                        if (self->accept_waiter_) { self->accept_waiter_(); self->accept_waiter_ = nullptr; }
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
         * @brief 异步等待 pump 协程完全退出。
         *
         * 内部 pump 协程（pump_in() && pump_out()）退出时，此函数返回 true。
         * 若在指定的 timeout 时间内 pump 协程仍未退出，返回 false。
         * 通常在调用 close() 后调用此函数，确保连接对象可安全销毁。
         *
         * @tparam Rep 时间精度的算术类型。
         * @tparam Period 时间单位的 std::ratio 类型。
         * @param timeout 最长等待时间。
         * @return awaitable<bool> 超时返回 false，pump 协程正常退出返回 true。
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
        /** @brief 当前连接中仍被跟踪的流数量（含已关闭但未释放的）。 */
        std::size_t stream_count() const noexcept { return streams_.size(); }

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

            auto payload_len = fc.payload_size();

            // 检查帧负载大小是否超过最大帧大小.
            // settings_.max_frame_size 是最大负载大小（不含帧头 9 字节）.
            auto total_size = payload_len + 9;
            if ((payload_len > settings_.max_frame_size) ||
                (total_size > fc.size_)) {
                ec = make_error_code(errc::frame_size_error);
                co_return 0;
            }

            // 读取帧数据.
            size = co_await net::async_read(next_layer_,
                net::buffer(fc.data_ + 9, payload_len), net_awaitable[ec]);
            if (ec) {
                co_return 0;
            }

            co_return size;
        }

        /**
         * @brief 带超时读取一帧（用于握手，防止对端不响应时永久挂起）。
         *
         * 成功返回 true 并清空 ec；超时或读取失败返回 false 并置 ec。
         */
        net::awaitable<bool> async_read_frame_timed(frame_codec& fc,
            std::chrono::milliseconds timeout, boost::system::error_code& ec)
        {
            using namespace net::experimental::awaitable_operators;
            boost::system::error_code read_ec;
            net::steady_timer timer(get_executor());
            timer.expires_after(timeout);
            co_await (async_read_frame(fc, read_ec) ||
                      timer.async_wait(net_awaitable[ec]));
            if (read_ec == net::error::operation_aborted) {
                // 计时器先到期 → 握手超时.
                ec = make_error_code(errc::protocol_error);
                co_return false;
            }
            if (read_ec) {
                ec = read_ec;
                co_return false;
            }
            ec.clear();
            co_return true;
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

        /**
         * @brief 将 frame_codec 的内容拷贝到新缓冲区并入队发送。
         *
         * 用于在处理接收帧后需要回送 ACK 或响应帧的常见场景
         * 消除 "memcpy + write_frame_data" 的重复代码。
         */
        void queue_frame(const frame_codec& fc)
        {
            std::vector<uint8_t> buf(fc.frame_size());
            std::memcpy(buf.data(), fc.data_, fc.frame_size());
            write_frame_data(std::move(buf));
        }

        /**
         * @brief 构建并发送一个简单的控制帧（RST_STREAM / WINDOW_UPDATE / GOAWAY 等）。
         *
         * 模板参数 Frame 为帧类型，setup 回调用于设置帧特有字段。
         */
        template <class Frame, class Setup>
        net::awaitable<void> send_control_frame(uint32_t sid, frame_type ft, Setup&& setup)
        {
            auto buf = std::vector<uint8_t>(64, 0);
            Frame f(buf.data(), buf.size(), false);
            f.stream_id(sid);
            f.type(ft);
            std::forward<Setup>(setup)(f);
            f.pack_payload();
            buf.resize(f.frame_size());
            write_frame_data(std::move(buf));
            co_return;
        }

    private:
        // 从对端 SETTINGS 更新本地配置. 返回 false 表示流控窗口越界
        // (RFC 7540 §6.5.2/§6.9.2 连接错误 FLOW_CONTROL_ERROR).
        bool apply_peer_settings(const std::vector<settings_entry>& entries)
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
                    // 窗口值不得超过 2^31-1 (RFC 7540 §6.5.2).
                    if (e.value_ > 0x7FFFFFFF)
                        return false;

                    int64_t delta = static_cast<int64_t>(e.value_)
                                  - static_cast<int64_t>(peer_initial_window_size_);
                    peer_initial_window_size_ = e.value_;
                    for (auto& [id, sd] : streams_) {
                        // 调整后任一流的远端窗口不得超过 2^31-1 (RFC 7540 §6.9.2).
                        if (sd.remote_window + delta > 0x7FFFFFFF)
                            return false;
                        sd.remote_window += delta;
                        // 窗口增大后必须唤醒等待发送的写入者; 否则发送协程
                        // 即使窗口已恢复也会永久挂起.
                        if (sd.write_waiter) {
                            sd.write_waiter();
                            sd.write_waiter = nullptr;
                        }
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
            return true;
        }

        // 分配流 ID：客户端使用奇数，服务端使用偶数.
        // 流 ID 为 31 位; 超出 0x7FFFFFFF 时返回 0 表示空间耗尽 (RFC 7540 §5.1.1),
        // 由 async_request 发起 GOAWAY.
        uint32_t allocate_stream_id()
        {
            uint32_t id = next_stream_id_;
            if (role_ == role::client) {
                if (id % 2 == 0) id++; // 确保奇数
            } else {
                if (id % 2 == 1) id++; // 确保偶数
            }
            if (id > 0x7FFFFFFF)
                return 0;
            next_stream_id_ = id + 2;
            return id;
        }

        // 流进入终止态且应用已消费完数据、无等待者时, 将其从流表移除,
        // 防止长连接/服务端上已关闭的流无限累积导致内存持续增长.
        // 终止判定: 远端已结束 (END_STREAM 或 RST) 且本端也已结束
        // (state 为 closed, 或 state 为 half_closed_local).
        // 注意: 远端 END_STREAM 在流仍为 idle 时只置 remote_end_stream,
        // 不迁移 state, 故不能用 state == closed 作为唯一条件.
        void maybe_release_stream(uint32_t sid)
        {
            auto it = streams_.find(sid);
            if (it == streams_.end())
                return;

            auto& sd = it->second;
            const bool remote_ended =
                sd.remote_end_stream || sd.reset_received;
            const bool local_ended =
                sd.state == stream_state::closed ||
                sd.state == stream_state::half_closed_local;
            if (remote_ended && local_ended &&
                sd.read_buffer.empty() &&
                sd.headers.empty() &&
                sd.pending_header_block.empty() &&
                !sd.read_waiter &&
                !sd.write_waiter) {
                streams_.erase(it);
            }
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
            data_frame df(fc.data_, fc.size_);
            int64_t data_len = static_cast<int64_t>(df.get_data().size());

            // 连接级窗口: 所有收到的 DATA 都消耗连接级窗口, 无论流是否
            // 存在/已关闭/被重置. 否则被丢弃的 DATA 不入账, 对端连接窗口
            // 会逐渐被本端少发的 WINDOW_UPDATE 透支而整条连接卡死.
            if (data_len > conn_local_window_) {
                // 连接级流控违规.
                co_await send_goaway(0, http2_error_code::FLOW_CONTROL_ERROR);
                abort_ = true;
                co_return;
            }
            conn_local_window_ -= data_len;
            if (conn_local_window_ < static_cast<int64_t>(settings_.initial_window_size / 2)) {
                uint32_t increment = static_cast<uint32_t>(
                    static_cast<int64_t>(settings_.initial_window_size) - conn_local_window_);
                co_await send_window_update(0, increment);
                conn_local_window_ = settings_.initial_window_size;
            }

            auto it = streams_.find(sid);
            if (it == streams_.end()) {
                // 流不存在，发送 RST_STREAM.
                co_await send_rst_stream(sid, http2_error_code::STREAM_CLOSED);
                co_return;
            }

            auto& sd = it->second;

            // 如果流已关闭或收到重置，忽略 DATA 帧 (连接级窗口已入账).
            if (sd.state == stream_state::closed || sd.reset_received) {
                co_return;
            }

            // 流级窗口.
            if (data_len > sd.local_window) {
                co_await send_rst_stream(sid, http2_error_code::FLOW_CONTROL_ERROR);
                co_return;
            }
            sd.local_window -= data_len;

            // 检查是否需要更新流级窗口.
            if (sd.local_window < static_cast<int64_t>(settings_.initial_window_size / 2)) {
                uint32_t increment = static_cast<uint32_t>(
                    static_cast<int64_t>(settings_.initial_window_size) - sd.local_window);
                co_await send_window_update(sid, increment);
                sd.local_window = settings_.initial_window_size;
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

            // 尝试释放已终止且数据已消费完的流.
            maybe_release_stream(sid);

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
                    co_await send_goaway(sid, http2_error_code::PROTOCOL_ERROR);
                    co_return;
                }

                // 并发流上限: 超过本端声明的 SETTINGS_MAX_CONCURRENT_STREAMS
                // 时拒绝新流 (RFC 7540 §5.1.2), 防止对端开无限流耗尽内存.
                size_t active = 0;
                for (auto& [id, sd] : streams_) {
                    if (sd.is_remote_initiated &&
                        sd.state != stream_state::closed) {
                        ++active;
                    }
                }
                if (active >= settings_.max_concurrent_streams) {
                    co_await send_rst_stream(sid, http2_error_code::REFUSED_STREAM);
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

            // 只解析 flags，不解码 HPACK（避免在 end_headers_=false 时解析截断数据导致异常）.
            headers_frame hf(fc.data_, fc.size_, false, &dynamic_table_);
            hf.parse_flags();

            if (hf.end_headers_) {
                // 完整头部块到达 — 执行完整 HPACK 解析.
                bool hpack_error = false;
                try {
                    hf.unpack_headers();
                } catch (const std::exception&) {
                    hpack_error = true;
                }

                if (hpack_error) {
                    co_await send_goaway(sid, http2_error_code::COMPRESSION_ERROR);
                    abort_ = true;
                    co_return;
                }

                // 解析 entry 并加入动态表.
                for (auto& h : hf.headers_) {
                    if (h.type_ == &G_LITERAL_INCREMENTAL_INDEXING) {
                        add_to_dynamic_table(h);
                    }
                    sd.headers.emplace_back(h);
                }

                if (hf.end_stream_) {
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

                // 先唤醒等待者, 再尝试释放终止的流 (避免释放后悬垂引用).
                maybe_release_stream(sid);

                // 通知 async_accept 有新流到达.
                if (accept_waiter_) {
                    accept_waiter_();
                    accept_waiter_ = nullptr;
                }
            } else {
                // 头部块有后续 CONTINUATION 帧 — 暂存原始 payload.
                // 上一个头部块尚未以 CONTINUATION 结束又收到新的 HEADERS → 协议错误.
                if (sd.headers_in_progress) {
                    co_await send_goaway(sid, http2_error_code::PROTOCOL_ERROR);
                    abort_ = true;
                    co_return;
                }
                sd.headers_in_progress = true;
                sd.pending_end_stream = hf.end_stream_;
                auto payload = fc.payload();
                auto plen = fc.payload_size();
                // 跳过 padding / priority 前缀 (与 unpack_headers 逻辑保持一致).
                size_t offset = 0;
                uint8_t pad_len = 0;
                if (hf.padded_) {
                    if (plen < 1) {
                        co_await send_goaway(sid, http2_error_code::PROTOCOL_ERROR);
                        abort_ = true;
                        co_return;
                    }
                    pad_len = payload[0];
                    if (pad_len >= plen - 1) {
                        co_await send_goaway(sid, http2_error_code::PROTOCOL_ERROR);
                        abort_ = true;
                        co_return;
                    }
                    offset += 1;
                }
                if (hf.priority_) {
                    if (plen - offset < 5) {
                        co_await send_goaway(sid, http2_error_code::PROTOCOL_ERROR);
                        abort_ = true;
                        co_return;
                    }
                    offset += 5;
                }
                sd.pending_header_block.insert(
                    sd.pending_header_block.end(),
                    payload + offset, payload + plen - pad_len);
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

                // 唤醒该流所有等待者, 使阻塞在 wait_until 的协程即时退出,
                if (it->second.read_waiter) {
                    it->second.read_waiter();
                    it->second.read_waiter = nullptr;
                }
                if (it->second.write_waiter) {
                    it->second.write_waiter();
                    it->second.write_waiter = nullptr;
                }

                // 重置流的缓冲数据已不可读, 唤醒等待者后直接移除, 防止累积.
                streams_.erase(it);
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
            if (!apply_peer_settings(sf.entries_)) {
                // 流控窗口越界 → 连接错误.
                co_await send_goaway(0, http2_error_code::FLOW_CONTROL_ERROR);
                abort_ = true;
                co_return;
            }

            // 发送 SETTINGS ACK.
            sf.ack_ = true;
            sf.entries_.clear();
            sf.pack_settings();
            queue_frame(sf);

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
                queue_frame(pf);
            }
            co_return;
        }

        net::awaitable<void> handle_goaway_frame(frame_codec& fc)
        {
            goaway_frame gf(fc.data_, fc.size_);

            // 记录 GOAWAY 信息并关闭连接.
            last_stream_id_ = gf.get_last_stream_id();
            abort_ = true;

            // GOAWAY 影响所有流: 先标记为已重置再唤醒等待者,
            // 使读取者返回 stream_closed 而非干净的 EOF.
            for (auto& [id, sd] : streams_) {
                sd.reset_received = true;
                if (sd.read_waiter) { sd.read_waiter(); sd.read_waiter = nullptr; }
                if (sd.write_waiter) { sd.write_waiter(); sd.write_waiter = nullptr; }
            }
            if (accept_waiter_) { accept_waiter_(); accept_waiter_ = nullptr; }

            co_return;
        }

        net::awaitable<void> handle_window_update_frame(frame_codec& fc)
        {
            auto sid = fc.stream_id();
            window_update_frame wuf(fc.data_, fc.size_);
            uint32_t increment = wuf.get_window_increment();

            // RFC 7540 §6.9: WINDOW_UPDATE 增量必须非 0.
            if (increment == 0) {
                co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }

            if (sid == 0) {
                // 连接级窗口更新. RFC 7540 §6.9.1: 窗口超过 2^31-1 是连接错误.
                if (conn_remote_window_ + increment > 0x7FFFFFFF) {
                    co_await send_goaway(0, http2_error_code::FLOW_CONTROL_ERROR);
                    abort_ = true;
                    co_return;
                }
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
                    if (it->second.remote_window + increment > 0x7FFFFFFF) {
                        co_await send_goaway(0, http2_error_code::FLOW_CONTROL_ERROR);
                        abort_ = true;
                        co_return;
                    }
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
            if (it == streams_.end()) {
                co_return;
            }

            auto& sd = it->second;

            // 没有在途的 HEADERS (END_HEADERS 未置位) 就收到 CONTINUATION → 协议错误.
            if (!sd.headers_in_progress) {
                co_await send_goaway(sid, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }

            // 累积本次 CONTINUATION 的头部块片段, 并设置大小上限防止内存耗尽.
            auto& frag = cf.get_header_block_fragment();
            size_t limit = settings_.max_header_list_size > 0
                ? settings_.max_header_list_size
                : (16 * 1024 * 1024);
            if (sd.pending_header_block.size() + frag.size() > limit) {
                co_await send_goaway(sid, http2_error_code::ENHANCE_YOUR_CALM);
                abort_ = true;
                co_return;
            }
            sd.pending_header_block.insert(
                sd.pending_header_block.end(),
                frag.begin(), frag.end());

            if (cf.is_end_headers()) {
                // 最后一块到达 — 构造合成 HEADERS 帧来解析完整头部块.
                auto total = sd.pending_header_block.size();
                std::vector<uint8_t> tmp(total + 9);
                tmp[3] = static_cast<uint8_t>(frame_type::HEADERS);
                tmp[4] = static_cast<uint8_t>(frame_flag::END_HEADERS);
                tmp[0] = (total >> 16) & 0xFF;
                tmp[1] = (total >> 8) & 0xFF;
                tmp[2] = total & 0xFF;
                tmp[5] = (sid >> 24) & 0xFF;
                tmp[6] = (sid >> 16) & 0xFF;
                tmp[7] = (sid >> 8) & 0xFF;
                tmp[8] = sid & 0xFF;
                std::memcpy(tmp.data() + 9, sd.pending_header_block.data(), total);

                // 解析累积的完整头部块，若 HPACK 数据损坏则发送 GOAWAY.
                bool hpack_error = false;
                try {
                    headers_frame cont_hf(tmp.data(), tmp.size(), true, &dynamic_table_);

                    for (auto& h : cont_hf.headers_) {
                        if (h.type_ == &G_LITERAL_INCREMENTAL_INDEXING) {
                            add_to_dynamic_table(h);
                        }
                        sd.headers.emplace_back(h);
                    }
                } catch (const std::exception&) {
                    hpack_error = true;
                }

                if (hpack_error) {
                    co_await send_goaway(sid, http2_error_code::COMPRESSION_ERROR);
                    abort_ = true;
                    co_return;
                }

                // 应用分片 HEADERS 帧的 END_STREAM 标志.
                if (sd.pending_end_stream) {
                    if (sd.state != stream_state::idle) {
                        sd.state = (sd.state == stream_state::half_closed_local)
                            ? stream_state::closed
                            : stream_state::half_closed_remote;
                    }
                    sd.remote_end_stream = true;
                    sd.pending_end_stream = false;
                }

                if (sd.read_waiter) {
                    sd.read_waiter();
                    sd.read_waiter = nullptr;
                }

                if (accept_waiter_) {
                    accept_waiter_();
                    accept_waiter_ = nullptr;
                }

                sd.pending_header_block.clear();
                sd.headers_in_progress = false;

                // 尝试释放已终止且数据已消费完的流.
                maybe_release_stream(sid);
            }

            co_return;
        }

        // ── 帧发送辅助 ──

        net::awaitable<void> send_rst_stream(uint32_t sid, http2_error_code code)
        {
            co_return co_await send_control_frame<rst_stream_frame>(
                sid, frame_type::RST_STREAM,
                [code](auto& f) { f.set_error_code(code); });
        }

        net::awaitable<void> send_window_update(uint32_t sid, uint32_t increment)
        {
            co_return co_await send_control_frame<window_update_frame>(
                sid, frame_type::WINDOW_UPDATE,
                [increment](auto& f) { f.set_window_increment(increment); });
        }

        net::awaitable<void> send_goaway(uint32_t last_sid, http2_error_code code)
        {
            co_return co_await send_control_frame<goaway_frame>(
                0, frame_type::GOAWAY,
                [last_sid, code](auto& f) {
                    f.set_last_stream_id(last_sid);
                    f.set_error_code(code);
                });
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
            // RFC 7541 §4.1: entry 的字节大小 = name 长度 + value 长度 + 32.
            size_t entry_size = 32;
            if (entry.name_) entry_size += entry.name_->size();
            if (entry.value_) entry_size += entry.value_->size();

            size_t max_size = settings_.header_table_size;

            // 如果单个 entry 超过上限，则清空整个表.
            if (entry_size > max_size) {
                dynamic_table_.clear();
                dynamic_table_map_.clear();
                dynamic_table_size_ = 0;
                return;
            }

            // 移除最旧的条目直到有足够空间.
            while (dynamic_table_size_ + entry_size > max_size &&
                   !dynamic_table_.empty()) {
                auto& old = dynamic_table_.back();
                size_t old_size = 32;
                if (old.name_) old_size += old.name_->size();
                if (old.value_) old_size += old.value_->size();
                dynamic_table_size_ -= old_size;
                dynamic_table_map_.erase(old.hash_);
                dynamic_table_.pop_back();
            }

            dynamic_table_.insert(dynamic_table_.begin(), entry);
            dynamic_table_size_ += entry_size;
            dynamic_table_map_[entry.hash_] = 0;

            // 重新索引.
            for (size_t i = dynamic_table_.size(); i > 0; --i) {
                dynamic_table_map_[dynamic_table_[i - 1].hash_] = static_cast<int>(i - 1);
            }
        }

        // 用于发送数据的处理 pump.
        net::awaitable<void> pump_out() noexcept
        {
            boost::system::error_code ec;

            while (!abort_) {
                while (out_queue_.empty()) {
                    if (abort_) break;
                    // 输出队列为空时, 等待.
                    // timer 永不自然超时, 仅靠 write_frame_data 中的
                    // out_notifier_.cancel() 唤醒.
                    out_notifier_.expires_at(
                        net::steady_timer::time_point::max());
                    co_await out_notifier_.async_wait(net_awaitable[ec]);
                    if (ec == net::error::operation_aborted)
                        ec.clear(); // 被 write_frame_data 唤醒.
                }
                if (abort_) break;
                // 从输出队列中取出数据.
                auto data = std::move(out_queue_.front());
                out_queue_.pop_front();
                // 异步发送数据.
                co_await net::async_write(next_layer_, net::buffer(data), net_awaitable[ec]);
                if (ec) {
                    if (!abort_) {
                        abort_ = true;
                    }
                    break;
                }
            }

            // pump_out 退出时, 关闭 socket 取消 pump_in 的 async_read,
            // 确保 pump_in 不会永久阻塞 (与 pump_in 的退出处理对称).
            {
                boost::system::error_code ignored;
                next_layer_.lowest_layer().close(ignored);
            }
            co_return;
        }

        // 用于接收数据的处理 pump.
        net::awaitable<void> pump_in()
        {
            boost::system::error_code ec;

            while (!abort_) {
                try {
                    // 使用持久分配缓冲区，避免每次迭代重复分配.
                    // 注意: 此时帧头尚未读入缓冲区, frame_codec 构造时
                    // 不能做 payload_size 校验 (会读到未初始化数据), 故传 validate=false;
                    // 真正的帧长校验由 async_read_frame 读入 9 字节帧头后执行.
                    frame_codec fc(pump_buf_.get(),
                        settings_.max_frame_size + 9, false);

                    // 异步读取帧.
                    co_await async_read_frame(fc, ec);
                    if (ec) {
                        if (!abort_) {
                            abort_ = true;
                        }
                        break;
                    }

                    // 分派帧处理.
                    co_await handle_frame(fc);
                } catch (const std::exception& e) {
                    // 防止 handle_frame (或其调用的 send_control_frame /
                    // pack_payload 等) 抛出异常时, pump_in 直接退出而跳过
                    // 下方的清理逻辑, 导致 pump_out 永久阻塞在
                    // out_notifier_.async_wait() 上, 进而使
                    // (pump_in() && pump_out()) 永不完成 → 死锁.
                    if (!abort_) {
                        abort_ = true;
                    }
                    break;
                }
            }

            // pump_in 退出时, 唤醒 pump_out 并关闭 socket, 确保 pump_out
            // 不会在 async_wait 或 async_write 上永久阻塞.
            // (&& 使用 wait_for_one_error, 仅在一方出错时取消另一方;
            //  若 pump_in 正常返回 (如 abort_ 被设置) 则不会取消 pump_out,
            //  导致 pump_out 永久阻塞在 out_notifier_.async_wait(), 进而
            //  使 && 永不完成, 唤醒等待者的 post-pump 代码永不执行 → 死锁.)
            out_notifier_.cancel();
            {
                boost::system::error_code ignored;
                next_layer_.lowest_layer().close(ignored);
            }
            co_return;
        }


    private:
        // 下一层协议栈.
        NextLayer next_layer_;

    private:
        // 输出队列, 用于存储待发送的数据.
        std::deque<std::vector<uint8_t>> out_queue_;

        // 用于通知输出处理 pump 发送数据的定时器.
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
        size_t dynamic_table_size_ = 0;

        // 用于标记是否需要中止连接.
        std::atomic_bool abort_{false};

        // pump 缓冲区（持久分配，避免每次 pump_in 迭代重复分配）.
        std::unique_ptr<uint8_t[]> pump_buf_;

        // pump 协程退出标志（pump_in/pump_out 完成时设为 true）.
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
            bool pending_end_stream = false;  // 暂存分片 HEADERS 的 END_STREAM 标志.
            bool headers_in_progress = false; // 分片 HEADERS (END_HEADERS 未置位) 是否在途.

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