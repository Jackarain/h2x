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
#include <boost/asio/post.hpp>
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

        // stream 的实现位于 h2_stream.hpp, 需要访问 connection 的私有成员,
        // 故声明为友元.
        friend stream_type;

        ////////////////////////////////////////////////////////////////////////////////

        template <typename Arg>
        connection(Arg&& next_layer)
            : next_layer_(static_cast<Arg&&>(next_layer))
            , out_notifier_(next_layer_.get_executor())
            , strand_(next_layer_.get_executor())
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

                // 立即采用调用方配置: 握手期间派发的流水线帧 (如 SETTINGS 后
                // 紧跟的 HEADERS) 必须基于本端真实设置处理, 而不是默认值.
                settings_ = s;
                dec_dynamic_table_max_ = s.header_table_size;

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

                // 构建并发送连接设置帧.
                // 缓冲区按最大帧大小分配, 避免对端 SETTINGS 帧过大时
                // 因固定 256 字节缓冲区而误报 frame_size_error.
                std::vector<uint8_t> bufs(settings_.max_frame_size + 9);

                settings_frame sf(bufs.data(), bufs.size(), false);

                sf.entries_.emplace_back(settings_id::SETTINGS_HEADER_TABLE_SIZE, s.header_table_size);
                sf.entries_.emplace_back(settings_id::SETTINGS_ENABLE_PUSH, s.enable_push);
                sf.entries_.emplace_back(settings_id::SETTINGS_MAX_CONCURRENT_STREAMS, s.max_concurrent_streams);
                sf.entries_.emplace_back(settings_id::SETTINGS_INITIAL_WINDOW_SIZE, s.initial_window_size);
                sf.entries_.emplace_back(settings_id::SETTINGS_MAX_FRAME_SIZE, s.max_frame_size);
                sf.entries_.emplace_back(settings_id::SETTINGS_MAX_HEADER_LIST_SIZE, s.max_header_list_size);
                sf.entries_.emplace_back(settings_id::SETTINGS_NO_RFC7540_PRIORITIES, s.no_rfc7540_priorities);
                sf.entries_.emplace_back(settings_id::SETTINGS_ENABLE_CONNECT_PROTOCOL, s.enable_connect_protocol);

                sf.pack_settings();

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
                if (auto err = apply_peer_settings(sf.entries_)) {
                    switch (*err) {
                    case http2_error_code::FRAME_SIZE_ERROR:
                        ec = make_error_code(errc::frame_size_error);
                        break;
                    case http2_error_code::FLOW_CONTROL_ERROR:
                        ec = make_error_code(errc::flow_control_error);
                        break;
                    default:
                        ec = make_error_code(errc::protocol_error);
                        break;
                    }
                    co_return;
                }

                // 发送连接设置帧 ACK.
                sf.ack_ = true;
                sf.entries_.clear();
                sf.pack_settings();

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
                        // SETTINGS ACK 不得携带 payload (RFC 9113 §6.5).
                        if (sf.payload_size() != 0) {
                            co_await async_write_goaway(0, http2_error_code::FRAME_SIZE_ERROR);
                            ec = make_error_code(errc::frame_size_error);
                            co_return;
                        }
                        got_ack = true;
                    } else {
                        co_await handle_frame(sf);
                    }
                }

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
                            wake_waiter(sd.read_waiter);
                            wake_waiter(sd.write_waiter);
                        }
                        wake_waiter(self->accept_waiter_);
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

        // 握手期间 pump 尚未启动, out_queue_ 不会被冲刷; 需要上报连接错误时
        // 直接写一个 GOAWAY 帧到对端.
        net::awaitable<void> async_write_goaway(uint32_t last_sid, http2_error_code code)
        {
            std::vector<uint8_t> buf(64, 0);
            goaway_frame f(buf.data(), buf.size(), false);
            f.stream_id(0);
            f.type(frame_type::GOAWAY);
            f.set_last_stream_id(last_sid);
            f.set_error_code(code);
            f.pack_payload();
            buf.resize(f.frame_size());

            boost::system::error_code ignored;
            co_await net::async_write(next_layer_, net::buffer(buf), net_awaitable[ignored]);
            co_return;
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
        void enqueue_control_frame(uint32_t sid, frame_type ft, Setup&& setup)
        {
            auto buf = std::vector<uint8_t>(64, 0);
            Frame f(buf.data(), buf.size(), false);
            f.stream_id(sid);
            f.type(ft);
            std::forward<Setup>(setup)(f);
            f.pack_payload();
            buf.resize(f.frame_size());
            write_frame_data(std::move(buf));
        }

        template <class Frame, class Setup>
        net::awaitable<void> send_control_frame(uint32_t sid, frame_type ft, Setup&& setup)
        {
            enqueue_control_frame<Frame>(sid, ft, std::forward<Setup>(setup));
            co_return;
        }

    private:
        // 从对端 SETTINGS 更新本地配置. 返回 false 表示流控窗口越界
        // (RFC 7540 §6.5.2/§6.9.2 连接错误 FLOW_CONTROL_ERROR).
        // 从对端 SETTINGS 更新本地配置. 返回 std::nullopt 表示应用成功;
        // 否则返回需要上报的连接错误码 (RFC 7540 §6.5.2).
        std::optional<http2_error_code>
        apply_peer_settings(const std::vector<settings_entry>& entries)
        {
            for (auto& e : entries) {
                switch (static_cast<settings_id>(e.identifier_)) {
                case settings_id::SETTINGS_HEADER_TABLE_SIZE:
                    if (e.value_ != peer_header_table_size_) {
                        peer_header_table_size_ = e.value_;
                        // 立即按新上限驱逐编码方向动态表 (RFC 7541 §4.3),
                        // 并记录需在下一个头部块开头发出的动态表大小更新.
                        hpack_dynamic_table_shrink(enc_dynamic_table_,
                            enc_dynamic_table_size_, e.value_,
                            &enc_dynamic_table_map_);
                        pending_enc_table_size_update_ = e.value_;
                    }
                    break;
                case settings_id::SETTINGS_ENABLE_PUSH:
                    // 取值只能是 0 或 1.
                    if (e.value_ > 1)
                        return http2_error_code::PROTOCOL_ERROR;
                    // 服务端不得显式把该值设为 1, 客户端收到即为连接错误
                    // (RFC 9113 §6.5.2).
                    if (role_ == role::client && e.value_ != 0)
                        return http2_error_code::PROTOCOL_ERROR;
                    break;
                case settings_id::SETTINGS_MAX_CONCURRENT_STREAMS:
                    peer_max_concurrent_streams_ = e.value_;
                    break;
                case settings_id::SETTINGS_INITIAL_WINDOW_SIZE:
                {
                    // 窗口值不得超过 2^31-1 (RFC 7540 §6.5.2).
                    if (e.value_ > 0x7FFFFFFF)
                        return http2_error_code::FLOW_CONTROL_ERROR;

                    int64_t delta = static_cast<int64_t>(e.value_)
                                  - static_cast<int64_t>(peer_initial_window_size_);
                    peer_initial_window_size_ = e.value_;
                    for (auto& [id, sd] : streams_) {
                        // 调整后任一流的远端窗口不得超过 2^31-1 (RFC 7540 §6.9.2).
                        if (sd.remote_window + delta > 0x7FFFFFFF)
                            return http2_error_code::FLOW_CONTROL_ERROR;
                        sd.remote_window += delta;
                        // 窗口增大后必须唤醒等待发送的写入者; 否则发送协程
                        // 即使窗口已恢复也会永久挂起.
                        wake_waiter(sd.write_waiter);
                    }
                    break;
                }
                case settings_id::SETTINGS_MAX_FRAME_SIZE:
                    // 取值范围 [2^14, 2^24-1], 越界属连接错误 PROTOCOL_ERROR
                    // (RFC 9113 §6.5.2).
                    if (e.value_ < 16384 || e.value_ > 0xFFFFFF)
                        return http2_error_code::PROTOCOL_ERROR;
                    peer_max_frame_size_ = e.value_;
                    break;
                case settings_id::SETTINGS_ENABLE_CONNECT_PROTOCOL:
                    // 取值必须是 0 或 1 (RFC 8441 §3).
                    if (e.value_ > 1)
                        return http2_error_code::PROTOCOL_ERROR;
                    break;
                case settings_id::SETTINGS_NO_RFC7540_PRIORITIES:
                    // 取值必须是 0 或 1 (RFC 9218 §2.1).
                    if (e.value_ > 1)
                        return http2_error_code::PROTOCOL_ERROR;
                    break;
                default:
                    break;
                }
            }
            return std::nullopt;
        }

        // 判断流标识符是否仍处于 idle 状态 (对端尚未在其上发起流).
        // 对端发起的流使用与本地相反的奇偶性; 本地已打开过的流由
        // next_stream_id_ 界定 (RFC 9113 §5.1.1).
        bool is_idle_stream(uint32_t sid) const
        {
            const bool peer_parity = (role_ == role::client)
                ? (sid % 2 == 0) : (sid % 2 == 1);
            return peer_parity
                ? (sid > last_peer_stream_id_)
                : (sid >= next_stream_id_);
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

        // ── 流状态数据结构 ──

        struct stream_state_data {
            uint32_t stream_id = 0;
            stream_state state = stream_state::idle;
            bool is_remote_initiated = false;
            bool remote_end_stream = false;
            bool reset_received = false;
            bool pending_end_stream = false;  // 暂存分片 HEADERS 的 END_STREAM 标志.
            bool discard_headers = false;     // 已关闭流上的头部块: 解码后丢弃.
            bool refused = false;             // 超过并发上限; 仅用于解码 HPACK 后拒绝.

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

        // 唤醒一个 waiter 槽位. 注意: 唤醒时不清理槽位, 槽位由挂起的
        // 协程恢复后自行清空 (见 wait_for). 这样在"唤醒后、协程恢复前"
        // 槽位仍非空, 使 maybe_release_stream 不会在该窗口内删除流状态,
        // 避免协程恢复时访问已释放的流状态导致 use-after-free.
        static void wake_waiter(std::function<void()>& waiter)
        {
            if (waiter) {
                waiter();
            }
        }

        // 收到对端 END_STREAM 后的流状态迁移.
        void mark_remote_end_stream(stream_state_data& sd)
        {
            // 仅在流已被 async_accept 拾取后（非 idle）才更新状态.
            if (sd.state != stream_state::idle) {
                sd.state = (sd.state == stream_state::half_closed_local)
                    ? stream_state::closed
                    : stream_state::half_closed_remote;
            }
            sd.remote_end_stream = true;
        }

        // 从流表中取走一个已就绪的远端流 ID (state==idle 且 is_remote_initiated),
        // 并将其状态置为 open; 没有可取的流时返回 0.
        uint32_t take_remote_stream_id()
        {
            for (auto& [sid, sd] : streams_) {
                if (sd.state == stream_state::idle && sd.is_remote_initiated) {
                    sd.state = stream_state::open;
                    sd.is_remote_initiated = false;
                    return sid;
                }
            }
            return 0;
        }

        // 通用等待: 注册 waiter 后挂起, 直到 pred 满足或被 abort 唤醒.
        // 实现说明:
        // - timer 设为永不自然超时 (time_point::max()), 仅靠 waiter_slot()
        //   即 timer.cancel() 唤醒.
        // - 注册 waiter 后、挂起前重检谓词, 关闭"注册到挂起之间"的竞态窗口.
        // - 依赖连接侧在所有改变等待条件的路径 (DATA/HEADERS/WINDOW_UPDATE/
        //   RST_STREAM/GOAWAY/close/pump 退出) 上调用 waiter_slot() 通知等待者.
        template <class Pred>
        net::awaitable<void> wait_for(std::function<void()>& waiter_slot, Pred pred)
        {
            boost::system::error_code ec;
            while (!pred() && !abort_) {
                net::steady_timer timer(get_executor());
                timer.expires_at(net::steady_timer::time_point::max());

                waiter_slot = [&timer]() { timer.cancel(); };

                // 注册 waiter 后、挂起前重检, 关闭竞态窗口:
                // 此段为同步执行 (无 co_await), 同 strand 上 pump 无法插入,
                // 故事件要么在此被捕获, 要么在挂起后被 waiter_slot() 唤醒.
                if (pred()) {
                    waiter_slot = nullptr;
                    break;
                }

                co_await timer.async_wait(net_awaitable[ec]);
                waiter_slot = nullptr;

                if (ec == net::error::operation_aborted) {
                    ec.clear(); // 被 waiter_slot() 唤醒.
                }
            }
            co_return;
        }

        // 处理接收到的各个类型帧.
        // 按帧类型校验 payload 长度 (RFC 9113 §4.2 / §6).
        // 返回 std::nullopt 表示合法; 否则返回应上报的连接错误码.
        static std::optional<http2_error_code> frame_length_error(
            frame_type type, uint32_t plen)
        {
            switch (type) {
            case frame_type::PING:
                if (plen != 8) return http2_error_code::FRAME_SIZE_ERROR;
                break;
            case frame_type::RST_STREAM:
                if (plen != 4) return http2_error_code::FRAME_SIZE_ERROR;
                break;
            case frame_type::PRIORITY:
                if (plen != 5) return http2_error_code::FRAME_SIZE_ERROR;
                break;
            case frame_type::SETTINGS:
                if (plen % 6 != 0) return http2_error_code::FRAME_SIZE_ERROR;
                break;
            case frame_type::GOAWAY:
                if (plen < 8) return http2_error_code::FRAME_SIZE_ERROR;
                break;
            case frame_type::PUSH_PROMISE:
                if (plen < 4) return http2_error_code::FRAME_SIZE_ERROR;
                break;
            default:
                break;
            }
            return std::nullopt;
        }

        // 校验 HEADERS/PUSH_PROMISE 的 Padding/Priority 前缀, 同时给出头部块
        // 的起始偏移与填充长度 (RFC 9113 §4.2/§6.2):
        //   - PADDED/PRIORITY 前缀不足必需字节数 → FRAME_SIZE_ERROR
        //   - pad length 超出前缀之后的剩余长度 → PROTOCOL_ERROR
        // 返回 std::nullopt 表示合法.
        static std::optional<http2_error_code> headers_prefix_error(
            const uint8_t* payload, size_t plen, bool padded, bool priority,
            size_t& offset, uint8_t& pad_len)
        {
            offset = 0;
            pad_len = 0;
            if (padded) {
                if (plen < 1)
                    return http2_error_code::FRAME_SIZE_ERROR;
                pad_len = payload[0];
                offset = 1;
            }
            if (priority) {
                if (plen - offset < 5)
                    return http2_error_code::FRAME_SIZE_ERROR;
                offset += 5;
            }
            if (static_cast<size_t>(pad_len) > plen - offset)
                return http2_error_code::PROTOCOL_ERROR;
            return std::nullopt;
        }

        net::awaitable<void> handle_frame(frame_codec& fc)
        {
            auto type = fc.type();
            auto sid = fc.stream_id();

            // 头部块在途期间 (HEADERS 未置 END_HEADERS), 只允许同一流上的
            // CONTINUATION 帧, 其它任何帧都是连接错误 (RFC 9113 §6.2/§6.10).
            if (header_block_sid_ != 0
                && !(type == frame_type::CONTINUATION && sid == header_block_sid_)) {
                co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }

            // CONTINUATION 必须紧跟在未置 END_HEADERS 的 HEADERS/PUSH_PROMISE
            // 之后; 没有在途头部块时收到 CONTINUATION 属连接错误
            // (RFC 9113 §6.10).
            if (type == frame_type::CONTINUATION && header_block_sid_ == 0) {
                co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }

            // 帧长度不合法属连接错误: 回对应错误帧而不是静默断连.
            if (auto err = frame_length_error(type, fc.payload_size())) {
                co_await send_goaway(0, *err);
                abort_ = true;
                co_return;
            }

            // 部分帧类型对 stream id 有强约束 (RFC 7540 §6): 违反即连接错误.
            switch (type) {
            case frame_type::SETTINGS:
            case frame_type::PING:
                // SETTINGS/PING 只作用于连接.
                if (sid != 0) {
                    co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                    abort_ = true;
                    co_return;
                }
                break;
            case frame_type::GOAWAY:
                // GOAWAY 只作用于连接, 流标识符必须为 0 (RFC 9113 §6.8).
                if (sid != 0) {
                    co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                    abort_ = true;
                    co_return;
                }
                break;
            case frame_type::PRIORITY:
            case frame_type::RST_STREAM:
                // PRIORITY/RST_STREAM 必须关联到具体流.
                if (sid == 0) {
                    co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                    abort_ = true;
                    co_return;
                }
                break;
            default:
                break;
            }

            switch (type) {
            case frame_type::DATA:
                co_await handle_data_frame(fc);
                break;
            case frame_type::HEADERS:
                co_await handle_headers_frame(fc);
                break;
            case frame_type::PRIORITY:
                co_await handle_priority_frame();
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

            // DATA 的流标识符不得为 0 (RFC 7540 §6.1): 连接错误.
            if (sid == 0) {
                co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }

            data_frame df(fc.data_, fc.size_);
            // 流控按整个 DATA 负载计量, 含 Pad Length 与 Padding 字段
            // (RFC 7540 §6.9.1); 仅剔除 padding 会让对端用 padding 绕过窗口.
            int64_t data_len = static_cast<int64_t>(fc.payload_size());

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
                // 空闲流上收到 DATA 属连接错误 PROTOCOL_ERROR (RFC 9113 §5.1);
                // 已关闭并被回收的流则回 RST_STREAM(STREAM_CLOSED).
                if (is_idle_stream(sid)) {
                    co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                    abort_ = true;
                    co_return;
                }
                co_await send_rst_stream(sid, http2_error_code::STREAM_CLOSED);
                co_return;
            }

            auto& sd = it->second;

            // 保留流 (reserved) 上不允许 DATA: 连接错误 PROTOCOL_ERROR
            // (RFC 9113 §5.1).
            if (sd.state == stream_state::reserved_remote ||
                sd.state == stream_state::reserved_local) {
                co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }

            // 如果流已关闭或收到重置，忽略 DATA 帧 (连接级窗口已入账).
            if (sd.state == stream_state::closed || sd.reset_received) {
                co_return;
            }

            // DATA 只允许出现在 open / half-closed(local) 状态 (RFC 9113 §6.1);
            // half-closed(remote) 表示对端已发送 END_STREAM, 之后不应再有 DATA.
            if (sd.state == stream_state::half_closed_remote) {
                co_await send_rst_stream(sid, http2_error_code::STREAM_CLOSED);
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
            wake_waiter(sd.read_waiter);

            if (df.is_end_stream()) {
                mark_remote_end_stream(sd);
            }

            // 尝试释放已终止且数据已消费完的流.
            maybe_release_stream(sid);

            co_return;
        }

        net::awaitable<void> handle_headers_frame(frame_codec& fc)
        {
            auto sid = fc.stream_id();

            // HEADERS 的流标识符不得为 0 (RFC 7540 §6.2): 连接错误.
            if (sid == 0) {
                co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }

            auto it = streams_.find(sid);

            // 如果是新流 ID（服务端收到客户端请求）.
            if (it == streams_.end()) {
                // 新流标识符必须严格递增, 且只能由对端经 HEADERS 发起:
                // - 服务端只能接受客户端发起的奇数流, 且 id > last_peer_stream_id_
                // - 客户端不能经 HEADERS 接受服务端发起的流 (必须经 PUSH_PROMISE)
                // (RFC 9113 §5.1/§5.1.1).
                const bool acceptable_new_stream =
                    (role_ == role::server) && (sid % 2 == 1) &&
                    (sid > last_peer_stream_id_);
                if (!acceptable_new_stream) {
                    co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                    abort_ = true;
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
                const bool refused =
                    active >= settings_.max_concurrent_streams;

                // 即使要拒绝该流, 也必须先解码其头部块, 以维持连接级 HPACK
                // 动态表状态 (RFC 7540 §4.3); 故先登记流状态承载解码, 稍后拒绝.
                it = streams_.emplace(sid, stream_state_data{}).first;
                it->second.stream_id = sid;
                if (sid > last_peer_stream_id_)
                    last_peer_stream_id_ = sid;
                if (refused) {
                    it->second.refused = true;
                    it->second.state = stream_state::closed;
                } else {
                    it->second.state = stream_state::idle;  // 等待 async_accept 拾取
                    it->second.is_remote_initiated = true;
                    it->second.local_window = settings_.initial_window_size;
                    it->second.remote_window = peer_initial_window_size_;
                }
            }

            auto& sd = it->second;

            // 远端已发送 END_STREAM (half-closed(remote)), 或流已关闭/被重置时,
            // 再收到 HEADERS 属流错误 STREAM_CLOSED (RFC 9113 §5.1).
            // 头部块仍须解码以维持 HPACK 动态表同步, 但字段不得交付应用.
            const bool headers_after_remote_end =
                (sd.state == stream_state::half_closed_remote) ||
                (sd.state == stream_state::closed) || sd.reset_received;

            // 只解析 flags，不解码 HPACK（避免在 end_headers_=false 时解析截断数据导致异常）.
            headers_frame hf(fc.data_, fc.size_, false, &dec_dynamic_table_);
            hf.parse_flags();
            // 解码方向动态表上下文: 解析过程中就地加入增量索引表项.
            hf.set_decoder_table(&dec_dynamic_table_, &dec_dynamic_table_size_,
                &dec_dynamic_table_max_, settings_.header_table_size);

            // 前缀字段必须先于 HPACK 解码校验: 前缀过短/padding 越界时
            // unpack_headers 抛异常会被下方误判为 COMPRESSION_ERROR,
            // 而 RFC 9113 §4.2/§6.2 要求 FRAME_SIZE_ERROR / PROTOCOL_ERROR.
            size_t prefix_offset = 0;
            uint8_t pad_len = 0;
            if (auto err = headers_prefix_error(fc.payload(), fc.payload_size(),
                    hf.padded_, hf.priority_, prefix_offset, pad_len)) {
                co_await send_goaway(0, *err);
                abort_ = true;
                co_return;
            }

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

                // 头部块已解码 (动态表已同步), 此时再拒绝超限的新流.
                if (sd.refused) {
                    sd.headers.clear();
                    co_await send_rst_stream(sid, http2_error_code::REFUSED_STREAM);
                    streams_.erase(sid);
                    co_return;
                }

                // 远端方向已结束的流上收到的 HEADERS 仅用于同步 HPACK,
                // 字段必须丢弃, 并按流错误回 STREAM_CLOSED (RFC 9113 §5.1).
                if (headers_after_remote_end) {
                    if (sd.state == stream_state::half_closed_remote) {
                        co_await send_rst_stream(sid, http2_error_code::STREAM_CLOSED);
                    }
                    co_return;
                }

                // 复制解码结果 (动态表已在解析过程中就地更新).
                for (auto& h : hf.headers_) {
                    sd.headers.emplace_back(h);
                }

                if (hf.end_stream_) {
                    mark_remote_end_stream(sd);
                }

                // 通知等待的读取者.
                wake_waiter(sd.read_waiter);

                // 先唤醒等待者, 再尝试释放终止的流 (避免释放后悬垂引用).
                maybe_release_stream(sid);

                // 通知 async_accept 有新流到达.
                wake_waiter(accept_waiter_);
            } else {
                // 头部块有后续 CONTINUATION 帧 — 暂存原始 payload.
                header_block_sid_ = sid;
                header_block_promised_id_ = 0;
                sd.pending_end_stream = hf.end_stream_;
                if (headers_after_remote_end)
                    sd.discard_headers = true;
                auto payload = fc.payload();
                auto plen = fc.payload_size();
                // 跳过 padding / priority 前缀 (与 unpack_headers 逻辑保持一致).
                size_t offset = 0;
                uint8_t pad_len = 0;
                if (auto err = headers_prefix_error(payload, plen, hf.padded_,
                        hf.priority_, offset, pad_len)) {
                    co_await send_goaway(0, *err);
                    abort_ = true;
                    co_return;
                }
                sd.pending_header_block.insert(
                    sd.pending_header_block.end(),
                    payload + offset, payload + plen - pad_len);
            }

            co_return;
        }

        net::awaitable<void> handle_priority_frame()
        {
            // PRIORITY 帧在 RFC 7540 中可接收但不必须做任何事.
            co_return;
        }

        net::awaitable<void> handle_rst_stream_frame(frame_codec& fc)
        {
            auto sid = fc.stream_id();
            rst_stream_frame rf(fc.data_, fc.size_);

            auto it = streams_.find(sid);
            if (it == streams_.end()) {
                // 流不在表中: 可能是已关闭并被回收的流, 也可能是从未开启的
                // 空闲流. 对空闲流发送 RST_STREAM 是连接错误 (RFC 9113 §6.4).
                if (is_idle_stream(sid)) {
                    co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                    abort_ = true;
                    co_return;
                }
                co_return;
            }
            {
                it->second.state = stream_state::closed;
                it->second.reset_received = true;

                // 唤醒该流所有等待者, 使阻塞在 wait_until 的协程即时退出,
                wake_waiter(it->second.read_waiter);
                wake_waiter(it->second.write_waiter);

                // 重置流的缓冲数据已不可读, 唤醒等待者后延迟移除, 防止累积.
                // 延迟到被唤醒的协程恢复 (清空 waiter 槽位) 后再删除,
                // 避免协程恢复时访问已释放的流状态; 若仍有协程挂起则保留.
                net::post(strand_, [self = this->shared_from_this(), sid] {
                    auto it = self->streams_.find(sid);
                    if (it == self->streams_.end())
                        return;
                    if (it->second.read_waiter || it->second.write_waiter)
                        return;
                    self->streams_.erase(it);
                });
            }
            co_return;
        }

        net::awaitable<void> handle_settings_frame(frame_codec& fc)
        {
            settings_frame sf(fc.data_, fc.size_);

            // SETTINGS ACK 必须无 payload (RFC 9113 §6.5): 否则连接错误.
            if (sf.ack_ && fc.payload_size() != 0) {
                co_await send_goaway(0, http2_error_code::FRAME_SIZE_ERROR);
                abort_ = true;
                co_return;
            }

            // 如果是 ACK，不需要处理.
            if (sf.ack_) {
                co_return;
            }

            // 更新对端设置. 取值非法时使用对应错误码上报连接错误.
            if (auto err = apply_peer_settings(sf.entries_)) {
                co_await send_goaway(0, *err);
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

        // 解码一个完整的头部块, 维持连接级 HPACK 动态表 (RFC 9113 §4.3).
        // out 非空时把解出的字段追加到该流; 返回 false 表示 HPACK 数据损坏.
        bool decode_header_block(uint32_t assoc_sid, const uint8_t* block,
                                 size_t len, stream_state_data* out)
        {
            if (len == 0)
                return true;

            // 合成的 HEADERS 帧头只能表示 24 位负载长度.
            if (len > 0xFFFFFF)
                return false;

            std::vector<uint8_t> tmp(len + 9, 0);
            tmp[3] = static_cast<uint8_t>(frame_type::HEADERS);
            tmp[4] = static_cast<uint8_t>(frame_flag::END_HEADERS);
            tmp[0] = (len >> 16) & 0xFF;
            tmp[1] = (len >> 8) & 0xFF;
            tmp[2] = len & 0xFF;
            tmp[5] = (assoc_sid >> 24) & 0xFF;
            tmp[6] = (assoc_sid >> 16) & 0xFF;
            tmp[7] = (assoc_sid >> 8) & 0xFF;
            tmp[8] = assoc_sid & 0xFF;
            std::memcpy(tmp.data() + 9, block, len);

            try {
                headers_frame hf(tmp.data(), tmp.size(), false, &dec_dynamic_table_);
                hf.set_decoder_table(&dec_dynamic_table_, &dec_dynamic_table_size_,
                    &dec_dynamic_table_max_, settings_.header_table_size);
                hf.unpack_headers();
                if (out) {
                    for (auto& h : hf.headers_) {
                        out->headers.emplace_back(h);
                    }
                }
            } catch (const std::exception&) {
                return false;
            }
            return true;
        }

        net::awaitable<void> handle_push_promise_frame(frame_codec& fc)
        {
            push_promise_frame ppf(fc.data_, fc.size_);
            auto promised_id = ppf.get_promised_stream_id();

            // PUSH_PROMISE 只能由服务端发往客户端, 且接收方必须已启用推送
            // (RFC 9113 §5.1/§6.6): 服务端收到, 或客户端已声明
            // SETTINGS_ENABLE_PUSH=0 时收到, 均属连接错误.
            if (fc.stream_id() == 0 || role_ == role::server ||
                !settings_.enable_push) {
                co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }

            // 关联流必须是本端发起的流 (客户端为奇数), 且不能处于 idle;
            // 并且只允许 open / half-closed(local) 状态 (RFC 9113 §5.1/§6.6).
            const uint32_t sid = fc.stream_id();
            const bool local_initiated = (role_ == role::client)
                ? (sid % 2 == 1) : (sid % 2 == 0);
            if (!local_initiated || is_idle_stream(sid)) {
                co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }
            if (auto sit = streams_.find(sid); sit != streams_.end()) {
                const auto state = sit->second.state;
                if (state != stream_state::open &&
                    state != stream_state::half_closed_local) {
                    co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                    abort_ = true;
                    co_return;
                }
            }

            // promised stream id 必须是合法的下一个对端流标识符
            // (偶数且严格递增, RFC 9113 §5.1.1/§6.6).
            if (promised_id == 0 || promised_id % 2 != 0 ||
                promised_id <= last_peer_stream_id_) {
                co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }

            // PUSH_PROMISE 携带的头部块会修改连接级 HPACK 动态表; 即使应用
            // 不消费推送也必须解码, 否则后续 HEADERS 解码会失步
            // (RFC 9113 §4.3/§6.6).
            const auto& frag = ppf.get_header_block_fragment();
            if (!frag.empty() &&
                !decode_header_block(sid, frag.data(), frag.size(), nullptr)) {
                co_await send_goaway(sid, http2_error_code::COMPRESSION_ERROR);
                abort_ = true;
                co_return;
            }

            // 创建预留流.
            auto it = streams_.emplace(promised_id, stream_state_data{}).first;
            it->second.stream_id = promised_id;
            it->second.state = stream_state::reserved_remote;
            it->second.is_remote_initiated = true;
            if (promised_id > last_peer_stream_id_)
                last_peer_stream_id_ = promised_id;
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
                wake_waiter(sd.read_waiter);
                wake_waiter(sd.write_waiter);
            }
            wake_waiter(accept_waiter_);

            co_return;
        }

        net::awaitable<void> handle_window_update_frame(frame_codec& fc)
        {
            auto sid = fc.stream_id();

            // WINDOW_UPDATE 负载必须恰为 4 字节 (RFC 7540 §6.9): 连接错误.
            if (fc.payload_size() != 4) {
                co_await send_goaway(0, http2_error_code::FRAME_SIZE_ERROR);
                abort_ = true;
                co_return;
            }

            // 空闲流上收到 WINDOW_UPDATE 属连接错误 PROTOCOL_ERROR
            // (RFC 9113 §5.1); 已关闭并被回收的流则可安全忽略 (RFC 9113 §6.9).
            if (sid != 0 && is_idle_stream(sid)) {
                co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                abort_ = true;
                co_return;
            }

            // 保留流 (reserved) 上不允许 WINDOW_UPDATE: 连接错误 PROTOCOL_ERROR
            // (RFC 9113 §5.1); 该检查先于增量校验, 与 nghttp2 顺序一致.
            if (sid != 0) {
                auto rit = streams_.find(sid);
                if (rit != streams_.end() &&
                    (rit->second.state == stream_state::reserved_remote ||
                     rit->second.state == stream_state::reserved_local)) {
                    co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                    abort_ = true;
                    co_return;
                }
            }

            window_update_frame wuf(fc.data_, fc.size_);
            uint32_t increment = wuf.get_window_increment();

            // RFC 7540 §6.9: 增量必须非 0. 连接级为连接错误, 流级为流错误.
            if (increment == 0) {
                if (sid == 0) {
                    co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
                    abort_ = true;
                    co_return;
                }
                auto it = streams_.find(sid);
                if (it != streams_.end()) {
                    it->second.state = stream_state::closed;
                    it->second.reset_received = true;
                    wake_waiter(it->second.read_waiter);
                    wake_waiter(it->second.write_waiter);
                    co_await send_rst_stream(sid, http2_error_code::PROTOCOL_ERROR);
                }
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
                    wake_waiter(sd.write_waiter);
                }
            } else {
                // 流级窗口更新.
                auto it = streams_.find(sid);
                if (it != streams_.end()) {
                    // RFC 7540 §6.9.1: 流级窗口超过 2^31-1 属于流错误,
                    // 只重置该流; 以 GOAWAY 中断整条连接会牵连其它健康流.
                    if (it->second.remote_window + increment > 0x7FFFFFFF) {
                        it->second.state = stream_state::closed;
                        it->second.reset_received = true;
                        wake_waiter(it->second.read_waiter);
                        wake_waiter(it->second.write_waiter);
                        co_await send_rst_stream(sid, http2_error_code::FLOW_CONTROL_ERROR);
                        co_return;
                    }
                    it->second.remote_window += increment;
                    // 通知等待发送的写入者.
                    wake_waiter(it->second.write_waiter);
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
                // 最后一块到达 — 解析累积的完整头部块.
                if (!decode_header_block(sid, sd.pending_header_block.data(),
                        sd.pending_header_block.size(), &sd)) {
                    co_await send_goaway(sid, http2_error_code::COMPRESSION_ERROR);
                    abort_ = true;
                    co_return;
                }

                // 头部块已解码 (动态表已同步), 此时再拒绝超限的新流.
                if (sd.refused) {
                    sd.headers.clear();
                    sd.pending_header_block.clear();
                    header_block_sid_ = 0;
                    co_await send_rst_stream(sid, http2_error_code::REFUSED_STREAM);
                    streams_.erase(sid);
                    co_return;
                }

                // 远端方向已结束的流: 头部块仅用于同步 HPACK, 字段丢弃.
                if (sd.discard_headers) {
                    sd.discard_headers = false;
                    sd.pending_header_block.clear();
                    header_block_sid_ = 0;
                    if (sd.state == stream_state::half_closed_remote) {
                        co_await send_rst_stream(sid, http2_error_code::STREAM_CLOSED);
                    }
                    co_return;
                }

                // 应用分片 HEADERS 帧的 END_STREAM 标志.
                if (sd.pending_end_stream) {
                    mark_remote_end_stream(sd);
                    sd.pending_end_stream = false;
                }

                wake_waiter(sd.read_waiter);
                wake_waiter(accept_waiter_);

                sd.pending_header_block.clear();
                header_block_sid_ = 0;

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

        // 非协程版本, 供 catch 处理器 (不允许 co_await) 回错误帧使用.
        void enqueue_goaway(uint32_t last_sid, http2_error_code code)
        {
            enqueue_control_frame<goaway_frame>(
                0, frame_type::GOAWAY,
                [last_sid, code](auto& f) {
                    f.set_last_stream_id(last_sid);
                    f.set_error_code(code);
                });
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

        // 向动态表插入 entry 并按上限驱逐旧条目 (RFC 7541 §4.1/§4.3).
        // 编码/解码方向共用同一实现 (见 hpack_dynamic_table_add).
        static void dynamic_table_add(std::vector<header_entry>& table,
                                      std::unordered_map<uint32_t, int>* map,
                                      size_t& table_size,
                                      const header_entry& entry,
                                      size_t max_size)
        {
            hpack_dynamic_table_add(table, map, table_size, entry, max_size);
        }

        // 用于发送数据的处理 pump.
        net::awaitable<void> pump_out() noexcept
        {
            boost::system::error_code ec;

            // 退出条件基于"队列已空"而非仅 abort_: abort_ 置位后仍需把
            // 已排队的控制帧 (例如连接错误的 GOAWAY) 冲刷出去, 否则对端
            // 只会看到 TCP 连接被关闭而收不到任何错误信息.
            while (true) {
                while (out_queue_.empty() && !abort_) {
                    // 输出队列为空时, 等待.
                    // timer 永不自然超时, 仅靠 write_frame_data 中的
                    // out_notifier_.cancel() 唤醒.
                    out_notifier_.expires_at(
                        net::steady_timer::time_point::max());
                    co_await out_notifier_.async_wait(net_awaitable[ec]);
                    if (ec == net::error::operation_aborted)
                        ec.clear(); // 被 write_frame_data 唤醒.
                }
                if (out_queue_.empty())
                    break;
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
                            // 帧超过本端 SETTINGS_MAX_FRAME_SIZE 等长度问题
                            // 属于连接错误, 回 GOAWAY 而不是静默关闭连接.
                            if (ec == make_error_code(errc::frame_size_error)) {
                                co_await send_goaway(0, http2_error_code::FRAME_SIZE_ERROR);
                            }
                            abort_ = true;
                        }
                        break;
                    }

                    // 分派帧处理.
                    co_await handle_frame(fc);
                } catch (const std::runtime_error&) {
                    // 防止 handle_frame (或其调用的 send_control_frame /
                    // pack_payload 等) 抛出异常时, pump_in 直接退出而跳过
                    // 下方的清理逻辑, 导致 pump_out 永久阻塞在
                    // out_notifier_.async_wait() 上, 进而使
                    // (pump_in() && pump_out()) 永不完成 → 死锁.
                    // payload 解析失败 (如 padding 非法) 属连接错误, 回
                    // GOAWAY(PROTOCOL_ERROR) 而不是静默断开; catch 处理器
                    // 内不允许 co_await, 故用非协程入队.
                    if (!abort_) {
                        enqueue_goaway(0, http2_error_code::PROTOCOL_ERROR);
                        abort_ = true;
                    }
                    break;
                } catch (const std::exception&) {
                    // 非协议性异常 (如内存不足): 仅中止连接并退出循环,
                    // 不上报 PROTOCOL_ERROR, 避免把系统级故障误判为对端违规.
                    abort_ = true;
                    break;
                }
            }

            // pump_in 退出时, 唤醒 pump_out, 并给它一个有界窗口把队列中的
            // 控制帧 (如 GOAWAY) 冲刷出去, 避免对端只看到 TCP 关闭.
            // 队列清空即提前返回, 最多等待 200ms.
            // (&& 使用 wait_for_one_error, 仅在一方出错时取消另一方;
            //  若 pump_in 正常返回 (如 abort_ 被设置) 则不会取消 pump_out,
            //  导致 pump_out 永久阻塞在 out_notifier_.async_wait(), 进而
            //  使 && 永不完成, 唤醒等待者的 post-pump 代码永不执行 → 死锁.)
            out_notifier_.cancel();
            {
                auto deadline = std::chrono::steady_clock::now()
                    + std::chrono::milliseconds(200);
                while (!out_queue_.empty()
                       && std::chrono::steady_clock::now() < deadline) {
                    boost::system::error_code ignored;
                    net::steady_timer drain_timer(get_executor());
                    drain_timer.expires_after(std::chrono::milliseconds(2));
                    co_await drain_timer.async_wait(net_awaitable[ignored]);
                }
            }
            // 关闭 socket, 确保 pump_out 不会在 async_wait/async_write 上永久阻塞.
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

        // 正在接收的头部块所属流 ID (0 表示当前无在途头部块).
        // HEADERS 未置 END_HEADERS 后, 只允许同流的 CONTINUATION 帧.
        uint32_t header_block_sid_ = 0;

        // 在途头部块的来源: 0 表示 HEADERS, 非 0 表示 PUSH_PROMISE 且值为
        // 被承诺流 ID. PUSH_PROMISE 的块内容属于被承诺流, 但 CONTINUATION
        // 与 header_block_sid_ 一样使用关联流 ID (RFC 9113 §6.6/§6.10).
        uint32_t header_block_promised_id_ = 0;

        // 对端已发起的最大流 ID, 用于判定 RST_STREAM 是否落在空闲流上
        // (RFC 9113 §6.4): 高于该值的对端流从未开启, 属空闲流.
        uint32_t last_peer_stream_id_ = 0;

        // 解码方向动态表 (对端编码器写入), 上限为本端 SETTINGS_HEADER_TABLE_SIZE.
        std::vector<header_entry> dec_dynamic_table_;
        size_t dec_dynamic_table_size_ = 0;
        size_t dec_dynamic_table_max_ = 4096;  // 当前生效上限 (可被 size update 调整).

        // 编码方向动态表 (本端编码器写入), 上限为对端 SETTINGS_HEADER_TABLE_SIZE.
        std::vector<header_entry> enc_dynamic_table_;
        std::unordered_map<uint32_t, int> enc_dynamic_table_map_;
        size_t enc_dynamic_table_size_ = 0;

        // 对端修改 SETTINGS_HEADER_TABLE_SIZE 后, 需在下一个头部块开头发出的
        // 动态表大小更新 (RFC 7541 §4.2); 无待发送更新时为空.
        std::optional<uint32_t> pending_enc_table_size_update_;

        // 用于标记是否需要中止连接.
        std::atomic_bool abort_{false};

        // pump 缓冲区（持久分配，避免每次 pump_in 迭代重复分配）.
        std::unique_ptr<uint8_t[]> pump_buf_;

        // pump 协程退出标志（pump_in/pump_out 完成时设为 true）.
        std::shared_ptr<std::atomic<bool>> pump_done_{
            std::make_shared<std::atomic<bool>>(false)};

        // 用于通知 async_accept 有新流到达.
        std::function<void()> accept_waiter_;

        // 流容器.
        std::map<uint32_t, stream_state_data> streams_;
    };
} // namespace h2x

#endif // H2X_H2_CONNECTION_HPP
