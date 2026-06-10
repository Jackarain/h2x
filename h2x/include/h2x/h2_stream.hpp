//
// h2_stream.hpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef H2X_H2_STREAM_HPP
#define H2X_H2_STREAM_HPP

#include <algorithm>

#include "h2x/h2_connection.hpp"

namespace h2x {
    // ═══════════════════════════════════════════════════════════════
    // stream — 代表一个 HTTP/2 流.
    // ═══════════════════════════════════════════════════════════════

    /**
     * @brief 代表一个 HTTP/2 流的轻量句柄。
     *
     * `stream<Connection>` 是对连接内具体流状态的封装，提供
     * 异步读写头部与数据的方法。流对象不可拷贝但可移动，寿命
     * 由底层 `connection` 管理（通过 stream id 访问流状态）。
     *
     * 模板参数:
     * - Connection: 包含流状态表并提供底层 I/O 的连接类型。
     */
    template <class Connection>
    class stream {
    public:
        using executor_type = typename Connection::executor_type;

        stream(Connection& conn, uint32_t stream_id)
            : conn_(conn)
            , stream_id_(stream_id)
        {}

        ~stream() = default;

        // 移动构造/赋值.
        stream(stream&& other) noexcept
            : conn_(other.conn_)
            , stream_id_(other.stream_id_)
        {
            other.stream_id_ = 0;
        }

        stream& operator=(stream&& other) noexcept
        {
            if (this != &other) {
                conn_ = other.conn_;
                stream_id_ = other.stream_id_;
                other.stream_id_ = 0;
            }
            return *this;
        }

        // 不可拷贝.
        stream(const stream&) = delete;
        stream& operator=(const stream&) = delete;

        ////////////////////////////////////////////////////////////////////////////

        executor_type get_executor() noexcept
        {
            return conn_.get_executor();
        }

        /**
         * @brief 返回此流的流 ID（由 connection 分配）。
         */
        uint32_t stream_id() const noexcept { return stream_id_; }

        ////////////////////////////////////////////////////////////////////////////

        /**
         * @brief 异步发送 HEADERS 帧（用于请求或响应头）。
         *
         * @param headers 头部字段列表（name, value）。
         * @param end_stream 如果为 true，则该流发送 END_STREAM 标志。
         * @return awaitable 返回可能的 `boost::system::error_code`。
         */
        net::awaitable<boost::system::error_code>
        async_write_headers(const std::vector<std::pair<std::string, std::string>>& headers,
                            bool end_stream = false)
        {
            boost::system::error_code ec;

            auto it = conn_.streams_.find(stream_id_);
            if (it == conn_.streams_.end()) {
                ec = make_error_code(errc::stream_not_found);
                co_return ec;
            }

            auto& sd = it->second;

            // 检查流状态：如果流已关闭或本地已关闭，拒绝写入 HEADERS.
            if (sd.state == stream_state::closed ||
                sd.state == stream_state::half_closed_local ||
                sd.reset_received) {
                ec = make_error_code(errc::stream_closed);
                co_return ec;
            }

            // 构建 HEADERS 帧.
            size_t buf_size = conn_.settings_.max_frame_size + 9;
            auto buf = std::make_unique<uint8_t[]>(buf_size);
            std::memset(buf.get(), 0, buf_size);

            headers_frame hf(buf.get(), buf_size, false);
            hf.stream_id(stream_id_);
            hf.end_stream_ = end_stream;
            hf.end_headers_ = true;

            for (auto& [name, value] : headers) {
                hf.add_header(name, value);
            }

            int total = hf.pack_headers();
            if (total < 0 || static_cast<size_t>(total) > buf_size) {
                ec = make_error_code(errc::protocol_error);
                co_return ec;
            }

            // 发送帧.
            std::vector<uint8_t> data(total);
            std::memcpy(data.data(), buf.get(), total);
            conn_.write_frame_data(std::move(data));

            // 更新流状态.
            if (sd.state == stream_state::idle) {
                sd.state = stream_state::open;
            }
            if (end_stream) {
                // open → half_closed_local; half_closed_remote → closed
                sd.state = (sd.state == stream_state::half_closed_remote)
                    ? stream_state::closed
                    : stream_state::half_closed_local;
            }

            co_return ec;
        }

        /**
         * @brief 异步发送 DATA 帧数据，自动分片以适应远端/本地窗口和最大帧大小。
         *
         * @param data 指向要发送的数据缓冲区。
         * @param size 数据长度（字节）。
         * @param end_stream 如果为 true，则发送最后一块并在帧置 END_STREAM。
         * @return awaitable 返回可能的 `boost::system::error_code`。
         */
        net::awaitable<boost::system::error_code>
        async_write_data(const uint8_t* data, size_t size, bool end_stream = false)
        {
            boost::system::error_code ec;

            auto it = conn_.streams_.find(stream_id_);
            if (it == conn_.streams_.end()) {
                ec = make_error_code(errc::stream_not_found);
                co_return ec;
            }

            auto& sd = it->second;

            // 检查流状态：如果流已关闭或本地已关闭（发送过 END_STREAM），拒绝写入.
            if (sd.state == stream_state::closed ||
                sd.state == stream_state::half_closed_local ||
                sd.reset_received) {
                ec = make_error_code(errc::stream_closed);
                co_return ec;
            }

            size_t offset = 0;
            size_t max_payload = std::min(conn_.peer_max_frame_size_,
                                          conn_.settings_.max_frame_size);

            while (offset < size) {
                // 检查流级和连接级远端窗口.
                while ((sd.remote_window <= 0 || conn_.conn_remote_window_ <= 0) && !ec) {
                    // 等待 WINDOW_UPDATE.
                    net::steady_timer timer(get_executor());
                    timer.expires_after(std::chrono::milliseconds(100));

                    sd.write_waiter = [&timer]() { timer.cancel(); };
                    co_await timer.async_wait(net_awaitable[ec]);
                    sd.write_waiter = nullptr;

                    if (ec == net::error::operation_aborted) {
                        ec.clear(); // 被 write_waiter 唤醒，继续循环.
                    }
                }

                if (ec) co_return ec;

                // 计算本次发送大小（受流级和连接级窗口共同限制）.
                size_t chunk = std::min(size - offset, max_payload);
                chunk = std::min(chunk, static_cast<size_t>(sd.remote_window));
                chunk = std::min(chunk, static_cast<size_t>(conn_.conn_remote_window_));

                // 构建 DATA 帧.
                size_t buf_size = chunk + 9 + 1; // +1 for possible padding
                auto buf = std::make_unique<uint8_t[]>(buf_size);
                std::memset(buf.get(), 0, buf_size);

                data_frame df(buf.get(), buf_size, false);
                df.stream_id(stream_id_);
                df.type(frame_type::DATA);
                df.set_data(data + offset, chunk);

                bool is_last = (offset + chunk >= size) && end_stream;
                df.set_end_stream(is_last);

                df.pack_payload();

                size_t frame_len = df.frame_size();
                std::vector<uint8_t> frame_data(frame_len);
                std::memcpy(frame_data.data(), buf.get(), frame_len);
                conn_.write_frame_data(std::move(frame_data));

                // 更新远端窗口（流级和连接级）.
                sd.remote_window -= chunk;
                conn_.conn_remote_window_ -= chunk;
                offset += chunk;

                if (is_last) {
                    sd.state = (sd.state == stream_state::half_closed_remote)
                        ? stream_state::closed
                        : stream_state::half_closed_local;
                }
            }

            co_return ec;
        }

        // 异步写入字符串数据.
        net::awaitable<boost::system::error_code>
        async_write_data(std::string_view data, bool end_stream = false)
        {
            co_return co_await async_write_data(
                reinterpret_cast<const uint8_t*>(data.data()),
                data.size(), end_stream);
        }

        /**
         * @brief 从流中异步读取已接收的 HEADERS（如果尚未到达则等待）。
         *
         * @return awaitable 返回 `result<std::vector<header_entry>>` 或错误码。
         */
        net::awaitable<result<std::vector<header_entry>>>
        async_read_headers()
        {
            boost::system::error_code ec;

            auto it = conn_.streams_.find(stream_id_);
            if (it == conn_.streams_.end()) {
                ec = make_error_code(errc::stream_not_found);
                co_return ec;
            }

            auto& sd = it->second;

            // 等待头部到达.
            while (sd.headers.empty() && !sd.remote_end_stream && !sd.reset_received) {
                net::steady_timer timer(get_executor());
                timer.expires_after(std::chrono::milliseconds(100));

                sd.read_waiter = [&timer]() { timer.cancel(); };
                co_await timer.async_wait(net_awaitable[ec]);
                sd.read_waiter = nullptr;

                if (ec == net::error::operation_aborted) {
                    ec.clear();
                }
            }

            if (sd.reset_received) {
                ec = make_error_code(errc::stream_closed);
                co_return ec;
            }

            auto result = std::move(sd.headers);
            sd.headers.clear();
            co_return result;
        }

        /**
         * @brief 异步读取流中的 DATA 缓冲区内容；如果流结束返回空 vector。
         *
         * @return awaitable 返回 `result<std::vector<uint8_t>>` 或错误码。
         */
        net::awaitable<result<std::vector<uint8_t>>>
        async_read_data()
        {
            boost::system::error_code ec;

            auto it = conn_.streams_.find(stream_id_);
            if (it == conn_.streams_.end()) {
                ec = make_error_code(errc::stream_not_found);
                co_return ec;
            }

            auto& sd = it->second;

            // 等待数据到达或流结束.
            while (sd.read_buffer.empty() && !sd.remote_end_stream && !sd.reset_received) {
                net::steady_timer timer(get_executor());
                timer.expires_after(std::chrono::milliseconds(100));

                sd.read_waiter = [&timer]() { timer.cancel(); };
                co_await timer.async_wait(net_awaitable[ec]);
                sd.read_waiter = nullptr;

                if (ec == net::error::operation_aborted) {
                    ec.clear();
                }
            }

            if (sd.reset_received) {
                ec = make_error_code(errc::stream_closed);
                co_return ec;
            }

            // 如果有数据，返回数据；否则返回空（表示流结束）.
            if (!sd.read_buffer.empty()) {
                auto result = std::move(sd.read_buffer);
                sd.read_buffer.clear();
                co_return result;
            }

            // 流已结束，返回空.
            co_return std::vector<uint8_t>{};
        }

        /**
         * @brief 流是否存在未读数据。
         */
        bool has_data() const
        {
            auto it = conn_.streams_.find(stream_id_);
            if (it == conn_.streams_.end()) return false;
            return !it->second.read_buffer.empty();
        }

        /**
         * @brief 检查流是否已关闭或收到了重置。
         */
        bool is_done() const
        {
            auto it = conn_.streams_.find(stream_id_);
            if (it == conn_.streams_.end()) return true;
            auto& sd = it->second;
            return sd.state == stream_state::closed ||
                   sd.reset_received;
        }

        /**
         * @brief 发送 RST_STREAM 中止此流。
         *
         * @param code RST 错误码，默认使用 CANCEL。
         */
        net::awaitable<void> cancel(http2_error_code code = http2_error_code::CANCEL)
        {
            co_await conn_.send_rst_stream(stream_id_, code);
            co_return;
        }

    private:
        Connection& conn_;
        uint32_t stream_id_ = 0;
    };


    ////////////////////////////////////////////////////////////////////////////
    // ── connection 中依赖 stream 完整定义的方法实现 ──

    template <class NextLayer>
    auto connection<NextLayer>::async_request()
        -> net::awaitable<result<stream_type>>
    {
        boost::system::error_code ec;

        // 分配新的流 ID.
        uint32_t new_id = allocate_stream_id();
        if (new_id == 0) {
            ec = make_error_code(errc::stream_already_exists);
            co_return ec;
        }

        // 创建并注册流.
        auto stream_id = new_id;
        auto [it, ok] = streams_.emplace(stream_id, stream_state_data{});
        if (!ok) {
            ec = make_error_code(errc::stream_already_exists);
            co_return ec;
        }
        auto& sd = it->second;
        sd.state = stream_state::idle;
        sd.stream_id = stream_id;
        sd.local_window = settings_.initial_window_size;
        sd.remote_window = peer_initial_window_size_;  // 使用对端协商的初始窗口值

        stream_type s(*this, stream_id);
        co_return s;
    }

    template <class NextLayer>
    auto connection<NextLayer>::async_accept_stream()
        -> net::awaitable<result<stream_type>>
    {
        boost::system::error_code ec;

        // 等待直到有新的远端流到达.
        while (!abort_) {
            // 先检查已有流.
            for (auto& [sid, sd] : streams_) {
                if (sd.state == stream_state::idle &&
                    sd.is_remote_initiated) {
                    sd.state = stream_state::open;
                    sd.is_remote_initiated = false;
                    stream_type s(*this, sid);
                    co_return s;
                }
            }

            // 使用定时器等待，并通过 accept_waiter_ 接收通知.
            net::steady_timer timer(get_executor());
            timer.expires_after(std::chrono::milliseconds(100));

            accept_waiter_ = [&timer]() { timer.cancel(); };
            co_await timer.async_wait(net_awaitable[ec]);
            accept_waiter_ = nullptr;

            if (ec == net::error::operation_aborted) {
                ec.clear(); // 被 accept_waiter_ 唤醒，继续循环.
            }
        }

        ec = make_error_code(errc::stream_closed);
        co_return ec;
    }

} // namespace h2x

#endif // H2X_H2_STREAM_HPP
