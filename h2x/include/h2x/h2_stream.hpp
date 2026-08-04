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

        // 以 shared_ptr 持有连接: 只要流对象仍存在, 底层 connection 就不会被
        // 销毁, 避免流协程运行期间连接先一步析构导致 use-after-free.
        stream(std::shared_ptr<Connection> conn, uint32_t stream_id)
            : conn_(std::move(conn))
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
            return conn_->get_executor();
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

            auto* sd = find_stream(ec);
            if (!sd) co_return ec;

            if (!is_writable(*sd, ec)) co_return ec;

            // 打包头部块. 头部块可能超过单帧负载上限 (尤其当 SETTINGS
            // MAX_FRAME_SIZE 较小时), 故先打包到足够大的缓冲区, 再按需拆分.
            // 传入动态表指针, 使打包阶段能正确编码动态表命中的索引条目.
            const size_t max_payload = conn_->peer_max_frame_size_;
            const size_t max_block = 1024 * 1024;  // 头部块安全上限.
            size_t buf_size = max_payload + 9;
            std::vector<uint8_t> data;
            int total = -1;

            while (total < 0) {
                data.assign(buf_size, 0);
                headers_frame hf(data.data(), data.size(), false,
                    &conn_->dynamic_table_);
                hf.stream_id(stream_id_);
                hf.end_stream_ = end_stream;
                hf.end_headers_ = true;

                for (auto& [name, value] : headers) {
                    hf.add_header(name, value,
                        &conn_->dynamic_table_map_, &conn_->dynamic_table_);
                }

                total = hf.pack_headers();

                if (total >= 0) {
                    // 打包成功后才把增量索引条目加入动态表; 失败的条目
                    // 不加入, 保证编码端表状态与实际发送内容一致.
                    for (auto& entry : hf.headers_) {
                        if (entry.type_ == &G_LITERAL_INCREMENTAL_INDEXING) {
                            conn_->add_to_dynamic_table(entry);
                        }
                    }
                    break;
                }

                if (buf_size > max_block) {
                    ec = make_error_code(errc::protocol_error);
                    co_return ec;
                }
                buf_size *= 2;
            }

            // 发送帧: 单帧, 或拆分为 HEADERS + CONTINUATION (RFC 7540 §6.2).
            const size_t block_size = static_cast<size_t>(total) - 9;
            if (block_size <= max_payload) {
                data.resize(static_cast<size_t>(total));
                conn_->write_frame_data(std::move(data));
            } else {
                const uint8_t* block = data.data() + 9;
                size_t offset = 0;

                // 首帧 HEADERS: 不携带 END_HEADERS/END_STREAM (二者由最后的
                // CONTINUATION 帧携带).
                size_t chunk = max_payload;
                std::vector<uint8_t> first(9 + chunk);
                std::memcpy(first.data(), data.data(), 9);
                std::memcpy(first.data() + 9, block, chunk);
                first[0] = (chunk >> 16) & 0xFF;
                first[1] = (chunk >> 8) & 0xFF;
                first[2] = chunk & 0xFF;
                first[4] &= ~static_cast<uint8_t>(frame_flag::END_HEADERS);
                first[4] &= ~static_cast<uint8_t>(frame_flag::END_STREAM);
                conn_->write_frame_data(std::move(first));
                offset += chunk;

                // 后续 CONTINUATION 帧.
                while (offset < block_size) {
                    chunk = std::min(block_size - offset, max_payload);
                    const bool is_last = (offset + chunk >= block_size);
                    std::vector<uint8_t> cf(9 + chunk);
                    cf[0] = (chunk >> 16) & 0xFF;
                    cf[1] = (chunk >> 8) & 0xFF;
                    cf[2] = chunk & 0xFF;
                    cf[3] = static_cast<uint8_t>(frame_type::CONTINUATION);
                    cf[4] = 0;
                    cf[5] = (stream_id_ >> 24) & 0x7F;
                    cf[6] = (stream_id_ >> 16) & 0xFF;
                    cf[7] = (stream_id_ >> 8) & 0xFF;
                    cf[8] = stream_id_ & 0xFF;
                    if (is_last) {
                        cf[4] |= static_cast<uint8_t>(frame_flag::END_HEADERS);
                        if (end_stream) {
                            cf[4] |= static_cast<uint8_t>(frame_flag::END_STREAM);
                        }
                    }
                    std::memcpy(cf.data() + 9, block + offset, chunk);
                    conn_->write_frame_data(std::move(cf));
                    offset += chunk;
                }
            }

            // 更新流状态.
            transition_local_end_stream(*sd, end_stream);

            // 本端已半关闭, 若流数据已消费完则尝试释放.
            conn_->maybe_release_stream(stream_id_);

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

            auto* sdp = find_stream(ec);
            if (!sdp) co_return ec;
            auto& sd = *sdp;

            if (!is_writable(sd, ec)) co_return ec;

            size_t offset = 0;
            size_t max_payload = std::min(conn_->peer_max_frame_size_,
                                          conn_->settings_.max_frame_size);

            while (offset < size) {
                // 检查流级和连接级远端窗口.
                while ((sd.remote_window <= 0 || conn_->conn_remote_window_ <= 0) && !ec) {
                    // 流已被重置或连接已中止，停止写入.
                    if (sd.reset_received || conn_->abort_) {
                        ec = make_error_code(errc::stream_closed);
                        break;
                    }

                    // 等待 WINDOW_UPDATE.
                    net::steady_timer timer(get_executor());
                    timer.expires_at(net::steady_timer::time_point::max());

                    sd.write_waiter = [&timer]() { timer.cancel(); };

                    // 注册 waiter 后、挂起前重检，关闭竞态窗口.
                    if (sd.remote_window > 0 && conn_->conn_remote_window_ > 0
                        || sd.reset_received || conn_->abort_) {
                        sd.write_waiter = nullptr;
                        break;
                    }

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
                chunk = std::min(chunk, static_cast<size_t>(conn_->conn_remote_window_));

                // 构建 DATA 帧.
                size_t buf_size = chunk + 9 + 1; // +1 for possible padding
                auto frame_data = std::vector<uint8_t>(buf_size);

                data_frame df(frame_data.data(), frame_data.size(), false);
                df.stream_id(stream_id_);
                df.type(frame_type::DATA);
                df.set_data(data + offset, chunk);

                bool is_last = (offset + chunk >= size) && end_stream;
                df.set_end_stream(is_last);

                df.pack_payload();

                size_t frame_len = df.frame_size();
                frame_data.resize(frame_len);
                conn_->write_frame_data(std::move(frame_data));

                // 更新远端窗口（流级和连接级）.
                sd.remote_window -= chunk;
                conn_->conn_remote_window_ -= chunk;
                offset += chunk;

                if (is_last) {
                    transition_local_end_stream(sd, true);
                }
            }

            // 本端已半关闭, 若流数据已消费完则尝试释放 (必须在循环外,
            // 避免释放后 sd 悬垂).
            conn_->maybe_release_stream(stream_id_);

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

            auto* sdp = find_stream(ec);
            if (!sdp) co_return ec;
            auto& sd = *sdp;

            // 等待头部到达.
            co_await wait_until(sd, sd.read_waiter,
                [](auto& s) { return !s.headers.empty(); });

            if (sd.reset_received) {
                ec = make_error_code(errc::stream_closed);
                co_return ec;
            }

            auto result = std::move(sd.headers);
            sd.headers.clear();

            // 头部已消费, 若流已终止则尝试释放, 防止流对象累积.
            conn_->maybe_release_stream(stream_id_);

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

            auto* sdp = find_stream(ec);
            if (!sdp) co_return ec;
            auto& sd = *sdp;

            // 等待数据到达或流结束.
            co_await wait_until(sd, sd.read_waiter,
                [](auto& s) { return !s.read_buffer.empty(); });

            if (sd.reset_received) {
                ec = make_error_code(errc::stream_closed);
                co_return ec;
            }

            // 如果有数据，返回数据；否则返回空（表示流结束）.
            if (!sd.read_buffer.empty()) {
                auto result = std::move(sd.read_buffer);
                sd.read_buffer.clear();

                // 数据已消费, 若流已终止则尝试释放, 防止流对象累积.
                conn_->maybe_release_stream(stream_id_);

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
            auto it = conn_->streams_.find(stream_id_);
            if (it == conn_->streams_.end()) return false;
            return !it->second.read_buffer.empty();
        }

        /**
         * @brief 检查流是否已关闭或收到了重置。
         */
        bool is_done() const
        {
            auto it = conn_->streams_.find(stream_id_);
            if (it == conn_->streams_.end()) return true;
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
            co_await conn_->send_rst_stream(stream_id_, code);
            co_return;
        }

    private:
        // 查找本流的状态数据，未找到时设置 ec 并返回 nullptr.
        typename Connection::stream_state_data*
        find_stream(boost::system::error_code& ec)
        {
            auto it = conn_->streams_.find(stream_id_);
            if (it == conn_->streams_.end()) {
                ec = make_error_code(errc::stream_not_found);
                return nullptr;
            }
            return &it->second;
        }

        // 检查流是否可写（未关闭/未半关闭本地/未收到重置）.
        bool is_writable(const typename Connection::stream_state_data& sd,
                         boost::system::error_code& ec) const
        {
            if (sd.state == stream_state::closed ||
                sd.state == stream_state::half_closed_local ||
                sd.reset_received) {
                ec = make_error_code(errc::stream_closed);
                return false;
            }
            return true;
        }

        // 本端发送 END_STREAM 后的状态迁移.
        void transition_local_end_stream(
            typename Connection::stream_state_data& sd, bool end_stream)
        {
            if (sd.state == stream_state::idle) {
                sd.state = stream_state::open;
            }
            if (end_stream) {
                sd.state = (sd.state == stream_state::half_closed_remote)
                    ? stream_state::closed
                    : stream_state::half_closed_local;
            }
        }

        // 等待条件满足或流结束/重置，返回是否应继续.
        // pred 返回 true 表示条件满足可退出等待.
        //
        // 实现说明:
        // - timer 设为永不自然超时 (time_point::max()), 仅靠 waiter_slot()
        //   即 timer.cancel() 唤醒.
        // - 注册 waiter 后、挂起前重检谓词, 关闭"注册到挂起之间"的竞态窗口.
        // - 依赖连接侧在所有改变等待条件的路径 (DATA/HEADERS/WINDOW_UPDATE/
        //   RST_STREAM/GOAWAY/close/pump 退出) 上调用 waiter() 通知等待者.
        template <class Pred>
        net::awaitable<bool> wait_until(
            typename Connection::stream_state_data& sd,
            std::function<void()>& waiter_slot,
            Pred pred)
        {
            boost::system::error_code ec;
            while (!pred(sd) && !sd.remote_end_stream && !sd.reset_received && !conn_->abort_) {
                net::steady_timer timer(get_executor());
                timer.expires_at(net::steady_timer::time_point::max());

                waiter_slot = [&timer]() { timer.cancel(); };

                // 注册 waiter 后、挂起前重检, 关闭竞态窗口:
                // 此段为同步执行 (无 co_await), 同 strand 上 pump 无法插入,
                // 故事件要么在此被捕获, 要么在挂起后被 waiter() 唤醒.
                if (pred(sd) || sd.remote_end_stream || sd.reset_received) {
                    waiter_slot = nullptr;
                    break;
                }

                co_await timer.async_wait(net_awaitable[ec]);
                waiter_slot = nullptr;

                if (ec == net::error::operation_aborted) {
                    ec.clear(); // 被 waiter_slot() 唤醒.
                }
            }
            co_return true;
        }

        std::shared_ptr<Connection> conn_;
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
            // 流 ID 空间耗尽: 发起 GOAWAY 并返回错误.
            co_await send_goaway(0, http2_error_code::PROTOCOL_ERROR);
            abort_ = true;
            ec = make_error_code(errc::protocol_error);
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

        stream_type s(this->shared_from_this(), stream_id);
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
                    stream_type s(this->shared_from_this(), sid);
                    co_return s;
                }
            }

            // 使用定时器等待，并通过 accept_waiter_ 接收通知.
            // timer 永不自然超时, 仅靠 accept_waiter_() 即 cancel() 唤醒.
            // 依赖连接侧在 HEADERS/GOAWAY/close/pump 退出时调用 accept_waiter_() 通知.
            net::steady_timer timer(get_executor());
            timer.expires_at(net::steady_timer::time_point::max());

            accept_waiter_ = [&timer]() { timer.cancel(); };

            // 注册 waiter 后、挂起前重检, 关闭竞态窗口.
            if (abort_) {
                accept_waiter_ = nullptr;
                break;
            }
            for (auto& [sid, sd] : streams_) {
                if (sd.state == stream_state::idle &&
                    sd.is_remote_initiated) {
                    accept_waiter_ = nullptr;
                    sd.state = stream_state::open;
                    sd.is_remote_initiated = false;
                    stream_type s(this->shared_from_this(), sid);
                    co_return s;
                }
            }

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
