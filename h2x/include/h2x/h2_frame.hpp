//
// h2_frame.hpp
// ~~~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef H2X_HTTP2_FRAME_HPP
#define H2X_HTTP2_FRAME_HPP


#include <vector>
#include <unordered_map>
#include <map>
#include <exception>
#include <string>
#include <span>
#include <utility>
#include <cstdint>
#include <cstring>
#include <limits>

#include "h2x/h2_global_data.hpp"


namespace h2x {

/*
    HTTP Frame {
        Length (24),              // 指示 Frame Payload 的长度，最大为 16384 字节，不包括本帧头部这 9 个字节
                                    // 除非指定了 SETTINGS_MAX_FRAME_SIZE，否则最大为 16384 字节，
                                    // SETTINGS_MAX_FRAME_SIZE 值的范围是 [16,384 - 16,777,215] 之间的任意值.

        Type (8),                 // 指示帧类型，如 DATA、HEADERS、PRIORITY 等
        Flags (8),                // 指示帧的特殊属性，如 END_STREAM、END_HEADERS 等
        Reserved (1),             // 保留位，必须为 0
        Stream Identifier (31),   // 指示该帧所属的流，客户端发送的帧必须为奇数流 ID，服务器发送的帧必须为偶数流 ID

        Frame Payload (..),
    }

    stream 优先级设计
    每个流都有一个优先级，优先级是一个 31 位无符号整数，优先级值越高，流的优先级越高，优先级值为 0 表示默认优先级。
    优先级值的范围是 [0, 2^31 - 1] 之间的任意值。

    stream 依赖设计
    每个流都有一个依赖流，依赖流是一个 31 位无符号整数 id，依赖流表示该流依赖的流，依赖流必须是已存在的
    流，依赖流为 0 表示该流不依赖其他流。
    具体做法就是在发送流 A 时，确保流 A 的优先级大于流 B 的优先级。

*/

/*  PUSH_PROMISE 的完整流程（最常见场景）

    1. 客户端发起请求，打开流 1（奇数流）
        GET /index.html   →  Stream 1

    2. 服务器收到请求，开始响应 index.html 的 HEADERS + DATA

    3. 服务器同时决定要推送 /style.css 和 /script.js
        服务器发送：
        PUSH_PROMISE (Stream 1) → 承诺推送流 4（:path=/style.css）
        PUSH_PROMISE (Stream 1) → 承诺推送流 6（:path=/script.js）

    4. 服务器立刻在新的偶数流上发送真实的响应：
        HEADERS (Stream 4) + DATA (Stream 4)  ← 推送 style.css
        HEADERS (Stream 6) + DATA (Stream 6)  ← 推送 script.js

    5. 客户端收到 PUSH_PROMISE 后：
        • 如果已经缓存了对应资源 → 可以 RST_STREAM(取消) 推送流
        • 否则 → 接受推送，把资源放入缓存，并关联到当前页面

    注意：
    PUSH_PROMISE 只能由服务器发送，客户端不允许发送 PUSH_PROMISE 帧。
    推送流的 ID 必须是偶数且未使用过，服务器自己分配，递增使用
    客户端有权拒绝推送，可发送 RST_STREAM(CANCEL) 拒绝某个推送流
    SETTINGS_ENABLE_PUSH = 0 时禁用，客户端可通过 SETTINGS 帧关闭推送功能（默认开启）
    推送请求不能带 body，:method 必须是 GET 或 HEAD
    不能无限推送，受 SETTINGS_MAX_CONCURRENT_STREAMS 限制

    PUSH_PROMISE 帧是 HTTP/2 中服务器主动「预推送」资源的核心手段，通过提前发送资源的请
    求头部（并紧接着推送响应），极大减少了客户端的请求等待时间，是 HTTP/2 性能提升最显著的
    特性之一（也是最容易误用导致浪费带宽的特性）。
*/


    enum class http2_error_code : uint32_t {
        NO_ERROR = 0x00,
        PROTOCOL_ERROR = 0x01,
        INTERNAL_ERROR = 0x02,
        FLOW_CONTROL_ERROR = 0x03,
        SETTINGS_TIMEOUT = 0x04,
        STREAM_CLOSED = 0x05,
        FRAME_SIZE_ERROR = 0x06,
        REFUSED_STREAM = 0x07,
        CANCEL = 0x08,
        COMPRESSION_ERROR = 0x09,
        CONNECT_ERROR = 0x0A,
        ENHANCE_YOUR_CALM = 0x0B,
        INADEQUATE_SECURITY = 0x0C,
        HTTP_1_1_REQUIRED = 0x0D
    };

    inline std::string http2_error_code_to_string(http2_error_code code)
    {
        switch (code) {
        case http2_error_code::NO_ERROR:  return "NO_ERROR";
        case http2_error_code::PROTOCOL_ERROR: return "PROTOCOL_ERROR";
        case http2_error_code::INTERNAL_ERROR: return "INTERNAL_ERROR";
        case http2_error_code::FLOW_CONTROL_ERROR: return "FLOW_CONTROL_ERROR";
        case http2_error_code::SETTINGS_TIMEOUT: return "SETTINGS_TIMEOUT";
        case http2_error_code::STREAM_CLOSED: return "STREAM_CLOSED";
        case http2_error_code::FRAME_SIZE_ERROR: return "FRAME_SIZE_ERROR";
        case http2_error_code::REFUSED_STREAM:  return "REFUSED_STREAM";
        case http2_error_code::CANCEL: return "CANCEL";
        case http2_error_code::COMPRESSION_ERROR: return "COMPRESSION_ERROR";
        case http2_error_code::CONNECT_ERROR: return "CONNECT_ERROR";
        case http2_error_code::ENHANCE_YOUR_CALM:  return "ENHANCE_YOUR_CALM";
        case http2_error_code::INADEQUATE_SECURITY: return "INADEQUATE_SECURITY";
        case http2_error_code::HTTP_1_1_REQUIRED: return "HTTP_1_1_REQUIRED";
        default: return "UNKNOWN";
        }
    }

    /**
     * @brief 估算对输入进行 HPACK Huffman 编码后所需的字节数。
     *
     * @param input 待编码的字节序列视图。
     * @return 编码后所需的字节数（向上取整到字节）。
     */
    static int huffman_encode_size(std::span<const uint8_t> input)
    {
        int count = 0;

        // 统计字符串中每个字符的编码长度.
        for (auto& ch : input) {
            count += global_huffman_table[ch].first;
        }

        return (count + 7) / 8;
    }

    /**
     * @brief 使用 HPACK 的 Huffman 表对输入进行编码。
     *
     * @param input 待编码的数据视图。
     * @param result 输出缓冲区（会 append 编码后的字节）。
     * @return 成功返回 true；对于空输入返回 false（表示无编码）。
     */
    static bool huffman_encode(std::span<const uint8_t> input, std::vector<uint8_t>& result)
    {
        if (input.empty()) {
            return false;
        }

        result.reserve(input.size() * 2);

        uint64_t bits = 0;
        int nbits = 0;

        for (uint8_t c : input) {
            auto [len, code] = global_huffman_table[c];
            bits = (bits << len) | (code >> (32 - len));
            nbits += len;

            while (nbits >= 8) {
                nbits -= 8;
                result.push_back(static_cast<uint8_t>(bits >> nbits));
                bits &= (1ULL << nbits) - 1;
            }
        }

        if (nbits > 0) {
            int pad = 8 - nbits;
            uint64_t pad_mask = (1ULL << pad) - 1;
            bits = (bits << pad) | pad_mask;
            nbits += pad;
            result.push_back(static_cast<uint8_t>(bits >> (nbits - 8)));
        }

        return true;
    }

    /**
     * @brief 解码 Huffman 编码的数据。
     *
     * @param encoded Huffman 编码后的字节序列视图。
     * @return 解码后的字节向量。
     */
    static std::vector<uint8_t> huffman_decode(std::span<const uint8_t> encoded)
    {
        huffman_node t = { 0, 1, 0};
        std::vector<uint8_t> result;

        for (uint8_t ch : encoded) {
            t = global_huffman_tree[t.fstate][ch >> 4];
            if (t.flags & 2) {
                result.push_back(t.sym);
            }
            t = global_huffman_tree[t.fstate][ch & 0xf];
            if (t.flags & 2) {
                result.push_back(t.sym);
            }
        }

        return result;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // hpack 编码为前辍 + 压缩后的字符串
    // 前辍为 1 字节，低 7 位为压缩后的字符串长度，高 1 位为是否压缩标志位.

    // hpack 的整数解码, 返回解码后的整数和消耗的字节数, 返回 -1 表示解码失败.
    // nbit 为前辍字节的有效位数, 必须在 [1, 8] 范围内.
    /**
     * @brief 从 HPACK 字节序列中解码一个可变长度整数（prefix integer）。
     *
     * @param encoded 输入字节视图（含前缀字节）。
     * @param nbit 前缀的有效位数（1-8）。
     * @param result 输出解码得到的整数。
     * @return 成功返回消耗的字节数，失败返回 -1。
     */
    static int hpack_unpack_integer(std::span<const uint8_t> encoded, uint8_t nbit, uint64_t& result)
    {
        if (encoded.empty() || nbit > 8) {
            return -1;
        }

        const uint8_t mask = HPACK_HAS_BITS[nbit];

        uint8_t byte = encoded[0];
        result = static_cast<uint64_t>(byte & mask);

        // 如果前辍不是全 1，直接返回前辍, 表示这是一个小整数.
        if (result != mask) {
            return 1;
        }

        size_t encoded_size = encoded.size();
        uint64_t shift = 1;
        uint64_t fexp = 0;
        int idx = 1;

        do {
            if (idx >= encoded_size) {
                return -1;
            }

            byte = encoded[idx++];
            if (fexp > 64) {
                return -1;
            }
            uint64_t add = (byte & 0x7F) * shift;

            if (std::numeric_limits<uint64_t>::max() - result <= add) {
                return -1;
            }

            result += add; // 累加余数.

            shift <<= 7;
            fexp += 7;
        } while (byte & 128);

        return idx;
    }

    // hpack 的整数编码, 返回编码后的字节序列.
    // nbit 为前辍字节的有效位数, 必须在 [1, 8] 范围内.
    /**
     * @brief 将整数按 HPACK 的 prefix integer 规则编码为字节序列。
     *
     * @param value 待编码的整数值。
     * @param nbit 前缀的位数（1-8）。
     * @return 返回编码后的字节向量。
     */
    static std::vector<uint8_t> hpack_pack_integer(uint64_t value, uint8_t nbit)
    {
        std::vector<uint8_t> result;

        uint8_t mask = HPACK_HAS_BITS[nbit];
        uint8_t byte = static_cast<uint8_t>(value);

        if (value < mask) {
            byte |= value; // 低 nbit 位为 value, 高位不变
            result.push_back(byte);
            return result;
        } else {
            byte |= mask;   // 低 nbit 位为 mask, 高位不变
            result.push_back(byte);
            value -= mask;
        }

        // base-128 编码循环, 直到 value 小于 0x80.
        while (value >= 0x80) {
            byte = 0x80 | (0x7F & value);
            result.push_back(byte);
            value = value >> 7;
        }
        result.push_back(static_cast<uint8_t>(value));

        return result;
    }

    /**
     * @brief 对字符串进行 HPACK 的字符串字面量编码（可选 Huffman 压缩）。
     *
     * 如果 Huffman 压缩后长度更短，则设置高位并使用 Huffman 编码。
     *
     * @param input 待编码的数据视图。
     * @return 返回编码后的字节序列（包含长度前缀）。
     */
    static std::vector<uint8_t> hpack_pack(std::span<const uint8_t> input)
    {
        std::vector<uint8_t> result;

        // 计算 huffman 编码后的大小.
        auto size = static_cast<size_t>(huffman_encode_size(input));
        if (size >= input.size()) {
            size = input.size();
        }

        // 编码长度.
        result = hpack_pack_integer(size, 7);

        // 编码内容, 如果压缩后的大小小于原始大小, 则使用压缩后的内容.
        if (size < input.size()) {
            result[0] |= 0b10000000;
            std::vector<uint8_t> tmp;
            huffman_encode(input, tmp);
            result.insert(result.end(), tmp.begin(), tmp.end());
        } else {
            result.insert(result.end(), input.begin(), input.end());
        }

        return result;
    }

    // 解压缩 hpack 编码的字符串.
    // 返回从 encoded 中消费的字节数
    /**
     * @brief 解码 HPACK 字符串字面量（处理长度前缀与可选 Huffman）。
     *
     * @param encoded 输入字节视图（包含长度前缀）。
     * @param result 输出解码的数据。
     * @return 返回消费的字节数，失败返回 -1。
     */
    static int hpack_unpack(std::span<const uint8_t> encoded, std::vector<uint8_t>& result)
    {
        if (encoded.empty()) {
            return -1;
        }

        uint64_t len = 0;
        int ret = hpack_unpack_integer(encoded, 7, len);
        if (ret < 0) {
            return -1;
        }

        if (ret + len > encoded.size()) {
            return -1;
        }

        if (encoded[0] & 0b10000000) {
            result = huffman_decode(encoded.subspan(ret, len));
        } else {
            result.insert(result.end(), encoded.begin() + ret, encoded.begin() + ret + len);
        }

        return static_cast<int>(ret + len);
    }

    // 注意，hpack 动态索引表，索引从 62 开始，静态索引表索引从 1 开始.
    // 下面是 hpack 动态索引表，索引从 62 开始，最大 1024.
    // 将来移到 connection 类中作为成员变量，每个 connection 有一个动态索引表和静态表(复制一份).
    /**
     * @brief 全局 HPACK 动态索引表（简单实现，索引上限 1024）。
     *
     * 注意：当前为全局共享表的简化实现；更严谨的实现应当将动态表
     * 作为 `connection` 的成员以支持每连接独立的表状态。
     */
    inline std::array<std::optional<header_entry>, 1024> global_hpack_index_table;
    // 动态索引表大小, 最大 1024.
    inline int global_hpack_index_table_size = 0;

    static const header_entry* hpack_index_to_frame(uint32_t index)
    {
        if (index <= 61) {
            return &global_static_header_table[index - 1];
        }

        if (index <= static_cast<uint32_t>(global_hpack_index_table_size + 61)) {
            auto& entry = global_hpack_index_table[index - 61 - 1];
            if (entry.has_value()) {
                return &entry.value();
            }
        }

        return nullptr;
    }

    ////////////////////////////////////////////////////////////////////////////////

    static uint32_t frame_header_hash(const header_entry& nv)
    {
        /* 32 bit FNV-1a: http://isthe.com/chongo/tech/comp/fnv/ */
        uint32_t h = 2166136261u;
        size_t i;

        if (nv.name_.has_value() && nv.value_.has_value()) {
            for (i = 0; i < (*nv.name_).size(); ++i) {
                h ^= (*nv.name_)[i];
                h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
            }

            for (i = 0; i < (*nv.value_).size(); ++i) {
                h ^= (*nv.value_)[i];
                h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
            }
        }

        return h;
    }

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief HTTP/2 帧类型枚举（frame_type）。
     *
     * 描述了协议中可能出现的帧类型，例如 DATA、HEADERS、SETTINGS 等。
     */
    // 帧类型.
    enum class frame_type : uint8_t {
        DATA = 0x0,             // 数据帧
        HEADERS = 0x1,          // 头帧
        PRIORITY = 0x2,         // 优先级帧
        RST_STREAM = 0x3,       // 重置流帧
        SETTINGS = 0x4,         // 设置帧
        PUSH_PROMISE = 0x5,     // 推送承诺帧
        PING = 0x6,             // 心跳帧
        GOAWAY = 0x7,           // 关闭连接帧
        WINDOW_UPDATE = 0x8,    // 窗口更新帧
        CONTINUATION = 0x9,     // 继续帧，用于分块编码的头帧
        ALTSVC = 0x0a,          // 替代服务帧
        ORIGIN = 0x0c,          // 源帧
        PRIORITY_UPDATE = 0x10  // 优先级更新帧
    };

    // 帧标志位.
    enum class frame_flag : uint8_t {
        FLAG_NONE = 0x00,       // 无标志位
        END_STREAM = 0x01,      // 结束流标志位
        FLAG_ACK = 0x01,        // 确认标志位
        END_HEADERS = 0x04,     // 结束头标志位
        PADDED = 0x08,          // 填充标志位
        PRIORITY = 0x20         // 优先级标志位
    };

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief 基础帧编解码器结构。
     *
     * 使用外部提供的缓冲区进行帧头与负载的读写，不管理缓冲区生命周期。
     */
    struct frame_codec {
        frame_codec(uint8_t* data, size_t size)
            : data_(data), size_(size)
        {
            if (size_ < 9) {
                throw std::runtime_error("frame_codec: size must be at least 9");
            }
        }

        static bool check_stream_id(uint32_t stream_id)
        {
            // 0b10000000,00000000,00000000,00000000
            // 流标识符的最高位 (第 31 位) 必须为 0.
            return (stream_id & 0x80000000) == 0;
        }

        static bool check_frame_length(uint32_t length,
            uint32_t max_frame_size = global_frame_max_limit_size)
        {
            return length <= max_frame_size;
        }

        frame_type type() const
        {
            return static_cast<frame_type>(data_[3]);
        }

        uint8_t flags() const
        {
            return data_[4];
        }

        // 流由一个 31 位无符号整数标识.
        // 客户端发起的流 必须使用奇数编号的流标识符.
        // 服务器发起的流必须使用偶数编号流标识符.
        // 流标识符为零 (0x00) 用于连接控制消息.
        uint32_t stream_id() const
        {
            return (data_[5] & 0x7F) << 24 | (data_[6] << 16) | (data_[7] << 8) | data_[8];
        }

        uint8_t* payload() const
        {
            return data_ + 9;
        }

        size_t payload_size() const
        {
            return (data_[0] << 16) | (data_[1] << 8) | data_[2];
        }

        size_t frame_size() const
        {
            return 9 + payload_size();
        }


        // 以下方法用于设置帧的字段值.
        void payload_size(uint32_t length)
        {
            data_[0] = (length >> 16) & 0xFF;
            data_[1] = (length >> 8) & 0xFF;
            data_[2] = length & 0xFF;
        }

        void type(frame_type type)
        {
            data_[3] = static_cast<uint8_t>(type);
        }

        void flags(uint8_t flags)
        {
            data_[4] = flags;
        }

        void stream_id(uint32_t stream_id)
        {
            data_[5] = (stream_id >> 24) & 0xFF;
            data_[6] = (stream_id >> 16) & 0xFF;
            data_[7] = (stream_id >> 8) & 0xFF;
            data_[8] = stream_id & 0xFF;
        }

        void payload(const uint8_t* payload, size_t size)
        {
            if (size > payload_size()) {
                throw std::runtime_error("frame_codec: payload size must be at most payload_size");
            }

            std::memcpy(data_ + 9, payload, size);
        }

        uint8_t* data_;
        size_t size_;
    };

    ////////////////////////////////////////////////////////////////////////////////

    // 设置帧的标识定义.
    enum class settings_id : uint16_t {
        SETTINGS_HEADER_TABLE_SIZE = 0x01,          // 头表大小设置项
        SETTINGS_ENABLE_PUSH = 0x02,                // 推送启用设置项
        SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,     // 最大并发流设置项
        SETTINGS_INITIAL_WINDOW_SIZE = 0x04,        // 初始窗口大小设置项
        SETTINGS_MAX_FRAME_SIZE = 0x05,             // 最大帧大小设置项
        SETTINGS_MAX_HEADER_LIST_SIZE = 0x06,       // 最大头列表大小设置项
        SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08,    // 连接协议启用设置项
        SETTINGS_NO_RFC7540_PRIORITIES = 0x09       // 不使用 RFC7540 优先级设置项
    };

    inline std::string settings_id_to_string(settings_id identifier)
    {
        switch (identifier) {
        case settings_id::SETTINGS_HEADER_TABLE_SIZE: return "SETTINGS_HEADER_TABLE_SIZE";
        case settings_id::SETTINGS_ENABLE_PUSH: return "SETTINGS_ENABLE_PUSH";
        case settings_id::SETTINGS_MAX_CONCURRENT_STREAMS: return "SETTINGS_MAX_CONCURRENT_STREAMS";
        case settings_id::SETTINGS_INITIAL_WINDOW_SIZE: return "SETTINGS_INITIAL_WINDOW_SIZE";
        case settings_id::SETTINGS_MAX_FRAME_SIZE: return "SETTINGS_MAX_FRAME_SIZE";
        case settings_id::SETTINGS_MAX_HEADER_LIST_SIZE: return "SETTINGS_MAX_HEADER_LIST_SIZE";
        case settings_id::SETTINGS_ENABLE_CONNECT_PROTOCOL: return "SETTINGS_ENABLE_CONNECT_PROTOCOL";
        case settings_id::SETTINGS_NO_RFC7540_PRIORITIES: return "SETTINGS_NO_RFC7540_PRIORITIES";
        default: return "UNKNOWN";
        }
    }

    /**
     * @brief 表示 SETTINGS 中的单个条目（identifier + value）。
     */
    struct settings_entry {
        settings_entry() = default;
        settings_entry(settings_id id, uint32_t val)
            : identifier_(static_cast<uint16_t>(id))
            , value_(val)
        {}

        uint16_t identifier_ = 0;   // settings_id 枚举指定设置项的标识.
        uint32_t value_ = 0;        // settings_value 指定设置项的值.

        static const size_t settings_entry_size = 6;
    };

    /**
     * @brief SETTINGS 帧的封装类型，支持解析与打包。
     */
    struct settings_frame : public frame_codec {
        settings_frame(uint8_t* data, size_t size, bool unpack = true)
            : frame_codec(data, size)
        {
            if (unpack) {
                if (type() != frame_type::SETTINGS) {
                    throw std::runtime_error("settings_frame: type must be SETTINGS");
                }
                unpack_settings();
            }
        }

        // 解析设置项.
        void unpack_settings()
        {
            const uint8_t* payload = this->payload();
            size_t size = this->payload_size();

            if (size % settings_entry::settings_entry_size != 0) {
                throw std::runtime_error("settings_frame: payload size must be multiple of settings_entry");
            }

            if (static_cast<h2x::frame_flag>(flags()) == frame_flag::FLAG_ACK) {
                ack_ = true;
            }

            entries_.reserve(size / settings_entry::settings_entry_size);

            for (size_t i = 0; i < size; i += settings_entry::settings_entry_size) {
                settings_entry entry;
                entry.identifier_ = (payload[i] << 8) | payload[i + 1];
                entry.value_ = (payload[i + 2] << 24) | (payload[i + 3] << 16) | (payload[i + 4] << 8) | payload[i + 5];
                entries_.push_back(entry);
            }
        }

        int pack_settings()
        {
            // 设置类型.
            this->type(frame_type::SETTINGS);

            // 设置流标识为 0.
            this->stream_id(0);

            // 设置 ACK 标志位.
            if (ack_) {
                this->flags(static_cast<uint8_t>(frame_flag::FLAG_ACK));
                this->payload_size(0);
                return 9;
            } else {
                this->flags(static_cast<uint8_t>(frame_flag::FLAG_NONE));
            }

            // 计算 payload 大小.
            size_t payload_size = entries_.size() * settings_entry::settings_entry_size;
            this->payload_size(static_cast<uint32_t>(payload_size));

            // 填充 payload.
            uint8_t* payload = this->payload();
            for (size_t i = 0; i < entries_.size(); ++i) {
                payload[i * settings_entry::settings_entry_size] = (entries_[i].identifier_ >> 8) & 0xFF;
                payload[i * settings_entry::settings_entry_size + 1] = entries_[i].identifier_ & 0xFF;

                payload[i * settings_entry::settings_entry_size + 2] = (entries_[i].value_ >> 24) & 0xFF;
                payload[i * settings_entry::settings_entry_size + 3] = (entries_[i].value_ >> 16) & 0xFF;
                payload[i * settings_entry::settings_entry_size + 4] = (entries_[i].value_ >> 8) & 0xFF;
                payload[i * settings_entry::settings_entry_size + 5] = entries_[i].value_ & 0xFF;
            }

            return static_cast<int>(9 + payload_size);
        }

        bool ack_ = false;
        std::vector<settings_entry> entries_;
    };

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief HEADERS 帧封装，负责 HPACK 头部块的解析与打包（含 PADDED/PRIORITY 支持）。
     */
    struct headers_frame :  public frame_codec {
        // 部分内部用到的常量定义
        static constexpr uint8_t HPACK_INDEXED_MASK = 0x80;             // 0b1000,0000
        static constexpr uint8_t HPACK_INCREMENTAL_MASK = 0xC0;         // 0b0100,0000
        static constexpr uint8_t HPACK_WITHOUT_INDEXING_MASK = 0xF0;    // 0b0000,0000
        static constexpr uint8_t HPACK_NEVER_INDEXED_MASK = 0xF0;       // 0b0001,0000
        static constexpr uint8_t HPACK_TABLE_UPDATE_MASK = 0xE0;        // 0b0010,0000

        static uint32_t read_uint32(const uint8_t* data)
        {
            return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                ((uint32_t)data[2] << 8) | (uint32_t)data[3];
        }

        static void write_uint32(uint8_t* data, uint32_t value)
        {
            data[0] = (value >> 24) & 0xFF;
            data[1] = (value >> 16) & 0xFF;
            data[2] = (value >> 8) & 0xFF;
            data[3] = value & 0xFF;
        }

        headers_frame(uint8_t* data, size_t size, bool unpack = true)
            : frame_codec(data, size)
        {
            if (unpack) {
                if (type() != frame_type::HEADERS) {
                    throw std::runtime_error("headers_frame: type must be HEADERS");
                }
                unpack_headers();
            }
        }

        // 提取 flag 解析逻辑
        void parse_flags()
        {
            auto flag = flags();

            end_stream_ = !!(flag & (uint8_t)frame_flag::END_STREAM);
            end_headers_ = !!(flag & (uint8_t)frame_flag::END_HEADERS);
            padded_ = !!(flag & (uint8_t)frame_flag::PADDED);
            priority_ = !!(flag & (uint8_t)frame_flag::PRIORITY);
        }

        void unpack_headers()
        {
            parse_flags();

            const uint8_t* payload = this->payload();
            size_t payload_size = this->payload_size();

            if (payload_size < 1) {
                throw std:: runtime_error("headers_frame:  payload too small");
            }

            // 处理 padding
            size_t header_block_len = payload_size;
            if (padded_) {
                uint8_t padding_len = payload[0];
                if (padding_len >= payload_size) {
                    throw std::runtime_error("headers_frame: invalid padding");
                }
                padding_length_ = padding_len;
                payload += 1;
                payload_size -= 1;
                header_block_len = payload_size - padding_len;
            }

            // 处理 priority
            if (priority_) {
                if (payload_size < 5) {
                    throw std::runtime_error("headers_frame: insufficient data for priority");
                }

                int nbytes = parse_priority(payload, payload_size);

                payload += nbytes;
                payload_size -= nbytes;
                header_block_len -= nbytes;
            }

            // 解析 header block
            size_t offset = 0;
            while (offset < header_block_len) {
                header_entry entry;
                int nbytes = unpack_header_block(entry, payload + offset,
                                                header_block_len - offset);
                if (nbytes <= 0) {
                    throw std::runtime_error("headers_frame: parser failed");
                }
                offset += nbytes;
            }
        }

        int parse_priority(const uint8_t* payload, size_t payload_size)
        {
            // 读取 stream dependency（4 字节）
            uint32_t dep = read_uint32(payload);
            exclusive_ = (dep >> 31) & 0x01;
            stream_dependency_ = dep & 0x7FFFFFFF;  // 清除 exclusive bit

            // 读取 weight（1 字节）
            weight_ = payload[4];

            return 5;
        }

        uint8_t compute_flags() const
        {
            uint8_t flag = flags();

            if (end_stream_)  flag |= (uint8_t)frame_flag::END_STREAM;
            if (end_headers_) flag |= (uint8_t)frame_flag::END_HEADERS;
            if (padded_)      flag |= (uint8_t)frame_flag::PADDED;
            if (priority_)    flag |= (uint8_t)frame_flag::PRIORITY;
            return flag;
        }

        int pack_headers()
        {
            flags(compute_flags());

            uint8_t* payload = this->payload();
            size_t size = this->size_ - 9;

            int nbytes = 0;

            // 填充 padding
            if (padded_) {
                if (size < 1) {
                    return -1;
                }

                payload[0] = padding_length_;
                payload += 1;
                size -= 1;
                nbytes += 1;
            }

            // 填充 priority
            if (priority_) {
                if (size < 5) {
                    return -1;
                }

                if (stream_dependency_ > 0x7FFFFFFF) {
                    return -1;
                }

                uint32_t dep = stream_dependency_;
                if (exclusive_) {
                    dep |= 0x80000000;
                }
                write_uint32(payload, dep);
                payload[4] = weight_;

                payload += 5;
                size -= 5;
                nbytes += 5;
            }

            // 填充 header block
            for (const auto& entry : headers_) {
                int bytes = pack_header_block(entry, payload, size);
                if (bytes <= 0) {
                    continue;
                }

                payload += bytes;
                size -= bytes;
                nbytes += bytes;
            }

            this->type(frame_type::HEADERS);
            this->payload_size(nbytes);

            return 9 + nbytes;
        }

        int pack_header_block(const header_entry& entry, uint8_t* payload, size_t size)
        {
            if (!entry.type_ || size < 1) {
                return -1;
            }

            int nbytes = 0;
            payload[0] = entry.type_->pattern_;

            if (entry.index_ != 0) {
                auto ret = hpack_pack_integer(static_cast<uint64_t>(entry.index_), entry.type_->nbits_);
                if (ret.empty() || size < ret.size()) {
                    return -1;
                }

                ret[0] |= payload[0];
                std::memcpy(payload, ret.data(), ret.size());
                nbytes = static_cast<int>(ret.size());
                payload += nbytes;
                size -= nbytes;

                // 检查值是否需要更新
                const header_entry* tmp = hpack_index_to_frame(static_cast<uint32_t>(entry.index_));
                if (tmp && tmp->value_ == entry.value_) {
                    return nbytes;
                }
            } else {
                if (size < 1 || ! entry.name_) {
                    return -1;
                }

                payload += 1;
                size -= 1;
                nbytes += 1;

                auto ret = hpack_pack({(const uint8_t*)entry.name_->data(),
                                    entry.name_->size()});
                if (size < ret.size()) {
                    return -1;
                }

                std::memcpy(payload, ret.data(), ret.size());
                payload += ret.size();
                size -= ret.size();
                nbytes += static_cast<int>(ret.size());
            }

            // 填充 value
            std::string value_str = entry.value_.value_or("");
            auto ret = hpack_pack({(const uint8_t*)value_str.data(), value_str.size()});

            if (size < ret.size()) {
                return -1;
            }

            std::memcpy(payload, ret.data(), ret.size());
            nbytes += static_cast<int>(ret.size());

            return nbytes;
        }

        int unpack_header_block(header_entry& entry, const uint8_t* payload, size_t size)
        {
            if (size < 1) {
                return -1;
            }

            uint8_t prefix = payload[0];
            const hpack_op* op = identify_hpack_operation(prefix);
            if (!op) {
                throw std::runtime_error("headers_frame: invalid prefix");
            }

            switch (op->type_) {
                case operation_type::INDEXED:
                    return unpack_indexed(entry, payload, size, op);
                case operation_type::DYNAMICTABLESIZEUPDATE:
                    return unpack_dynamic_table_update(payload, size, op);
                case operation_type::LITERALINCREMENTALINDEXING:
                case operation_type::LITERALWITHOUTINDEXING:
                case operation_type::LITERALNEVERINDEXED:
                    return unpack_literal(entry, payload, size, op);
                default:
                    return -1;
            }
        }

        const hpack_op* identify_hpack_operation(uint8_t prefix) const
        {
            if ((prefix & HPACK_INDEXED_MASK) == 0x80) {
                return &G_INDEXED;
            } else if ((prefix & HPACK_INCREMENTAL_MASK) == 0x40) {
                return &G_LITERAL_INCREMENTAL_INDEXING;
            } else if ((prefix & HPACK_WITHOUT_INDEXING_MASK) == 0x00) {
                return &G_LITERAL_WITHOUT_INDEXING;
            } else if ((prefix & HPACK_NEVER_INDEXED_MASK) == 0x10) {
                return &G_LITERAL_NEVER_INDEXED;
            } else if ((prefix & HPACK_TABLE_UPDATE_MASK) == 0x20) {
                return &G_DYNAMIC_TABLE_SIZE_UPDATE;
            }
            return nullptr;
        }

        int unpack_indexed(header_entry& entry, const uint8_t* payload, size_t size, const hpack_op* op)
        {
            uint64_t index = 0;
            int nbytes = hpack_unpack_integer({payload, size}, op->nbits_, index);

            if (nbytes < 0 || index < 1 ||
                index > (uint64_t)global_hpack_index_table_size + 61) {
                throw std::runtime_error("headers_frame: invalid index");
            }

            auto frame = hpack_index_to_frame(static_cast<uint32_t>(index));
            if (!frame) {
                throw std::runtime_error("headers_frame: index out of range");
            }

            entry.index_ = static_cast<int64_t>(index);
            entry.name_ = frame->name_;
            entry.value_ = frame->value_;
            entry.hash_ = frame->hash_;
            entry.type_ = op;

            headers_.push_back(entry);
            return nbytes;
        }

        int unpack_dynamic_table_update(const uint8_t* payload, size_t size, const hpack_op* op)
        {
            uint64_t length = 0;
            int nbytes = hpack_unpack_integer({payload, size}, op->nbits_, length);

            if (nbytes < 0) {
                throw std::runtime_error("headers_frame: invalid integer");
            }

            dynamic_table_size_update_.emplace(length);
            return nbytes;
        }

        int unpack_literal(header_entry& entry, const uint8_t* payload, size_t size, const hpack_op* op)
        {
            entry.index_ = 0;
            uint8_t prefix = payload[0] & (uint8_t)((1 << op->nbits_) - 1);
            int nbytes = 0;

            if (prefix == 0) {
                // 无索引字段
                nbytes = 1;
                payload += 1;
                size -= 1;

                std::vector<uint8_t> name;
                int ret = hpack_unpack({payload, size}, name);
                if (ret < 0) {
                    throw std:: runtime_error("headers_frame:  hpack_unpack name failed");
                }
                entry.name_.emplace(name.begin(), name.end());
                nbytes += ret;
                payload += ret;
                size -= ret;
            } else {
                // 有索引字段
                uint64_t index = 0;
                int ret = hpack_unpack_integer({payload, size}, op->nbits_, index);
                if (ret < 0) {
                    throw std::runtime_error("headers_frame: invalid integer");
                }

                auto frame = hpack_index_to_frame(static_cast<uint32_t>(index));
                if (!frame) {
                    throw std::runtime_error("headers_frame: index out of range");
                }

                entry.index_ = static_cast<int64_t>(index);
                entry.name_ = frame->name_;
                nbytes = ret;
                payload += ret;
                size -= ret;
            }

            std::vector<uint8_t> value;
            int ret = hpack_unpack({payload, size}, value);
            if (ret < 0) {
                throw std::runtime_error("headers_frame: hpack_unpack value failed");
            }
            nbytes += ret;

            entry.value_.emplace(value.begin(), value.end());
            entry.type_ = op;
            headers_.push_back(entry);

            return nbytes;
        }

        void add_header(const std::string& name, const std::string& value)
        {
            auto uhash = frame_header_hash({0, name, value, 0, nullptr});

            auto it = global_static_header_table_map.find(uhash);
            if (it != global_static_header_table_map.end()) {
                headers_.push_back(global_static_header_table[it->second]);
            } else {
                headers_.push_back({0, name, value, uhash, &G_LITERAL_INCREMENTAL_INDEXING});
            }
        }

        std::vector<header_entry> headers_;
        std::optional<size_t> dynamic_table_size_update_;

        bool end_stream_ = false;
        bool end_headers_ = false;
        bool padded_ = false;
        bool priority_ = false;

        uint32_t stream_dependency_ = 0;
        uint8_t weight_ = 16;
        uint8_t exclusive_ = 0;
        uint8_t padding_length_ = 0;
    };


    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief PUSH_PROMISE 帧封装，表示服务器对将来推送流的承诺。
     */
    struct push_promise_frame : public frame_codec {
        push_promise_frame(uint8_t* data, size_t size, bool unpack = true)
            : frame_codec(data, size)
        {
            if (type() != frame_type::PUSH_PROMISE) {
                throw std::runtime_error("push_promise_frame: type must be PUSH_PROMISE");
            }

            if (unpack) {
                unpack_payload();
            }
        }

        // 解析 PUSH_PROMISE 帧有效负载
        void unpack_payload()
        {
            const uint8_t* payload = this->payload();
            size_t size = this->payload_size();

            uint8_t frame_flags = flags();
            bool is_padded = (frame_flags & static_cast<uint8_t>(frame_flag::PADDED)) != 0;
            bool is_end_headers = (frame_flags & static_cast<uint8_t>(frame_flag::END_HEADERS)) != 0;

            end_headers_ = is_end_headers;
            pad_length_ = 0;

            size_t offset = 0;

            // 如果设置了 PADDED 标志，第一个字节表示填充长度
            if (is_padded) {
                if (size < 1) {
                    throw std::runtime_error("push_promise_frame: padded frame must have at least 1 byte for pad length");
                }
                pad_length_ = payload[offset++];

                // 验证填充长度的合法性
                if (pad_length_ >= size) {
                    throw std::runtime_error("push_promise_frame: pad length is greater than or equal to frame payload size");
                }
            }

            // 接下来 4 字节是承诺的流 ID (R + 31 位流 ID)
            if (offset + 4 > size - pad_length_) {
                throw std::runtime_error("push_promise_frame: payload size too small for promised stream id");
            }

            promised_stream_id_ = ((payload[offset] & 0x7F) << 24) | (payload[offset + 1] << 16) |
                                (payload[offset + 2] << 8) | payload[offset + 3];
            offset += 4;

            // 剩余的是头部块片段（除去填充数据）
            size_t header_block_size = size - offset - pad_length_;
            if (header_block_size > 0) {
                header_block_fragment_.assign(payload + offset, payload + offset + header_block_size);
            }
        }

        // 打包 PUSH_PROMISE 帧
        int pack_payload()
        {
            size_t header_block_size = header_block_fragment_.size();
            size_t payload_size = 4 + header_block_size;

            // 如果设置了 PADDED 标志，需要额外的空间
            if (pad_length_ > 0) {
                payload_size += 1 + pad_length_;  // 1 字节用于存储 pad_length，pad_length 字节用于填充
            }
            this->payload_size(payload_size);

            // 设置标志位
            uint8_t frame_flags = 0;

            if (end_headers_) {
                frame_flags |= static_cast<uint8_t>(frame_flag::END_HEADERS);
            }

            if (pad_length_ > 0) {
                frame_flags |= static_cast<uint8_t>(frame_flag::PADDED);
            }

            this->flags(frame_flags);

            // 填充 payload
            uint8_t* payload = this->payload();
            size_t offset = 0;

            // 如果设置了 PADDED 标志，先写入 pad_length
            if (pad_length_ > 0) {
                payload[offset++] = pad_length_;
            }

            // 写入承诺的流 ID (保留 1 位为 0)
            payload[offset] = (promised_stream_id_ >> 24) & 0x7F;
            payload[offset + 1] = (promised_stream_id_ >> 16) & 0xFF;
            payload[offset + 2] = (promised_stream_id_ >> 8) & 0xFF;
            payload[offset + 3] = promised_stream_id_ & 0xFF;
            offset += 4;

            // 写入头部块片段
            if (! header_block_fragment_.empty()) {
                std::memcpy(payload + offset, header_block_fragment_.data(), header_block_size);
                offset += header_block_size;
            }

            // 写入填充数据（通常是 0x00）
            if (pad_length_ > 0) {
                std::memset(payload + offset, 0, pad_length_);
            }

            return 9 + payload_size;
        }

        // 获取承诺的流 ID
        uint32_t get_promised_stream_id() const
        {
            return promised_stream_id_;
        }

        // 设置承诺的流 ID
        void set_promised_stream_id(uint32_t stream_id)
        {
            promised_stream_id_ = stream_id & 0x7FFFFFFF;
        }

        // 获取头部块片段
        const std::vector<uint8_t>& get_header_block_fragment() const
        {
            return header_block_fragment_;
        }

        // 设置头部块片段
        void set_header_block_fragment(const std::vector<uint8_t>& fragment)
        {
            header_block_fragment_ = fragment;
        }

        void set_header_block_fragment(const uint8_t* data, size_t size)
        {
            header_block_fragment_.assign(data, data + size);
        }

        // 追加头部块片段
        void append_header_block_fragment(const uint8_t* data, size_t size)
        {
            header_block_fragment_.insert(header_block_fragment_.end(), data, data + size);
        }

        // 检查是否头部结束
        bool is_end_headers() const
        {
            return end_headers_;
        }

        // 设置头部结束标志
        void set_end_headers(bool end)
        {
            end_headers_ = end;
        }

        // 获取填充长度
        uint8_t get_pad_length() const
        {
            return pad_length_;
        }

        // 设置填充长度
        void set_pad_length(uint8_t pad_length)
        {
            pad_length_ = pad_length;
        }

    private:
        uint32_t promised_stream_id_ = 0;            // 承诺的流 ID (31 位)
        std::vector<uint8_t> header_block_fragment_; // 头部块片段
        bool end_headers_ = false;                   // END_HEADERS 标志位
        uint8_t pad_length_ = 0;                     // 填充字节数
    };

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief CONTINUATION 帧封装，用于分块头部的继续承载。
     */
    struct continuation_frame : public frame_codec {
        continuation_frame(uint8_t* data, size_t size, bool unpack = true)
            : frame_codec(data, size)
        {
            if (type() != frame_type::CONTINUATION) {
                throw std:: runtime_error("continuation_frame:  type must be CONTINUATION");
            }

            if (unpack) {
                unpack_payload();
            }
        }

        // 解析 CONTINUATION 帧有效负载
        void unpack_payload()
        {
            const uint8_t* payload = this->payload();
            size_t size = this->payload_size();

            // 检查 END_HEADERS 标志
            uint8_t frame_flags = flags();
            end_headers_ = (frame_flags & static_cast<uint8_t>(frame_flag::END_HEADERS)) != 0;

            // 整个 payload 都是头部块片段数据
            if (size > 0) {
                header_block_fragment_.assign(payload, payload + size);
            }
        }

        // 打包 CONTINUATION 帧
        int pack_payload()
        {
            size_t payload_size = header_block_fragment_.size();
            this->payload_size(payload_size);

            // 设置 END_HEADERS 标志位
            if (end_headers_) {
                this->flags(static_cast<uint8_t>(frame_flag::END_HEADERS));
            } else {
                this->flags(0x00);
            }

            // 填充 payload
            if (payload_size > 0) {
                uint8_t* payload = this->payload();
                std::memcpy(payload, header_block_fragment_.data(), payload_size);
            }

            return 9 + payload_size;
        }

        // 获取头部块片段
        const std::vector<uint8_t>& get_header_block_fragment() const
        {
            return header_block_fragment_;
        }

        // 设置头部块片段
        void set_header_block_fragment(const std::vector<uint8_t>& fragment)
        {
            header_block_fragment_ = fragment;
        }

        void set_header_block_fragment(const uint8_t* data, size_t size)
        {
            header_block_fragment_.assign(data, data + size);
        }

        // 追加头部块片段
        void append_header_block_fragment(const uint8_t* data, size_t size)
        {
            header_block_fragment_.insert(header_block_fragment_.end(), data, data + size);
        }

        // 检查是否头部结束
        bool is_end_headers() const
        {
            return end_headers_;
        }

        // 设置头部结束标志
        void set_end_headers(bool end)
        {
            end_headers_ = end;
        }

    private:
        std::vector<uint8_t> header_block_fragment_;
        bool end_headers_ = false;
    };

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief DATA 帧封装，处理 payload 的解析/打包及 PADDED/END_STREAM 标志。
     */
    struct data_frame : public frame_codec {
        data_frame(uint8_t* data, size_t size, bool unpack = true)
            : frame_codec(data, size)
        {
            if (type() != frame_type::DATA) {
                throw std::runtime_error("data_frame:  type must be DATA");
            }

            if (unpack) {
                unpack_payload();
            }
        }

        // 解析 DATA 帧有效负载
        void unpack_payload()
        {
            const uint8_t* payload = this->payload();
            size_t size = this->payload_size();

            uint8_t frame_flags = flags();

            padded_ = (frame_flags & static_cast<uint8_t>(frame_flag::PADDED)) != 0;
            end_stream_ = (frame_flags & static_cast<uint8_t>(frame_flag::END_STREAM)) != 0;

            pad_length_ = 0;

            // 如果设置了 PADDED 标志，第一个字节表示填充长度
            if (padded_) {
                if (size < 1) {
                    throw std::runtime_error("data_frame: padded frame must have at least 1 byte for pad length");
                }
                pad_length_ = payload[0];

                // 验证填充长度的合法性
                if (pad_length_ >= size) {
                    throw std::runtime_error("data_frame: pad length is greater than or equal to frame payload size");
                }

                // 实际数据 = payload - pad_length字节 - pad_length字节
                size_t data_size = size - 1 - pad_length_;
                frame_data_.assign(payload + 1, payload + 1 + data_size);
            } else {
                // 没有填充，整个 payload 都是数据
                frame_data_.assign(payload, payload + size);
            }
        }

        // 打包 DATA 帧
        int pack_payload()
        {
            // 计算总的 payload 大小
            size_t data_size = frame_data_.size();
            size_t total_size = data_size;

            // 如果设置了 PADDED 标志，需要额外的空间存储 pad_length 和填充数据
            if (pad_length_ > 0) {
                total_size += 1 + pad_length_;  // 1 字节用于存储 pad_length，pad_length 字节用于填充
            }

            this->payload_size(total_size);

            // 设置标志位
            uint8_t frame_flags = 0;

            if (end_stream_) {
                frame_flags |= static_cast<uint8_t>(frame_flag::END_STREAM);
            }

            if (pad_length_ > 0) {
                frame_flags |= static_cast<uint8_t>(frame_flag::PADDED);
            }

            this->flags(frame_flags);

            // 填充 payload
            uint8_t* payload = this->payload();
            size_t offset = 0;

            // 如果设置了 PADDED 标志，先写入 pad_length
            if (pad_length_ > 0) {
                payload[offset++] = pad_length_;
            }

            // 写入实际数据
            if (!frame_data_.empty()) {
                std::memcpy(payload + offset, frame_data_.data(), frame_data_.size());
                offset += frame_data_.size();
            }

            // 写入填充数据（通常是 0x00）
            if (pad_length_ > 0) {
                std::memset(payload + offset, 0, pad_length_);
            }

            return 9 + total_size;
        }

        // 获取数据内容
        const std::vector<uint8_t>& get_data() const
        {
            return frame_data_;
        }

        // 设置数据内容
        void set_data(const std::vector<uint8_t>& data)
        {
            frame_data_ = data;
        }

        // 设置数据内容（从指针）
        void set_data(const uint8_t* data, size_t size)
        {
            frame_data_.assign(data, data + size);
        }

        // 检查是否是流结束
        bool is_end_stream() const
        {
            return end_stream_;
        }

        // 设置流结束标志
        void set_end_stream(bool end)
        {
            end_stream_ = end;
        }

        // 获取填充长度
        uint8_t get_pad_length() const
        {
            return pad_length_;
        }

        // 设置填充长度
        void set_pad_length(uint8_t pad_length)
        {
            pad_length_ = pad_length;
        }

    private:
        std::vector<uint8_t> frame_data_;       // 实际的数据内容
        bool end_stream_ = false;               // END_STREAM 标志位
        bool padded_ = false;                   // PADDED 标志位
        uint8_t pad_length_ = 0;                // 填充字节数
    };

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief GOAWAY 帧封装，携带最后已处理的流 ID 与错误码。
     */
    struct goaway_frame : public frame_codec {
        goaway_frame(uint8_t* data, size_t size, bool unpack = true)
            : frame_codec(data, size)
        {
            if (type() != frame_type::GOAWAY) {
                throw std::runtime_error("goaway_frame:  type must be GOAWAY");
            }

            if (unpack) {
                unpack_payload();
            }
        }

        // 解析 GOAWAY 帧有效负载
        void unpack_payload()
        {
            const uint8_t* payload = this->payload();
            size_t size = this->payload_size();

            if (size < 8) {
                throw std::runtime_error("goaway_frame:  payload size must be at least 8 bytes");
            }

            // 前 4 字节是预留位 + 最后一个流 ID (31位)
            last_stream_id_ = ((payload[0] & 0x7F) << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];

            // 接下来 4 字节是错误码
            error_code_ = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7];

            // 剩余的是调试数据
            if (size > 8) {
                debug_data_.assign(payload + 8, payload + size);
            }
        }

        // 打包 GOAWAY 帧
        int pack_payload()
        {
            size_t debug_data_size = debug_data_.size();
            size_t payload_size = 8 + debug_data_size;
            this->payload_size(payload_size);

            uint8_t* payload = this->payload();

            // 写入最后一个流 ID (保留 1 位为 0)
            payload[0] = (last_stream_id_ >> 24) & 0x7F;
            payload[1] = (last_stream_id_ >> 16) & 0xFF;
            payload[2] = (last_stream_id_ >> 8) & 0xFF;
            payload[3] = last_stream_id_ & 0xFF;

            // 写入错误码
            payload[4] = (error_code_ >> 24) & 0xFF;
            payload[5] = (error_code_ >> 16) & 0xFF;
            payload[6] = (error_code_ >> 8) & 0xFF;
            payload[7] = error_code_ & 0xFF;

            // 写入调试数据
            if (!debug_data_.empty()) {
                std::memcpy(payload + 8, debug_data_.data(), debug_data_size);
            }

            return 9 + payload_size;
        }

        uint32_t get_last_stream_id() const { return last_stream_id_; }
        void set_last_stream_id(uint32_t id) { last_stream_id_ = id & 0x7FFFFFFF; }

        http2_error_code get_error_code() const { return static_cast<http2_error_code>(error_code_); }
        void set_error_code(http2_error_code code) { error_code_ = static_cast<uint32_t>(code); }

        const std::vector<uint8_t>& get_debug_data() const { return debug_data_; }
        void set_debug_data(const std::vector<uint8_t>& data) { debug_data_ = data; }
        void set_debug_data(const uint8_t* data, size_t size) { debug_data_.assign(data, data + size); }

    private:
        uint32_t last_stream_id_ = 0;
        uint32_t error_code_ = 0;
        std::vector<uint8_t> debug_data_;
    };

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief WINDOW_UPDATE 帧封装，用于连接或流级别的流控窗口更新。
     */
    struct window_update_frame : public frame_codec {
        window_update_frame(uint8_t* data, size_t size, bool unpack = true)
            : frame_codec(data, size)
        {
            if (type() != frame_type::WINDOW_UPDATE) {
                throw std::runtime_error("window_update_frame: type must be WINDOW_UPDATE");
            }

            if (unpack) {
                unpack_payload();
            }
        }

        // 解析 WINDOW_UPDATE 帧有效负载
        void unpack_payload()
        {
            const uint8_t* payload = this->payload();
            size_t size = this->payload_size();

            if (size != 4) {
                throw std::runtime_error("window_update_frame: payload size must be exactly 4 bytes");
            }

            // 前 1 位是保留位，后 31 位是窗口大小增量
            window_increment_ = ((payload[0] & 0x7F) << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];

            if (window_increment_ == 0) {
                throw std::runtime_error("window_update_frame: window increment must be > 0");
            }
        }

        // 打包 WINDOW_UPDATE 帧
        int pack_payload()
        {
            if (window_increment_ == 0 || window_increment_ > 0x7FFFFFFF) {
                throw std::runtime_error("window_update_frame: window increment must be between 1 and 2^31-1");
            }

            this->payload_size(4);

            uint8_t* payload = this->payload();
            payload[0] = (window_increment_ >> 24) & 0x7F;  // 保留首位为 0
            payload[1] = (window_increment_ >> 16) & 0xFF;
            payload[2] = (window_increment_ >> 8) & 0xFF;
            payload[3] = window_increment_ & 0xFF;

            return 9 + 4;
        }

        uint32_t get_window_increment() const { return window_increment_; }
        void set_window_increment(uint32_t increment)
        {
            if (increment == 0 || increment > 0x7FFFFFFF) {
                throw std::runtime_error("window_update_frame: window increment must be between 1 and 2^31-1");
            }
            window_increment_ = increment;
        }

    private:
        uint32_t window_increment_ = 0;
    };

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief PING 帧封装，携带 8 字节的 opaque 数据与 ACK 标志。
     */
    struct ping_frame : public frame_codec {
        static const size_t ping_data_size = 8;

        ping_frame(uint8_t* data, size_t size, bool unpack = true)
            : frame_codec(data, size)
        {
            if (type() != frame_type::PING) {
                throw std::runtime_error("ping_frame: type must be PING");
            }

            if (unpack) {
                unpack_payload();
            }
        }

        // 解析 PING 帧有效负载
        void unpack_payload()
        {
            const uint8_t* payload = this->payload();
            size_t size = this->payload_size();

            if (size != ping_data_size) {
                throw std::runtime_error("ping_frame: payload size must be exactly 8 bytes");
            }

            // 检查 ACK 标志
            uint8_t frame_flags = flags();
            ack_ = (frame_flags & 0x01) != 0;

            // 复制 8 字节的 opaque data
            std::memcpy(opaque_data_, payload, ping_data_size);
        }

        // 打包 PING 帧
        int pack_payload()
        {
            this->payload_size(ping_data_size);

            // 设置 ACK 标志位
            if (ack_) {
                this->flags(0x01);
            } else {
                this->flags(0x00);
            }

            uint8_t* payload = this->payload();
            std::memcpy(payload, opaque_data_, ping_data_size);

            return 9 + ping_data_size;
        }

        // 获取 opaque data
        const uint8_t* get_opaque_data() const { return opaque_data_; }
        void set_opaque_data(const uint8_t* data)
        {
            if (data) {
                std::memcpy(opaque_data_, data, ping_data_size);
            } else {
                std::memset(opaque_data_, 0, ping_data_size);
            }
        }

        bool is_ack() const { return ack_; }
        void set_ack(bool ack) { ack_ = ack; }

    private:
        uint8_t opaque_data_[ping_data_size] = {0};
        bool ack_ = false;
    };

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief RST_STREAM 帧封装，用于中止特定流并携带错误码。
     */
    struct rst_stream_frame : public frame_codec {
        rst_stream_frame(uint8_t* data, size_t size, bool unpack = true)
            : frame_codec(data, size)
        {
            if (type() != frame_type::RST_STREAM) {
                throw std::runtime_error("rst_stream_frame: type must be RST_STREAM");
            }

            if (unpack) {
                unpack_payload();
            }
        }

        // 解析 RST_STREAM 帧有效负载
        void unpack_payload()
        {
            const uint8_t* payload = this->payload();
            size_t size = this->payload_size();

            if (size != 4) {
                throw std::runtime_error("rst_stream_frame: payload size must be exactly 4 bytes");
            }

            error_code_ = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
        }

        // 打包 RST_STREAM 帧
        int pack_payload()
        {
            this->payload_size(4);

            uint8_t* payload = this->payload();
            payload[0] = (error_code_ >> 24) & 0xFF;
            payload[1] = (error_code_ >> 16) & 0xFF;
            payload[2] = (error_code_ >> 8) & 0xFF;
            payload[3] = error_code_ & 0xFF;

            return 9 + 4;
        }

        http2_error_code get_error_code() const { return static_cast<http2_error_code>(error_code_); }
        void set_error_code(http2_error_code code) { error_code_ = static_cast<uint32_t>(code); }

    private:
        uint32_t error_code_ = 0;
    };

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @brief PRIORITY 帧封装，描述流的依赖与权重信息。
     */
    struct priority_frame : public frame_codec {
        priority_frame(uint8_t* data, size_t size, bool unpack = true)
            : frame_codec(data, size)
        {
            if (type() != frame_type::PRIORITY) {
                throw std::runtime_error("priority_frame: type must be PRIORITY");
            }

            if (unpack) {
                unpack_payload();
            }
        }

        // 解析 PRIORITY 帧有效负载
        void unpack_payload()
        {
            const uint8_t* payload = this->payload();
            size_t size = this->payload_size();

            if (size != 5) {
                throw std::runtime_error("priority_frame: payload size must be exactly 5 bytes");
            }

            // 第一个字节的首位是 E 标志（exclusive），后面 31 位是依赖的流 ID
            exclusive_ = (payload[0] & 0x80) != 0;
            depends_on_ = ((payload[0] & 0x7F) << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];

            // 最后一个字节是权重（1-256 映射为 0-255）
            weight_ = payload[4];
        }

        // 打包 PRIORITY 帧
        int pack_payload()
        {
            this->payload_size(5);

            uint8_t* payload = this->payload();

            // 写入 E 标志 + 依赖的流 ID
            if (exclusive_) {
                payload[0] = ((depends_on_ >> 24) & 0x7F) | 0x80;  // 设置首位为 1
            } else {
                payload[0] = (depends_on_ >> 24) & 0x7F;  // 首位为 0
            }
            payload[1] = (depends_on_ >> 16) & 0xFF;
            payload[2] = (depends_on_ >> 8) & 0xFF;
            payload[3] = depends_on_ & 0xFF;

            // 写入权重
            payload[4] = weight_;

            return 9 + 5;
        }

        uint32_t get_depends_on() const { return depends_on_; }
        void set_depends_on(uint32_t stream_id) { depends_on_ = stream_id & 0x7FFFFFFF; }

        uint8_t get_weight() const { return weight_; }
        void set_weight(uint8_t weight) { weight_ = weight; }

        bool is_exclusive() const { return exclusive_; }
        void set_exclusive(bool exclusive) { exclusive_ = exclusive; }

    private:
        uint32_t depends_on_ = 0;  // 依赖的流 ID (31 位)
        uint8_t weight_ = 16;      // 权重 (0-255，表示 1-256)
        bool exclusive_ = false;   // 是否为独占依赖
    };

    ////////////////////////////////////////////////////////////////////////////////

} // namespace h2x

#endif // H2X_HTTP2_FRAME_HPP
