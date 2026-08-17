//
// h2_error_code.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2025 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef H2X_HTTP2_ERROR_CODE_HPP
#define H2X_HTTP2_ERROR_CODE_HPP


#include <boost/system/error_code.hpp>

namespace h2x {

	/**
	 * @brief HTTP/2 专属错误类别与辅助函数。
	 *
	 * 提供 `errc` 枚举与 `make_error_code` 以便与 `boost::system::error_code` 集成。
	 */
	class error_category_impl;

	namespace errc {
		/**
		 * @brief 库使用的错误代码枚举（可转换为 boost::system::error_code）。
		 */
		enum errc_t
		{
			success = 0,
			stream_not_found = 1,
			stream_already_exists = 2,
			connection_error = 3,
			flow_control_error = 4,
			protocol_error = 5,
			frame_size_error = 6,
			stream_closed = 7,
			next_layer_not_open = 8,
		};
	}

	class error_category_impl
		: public boost::system::error_category
	{
		const char* name() const noexcept override
		{
			return "HTTP/2";
		}

		std::string message(int e) const override
		{
			switch (static_cast<errc::errc_t>(e))
			{
			case errc::success:
				return "Success";
			case errc::stream_not_found:
				return "Stream not found";
			case errc::stream_already_exists:
				return "Stream already exists";
			case errc::connection_error:
				return "Connection error";
			case errc::flow_control_error:
				return "Flow control error";
			case errc::protocol_error:
				return "Protocol error";
			case errc::frame_size_error:
				return "Frame size error";
			case errc::stream_closed:
				return "Stream closed";
			case errc::next_layer_not_open:
				return "NextLayer is not open";
			default:
				return "Unknown error";
			}
		}
	};

	// 以函数局部静态变量延迟初始化类别实例, 避免静态初始化顺序问题,
	// 同时省去 reinterpret_cast 的模板间接层.
	inline const boost::system::error_category& error_category()
	{
		static const error_category_impl instance;
		return instance;
	}

	namespace errc {
		inline boost::system::error_code make_error_code(errc_t e) noexcept
		{
			return boost::system::error_code(
				static_cast<int>(e), error_category());
		}
	}

}

namespace boost::system {
	template <>
	struct is_error_code_enum<h2x::errc::errc_t>
	{
		static const inline bool value = true;
	};

} // namespace boost

#endif // H2X_HTTP2_ERROR_CODE_HPP
