cmake_minimum_required(VERSION 3.16)
project(h2x)

add_library(h2x INTERFACE)

# 为 FetchContent / add_subdirectory 使用场景提供别名目标，
# 方便消费方以 h2x::h2x 形式链接。
add_library(h2x::h2x ALIAS h2x)

target_include_directories(h2x
	INTERFACE
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# h2x 是 header-only 库，依赖 Boost.Asio 分离编译和 C++20。
# 传播必要的编译定义供消费方（通过 FetchContent 使用时无需重复设置）。
target_compile_definitions(h2x
	INTERFACE
		$<BUILD_INTERFACE:BOOST_ASIO_SEPARATE_COMPILATION>
		$<BUILD_INTERFACE:BOOST_BEAST_SEPARATE_COMPILATION>
		$<BUILD_INTERFACE:BOOST_LOCALE_HIDE_AUTO_PTR>
		$<BUILD_INTERFACE:BOOST_BIND_GLOBAL_PLACEHOLDERS>
		$<BUILD_INTERFACE:BOOST_DISABLE_PRAGMA_MESSAGE>
		$<BUILD_INTERFACE:BOOST_COROUTINES_NO_DEPRECATION_WARNING>
		$<BUILD_INTERFACE:BOOST_PROCESS_USE_STD_FS>
)

# 设置 C++ 标准要求
target_compile_features(h2x INTERFACE cxx_std_20)

file(GLOB_RECURSE H2X_HEADERS CONFIGURE_DEPENDS
	${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp
)

target_sources(h2x
	PRIVATE
	${H2X_HEADERS}
)