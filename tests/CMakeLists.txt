cmake_minimum_required(VERSION 3.16)
project(h2x_test LANGUAGES CXX)

# 该构建仅在有 ENABLE_BUILD_TESTS 时触发
if(NOT ENABLE_BUILD_TESTS)
    return()
endif()

# ── 测试可执行文件 ──

set(TEST_SOURCES
    main.cpp
    hpack_test.cpp
    frame_test.cpp
    global_data_test.cpp
    error_code_test.cpp
)

add_executable(h2x_test ${TEST_SOURCES})

target_link_libraries(h2x_test
    PRIVATE
        h2x
        Boost::unit_test_framework
        Boost::system
)

target_include_directories(h2x_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../h2x/include
)

set_property(TARGET h2x_test PROPERTY FOLDER "test")

# 添加测试到 CMake CTest
include(CTest)
add_test(NAME h2x_test COMMAND h2x_test)

set_tests_properties(h2x_test PROPERTIES
    ENVIRONMENT "BOOST_TEST_LOG_LEVEL=test_suite"
)

if(MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129 AND CMAKE_VERSION VERSION_GREATER 3.20.3)
    set_property(TARGET h2x_test PROPERTY CXX_STANDARD 23)
    message(STATUS "h2x_test set cxx standard: C++23")
else()
    set_property(TARGET h2x_test PROPERTY CXX_STANDARD 20)
    message(STATUS "h2x_test set cxx standard: C++20")
endif()

if(ENABLE_BUILD_WERROR)
    if(MSVC)
        target_compile_options(h2x_test PRIVATE /W4 /WX)
    else()
        target_compile_options(h2x_test PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
    endif()
endif()