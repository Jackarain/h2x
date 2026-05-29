
add_executable(client
    client.cpp
    ../lib_asio.cpp
)

add_executable(tcp_client
	tcp_client.cpp
	../lib_asio.cpp
)

target_link_libraries(client
    PRIVATE h2x
    Boost::asio
    Boost::system
)

target_link_libraries(tcp_client
	PRIVATE h2x
	Boost::asio
	Boost::system
)

set_property(TARGET client PROPERTY FOLDER "example/client")

if (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129 AND CMAKE_VERSION VERSION_GREATER 3.20.3)
	set_property(TARGET client PROPERTY CXX_STANDARD 23)
	message(STATUS "client set cxx standard: C++23")
else()
	set_property(TARGET client PROPERTY CXX_STANDARD 20)
	message(STATUS "client set cxx standard: C++20")
endif()

if(ENABLE_BUILD_WERROR)
	if(MSVC)
		target_compile_options(client PRIVATE /W4 /WX)
	elseif(UNIX AND NOT APPLE)
		if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
			target_compile_options(client PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
		else()
			target_compile_options(client PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated -Wno-deprecated-copy -Wno-error=deprecated-copy -Wno-pessimizing-move)
		endif()
	endif()
endif()
