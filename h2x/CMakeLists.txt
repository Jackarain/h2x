cmake_minimum_required(VERSION 3.16)
project(h2x)

add_library(h2x INTERFACE)

target_include_directories(h2x
	INTERFACE
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

file(GLOB_RECURSE H2X_HEADERS CONFIGURE_DEPENDS
	${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp
)

target_sources(h2x
	INTERFACE
	${H2X_HEADERS}
)