cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(platform_freebsd)

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	${PROJECT_SOURCE_DIR}/*.cpp
	${PROJECT_SOURCE_DIR}/*.h)

if(DEMO)
	add_library(platform_freebsd STATIC ${SOURCES})
else()
	add_library(platform_freebsd SHARED ${SOURCES})
endif()

target_link_libraries(platform_freebsd binaryninjaapi)

set_target_properties(platform_freebsd PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(platform_freebsd)
	set_target_properties(platform_freebsd PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
