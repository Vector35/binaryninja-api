cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(platform_windows_kernel)

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	*.cpp
	*.h)

if(DEMO)
	add_library(platform_windows_kernel STATIC ${SOURCES})
else()
	add_library(platform_windows_kernel SHARED ${SOURCES})
endif()

target_link_libraries(platform_windows_kernel binaryninjaapi)

set_target_properties(platform_windows_kernel PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(platform_windows_kernel)
	set_target_properties(platform_windows_kernel PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
