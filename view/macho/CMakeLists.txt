cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(view_macho)

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	*.cpp
	*.h)

if(DEMO)
	add_library(view_macho STATIC ${SOURCES})
else()
	add_library(view_macho SHARED ${SOURCES})
endif()

target_link_libraries(view_macho binaryninjaapi)

set_target_properties(view_macho PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(view_macho)
	set_target_properties(view_macho PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
	bn_install_plugin(view_macho)
endif()
