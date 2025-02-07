cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(formatter_generic)

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	*.cpp
	*.h)

if(DEMO)
	add_library(formatter_generic STATIC ${SOURCES})
else()
	add_library(formatter_generic SHARED ${SOURCES})
endif()

target_include_directories(formatter_generic
	PRIVATE ${PROJECT_SOURCE_DIR})

if(WIN32)
	target_link_directories(formatter_generic
		PRIVATE ${BN_INSTALL_DIR})
	target_link_libraries(formatter_generic binaryninjaapi binaryninjacore)
else()
	target_link_libraries(formatter_generic binaryninjaapi)
endif()

set_target_properties(formatter_generic PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(formatter_generic)
	set_target_properties(formatter_generic PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
