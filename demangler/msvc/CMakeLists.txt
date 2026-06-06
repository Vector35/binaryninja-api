cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(demangle_msvc)

file(GLOB SOURCES CONFIGURE_DEPENDS
	*.cpp
	*.c
	*.h
	../gnu3/demangled_type_node.cpp
	../gnu3/demangled_type_node.h)

if(DEMO)
	add_library(${PROJECT_NAME} STATIC ${SOURCES})
else()
	add_library(${PROJECT_NAME} SHARED ${SOURCES})
endif()

if(NOT BN_INTERNAL_BUILD)
    # Out-of-tree build
    find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h
        HINTS ../../.. binaryninjaapi $ENV{BN_API_PATH}
        REQUIRED
    )
    add_subdirectory(${BN_API_PATH} api)
endif()

target_link_libraries(${PROJECT_NAME} binaryninjaapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
	CXX_STANDARD 20
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
	C_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(${PROJECT_NAME})
	set_target_properties(${PROJECT_NAME} PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
	bn_install_plugin(${PROJECT_NAME})
endif()
