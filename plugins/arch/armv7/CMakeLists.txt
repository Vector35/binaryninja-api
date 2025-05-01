cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(arch_armv7)

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	*.cpp
	*.h
	armv7_disasm/*.c
	armv7_disasm/*.h
	thumb2_disasm/*.cpp
	thumb2_disasm/*.h)

if(DEMO)
	add_library(arch_armv7 STATIC ${SOURCES})
else()
	add_library(arch_armv7 SHARED ${SOURCES})
endif()

target_include_directories(arch_armv7
	PRIVATE ${PROJECT_SOURCE_DIR}
	PRIVATE ${PROJECT_SOURCE_DIR}/armv7_disasm
	PRIVATE ${PROJECT_SOURCE_DIR}/thumb2_disasm)

target_link_libraries(arch_armv7 binaryninjaapi)

set_target_properties(arch_armv7 PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(arch_armv7)
	set_target_properties(arch_armv7 PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
