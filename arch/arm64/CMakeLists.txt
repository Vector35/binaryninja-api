cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(arch_arm64 CXX C)

file(GLOB SOURCES
	*.cpp
	*.c
	*.h
	disassembler/decode.c
	disassembler/format.c
	disassembler/sysregs.c
	disassembler/regs.c
	disassembler/encodings_dec.c
	disassembler/encodings_fmt.c
	disassembler/operations.c
	disassembler/pcode.c
	disassembler/decode0.c
	disassembler/decode1.c
	disassembler/decode2.c
	disassembler/decode_fields32.c
	disassembler/decode_scratchpad.c
	disassembler/*.h)

if(DEMO)
	add_library(${PROJECT_NAME} STATIC ${SOURCES})
else()
	add_library(${PROJECT_NAME} SHARED ${SOURCES})
endif()


if(NOT WIN32)
	set_source_files_properties(disassembler/arm64dis.c PROPERTIES COMPILE_FLAGS -fno-strict-aliasing)
endif()

target_include_directories(${PROJECT_NAME}
	PRIVATE ${PROJECT_SOURCE_DIR}
	PRIVATE ${PROJECT_SOURCE_DIR}/disassembler)

if((NOT BN_API_BUILD_EXAMPLES) AND (NOT BN_INTERNAL_BUILD))
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
	target_link_libraries(${PROJECT_NAME} binaryninjaapi)
else()
	if(WIN32)
		target_link_directories(${PROJECT_NAME}
			PRIVATE ${BN_INSTALL_DIR})
		target_link_libraries(${PROJECT_NAME} binaryninjaapi binaryninjacore)
	else()
		target_link_libraries(${PROJECT_NAME} binaryninjaapi)
	endif()
endif()

IF(DEFINED ENV{ARM64_WARNINGS})
    MESSAGE(STATUS "ARM64 WARNINGS ON")
	target_compile_options(${PROJECT_NAME} PRIVATE -Wall)
ELSE()
    MESSAGE(STATUS "ARM64 WARNINGS OFF")
ENDIF()

set_target_properties(${PROJECT_NAME} PROPERTIES
	CXX_STANDARD 17
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
