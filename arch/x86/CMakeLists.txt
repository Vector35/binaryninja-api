cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(arch_x86)

OPTION(BUILD_SHARED_LIBS "Build shared libraries" OFF)
OPTION(YASM_BUILD_TESTS "Enable building of tests" OFF)
add_subdirectory(yasm)

set(XED_CONFIGURE_ARGS --no-encoder just-gen)
if(WIN32)
	execute_process(COMMAND ${CMAKE_COMMAND} -E env OS=Windows_NT PYTHONPATH=${PROJECT_SOURCE_DIR}/mbuild
		py -3 ${PROJECT_SOURCE_DIR}/xed/mfile.py ${XED_CONFIGURE_ARGS}
		WORKING_DIRECTORY ${PROJECT_BINARY_DIR})
else()
	execute_process(COMMAND python3 ${PROJECT_SOURCE_DIR}/xed/mfile.py ${XED_CONFIGURE_ARGS}
		WORKING_DIRECTORY ${PROJECT_BINARY_DIR})
endif()

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES *.cpp *.h
	${PROJECT_SOURCE_DIR}/xed/src/common/*.c
	${PROJECT_SOURCE_DIR}/xed/src/dec/*.c
	${PROJECT_BINARY_DIR}/obj/*.c)

# This accounts for the source code file replacement in
# https://github.com/intelxed/xed/blob/d41e876ba1bda5e53af2db74700216da29752fd7/datafiles/knc/files-no-avx512f.cfg#L58-L59
# See https://github.com/Vector35/binaryninja-api/issues/4617 for more details
# Note to who updates xed: the path replacement file may change, search for its name in the xed directory to find its
# newest location
list(REMOVE_ITEM SOURCES ${PROJECT_SOURCE_DIR}/xed/src/common/xed-operand-values-interface-repl.c)
list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/xed/datafiles/knc/xed-operand-values-interface-uisa.c)

if(DEMO)
	add_library(arch_x86 STATIC ${SOURCES})
else()
	add_library(arch_x86 SHARED ${SOURCES})
endif()

target_include_directories(arch_x86
	PRIVATE ${PROJECT_SOURCE_DIR}
	PRIVATE ${PROJECT_SOURCE_DIR}/xed/include/public/xed
	PRIVATE ${PROJECT_SOURCE_DIR}/xed/include/private
	PRIVATE ${PROJECT_BINARY_DIR}/obj
	PRIVATE ${PROJECT_BINARY_DIR}/obj/include-private)

add_compile_definitions(XED_DECODER XED_AMD_ENABLED XED_VIA_ENABLED XED_AVX XED_SUPPORTS_AVX512
	XED_MPX XED_CET XED_SUPPORTS_SHA XED_SUPPORTS_WBNOINVD)

target_link_libraries(arch_x86 binaryninjaapi)

if(UNIX AND NOT APPLE)
	target_link_options(arch_x86 PRIVATE "LINKER:--exclude-libs,ALL")
endif()

set_target_properties(arch_x86 PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 11
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(arch_x86)
	set_target_properties(arch_x86 PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
	add_custom_command(TARGET arch_x86 POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:yasm> ${BN_CORE_PLUGIN_DIR})
endif()
