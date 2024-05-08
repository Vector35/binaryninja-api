cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(arch_mips)

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	*.cpp
	*.h
	mips/*.c
	mips/*.h)

if(DEMO)
	add_library(arch_mips STATIC ${SOURCES})
else()
	add_library(arch_mips SHARED ${SOURCES})
endif()

target_include_directories(arch_mips
	PRIVATE ${PROJECT_SOURCE_DIR}
	PRIVATE ${PROJECT_SOURCE_DIR}/mips)

if(WIN32)
	target_link_directories(arch_mips
		PRIVATE ${BN_INSTALL_DIR})
	target_link_libraries(arch_mips binaryninjaapi binaryninjacore)
else()
	target_link_libraries(arch_mips binaryninjaapi)
endif()

set_target_properties(arch_mips PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(arch_mips)
	set_target_properties(arch_mips PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()

add_executable(mipstest mips/mips.c mips/test.c)
target_link_libraries(mipstest PRIVATE arch_mips)
