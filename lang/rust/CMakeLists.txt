cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(lang_pseudorust)

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	*.cpp
	*.h)

if(DEMO)
	add_library(lang_pseudorust STATIC ${SOURCES})
else()
	add_library(lang_pseudorust SHARED ${SOURCES})
endif()

target_include_directories(lang_pseudorust
	PRIVATE ${PROJECT_SOURCE_DIR})

if(WIN32)
	target_link_directories(lang_pseudorust
		PRIVATE ${BN_INSTALL_DIR})
	target_link_libraries(lang_pseudorust binaryninjaapi binaryninjacore)
else()
	target_link_libraries(lang_pseudorust binaryninjaapi)
endif()

set_target_properties(lang_pseudorust PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(lang_pseudorust)
	set_target_properties(lang_pseudorust PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
