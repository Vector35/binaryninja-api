cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(lang_pseudoc)

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	*.cpp
	*.h)

if(DEMO)
	add_library(lang_pseudoc STATIC ${SOURCES})
else()
	add_library(lang_pseudoc SHARED ${SOURCES})
endif()

target_include_directories(lang_pseudoc
	PRIVATE ${PROJECT_SOURCE_DIR})

if(WIN32)
	target_link_directories(lang_pseudoc
		PRIVATE ${BN_INSTALL_DIR})
	target_link_libraries(lang_pseudoc binaryninjaapi binaryninjacore)
else()
	target_link_libraries(lang_pseudoc binaryninjaapi)
endif()

set_target_properties(lang_pseudoc PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(lang_pseudoc)
	set_target_properties(lang_pseudoc PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
