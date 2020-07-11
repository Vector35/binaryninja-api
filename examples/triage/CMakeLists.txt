cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(triage)

file(GLOB SOURCES
	*.cpp
	*.h)

if(DEMO)
	add_library(triage STATIC ${SOURCES})
else()
	add_library(triage SHARED ${SOURCES})
endif()

target_link_libraries(triage binaryninjaapi binaryninjaui)

set_target_properties(triage PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	ui_plugin_rpath(triage)
	set_target_properties(triage PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
