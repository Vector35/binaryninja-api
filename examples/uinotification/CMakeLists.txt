cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(uinotification)

file(GLOB SOURCES
	*.cpp
	*.h)

add_library(uinotification SHARED ${SOURCES})
target_link_libraries(uinotification binaryninjaapi binaryninjaui)

set_target_properties(uinotification PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON
	LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../bin)

if(BN_INTERNAL_BUILD)
	ui_plugin_rpath(uinotification)
endif()

bn_install_plugin(${PROJECT_NAME})
