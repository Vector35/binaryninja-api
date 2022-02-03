cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

option(QT6 "Target Qt 6" OFF)

project(uinotification CXX C)

if(NOT QT6)
	set(CMAKE_OSX_ARCHITECTURES x86_64)
endif()

file(GLOB SOURCES
	*.cpp
	*.h)

add_library(uinotification SHARED ${SOURCES})

if(NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    # Out-of-tree build
    find_path(
        BN_API_DIR
        NAMES binaryninjaapi.h
        HINTS ../.. binaryninjaapi $ENV{BN_API_DIR}
        REQUIRED
    )
    add_subdirectory(${BN_API_DIR} api)
endif()

target_link_libraries(uinotification binaryninjaapi binaryninjaui)

set_target_properties(uinotification PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON
	LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)

if(BN_INTERNAL_BUILD)
	ui_plugin_rpath(uinotification)
endif()

bn_install_plugin(${PROJECT_NAME})
