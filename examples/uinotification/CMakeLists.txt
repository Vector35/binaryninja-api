cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(uinotification)


find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

file(GLOB SOURCES
	*.cpp
	*.h)

add_library(uinotification SHARED ${SOURCES})

target_link_libraries(uinotification binaryninjaapi binaryninjaui
	Qt6::Core Qt6::Gui Qt6::Widgets)


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
