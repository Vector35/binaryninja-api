cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

option(QT6 "Target Qt 6" OFF)

project(uinotification)

if(NOT QT6)
	set(CMAKE_OSX_ARCHITECTURES x86_64)
endif()

if(QT6)
	find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)
else()
	find_package(Qt5 COMPONENTS Core Gui Widgets REQUIRED)
endif()

file(GLOB SOURCES
	*.cpp
	*.h)

add_library(uinotification SHARED ${SOURCES})

if(QT6)
	target_link_libraries(uinotification binaryninjaapi binaryninjaui
		Qt6::Core Qt6::Gui Qt6::Widgets)
else()
	target_link_libraries(uinotification binaryninjaapi binaryninjaui
		Qt5::Core Qt5::Gui Qt5::Widgets)
endif()

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
