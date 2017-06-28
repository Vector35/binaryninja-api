cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

project(binaryninja-api)

file( GLOB SRCS *.cpp json/json.h json/jsoncpp.cpp json/json-forwards.h)

add_library(binaryninjaapi STATIC ${SRCS})

set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)

include_directories(${PROJECT_SOURCE_DIR})

set_target_properties(binaryninjaapi PROPERTIES
	CXX_STANDARD 11
	ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
	)
