cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

project(binaryninja-api)

add_library(binaryninjaapi STATIC
	architecture.cpp
	backgroundtask.cpp
	basicblock.cpp
	binaryninjaapi.cpp
	binaryreader.cpp
	binaryview.cpp
	binaryviewtype.cpp
	binarywriter.cpp
	callingconvention.cpp
	databuffer.cpp
	demangle.cpp
	fileaccessor.cpp
	filemetadata.cpp
	function.cpp
	functiongraph.cpp
	functiongraphblock.cpp
	functionrecognizer.cpp
	interaction.cpp
	json/jsoncpp.cpp
	log.cpp
	lowlevelil.cpp
	mainthread.cpp
    mediumlevelil.cpp
    metadata.cpp
	platform.cpp
	plugin.cpp
    pluginmanager.cpp
	scriptingprovider.cpp
    settings.cpp
	tempfile.cpp
	transform.cpp
	type.cpp
	update.cpp
	)

set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)

include_directories(${PROJECT_SOURCE_DIR})

set_target_properties(binaryninjaapi PROPERTIES
	CXX_STANDARD 11
	ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
	)
