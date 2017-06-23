cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

project(breakpoint CXX)

add_library(${PROJECT_NAME} SHARED
	src/breakpoint.cpp)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../..)

if(WIN32)
	set(BINJA_DIR "C:\\Program Files\\Vector35\\Binary Ninja"
		CACHE PATH "Binary Ninja installation directory")
	set(BINJA_BIN_DIR "${BINJA_DIR}")
	set(BINJA_PLUGINS_DIR "$ENV{APPDATA}/Binary Ninja/plugins"
		CACHE PATH "Binary Ninja user plugins directory")
elseif(APPLE)
	set(BINJA_DIR "/Applications/Binary Ninja.app"
		CACHE PATH "Binary Ninja installation directory")
	set(BINJA_BIN_DIR "${BINJA_DIR}/Contents/MacOS")
	set(BINJA_PLUGINS_DIR "$ENV{HOME}/Library/Application Support/Binary Ninja/plugins"
		CACHE PATH "Binary Ninja user plugins directory")
else()
	set(BINJA_DIR "$ENV{HOME}/binaryninja"
		CACHE PATH "Binary Ninja installation directory")
	set(BINJA_BIN_DIR "${BINJA_DIR}")
	set(BINJA_PLUGINS_DIR "$ENV{HOME}/.binaryninja/plugins"
		CACHE PATH "Binary Ninja user plugins directory")
endif()

find_library(BINJA_API_LIBRARY binaryninjaapi
	HINTS ${CMAKE_CURRENT_SOURCE_DIR}/../../bin)
find_library(BINJA_CORE_LIBRARY binaryninjacore
	HINTS ${BINJA_BIN_DIR})

target_link_libraries(${PROJECT_NAME}
	${BINJA_API_LIBRARY}
	${BINJA_CORE_LIBRARY}
	)

set_target_properties(${PROJECT_NAME} PROPERTIES
	CXX_STANDARD 11
	LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../bin
	)

install(TARGETS ${PROJECT_NAME} DESTINATION ${BINJA_PLUGINS_DIR})
