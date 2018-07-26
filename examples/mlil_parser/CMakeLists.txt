# Mostly copied from https://github.com/Vector35/binaryninja-api/blob/dev/examples/breakpoint/CMakeLists.txt

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

project(MLIL_Parser)

#-----------------------------------------------------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../..)
#-----------------------------------------------------------------------------
set(SRCS src/mlil_parser.cpp)
#-----------------------------------------------------------------------------
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
#-----------------------------------------------------------------------------
if(WIN32)
	set(BINJA_DIR "C:\\Program Files\\Vector35\\BinaryNinja"
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
#-----------------------------------------------------------------------------
add_executable (${PROJECT_NAME} ${SRCS})
#-----------------------------------------------------------------------------
find_library(BINJA_API_LIBRARY binaryninjaapi
	HINTS ${CMAKE_CURRENT_SOURCE_DIR}/../../bin ${CMAKE_CURRENT_SOURCE_DIR}/../../bin/Release ${CMAKE_CURRENT_SOURCE_DIR}/../../bin/Debug)
find_library(BINJA_CORE_LIBRARY binaryninjacore
	HINTS ${BINJA_BIN_DIR})
#-----------------------------------------------------------------------------
target_link_libraries(${PROJECT_NAME}
	${BINJA_API_LIBRARY}
	${BINJA_CORE_LIBRARY}
	)
#-----------------------------------------------------------------------------
install (TARGETS	${PROJECT_NAME}
			RUNTIME DESTINATION bin
			LIBRARY DESTINATION Lib
			ARCHIVE DESTINATION Lib)

