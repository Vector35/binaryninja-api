cmake_minimum_required(VERSION 3.4 FATAL_ERROR)

project(binaryninja-api)

option(BINJA_BUILD_EXAMPLES "Builds example plugins" OFF)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    if (MSVC)
        message(FATAL_ERROR "Binary Ninja is 64-bit only (try -G \"${CMAKE_GENERATOR} Win64\")")
    else()
        message(FATAL_ERROR "Binary Ninja is 64-bit only")
    endif()
endif()

if(WIN32)
    set(BINJA_DIR "C:\\Program Files\\Vector35\\BinaryNinja"
        CACHE PATH "Binary Ninja installation directory")
    set(BINJA_BIN_DIR "${BINJA_DIR}"
        CACHE PATH "Binary Ninja binary directory")
    set(BINJA_PLUGINS_DIR "$ENV{APPDATA}/Binary Ninja/plugins"
        CACHE PATH "Binary Ninja user plugins directory")
elseif(APPLE)
    set(BINJA_DIR "/Applications/Binary Ninja.app"
        CACHE PATH "Binary Ninja installation directory")
    set(BINJA_BIN_DIR "${BINJA_DIR}/Contents/MacOS"
        CACHE PATH "Binary Ninja binary directory")
    set(BINJA_PLUGINS_DIR "$ENV{HOME}/Library/Application Support/Binary Ninja/plugins"
        CACHE PATH "Binary Ninja user plugins directory")
else()
    set(BINJA_DIR "$ENV{HOME}/binaryninja"
        CACHE PATH "Binary Ninja installation directory")
    set(BINJA_BIN_DIR "${BINJA_DIR}"
        CACHE PATH "Binary Ninja binary directory")
    set(BINJA_PLUGINS_DIR "$ENV{HOME}/.binaryninja/plugins"
        CACHE PATH "Binary Ninja user plugins directory")
endif()

if(NOT BINJA_CORE_LIBRARY)
    find_library(BINJA_CORE_LIBRARY
        NAMES binaryninjacore libbinaryninjacore.so.1
        PATHS ${BINJA_BIN_DIR})

    if(BINJA_CORE_LIBRARY)
        message(STATUS "Binary Ninja Core: ${BINJA_CORE_LIBRARY}")
    else()
        message(FATAL_ERROR "Binary Ninja Core Not Found")
    endif()
endif()

file(GLOB BINJA_SOURCES *.cpp *.h json/json.h json/jsoncpp.cpp json/json-forwards.h)

add_library(binaryninjaapi STATIC ${BINJA_SOURCES})

target_include_directories(binaryninjaapi
    PUBLIC ${PROJECT_SOURCE_DIR})

target_link_libraries(binaryninjaapi
    ${BINJA_CORE_LIBRARY})

set_target_properties(binaryninjaapi PROPERTIES
    CXX_STANDARD 11
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

function(binja_install_plugin target)
    if(WIN32)
        install(TARGETS ${target} RUNTIME
            DESTINATION ${BINJA_PLUGINS_DIR})

        install(FILES $<TARGET_PDB_FILE:${target}>
            DESTINATION ${BINJA_PLUGINS_DIR} OPTIONAL)
    else()
        install(TARGETS ${target} LIBRARY
            DESTINATION ${BINJA_PLUGINS_DIR})
    endif()
endfunction()

if(BINJA_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
