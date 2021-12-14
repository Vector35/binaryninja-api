cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(binaryninjaapi)

option(BN_API_BUILD_EXAMPLES "Builds example plugins" OFF)

set(CARGO_API_VERSION stable-2021-06-17)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    if (MSVC)
        message(FATAL_ERROR "Binary Ninja is 64-bit only (try -G \"${CMAKE_GENERATOR} Win64\")")
    else()
        message(FATAL_ERROR "Binary Ninja is 64-bit only")
    endif()
endif()

if(WIN32)
    if(NOT BN_INSTALL_DIR)
        set(BN_INSTALL_DIR "C:\\Program Files\\Vector35\\BinaryNinja"
            CACHE PATH "Binary Ninja installation directory")
    endif()
    set(BN_INSTALL_BIN_DIR "${BN_INSTALL_DIR}"
        CACHE PATH "Binary Ninja binary directory")
    set(BN_USER_PLUGINS_DIR "$ENV{APPDATA}/Binary Ninja/plugins"
        CACHE PATH "Binary Ninja user plugins directory")
elseif(APPLE)
    if(NOT BN_INSTALL_DIR)
        set(BN_INSTALL_DIR "/Applications/Binary Ninja.app"
            CACHE PATH "Binary Ninja installation directory")
    endif()
    set(BN_INSTALL_BIN_DIR "${BN_INSTALL_DIR}/Contents/MacOS"
        CACHE PATH "Binary Ninja binary directory")
    set(BN_USER_PLUGINS_DIR "$ENV{HOME}/Library/Application Support/Binary Ninja/plugins"
        CACHE PATH "Binary Ninja user plugins directory")
else()
    if(NOT BN_INSTALL_DIR)
        set(BN_INSTALL_DIR "$ENV{HOME}/binaryninja"
            CACHE PATH "Binary Ninja installation directory")
    endif()
    set(BN_INSTALL_BIN_DIR "${BN_INSTALL_DIR}"
        CACHE PATH "Binary Ninja binary directory")
    set(BN_USER_PLUGINS_DIR "$ENV{HOME}/.binaryninja/plugins"
        CACHE PATH "Binary Ninja user plugins directory")
endif()

file(GLOB BN_API_SOURCES *.cpp *.h json/json.h json/json-forwards.h)
if(NOT DEMO)
    list(APPEND BN_API_SOURCES json/jsoncpp.cpp)
endif()

add_library(binaryninjaapi STATIC ${BN_API_SOURCES})

target_include_directories(binaryninjaapi
    PUBLIC ${PROJECT_SOURCE_DIR})

# We only need to find the core and UI when we also build the examples
if((NOT BN_CORE_LIBRARY) AND (NOT BN_INTERNAL_BUILD))
    find_library(BN_CORE_LIBRARY REQUIRED
            NAMES binaryninjacore libbinaryninjacore.so.1
            PATHS ${BN_INSTALL_BIN_DIR})

    if(BN_CORE_LIBRARY)
        message(STATUS "Binary Ninja Core: ${BN_CORE_LIBRARY}")
    else()
        message(FATAL_ERROR "Binary Ninja Core Not Found")
    endif()
endif()

if(NOT HEADLESS)
    if((NOT BN_UI_LIBRARY) AND (NOT BN_INTERNAL_BUILD))
        find_library(BN_UI_LIBRARY REQUIRED
                NAMES binaryninjaui libbinaryninjaui.so.1
                PATHS ${BN_INSTALL_BIN_DIR})

        if(BN_UI_LIBRARY)
            message(STATUS "Binary Ninja UI: ${BN_UI_LIBRARY}")
        else()
            message(FATAL_ERROR "Binary Ninja UI Not Found")
        endif()
    endif()
endif()

if(NOT BN_INTERNAL_BUILD)
    target_link_libraries(binaryninjaapi PUBLIC ${BN_CORE_LIBRARY})
    target_link_directories(binaryninjaapi PUBLIC ${BN_INSTALL_BIN_DIR})
else()
    target_link_libraries(binaryninjaapi PUBLIC binaryninjacore)
endif()

if(NOT HEADLESS)
    target_include_directories(binaryninjaapi PUBLIC ${PROJECT_SOURCE_DIR}/ui)

    if(NOT BN_INTERNAL_BUILD)
        target_link_libraries(binaryninjaapi PUBLIC ${BN_UI_LIBRARY})
        target_link_directories(binaryninjaapi PUBLIC ${BN_INSTALL_BIN_DIR})
    else()
        # Nothing
    endif()
endif()

set_target_properties(binaryninjaapi PROPERTIES
    CXX_STANDARD 17
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/out)

function(bn_install_plugin target)
    if(NOT BN_INTERNAL_BUILD)
        if(WIN32)
            install(TARGETS ${target} RUNTIME
                DESTINATION ${BN_USER_PLUGINS_DIR})

            install(FILES $<TARGET_PDB_FILE:${target}>
                DESTINATION ${BN_USER_PLUGINS_DIR} OPTIONAL)
        else()
            install(TARGETS ${target} LIBRARY
                DESTINATION ${BN_USER_PLUGINS_DIR})
        endif()
    endif()
endfunction()

if(BN_API_BUILD_EXAMPLES)
    add_subdirectory(examples)
    add_subdirectory(rust/examples/basic_script)
endif()
