cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(sharedcache)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
    set(BN_API_PATH $ENV{BN_API_PATH} CACHE STRING "Path to Binary Ninja API source")
    if(NOT BN_API_PATH)
        message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
    endif()
endif()

if (NOT BN_INTERNAL_BUILD)
    if(WIN32)
        set(MSVC_VERSION msvc2022_64 CACHE STRING "Version of MSVC Qt is built with" )
    endif()
    set(QT_VERSION 6.7.2 CACHE STRING "Version of Qt to use")

    if(NOT CMAKE_PREFIX_PATH)
        if(APPLE)
            set(CMAKE_PREFIX_PATH $ENV{HOME}/Qt/${QT_VERSION}/clang_64/lib/cmake)
        elseif(WIN32)
            set(CMAKE_PREFIX_PATH $ENV{HOMEDRIVE}$ENV{HOMEPATH}/Qt/${QT_VERSION}/${MSVC_VERSION}/lib/cmake)
        else()
            set(CMAKE_PREFIX_PATH $ENV{HOME}/Qt/${QT_VERSION}/gcc_64/lib/cmake)
        endif()
    endif()
    message("CMAKE_PREFIX_PATH is: ${CMAKE_PREFIX_PATH}")
endif()

set(HARD_FAIL_MODE OFF CACHE BOOL "Enable hard fail mode")
set(SLIDEINFO_DEBUG_TAGS OFF CACHE BOOL "Enable debug tags in slideinfo")
set(VIEW_NAME "DSCView" CACHE STRING "Name of the view")
set(METADATA_VERSION 2 CACHE STRING "Version of the metadata")

add_subdirectory(core)
add_subdirectory(api)
add_subdirectory(workflow)

add_library(sharedcache SHARED
    HeadlessPlugin.cpp)


if(BN_INTERNAL_BUILD)
    set_target_properties(sharedcache PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
            RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
    set_target_properties(sharedcache PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins
            )
endif()

set_target_properties(sharedcache PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        )

target_include_directories(sharedcache PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/core ${CMAKE_CURRENT_SOURCE_DIR}/api ${CMAKE_CURRENT_SOURCE_DIR}/workflow)

target_link_libraries(sharedcache PUBLIC sharedcacheapi binaryninjaapi sharedcachecore sharedcacheworkflow)


set(COMPILE_DEFS "")

if (HARD_FAIL_MODE)
    set(COMPILE_DEFS "${COMPILE_DEFS} ABORT_FAILURES;")
endif()

if (BN_REF_COUNT_DEBUG)
    set(COMPILE_DEFS "${COMPILE_DEFS} BN_REF_COUNT_DEBUG;")
endif()

if (SLIDEINFO_DEBUG_TAGS)
    set(COMPILE_DEFS "${COMPILE_DEFS} SLIDEINFO_DEBUG_TAGS;")
endif()

if (METADATA_VERSION)
    set(COMPILE_DEFS "${COMPILE_DEFS} METADATA_VERSION=${METADATA_VERSION};")
else()
    message(FATAL_ERROR "No metadata version provided. Fatal.")
endif()

if (VIEW_NAME)
    set(COMPILE_DEFS "${COMPILE_DEFS} VIEW_NAME=\"${VIEW_NAME}\";")
else()
    message(FATAL_ERROR "No view name provided. Fatal.")
endif()

target_compile_definitions(sharedcache PRIVATE ${COMPILE_DEFS})

if(NOT HEADLESS)
    add_subdirectory(ui)
endif()

message("
▓█████▄    ██████   ▄████▄     Shared Cache Plugin
▒██▀ ██▌ ▒██    ▒  ▒██▀ ▀█
░██   █▌ ░ ▓██▄    ▒▓█    ▄    Metadata Version:      ${METADATA_VERSION}
░▓█▄  █▌   ▒   ██▒ ▒▓▓▄ ▄██▒   CMake Prefix Path:     ${CMAKE_PREFIX_PATH}
░▒████▓  ▒██████▒▒▒  ▓███▀ ░   Qt Version:            ${QT_VERSION}
 ▒▒▓  ▒ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░     Crash on Failure:      ${HARD_FAIL_MODE}
 ░ ▒  ▒ ░ ░▒  ░ ░  ░  ▒        Slideinfo Debug Tags:  ${SLIDEINFO_DEBUG_TAGS}
 ░ ░  ░ ░  ░  ░  ░             REFCOUNT_DEBUG:        ${BN_REF_COUNT_DEBUG}
")