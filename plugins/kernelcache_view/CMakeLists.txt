cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(kernelcache)

if(NOT BN_INTERNAL_BUILD)
    find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h
        HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
        REQUIRED
    )
    add_subdirectory(${BN_API_PATH} binaryninjaapi)
endif()

if (NOT BN_INTERNAL_BUILD)
    set(QT_VERSION 6.7.2 CACHE STRING "Version of Qt to use")

    if(NOT CMAKE_PREFIX_PATH)
        if(WIN32)
            set(CMAKE_PREFIX_PATH $ENV{HOMEDRIVE}$ENV{HOMEPATH}/Qt/${QT_VERSION}/lib/cmake)
        else()
            set(CMAKE_PREFIX_PATH $ENV{HOME}/Qt/${QT_VERSION}/lib/cmake)
        endif()
    endif()
    message("CMAKE_PREFIX_PATH is: ${CMAKE_PREFIX_PATH}")
endif()

set(HARD_FAIL_MODE OFF CACHE BOOL "Enable hard fail mode")
set(SLIDEINFO_DEBUG_TAGS OFF CACHE BOOL "Enable debug tags in slideinfo")
set(KC_VIEW_NAME "KCView" CACHE STRING "Name of the view")
set(METADATA_VERSION 3 CACHE STRING "Version of the metadata")

add_subdirectory(core)
add_subdirectory(api)
add_subdirectory(workflow)

add_library(kernelcache SHARED
    HeadlessPlugin.cpp)


if(BN_INTERNAL_BUILD)
    set_target_properties(kernelcache PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
            RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
    plugin_rpath(kernelcache)
else()
    set_target_properties(kernelcache PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins
            )
endif()

set_target_properties(kernelcache PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        )

target_include_directories(kernelcache PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/core ${CMAKE_CURRENT_SOURCE_DIR}/api ${CMAKE_CURRENT_SOURCE_DIR}/workflow)

target_link_libraries(kernelcache PUBLIC kernelcacheapi binaryninjaapi kernelcachecore kernelcacheworkflow)



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

if (KC_VIEW_NAME)
    set(COMPILE_DEFS "${COMPILE_DEFS} KC_VIEW_NAME=\"${KC_VIEW_NAME}\";")
else()
    message(FATAL_ERROR "No view name provided. Fatal.")
endif()

target_compile_definitions(kernelcache PRIVATE ${COMPILE_DEFS})

if(NOT HEADLESS)
    add_subdirectory(ui)
endif()
