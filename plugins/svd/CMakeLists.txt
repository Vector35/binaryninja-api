cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(svd_ninja)

if(NOT BN_INTERNAL_BUILD)
    if(NOT BN_API_BUILD_EXAMPLES)
        if(NOT BN_API_PATH)
            find_path(
                BN_API_PATH
                NAMES binaryninjaapi.h
                HINTS ../../.. ../../binaryninja/api/ binaryninjaapi binaryninja-api $ENV{BN_API_PATH}
                REQUIRED
            )
        endif()
        add_subdirectory(${BN_API_PATH} binaryninjaapi)
    endif()
    get_target_property(BN_API_SOURCE_DIR binaryninjaapi SOURCE_DIR)
    list(APPEND CMAKE_MODULE_PATH "${BN_API_SOURCE_DIR}/cmake")
    include(RustBuild)
    find_package(BinaryNinjaCore REQUIRED)
endif()

bn_add_rust_crate(
    TARGET ${PROJECT_NAME}
    CRATE svd_ninja
    WORKSPACE ${BN_API_SOURCE_DIR}
    OUTPUT_TYPE SHARED
    OUTPUT_DIR ${BN_PLUGIN_OUTPUT_DIR}
    GROUP plugins
    DEMO_STATIC
    EXTRA_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/fixtures
)

add_dependencies(${PROJECT_NAME} binaryninjaapi)
