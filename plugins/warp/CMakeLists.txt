cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(warp_ninja)

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

# Add C++ API library and UI plugin
add_subdirectory(api)
if(NOT HEADLESS)
    add_subdirectory(ui)
endif()

if(NOT DEMO)
    # Non-DEMO uses --no-default-features to exclude test artifacts
    set(CARGO_ARGS "--no-default-features")
endif()

bn_add_rust_crate(
    TARGET ${PROJECT_NAME}
    CRATE warp_ninja
    WORKSPACE ${BN_API_SOURCE_DIR}
    OUTPUT_TYPE SHARED
    OUTPUT_DIR ${BN_PLUGIN_OUTPUT_DIR}
    CARGO_ARGS ${CARGO_ARGS}
    GROUP plugins
    DEMO_STATIC
    EXTRA_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/templates
        ${CMAKE_CURRENT_SOURCE_DIR}/fixtures
)

add_dependencies(${PROJECT_NAME} binaryninjaapi)

# warp_ninja_interface is the target hack im going with for now to get warp_api to build on windows
add_library(${PROJECT_NAME}_interface INTERFACE)
add_dependencies(${PROJECT_NAME}_interface ${PROJECT_NAME})
