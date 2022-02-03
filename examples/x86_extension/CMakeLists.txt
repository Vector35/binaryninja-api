cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(x86_extension CXX C)

add_library(${PROJECT_NAME} SHARED
    src/x86_extension.cpp
    src/asmx86/asmx86.c
    src/asmx86/asmx86.h)

if(NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    # Out-of-tree build
    find_path(
        BN_API_DIR
        NAMES binaryninjaapi.h
        HINTS ../.. binaryninjaapi $ENV{BN_API_DIR}
        REQUIRED
    )
    add_subdirectory(${BN_API_DIR} api)
endif()

target_link_libraries(${PROJECT_NAME}
    binaryninjaapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)

bn_install_plugin(${PROJECT_NAME})
