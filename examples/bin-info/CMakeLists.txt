cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(bin-info CXX C)

add_executable(${PROJECT_NAME}
    src/bin-info.cpp)

if(NOT BN_API_BUILD_EXAMPLES)
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

if (NOT WIN32)
    target_link_libraries(${PROJECT_NAME}
    dl)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
