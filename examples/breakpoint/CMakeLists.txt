cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(breakpoint CXX)

add_library(${PROJECT_NAME} SHARED
    src/breakpoint.cpp)

target_link_libraries(${PROJECT_NAME}
    binaryninjaapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 11
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../bin)

bn_install_plugin(${PROJECT_NAME})
