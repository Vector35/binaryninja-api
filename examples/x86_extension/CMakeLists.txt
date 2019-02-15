cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

project(x86_extension CXX)

add_library(${PROJECT_NAME} SHARED
    src/x86_extension.cpp
    src/asmx86/asmx86.c
    src/asmx86/asmx86.h)

target_link_libraries(${PROJECT_NAME}
    binaryninjaapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 11
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../bin)

binja_install_plugin(${PROJECT_NAME})
