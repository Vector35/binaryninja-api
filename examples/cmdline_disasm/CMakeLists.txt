cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

project(cmdline_disasm CXX)

add_executable(${PROJECT_NAME}
    src/disasm.cpp)

target_link_libraries(${PROJECT_NAME}
    binaryninjaapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 11
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../bin)
