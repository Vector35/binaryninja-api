cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)

project(bn-st10-arch CXX)

add_library(${PROJECT_NAME} SHARED
        src/architecture.cpp
        src/architecture.h
        src/conditions.h
        src/flags.h
        src/info.cpp
        src/instructions.h
        src/lift.cpp
        src/opcodes.h
        src/registers.h
        src/sfr.h
        src/text.cpp
        src/util.cpp
        src/util.h
)

target_link_libraries(${PROJECT_NAME}
        binaryninjaapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
        CXX_STANDARD 20
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)

set(CMAKE_CXX_FLAGS_DEBUG "-Og -g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

bn_install_plugin(${PROJECT_NAME})
