cmake_minimum_required(VERSION 3.28 FATAL_ERROR)
project(binaryninjacore_stubs)

find_package(Python3 COMPONENTS Interpreter REQUIRED)

file(REAL_PATH "${PROJECT_SOURCE_DIR}/../" ABSOLUTE_API_PATH)

# Remove long path prefix because it makes cl.exe very angry
string(REGEX REPLACE "^//\\?/" "" ABSOLUTE_API_PATH "${ABSOLUTE_API_PATH}")

# Generate stubs.cpp with implementations of all the BNAPI functions
add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/stubs.cpp
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/generate_stubs.py ${ABSOLUTE_API_PATH}/binaryninjacore.h ${PROJECT_BINARY_DIR}
    DEPENDS ${PROJECT_SOURCE_DIR}/generate_stubs.py ${ABSOLUTE_API_PATH}/binaryninjacore.h
    COMMENT "Generating stubs.cpp from binaryninjacore.h"
)

# Compile those stubs into a stub library we can use to fool the linker
add_library(binaryninjacore_stubs SHARED ${PROJECT_BINARY_DIR}/stubs.cpp)

set_target_properties(binaryninjacore_stubs
    PROPERTIES OUTPUT_NAME binaryninjacore
    SOVERSION 1
    CXX_STANDARD 20
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}"
)

target_include_directories(binaryninjacore_stubs PUBLIC ${ABSOLUTE_API_PATH})

install(TARGETS binaryninjacore_stubs LIBRARY DESTINATION ${PROJECT_BINARY_DIR})
