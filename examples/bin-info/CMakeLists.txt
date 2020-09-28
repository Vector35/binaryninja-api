cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(bin-info CXX)

add_executable(${PROJECT_NAME}
    src/bin-info.cpp)

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
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../bin)
