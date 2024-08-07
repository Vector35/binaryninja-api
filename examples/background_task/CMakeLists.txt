cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(background_task CXX C)

add_library(background_task SHARED
        src/backgroundtask.cpp)

if(NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    # Out-of-tree build
    find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h
        HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
        REQUIRED
    )
    add_subdirectory(${BN_API_PATH} api)
endif()

target_link_libraries(${PROJECT_NAME}
        binaryninjaapi)

set_target_properties(background_task PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON
	LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)

bn_install_plugin(${PROJECT_NAME})
