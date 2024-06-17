cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(view_vxworks)

if(NOT BN_INTERNAL_BUILD)
    add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
        *.cpp
        *.h)

if(DEMO)
    add_library(view_vxworks STATIC ${SOURCES})
else()
    add_library(view_vxworks SHARED ${SOURCES})
endif()

target_link_libraries(view_vxworks binaryninjaapi)

set_target_properties(view_vxworks PROPERTIES
        CXX_STANDARD 17
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
    plugin_rpath(view_vxworks)
    set_target_properties(view_vxworks PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
            RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
