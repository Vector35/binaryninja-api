cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(view_md1rom)

file(GLOB SOURCES
        *.cpp
        *.h)

if(DEMO)
    add_library(view_md1rom STATIC ${SOURCES})
else()
    add_library(view_md1rom SHARED ${SOURCES})
endif()

target_link_libraries(view_md1rom binaryninjaapi)

set_target_properties(view_md1rom PROPERTIES
        CXX_STANDARD 17
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
    plugin_rpath(view_md1rom)
    set_target_properties(view_md1rom PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
            RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
    set_target_properties(view_md1rom PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out/plugins")
endif()
