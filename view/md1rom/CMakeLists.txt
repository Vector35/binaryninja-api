cmake_minimum_required(VERSION 3.28 FATAL_ERROR)

project(view_md1rom)

if(NOT BN_INTERNAL_BUILD)
    add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES CONFIGURE_DEPENDS
        *.cpp
        *.h)

if(DEMO)
    add_library(view_md1rom STATIC ${SOURCES})
else()
    add_library(view_md1rom SHARED ${SOURCES})
endif()

target_link_libraries(view_md1rom binaryninjaapi)

set_target_properties(view_md1rom PROPERTIES
        CXX_STANDARD 20
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
    bn_plugin(view_md1rom)
endif()
