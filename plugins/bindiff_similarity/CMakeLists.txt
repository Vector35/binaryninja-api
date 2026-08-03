cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

project(bindiff_similarity)

file(GLOB SOURCES CONFIGURE_DEPENDS
        *.cpp
        *.c
        *.h)

if (DEMO)
    add_library(${PROJECT_NAME} STATIC ${SOURCES})
else ()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
endif ()

if (NOT BN_INTERNAL_BUILD)
    # Out-of-tree build
    find_path(
            BN_API_PATH
            NAMES binaryninjaapi.h
            HINTS ../../.. binaryninjaapi $ENV{BN_API_PATH}
            REQUIRED
    )
    add_subdirectory(${BN_API_PATH} api)
endif ()

set(BINDIFF_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BINDIFF_ENABLE_IDAPRO OFF CACHE BOOL "" FORCE)
set(BINEXPORT_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BINEXPORT_ENABLE_IDAPRO OFF CACHE BOOL "" FORCE)
set(BINEXPORT_ENABLE_BINARYNINJA OFF CACHE BOOL "" FORCE)
set(BINEXPORT_MSVC_STATIC_RUNTIME OFF CACHE BOOL "" FORCE)

add_subdirectory(
        "${CMAKE_CURRENT_LIST_DIR}/../../vendor/bindiff"
        "${CMAKE_CURRENT_BINARY_DIR}/vendor_bindiff"
        EXCLUDE_FROM_ALL
)

target_link_libraries(${PROJECT_NAME}
        PRIVATE
        binaryninjaapi
        binexport_core
        bindiff_base
        bindiff_shared
)

if (APPLE)
    target_link_options(${PROJECT_NAME} PRIVATE
            "LINKER:-exported_symbol,_CorePluginABIVersion"
            "LINKER:-exported_symbol,_CorePluginInit")
elseif (UNIX)
    target_link_options(${PROJECT_NAME} PRIVATE "LINKER:--exclude-libs,ALL")
endif ()

set_target_properties(${PROJECT_NAME} PROPERTIES
        CXX_STANDARD 20
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        C_STANDARD 99
        C_STANDARD_REQUIRED ON
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON)

if (BN_INTERNAL_BUILD)
    plugin_rpath(${PROJECT_NAME})
    set_target_properties(${PROJECT_NAME} PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
            RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})

else ()
    bn_install_plugin(${PROJECT_NAME})
endif ()
