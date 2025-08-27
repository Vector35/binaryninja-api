cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(warp_ui CXX C)

file(GLOB SOURCES CONFIGURE_DEPENDS
        plugin.cpp plugin.h
        matches.cpp matches.h
        matched.cpp matched.h
        shared/misc.cpp shared/misc.h
        shared/constraint.cpp shared/constraint.h
        shared/function.cpp shared/function.h
        containers.cpp containers.h
        shared/search.cpp shared/search.h
        shared/fetcher.cpp shared/fetcher.h
        shared/fetchdialog.cpp shared/fetchdialog.h)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${MOCS})

target_include_directories(${PROJECT_NAME} PRIVATE ../api)

if (NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    # Out-of-tree build
    find_path(
            BN_API_PATH
            NAMES binaryninjaapi.h
            HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
            REQUIRED
    )
    add_subdirectory(${BN_API_PATH} api)
endif ()

target_link_libraries(${PROJECT_NAME} binaryninjaui warp_api Qt6::Core Qt6::Gui Qt6::Widgets)

set_target_properties(${PROJECT_NAME} PROPERTIES
        CXX_STANDARD 20
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON)

if (BN_INTERNAL_BUILD)
    ui_plugin_rpath(${PROJECT_NAME})

    if (UNIX)
        # A hack to get the ui plugin to find the warp core plugin.
        set_target_properties(${PROJECT_NAME} PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE INSTALL_RPATH "$ORIGIN")
    endif()

    set_target_properties(${PROJECT_NAME} PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
            RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else ()
    # TODO: There is a possibility that linux will fail to load the correct core warp.
    bn_install_plugin(${PROJECT_NAME})
endif ()
