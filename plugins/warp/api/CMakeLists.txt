cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(warp_api CXX C)

add_library(warp_api STATIC warp.cpp warp.h warpcore.h)
target_include_directories(warp_api PUBLIC ${PROJECT_SOURCE_DIR})

if (NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    # Out-of-tree build
    find_path(
            BN_API_PATH
            NAMES binaryninjaapi.h
            HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
            REQUIRED
    )
    add_subdirectory(${BN_API_PATH} api)
endif()

# Make sure the core rust dylib is built before warp_api.
add_dependencies(warp_api warp_ninja)

target_link_libraries(warp_api binaryninjaapi)

if (NOT DEMO)
    add_subdirectory(python)
endif()

# Link to the warp plugin.
# TODO: Need to make this less scuffed, but this will do for now.
if (DEMO)
    target_link_libraries(${PROJECT_NAME} warp_ninja_interface ${CMAKE_BINARY_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}warp_ninja_static${CMAKE_STATIC_LIBRARY_SUFFIX})
else ()
    if (WIN32)
        # By linking to warp_ninja_interface we insure that we get built _after_ the lib has been generated.
        target_link_libraries(${PROJECT_NAME} warp_ninja_interface "${BN_CORE_PLUGIN_DIR}/warp_ninja.lib")
    else ()
        target_link_libraries(${PROJECT_NAME} warp_ninja_interface ${BN_CORE_PLUGIN_DIR}/libwarp_ninja${CMAKE_SHARED_LIBRARY_SUFFIX})
        # Set RPATH so the library can be found at runtime
        if(APPLE)
            set_target_properties(${PROJECT_NAME} PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE INSTALL_RPATH "@loader_path")
        else()
            set_target_properties(${PROJECT_NAME} PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE INSTALL_RPATH "$ORIGIN")
        endif()
    endif()
endif ()

set_target_properties(warp_api PROPERTIES
        CXX_STANDARD 20
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/out)