cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(binaryninjaapi CXX C)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(BN_API_BUILD_EXAMPLES "Builds example plugins" OFF)
option(BN_ALLOW_STUBS "Allow generating and linking against stubs if a Binary Ninja installation was not found" OFF)

option(BN_REF_COUNT_DEBUG "Add extra debugging checks for RefCountObject leaks" OFF)
mark_as_advanced(BN_REF_COUNT_DEBUG)

find_package(Python3 3.10 COMPONENTS Interpreter REQUIRED)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    if (MSVC)
        message(FATAL_ERROR "Binary Ninja is 64-bit only (try -G \"${CMAKE_GENERATOR} Win64\")")
    else()
        message(FATAL_ERROR "Binary Ninja is 64-bit only")
    endif()
endif()

file(GLOB BN_API_SOURCES CONFIGURE_DEPENDS *.cpp *.h json/*.cpp json/*.h)
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set_source_files_properties(json/jsoncpp.cpp PROPERTIES COMPILE_FLAGS /w)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set_source_files_properties(json/jsoncpp.cpp PROPERTIES COMPILE_FLAGS -Wno-everything)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(json/jsoncpp.cpp PROPERTIES COMPILE_FLAGS -w)
endif()

if(NOT BN_INTERNAL_BUILD)
    add_subdirectory(base)
endif()

add_library(binaryninjaapi STATIC ${BN_API_SOURCES})

if(COVERAGE)
    target_link_libraries(binaryninjaapi PRIVATE coverage_config)
endif()

target_include_directories(binaryninjaapi
    PUBLIC ${PROJECT_SOURCE_DIR})

target_link_libraries(binaryninjaapi PUBLIC binaryninjabase)

# Store path to user plugin dir
if(WIN32)
    set(plugin_dir "$ENV{APPDATA}\\Binary Ninja\\plugins")
elseif(APPLE)
    set(plugin_dir "$ENV{HOME}/Library/Application Support/Binary Ninja/plugins")
else()
    set(plugin_dir "$ENV{HOME}/.binaryninja/plugins")
endif()
set(BN_USER_PLUGINS_DIR "${plugin_dir}" CACHE PATH "Path to Binary Ninja user plugins")
message(STATUS "Binary Ninja User Plugins Dir: ${BN_USER_PLUGINS_DIR}")

find_package(BinaryNinjaCore)
if(BinaryNinjaCore_FOUND)
    target_link_libraries(binaryninjaapi PUBLIC ${BinaryNinjaCore_LIBRARIES})
    target_link_directories(binaryninjaapi PUBLIC ${BinaryNinjaCore_LIBRARY_DIRS})
    target_compile_definitions(binaryninjaapi PUBLIC ${BinaryNinjaCore_DEFINITIONS})
elseif(BN_ALLOW_STUBS)
    add_subdirectory(stubs EXCLUDE_FROM_ALL)

    # Be sure to only link against the stubs archive file
    add_dependencies(binaryninjaapi binaryninjacore_stubs)
    target_link_libraries(binaryninjaapi PUBLIC binaryninjacore_stubs)
else()
    message(FATAL_ERROR "Could NOT find Binary Ninja installation. Please configure with -DBN_INSTALL_DIR=<path to Binary Ninja>, set the BN_INSTALL_DIR environment variable, or enable stub generation with -DBN_ALLOW_STUBS=ON")
endif()

if(BN_REF_COUNT_DEBUG)
    target_compile_definitions(binaryninjaapi PUBLIC BN_REF_COUNT_DEBUG)
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug OR CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
    target_compile_definitions(binaryninjaapi PRIVATE BN_ENABLE_LOG_TRACE)
endif()

add_subdirectory(vendor/fmt EXCLUDE_FROM_ALL)
set_target_properties(fmt PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(binaryninjaapi PUBLIC fmt::fmt)

if(APPLE)
    find_library(CORE_SERVICES_LIBRARY NAMES CoreServices)
    target_link_libraries(binaryninjaapi PRIVATE ${CORE_SERVICES_LIBRARY})
endif()

set_target_properties(binaryninjaapi PROPERTIES
    CXX_STANDARD 20
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/out)

if(NOT HEADLESS)
    if(NOT BN_INTERNAL_BUILD)
        # For backwards compatibility, include binaryninjaui in the api module
        # If you don't need it, you can safely ignore these warnings

        find_package(BinaryNinjaUI)
        if(BinaryNinjaUI_FOUND)
            # Precompiled ui library
            add_library(binaryninjaui INTERFACE)
            target_link_libraries(binaryninjaui INTERFACE binaryninjaapi ${BinaryNinjaUI_LIBRARIES})
            target_link_directories(binaryninjaui INTERFACE ${BinaryNinjaUI_LIBRARY_DIRS})
            target_compile_definitions(binaryninjaui INTERFACE ${BinaryNinjaUI_DEFINITIONS})

            # UI headers are in here
            target_include_directories(binaryninjaui INTERFACE ${PROJECT_SOURCE_DIR}/ui)
        else()
            # Add a fake target for binaryninjaui to intentionally break anything that tries to link against it,
            # since the find script failed and your build would otherwise break in less obvious places.
            add_custom_target(binaryninjaui
                COMMAND ${CMAKE_COMMAND} -E false)
            message(WARNING "Binary Ninja UI not found but -DHEADLESS was not specified. You will not be able to build UI plugins.")
        endif()
    else()
        # Nothing
    endif()
endif()

function(bn_install_plugin target)
    if(WIN32)
        set(plugin_dir "$ENV{APPDATA}\\Binary Ninja\\plugins")
    elseif(APPLE)
        set(plugin_dir "$ENV{HOME}/Library/Application Support/Binary Ninja/plugins")
    else()
        set(plugin_dir "$ENV{HOME}/.binaryninja/plugins")
    endif()
    set(BN_USER_PLUGINS_DIR "${plugin_dir}" CACHE PATH "Path to Binary Ninja user plugins")

    if(NOT BN_INTERNAL_BUILD)
        if(WIN32)
            install(TARGETS ${target} RUNTIME
                DESTINATION ${BN_USER_PLUGINS_DIR})

            install(FILES $<TARGET_PDB_FILE:${target}>
                DESTINATION ${BN_USER_PLUGINS_DIR} OPTIONAL)
        else()
            install(TARGETS ${target} LIBRARY
                DESTINATION ${BN_USER_PLUGINS_DIR})
        endif()
    endif()
endfunction()

if(RUST_API)
    add_subdirectory(rust)
endif()

if(BN_API_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if (DEBUGGER)
    add_custom_command(TARGET binaryninjaapi PRE_BUILD
            COMMAND ${CMAKE_COMMAND} -E echo "Copying Debugger Docs"
            COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/../public/debugger/docs/guide
                                            ${CMAKE_CURRENT_SOURCE_DIR}/docs/guide/debugger
            COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/../public/debugger/docs/img
                                            ${CMAKE_CURRENT_SOURCE_DIR}/docs/img
            )
endif()
