cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(binaryninjaapi CXX C)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(BN_API_BUILD_EXAMPLES "Builds example plugins" OFF)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    if (MSVC)
        message(FATAL_ERROR "Binary Ninja is 64-bit only (try -G \"${CMAKE_GENERATOR} Win64\")")
    else()
        message(FATAL_ERROR "Binary Ninja is 64-bit only")
    endif()
endif()

file(GLOB BN_API_SOURCES CONFIGURE_DEPENDS *.cpp *.h json/json.h json/json-forwards.h)
if(NOT DEMO)
    list(APPEND BN_API_SOURCES json/jsoncpp.cpp)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        set_source_files_properties(json/jsoncpp.cpp PROPERTIES COMPILE_FLAGS /w)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set_source_files_properties(json/jsoncpp.cpp PROPERTIES COMPILE_FLAGS -Wno-everything)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set_source_files_properties(json/jsoncpp.cpp PROPERTIES COMPILE_FLAGS -w)
    endif()
endif()

add_library(binaryninjaapi STATIC ${BN_API_SOURCES})

target_include_directories(binaryninjaapi
    PUBLIC ${PROJECT_SOURCE_DIR})

find_package(BinaryNinjaCore REQUIRED)
target_link_libraries(binaryninjaapi PUBLIC ${BinaryNinjaCore_LIBRARIES})
target_link_directories(binaryninjaapi PUBLIC ${BinaryNinjaCore_LIBRARY_DIRS})
target_compile_definitions(binaryninjaapi PUBLIC ${BinaryNinjaCore_DEFINITIONS})

add_subdirectory(vendor/fmt EXCLUDE_FROM_ALL)
set_target_properties(fmt PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(binaryninjaapi PUBLIC fmt::fmt)

if(APPLE)
    find_library(CORE_SERVICES_LIBRARY NAMES CoreServices)
    target_link_libraries(binaryninjaapi PRIVATE ${CORE_SERVICES_LIBRARY})
endif()

set_target_properties(binaryninjaapi PROPERTIES
    CXX_STANDARD 17
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
            target_link_libraries(binaryninjaui INTERFACE ${BinaryNinjaUI_LIBRARIES})
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
    if(NOT BN_INTERNAL_BUILD)
        # Get API source directory so we can find BinaryNinjaCore
        get_target_property(BN_API_SOURCE_DIR binaryninjaapi SOURCE_DIR)
        message(STATUS "${BN_API_SOURCE_DIR}")
        list(APPEND CMAKE_MODULE_PATH "${BN_API_SOURCE_DIR}/cmake")

        # BinaryNinjaCore has the user plugins dir define that we want
        find_package(BinaryNinjaCore REQUIRED)
        if(WIN32)
            install(TARGETS ${target} RUNTIME
                DESTINATION ${BinaryNinjaCore_USER_PLUGINS_DIR})

            install(FILES $<TARGET_PDB_FILE:${target}>
                DESTINATION ${BinaryNinjaCore_USER_PLUGINS_DIR} OPTIONAL)
        else()
            install(TARGETS ${target} LIBRARY
                DESTINATION ${BinaryNinjaCore_USER_PLUGINS_DIR})
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
                                            ${CMAKE_CURRENT_SOURCE_DIR}/docs/guide
            COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/../public/debugger/docs/img
                                            ${CMAKE_CURRENT_SOURCE_DIR}/docs/img
            )
endif()
