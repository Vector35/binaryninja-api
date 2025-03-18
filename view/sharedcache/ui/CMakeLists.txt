cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(sharedcacheui)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

file(GLOB SOURCES *.cpp *.h)
list(FILTER SOURCES EXCLUDE REGEX moc_.*)
list(FILTER SOURCES EXCLUDE REGEX qrc_.*)

add_library(sharedcacheui SHARED ${SOURCES})

set(COMPILE_DEFS "")

if (HARD_FAIL_MODE)
    set(COMPILE_DEFS "${COMPILE_DEFS} ABORT_FAILURES;")
endif()

if (BN_REF_COUNT_DEBUG)
    set(COMPILE_DEFS "${COMPILE_DEFS} BN_REF_COUNT_DEBUG;")
endif()

if (SLIDEINFO_DEBUG_TAGS)
    set(COMPILE_DEFS "${COMPILE_DEFS} SLIDEINFO_DEBUG_TAGS;")
endif()

if (METADATA_VERSION)
    set(COMPILE_DEFS "${COMPILE_DEFS} METADATA_VERSION=${METADATA_VERSION};")
else()
    message(FATAL_ERROR "No metadata version provided. Fatal.")
endif()

if (VIEW_NAME)
    set(COMPILE_DEFS "${COMPILE_DEFS} VIEW_NAME=\"${VIEW_NAME}\";")
else()
    message(FATAL_ERROR "No view name provided. Fatal.")
endif()

target_compile_definitions(sharedcacheui PRIVATE ${COMPILE_DEFS})


if(BN_INTERNAL_BUILD)
    set_target_properties(sharedcacheui PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
            RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
    set_target_properties(sharedcacheui PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins
            )
    bn_install_plugin(sharedcacheui)
endif()

set_target_properties(sharedcacheui PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        )

function(get_recursive_include_dirs target result)
    # Initialize an empty list to store include directories
    set(include_dirs "")

    # Get the include directories of the current target
    get_target_property(current_target_includes ${target} INTERFACE_INCLUDE_DIRECTORIES)
    if(current_target_includes)
        list(APPEND include_dirs ${current_target_includes})
    endif()

    # Get the libraries that this target links to
    get_target_property(linked_libraries ${target} INTERFACE_LINK_LIBRARIES)
    if(linked_libraries)
        foreach(linked_library IN LISTS linked_libraries)
            # Skip plain library names (non-target libraries)
            if(TARGET ${linked_library})
                # Recursively get include directories from linked libraries
                get_recursive_include_dirs(${linked_library} linked_library_includes)
                list(APPEND include_dirs ${linked_library_includes})
            endif()
        endforeach()
    endif()

    # Set the result to the collected include directories
    set(${result} ${include_dirs} PARENT_SCOPE)
endfunction()

get_recursive_include_dirs(sharedcacheapi INCLUDES)

target_include_directories(sharedcacheui PRIVATE ${INCLUDES})

target_link_libraries(sharedcacheui sharedcacheapi sharedcache binaryninjaui Qt6::Core Qt6::Gui Qt6::Widgets)

