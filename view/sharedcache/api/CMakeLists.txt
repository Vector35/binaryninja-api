cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(sharedcacheapi)
file(GLOB BN_MACHO_API_SOURCES *.cpp *.h)
add_library(sharedcacheapi OBJECT ${BN_MACHO_API_SOURCES})


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

target_compile_definitions(sharedcacheapi PRIVATE ${COMPILE_DEFS})


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

get_recursive_include_dirs(binaryninjaapi INCLUDES)

target_include_directories(sharedcacheapi
        PUBLIC ${PROJECT_SOURCE_DIR} ${INCLUDES})

set_target_properties(sharedcacheapi PROPERTIES
        CXX_STANDARD 17
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/out)

if (NOT DEMO)
        add_subdirectory(python)
endif()