cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(sharedcacheapi)
file(GLOB BN_MACHO_API_SOURCES *.cpp *.h)
add_library(sharedcacheapi OBJECT ${BN_MACHO_API_SOURCES})

if (VIEW_NAME)
        target_compile_definitions(sharedcacheapi PRIVATE VIEW_NAME="${VIEW_NAME}")
else()
        error("VIEW_NAME must be defined")
endif()

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