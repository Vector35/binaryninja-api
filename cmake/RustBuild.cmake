# Centeralized Rust build functions
#
# This module provides functions to build Rust crates in both standalone (open source)
# and combined (internal) build modes.
#
# Standalone mode:
#   Each crate invokes cargo directly. Used for open-source api/ builds.
#
# Combined mode (BN_INTERNAL_BUILD=ON):
#   Crates register with build groups; cargo is invoked once per group to avoid
#   lock contention. Each crate specifies a GROUP (e.g. "plugins", "internal").
#
#   Groups are created with bn_add_rust_crate_group() and build all SHARED crates
#   registered to that group in a single cargo invocation.
#
#   STATIC crates are not built by groups directly. Instead, they are collected
#   and combined into a single staticlib via bn_add_rust_static_umbrella(). This
#   avoids duplicate symbol errors related to Rust standard library symbols
#   that occur when linking multiple Rust staticlibs into one binary. The umbrella
#   generates a wrapper crate that re-exports all the static crates as dependencies.
#
#   For STATIC crates, a static variant of the Cargo.toml is auto-generated
#   at configure time (cdylib -> rlib, workspace deps resolved, features added).
#
# Public API:
#   bn_add_rust_crate()          - Register a Rust crate for building
#   bn_add_rust_crate_group()       - Create a group target (combined mode)
#   bn_declare_rust_static_umbrella() - Forward-declare umbrella target before crates register
#   bn_add_rust_static_umbrella()   - Combine static crates into one staticlib
#
# Example:
#   bn_add_rust_crate(
#       TARGET pdb_import_plugin
#       CRATE pdb-import-plugin
#       WORKSPACE ${BN_API_SOURCE_DIR}
#       OUTPUT_TYPE SHARED
#       OUTPUT_DIR ${BN_PLUGIN_OUTPUT_DIR}
#       GROUP plugins
#       DEMO_STATIC              # in DEMO builds, switch to static output
#   )
#   # Later:
#   bn_add_rust_crate_group(plugins WORKSPACE ${BN_API_SOURCE_DIR})
#   bn_add_rust_static_umbrella(rust_static GROUPS plugins
#       OUTPUT_DIR ${CMAKE_BINARY_DIR})

cmake_minimum_required(VERSION 3.15)

# Guard against multiple inclusion
if(DEFINED _BN_RUST_BUILD_CMAKE_INCLUDED)
    return()
endif()
set(_BN_RUST_BUILD_CMAKE_INCLUDED TRUE)

# Set default target directory if not already set
# Combined builds use BN_RUST_TARGET_DIR
# Standalone builds use per-target directories (rust-target-${TARGET}/) to avoid lock contention
if(NOT DEFINED BN_RUST_TARGET_DIR)
    set(BN_RUST_TARGET_DIR ${CMAKE_BINARY_DIR}/rust-target)
endif()

# Get the rust target directory for a given target name
# For combined builds (BN_INTERNAL_BUILD), returns BN_RUST_TARGET_DIR
# For standalone builds, returns a per-target directory
function(bn_get_rust_target_dir TARGET_NAME OUT_VAR)
    if(BN_INTERNAL_BUILD)
        set(${OUT_VAR} ${BN_RUST_TARGET_DIR} PARENT_SCOPE)
    else()
        set(${OUT_VAR} ${CMAKE_BINARY_DIR}/rust-target-${TARGET_NAME} PARENT_SCOPE)
    endif()
endfunction()

# Find rustup
find_program(BN_RUSTUP_PATH rustup REQUIRED HINTS ~/.cargo/bin)

# Use CARGO_STABLE_VERSION if set, otherwise default
if(NOT DEFINED CARGO_STABLE_VERSION)
    set(CARGO_STABLE_VERSION 1.91.1)
endif()

set(BN_CARGO_COMMAND ${BN_RUSTUP_PATH} run ${CARGO_STABLE_VERSION} cargo)

# Derive api path from this file's location (api/cmake/RustBuild.cmake -> api/)
get_filename_component(_BN_RUST_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)
get_filename_component(_BN_API_PATH "${_BN_RUST_CMAKE_DIR}" DIRECTORY)
# Python scripts for Rust build support (run at configure time)
set(_BN_GENERATE_STATIC_CRATE_SCRIPT "${_BN_RUST_CMAKE_DIR}/rust/generate_static_crate.py")
set(_BN_GENERATE_STATIC_UMBRELLA_SCRIPT "${_BN_RUST_CMAKE_DIR}/rust/generate_static_umbrella.py")
set(_BN_RESOLVE_PATH_DEPS_SCRIPT "${_BN_RUST_CMAKE_DIR}/rust/resolve_path_deps.py")
find_package(Python3 REQUIRED COMPONENTS Interpreter)
# Reconfigure when the Python scripts change
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${_BN_GENERATE_STATIC_CRATE_SCRIPT}
    ${_BN_GENERATE_STATIC_UMBRELLA_SCRIPT}
    ${_BN_RESOLVE_PATH_DEPS_SCRIPT})


# Get cargo profile info: the command-line argument and output directory name
# OUT_ARG: "" for debug, "--release" for release, "--profile=X" for custom
# OUT_DIR: "debug", "release", or the custom profile name
function(_bn_get_cargo_profile OUT_ARG OUT_DIR)
    if(CMAKE_BUILD_TYPE MATCHES Debug)
        if(DEMO)
            set(${OUT_ARG} "--profile=dev-demo" PARENT_SCOPE)
            set(${OUT_DIR} "dev-demo" PARENT_SCOPE)
        else()
            set(${OUT_ARG} "" PARENT_SCOPE)
            set(${OUT_DIR} "debug" PARENT_SCOPE)
        endif()
    else()
        if(DEMO)
            set(${OUT_ARG} "--profile=release-demo" PARENT_SCOPE)
            set(${OUT_DIR} "release-demo" PARENT_SCOPE)
        else()
            set(${OUT_ARG} "--release" PARENT_SCOPE)
            set(${OUT_DIR} "release" PARENT_SCOPE)
        endif()
    endif()
endfunction()

# Get the cargo options list
# Optional second argument specifies target directory (defaults to BN_RUST_TARGET_DIR)
function(_bn_get_cargo_opts OUT_VAR)
    if(ARGC GREATER 1)
        set(TARGET_DIR_ARG ${ARGV1})
    else()
        set(TARGET_DIR_ARG ${BN_RUST_TARGET_DIR})
    endif()
    _bn_get_cargo_profile(PROFILE_ARG _unused)
    set(OPTS --target-dir=${TARGET_DIR_ARG})
    if(PROFILE_ARG)
        list(APPEND OPTS ${PROFILE_ARG})
    endif()
    if(FORCE_COLORED_OUTPUT)
        list(APPEND OPTS --color always)
    endif()
    set(${OUT_VAR} ${OPTS} PARENT_SCOPE)
endfunction()

# Gather source files for a plugin (for dependency tracking)
function(_bn_gather_plugin_sources OUT_VAR)
    cmake_parse_arguments(ARG "" "SOURCE_DIR" "EXPLICIT_SOURCES" ${ARGN})

    if(ARG_EXPLICIT_SOURCES)
        set(${OUT_VAR} ${ARG_EXPLICIT_SOURCES} PARENT_SCOPE)
        return()
    endif()

    if(NOT ARG_SOURCE_DIR)
        set(ARG_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
        ${ARG_SOURCE_DIR}/Cargo.toml
        ${ARG_SOURCE_DIR}/build.rs
        ${ARG_SOURCE_DIR}/src/*.rs)

    if(TARGET binaryninjaapi)
        get_target_property(BN_API_SOURCE_DIR binaryninjaapi SOURCE_DIR)
        list(APPEND SOURCES ${BN_API_SOURCE_DIR}/binaryninjacore.h)
    endif()

    # Resolve path dependencies and track their sources
    if(EXISTS "${ARG_SOURCE_DIR}/Cargo.toml")
        # Reconfigure when Cargo.toml changes so path dependency resolution reruns
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
            "${ARG_SOURCE_DIR}/Cargo.toml")

        execute_process(
            COMMAND ${Python3_EXECUTABLE} "${_BN_RESOLVE_PATH_DEPS_SCRIPT}"
                --manifest-path "${ARG_SOURCE_DIR}/Cargo.toml"
                --cargo ${BN_CARGO_COMMAND}
            OUTPUT_VARIABLE _PATH_DEPS_OUTPUT
            ERROR_VARIABLE _PATH_DEPS_ERROR
            RESULT_VARIABLE _PATH_DEPS_RESULT
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )

        if(_PATH_DEPS_RESULT EQUAL 0 AND _PATH_DEPS_OUTPUT)
            string(REPLACE "\n" ";" _PATH_DEP_DIRS "${_PATH_DEPS_OUTPUT}")
            foreach(_DEP_DIR ${_PATH_DEP_DIRS})
                file(TO_CMAKE_PATH "${_DEP_DIR}" _DEP_DIR)
                file(GLOB_RECURSE _DEP_SOURCES CONFIGURE_DEPENDS
                    ${_DEP_DIR}/Cargo.toml
                    ${_DEP_DIR}/build.rs
                    ${_DEP_DIR}/src/*.rs)
                list(APPEND SOURCES ${_DEP_SOURCES})
                # Reconfigure if a path dep's Cargo.toml changes (may gain new path deps)
                set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
                    "${_DEP_DIR}/Cargo.toml")
            endforeach()
        endif()
    endif()

    set(${OUT_VAR} ${SOURCES} PARENT_SCOPE)
endfunction()

# Compute the library filename cargo will produce for a given crate name and output type.
# Cargo converts hyphens to underscores in output filenames.
# Sets OUT_FILE_NAME in parent scope.
function(_bn_cargo_output_name OUT_FILE_NAME CRATE_NAME OUTPUT_TYPE)
    string(REPLACE "-" "_" LIB_NAME ${CRATE_NAME})
    if(OUTPUT_TYPE STREQUAL "SHARED")
        set(${OUT_FILE_NAME} ${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX} PARENT_SCOPE)
    else()
        set(${OUT_FILE_NAME} ${CMAKE_STATIC_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX} PARENT_SCOPE)
    endif()
endfunction()

# Compute cargo output paths based on platform
# Sets in parent scope:
#   OUT_CARGO_DIR - directory containing output (non-universal only)
#   OUT_CARGO_FILES - list of cargo output files
function(_bn_compute_cargo_paths TARGET_DIR PROFILE_DIR OUTPUT_FILE_NAME)
    if(APPLE AND UNIVERSAL)
        set(OUT_CARGO_DIR "" PARENT_SCOPE)
        set(AARCH64_PATH ${TARGET_DIR}/aarch64-apple-darwin/${PROFILE_DIR}/${OUTPUT_FILE_NAME})
        set(X86_64_PATH ${TARGET_DIR}/x86_64-apple-darwin/${PROFILE_DIR}/${OUTPUT_FILE_NAME})
        set(OUT_CARGO_FILES ${AARCH64_PATH} ${X86_64_PATH} PARENT_SCOPE)
    else()
        set(OUT_CARGO_DIR ${TARGET_DIR}/${PROFILE_DIR} PARENT_SCOPE)
        set(OUT_CARGO_FILES ${TARGET_DIR}/${PROFILE_DIR}/${OUTPUT_FILE_NAME} PARENT_SCOPE)
    endif()
endfunction()

# Create a custom command for cargo build and/or copy operations
#
# Modes (based on which parameters are provided):
#   1. Group build (CARGO_OPTS + OUTPUT_FILES): cargo build only, outputs are cargo files
#   2. Standalone build (CARGO_OPTS + COPY_TO): cargo build + copy/lipo to final destination
#   3. Copy only (COPY_TO + COPY_FROM_FILES): copy/lipo only, depends on cargo output files
#
function(_bn_create_build_command)
    cmake_parse_arguments(ARG
        ""
        "COPY_TO;OUTPUT_FILE_NAME;OUTPUT_TYPE;TARGET_NAME;WORKSPACE;MANIFEST_PATH;TARGET_DIR"
        "CARGO_OPTS;PACKAGE_ARGS;DEPENDS;OUTPUT_FILES;COPY_FROM_FILES;BYPRODUCTS"
        ${ARGN})

    set(ALL_COMMANDS "")
    set(CMD_OUTPUT "")
    set(CMD_DEPENDS ${ARG_DEPENDS})

    if(ARG_CARGO_OPTS)
        set(CMD_COMMENT "Building ${ARG_TARGET_NAME}")
    else()
        set(CMD_COMMENT "Copying ${ARG_TARGET_NAME}")
    endif()

    # Add manifest path to package args if specified
    set(FULL_PACKAGE_ARGS ${ARG_PACKAGE_ARGS})
    if(ARG_MANIFEST_PATH)
        list(APPEND FULL_PACKAGE_ARGS --manifest-path=${ARG_MANIFEST_PATH})
    endif()

    # Build cargo commands if CARGO_OPTS provided
    if(ARG_CARGO_OPTS)
        # Build env var list - BN_RUST_TARGET_DIR lets build.rs know where to write generated files
        set(CARGO_ENV_VARS BINARYNINJADIR=${BN_INSTALL_BIN_DIR})
        if(ARG_TARGET_DIR)
            list(APPEND CARGO_ENV_VARS BN_RUST_TARGET_DIR=${ARG_TARGET_DIR})
        endif()

        if(APPLE)
            set(ENV_PREFIX ${CMAKE_COMMAND} -E env MACOSX_DEPLOYMENT_TARGET=10.14 ${CARGO_ENV_VARS})
            if(UNIVERSAL)
                list(APPEND ALL_COMMANDS
                    COMMAND ${ENV_PREFIX} ${BN_CARGO_COMMAND} build --target=aarch64-apple-darwin ${ARG_CARGO_OPTS} ${FULL_PACKAGE_ARGS}
                    COMMAND ${ENV_PREFIX} ${BN_CARGO_COMMAND} build --target=x86_64-apple-darwin ${ARG_CARGO_OPTS} ${FULL_PACKAGE_ARGS})
            else()
                list(APPEND ALL_COMMANDS
                    COMMAND ${ENV_PREFIX} ${BN_CARGO_COMMAND} build ${ARG_CARGO_OPTS} ${FULL_PACKAGE_ARGS})
            endif()
        else()
            list(APPEND ALL_COMMANDS
                COMMAND ${CMAKE_COMMAND} -E env ${CARGO_ENV_VARS}
                    ${BN_CARGO_COMMAND} build ${ARG_CARGO_OPTS} ${FULL_PACKAGE_ARGS})
        endif()
    endif()

    # Build copy/lipo commands if COPY_TO provided
    if(ARG_COPY_TO)
        # Get source files - either from COPY_FROM_FILES or OUTPUT_FILES
        if(ARG_COPY_FROM_FILES)
            set(SRC_FILES ${ARG_COPY_FROM_FILES})
            list(APPEND CMD_DEPENDS ${SRC_FILES})
        else()
            set(SRC_FILES ${ARG_OUTPUT_FILES})
        endif()

        if(APPLE AND UNIVERSAL)
            list(GET SRC_FILES 0 AARCH64_PATH)
            list(GET SRC_FILES 1 X86_64_PATH)
            list(APPEND ALL_COMMANDS
                COMMAND lipo -create ${AARCH64_PATH} ${X86_64_PATH} -output ${ARG_COPY_TO})
        else()
            list(GET SRC_FILES 0 SRC_PATH)
            get_filename_component(SRC_DIR ${SRC_PATH} DIRECTORY)
            list(APPEND ALL_COMMANDS
                COMMAND ${CMAKE_COMMAND} -E copy ${SRC_PATH} ${ARG_COPY_TO})
            # Copy PDB on Windows for non-DEMO shared libraries
            if(WIN32 AND ARG_OUTPUT_TYPE STREQUAL "SHARED" AND NOT DEMO)
                get_filename_component(DST_DIR ${ARG_COPY_TO} DIRECTORY)
                set(PDB_NAME ${CMAKE_SHARED_LIBRARY_PREFIX}${ARG_TARGET_NAME}.pdb)
                list(APPEND ALL_COMMANDS
                    COMMAND ${CMAKE_COMMAND} -E copy ${SRC_DIR}/${PDB_NAME} ${DST_DIR}/${PDB_NAME})
            endif()
            # Copy import library on Windows for shared libraries
            # Cargo produces <name>.dll.lib; consumers expect <name>.lib
            if(WIN32 AND ARG_OUTPUT_TYPE STREQUAL "SHARED")
                get_filename_component(_IMPLIB_DST_DIR ${ARG_COPY_TO} DIRECTORY)
                get_filename_component(_IMPLIB_STEM ${ARG_OUTPUT_FILE_NAME} NAME_WE)
                set(_IMPLIB_DST ${_IMPLIB_DST_DIR}/${_IMPLIB_STEM}.lib)
                list(APPEND ALL_COMMANDS
                    COMMAND ${CMAKE_COMMAND} -E copy
                        ${SRC_DIR}/${ARG_OUTPUT_FILE_NAME}.lib ${_IMPLIB_DST})
            endif()
        endif()
        set(CMD_OUTPUT ${ARG_COPY_TO})
        if(_IMPLIB_DST)
            list(APPEND CMD_OUTPUT ${_IMPLIB_DST})
        endif()
    else()
        set(CMD_OUTPUT ${ARG_OUTPUT_FILES})
    endif()

    if(ARG_WORKSPACE)
        set(WORKING_DIR_ARG WORKING_DIRECTORY ${ARG_WORKSPACE})
    else()
        set(WORKING_DIR_ARG "")
    endif()

    if(ARG_BYPRODUCTS)
        set(BYPRODUCTS_ARG BYPRODUCTS ${ARG_BYPRODUCTS})
    else()
        set(BYPRODUCTS_ARG "")
    endif()

    add_custom_command(
        OUTPUT ${CMD_OUTPUT}
        ${ALL_COMMANDS}
        ${WORKING_DIR_ARG}
        DEPENDS ${CMD_DEPENDS}
        ${BYPRODUCTS_ARG}
        COMMENT "${CMD_COMMENT}"
    )
endfunction()

# Generate a static variant of a Cargo.toml
# Uses Python script for TOML manipulation
# Transforms: cdylib -> rlib, workspace deps -> path deps, adds features
function(_bn_generate_static_crate)
    cmake_parse_arguments(ARG "" "SOURCE_CARGO_TOML;OUTPUT_DIR;CRATE_NAME;API_PATH;BN_FEATURE;CRATE_FEATURE" "" ${ARGN})

    execute_process(
        COMMAND ${Python3_EXECUTABLE} "${_BN_GENERATE_STATIC_CRATE_SCRIPT}"
            --source "${ARG_SOURCE_CARGO_TOML}"
            --output-dir "${ARG_OUTPUT_DIR}"
            --crate-name "${ARG_CRATE_NAME}"
            --api-path "${ARG_API_PATH}"
            --bn-feature "${ARG_BN_FEATURE}"
            --crate-feature "${ARG_CRATE_FEATURE}"
        OUTPUT_VARIABLE _OUTPUT
        ERROR_VARIABLE _ERROR
        RESULT_VARIABLE _RESULT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(NOT _RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to generate static crate:\n${_ERROR}")
    endif()

    # The script prints the generated crate path
    set(GENERATED_CRATE_PATH ${_OUTPUT} PARENT_SCOPE)
endfunction()

# Generate an umbrella crate that combines multiple static crates into one staticlib
# This avoids duplicate symbol errors when linking multiple Rust staticlibs into
# a single shared library or executable.
function(_bn_generate_static_umbrella UMBRELLA_NAME)
    cmake_parse_arguments(ARG "" "OUTPUT_DIR" "CRATES" ${ARGN})

    set(CRATE_ARGS "")
    foreach(ENTRY ${ARG_CRATES})
        list(APPEND CRATE_ARGS --crate "${ENTRY}")
    endforeach()

    execute_process(
        COMMAND ${Python3_EXECUTABLE} "${_BN_GENERATE_STATIC_UMBRELLA_SCRIPT}"
            --name "${UMBRELLA_NAME}"
            --output-dir "${ARG_OUTPUT_DIR}"
            ${CRATE_ARGS}
        OUTPUT_VARIABLE _OUTPUT
        ERROR_VARIABLE _ERROR
        RESULT_VARIABLE _RESULT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(NOT _RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to generate static umbrella:\n${_ERROR}")
    endif()

    # Return the umbrella directory
    set(UMBRELLA_DIR ${_OUTPUT} PARENT_SCOPE)
endfunction()

# Create a Rust build group target for shared libraries
function(bn_add_rust_crate_group GROUP_NAME)
    cmake_parse_arguments(ARG "" "WORKSPACE;DEPENDS" "" ${ARGN})

    if(NOT ARG_WORKSPACE)
        message(FATAL_ERROR "bn_add_rust_crate_group: WORKSPACE is required")
    endif()

    get_property(PACKAGES GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP_NAME}_PACKAGES)
    if(NOT PACKAGES)
        # No shared packages - check if we have only static crates
        get_property(STATIC_CRATES GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP_NAME}_STATIC_CRATES)
        if(NOT STATIC_CRATES)
            message(WARNING "bn_add_rust_crate_group: no packages registered for group '${GROUP_NAME}'")
        endif()
        return()
    endif()

    _bn_get_cargo_opts(CARGO_OPTS)

    get_property(OUTPUT_FILES GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP_NAME}_OUTPUT_FILES)
    get_property(SOURCE_FILES GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP_NAME}_SOURCE_FILES)

    set(PACKAGE_ARGS "")
    foreach(PKG ${PACKAGES})
        list(APPEND PACKAGE_ARGS -p ${PKG})
    endforeach()

    _bn_create_build_command(
        TARGET_NAME ${GROUP_NAME}
        OUTPUT_FILES ${OUTPUT_FILES}
        WORKSPACE ${ARG_WORKSPACE}
        CARGO_OPTS ${CARGO_OPTS}
        PACKAGE_ARGS ${PACKAGE_ARGS}
        DEPENDS ${SOURCE_FILES}
        TARGET_DIR ${BN_RUST_TARGET_DIR}
    )

    add_custom_target(${GROUP_NAME} DEPENDS ${OUTPUT_FILES})

    # Collect target dependencies from registered crates and function argument
    get_property(TARGET_DEPS GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP_NAME}_TARGET_DEPENDS)
    if(ARG_DEPENDS)
        list(APPEND TARGET_DEPS ${ARG_DEPENDS})
    endif()
    if(TARGET_DEPS)
        add_dependencies(${GROUP_NAME} ${TARGET_DEPS})
    endif()

    # Connect wrapper targets to this group
    get_property(WRAPPER_TARGETS GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP_NAME}_WRAPPER_TARGETS)
    foreach(TARGET_NAME ${WRAPPER_TARGETS})
        add_dependencies(${TARGET_NAME} ${GROUP_NAME})
    endforeach()
endfunction()

# Declare a static umbrella target so it can be referenced before crates have
# registered. Call bn_add_rust_static_umbrella() later to configure the build.
function(bn_declare_rust_static_umbrella UMBRELLA_TARGET OUTPUT_DIR)
    _bn_cargo_output_name(_FILE_NAME ${UMBRELLA_TARGET} STATIC)
    add_library(${UMBRELLA_TARGET} STATIC IMPORTED GLOBAL)
    set_target_properties(${UMBRELLA_TARGET} PROPERTIES
        IMPORTED_LOCATION ${OUTPUT_DIR}/${_FILE_NAME})
    # Create interface library to carry link dependencies (populated by bn_add_rust_static_umbrella)
    add_library(${UMBRELLA_TARGET}_deps INTERFACE)
endfunction()

# Build a static umbrella crate combining static crates from specified groups
# Creates a single staticlib that includes all static crates to avoid duplicate symbols
function(bn_add_rust_static_umbrella UMBRELLA_TARGET)
    cmake_parse_arguments(ARG "" "OUTPUT_DIR" "GROUPS;DEPENDS" ${ARGN})

    if(NOT ARG_GROUPS)
        message(FATAL_ERROR "bn_add_rust_static_umbrella: GROUPS is required")
    endif()
    if(NOT ARG_OUTPUT_DIR)
        message(FATAL_ERROR "bn_add_rust_static_umbrella: OUTPUT_DIR is required")
    endif()

    set(ALL_CRATES "")
    set(ALL_SOURCE_FILES "")
    set(ALL_TARGET_DEPENDS "")
    set(ALL_BYPRODUCTS "")
    set(ALL_LINK_DEPS "")

    foreach(GROUP ${ARG_GROUPS})
        get_property(CRATES GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP}_STATIC_CRATES)
        get_property(SOURCES GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP}_STATIC_SOURCE_FILES)
        get_property(TARGET_DEPS GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP}_TARGET_DEPENDS)
        get_property(BYPRODUCTS GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP}_BYPRODUCTS)
        get_property(LINK_DEPS GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP}_LINK_DEPS)

        list(APPEND ALL_CRATES ${CRATES})
        list(APPEND ALL_SOURCE_FILES ${SOURCES})
        list(APPEND ALL_TARGET_DEPENDS ${TARGET_DEPS})
        list(APPEND ALL_BYPRODUCTS ${BYPRODUCTS})
        list(APPEND ALL_LINK_DEPS ${LINK_DEPS})
    endforeach()

    list(LENGTH ALL_CRATES CRATE_COUNT)
    if(CRATE_COUNT EQUAL 0)
        message(WARNING "bn_add_rust_static_umbrella: no static crates registered for groups: ${ARG_GROUPS}")
        return()
    endif()

    set(UMBRELLA_GEN_DIR ${CMAKE_BINARY_DIR}/generated-rust)
    _bn_generate_static_umbrella(${UMBRELLA_TARGET}
        OUTPUT_DIR ${UMBRELLA_GEN_DIR}
        CRATES ${ALL_CRATES}
    )

    _bn_get_cargo_profile(_unused PROFILE_DIR)
    _bn_cargo_output_name(CARGO_OUTPUT_NAME ${UMBRELLA_TARGET} STATIC)
    set(OUTPUT_FILE_PATH ${ARG_OUTPUT_DIR}/${CARGO_OUTPUT_NAME})

    _bn_get_cargo_opts(CARGO_OPTS)
    _bn_compute_cargo_paths(${BN_RUST_TARGET_DIR} ${PROFILE_DIR} ${CARGO_OUTPUT_NAME})

    set(UMBRELLA_DIR ${UMBRELLA_GEN_DIR}/${UMBRELLA_TARGET})
    _bn_create_build_command(
        TARGET_NAME ${UMBRELLA_TARGET}
        OUTPUT_FILES ${OUT_CARGO_FILES}
        COPY_TO ${OUTPUT_FILE_PATH}
        OUTPUT_FILE_NAME ${CARGO_OUTPUT_NAME}
        OUTPUT_TYPE STATIC
        WORKSPACE ${UMBRELLA_DIR}
        CARGO_OPTS ${CARGO_OPTS}
        DEPENDS ${ALL_SOURCE_FILES}
            ${UMBRELLA_DIR}/Cargo.toml
            ${UMBRELLA_DIR}/src/lib.rs
        BYPRODUCTS ${ALL_BYPRODUCTS}
        TARGET_DIR ${BN_RUST_TARGET_DIR}
    )

    add_custom_target(${UMBRELLA_TARGET}_build ALL DEPENDS ${OUTPUT_FILE_PATH})

    if(ARG_DEPENDS)
        list(APPEND ALL_TARGET_DEPENDS ${ARG_DEPENDS})
    endif()
    if(ALL_TARGET_DEPENDS)
        add_dependencies(${UMBRELLA_TARGET}_build ${ALL_TARGET_DEPENDS})
    endif()

    if(NOT TARGET ${UMBRELLA_TARGET})
        add_library(${UMBRELLA_TARGET} STATIC IMPORTED GLOBAL)
    endif()
    set_target_properties(${UMBRELLA_TARGET} PROPERTIES IMPORTED_LOCATION ${OUTPUT_FILE_PATH})
    add_dependencies(${UMBRELLA_TARGET} ${UMBRELLA_TARGET}_build)

    # Populate the _deps interface library with link dependencies that must come after rust_static.
    # This is needed because GNU ld requires libraries to appear in dependency order.
    if(ALL_LINK_DEPS)
        target_link_libraries(${UMBRELLA_TARGET}_deps INTERFACE ${ALL_LINK_DEPS})
    endif()

    # Connect static wrapper targets to umbrella
    foreach(GROUP ${ARG_GROUPS})
        get_property(WRAPPER_TARGETS GLOBAL PROPERTY _BN_RUST_GROUP_${GROUP}_WRAPPER_TARGETS)
        foreach(TARGET_NAME ${WRAPPER_TARGETS})
            # Only add dependency for static targets
            get_target_property(OUTPUT_PATH ${TARGET_NAME} OUTPUT_FILE_PATH)
            if(OUTPUT_PATH MATCHES "\\${CMAKE_STATIC_LIBRARY_SUFFIX}$")
                add_dependencies(${TARGET_NAME} ${UMBRELLA_TARGET}_build)
            endif()
        endforeach()
    endforeach()
endfunction()

function(bn_add_rust_crate)
    cmake_parse_arguments(ARG "DEMO_STATIC" "TARGET;CRATE;WORKSPACE;OUTPUT_TYPE;OUTPUT_DIR;GROUP;CARGO_ARGS;CRATE_PATH;BN_FEATURE;CRATE_FEATURE" "SOURCES;EXTRA_SOURCES;DEPENDS;BYPRODUCTS" ${ARGN})

    if(NOT ARG_TARGET)
        message(FATAL_ERROR "bn_add_rust_crate: TARGET is required")
    endif()
    set(TARGET_NAME ${ARG_TARGET})

    if(NOT ARG_CRATE)
        message(FATAL_ERROR "bn_add_rust_crate: CRATE is required")
    endif()

    if(NOT ARG_OUTPUT_TYPE)
        message(FATAL_ERROR "bn_add_rust_crate: OUTPUT_TYPE (SHARED or STATIC) is required")
    endif()
    if(NOT ARG_OUTPUT_DIR)
        message(FATAL_ERROR "bn_add_rust_crate: OUTPUT_DIR is required")
    endif()

    if(NOT ARG_WORKSPACE)
        set(ARG_WORKSPACE ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
    if(NOT ARG_CRATE_PATH)
        set(ARG_CRATE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    # DEMO_STATIC: For DEMO builds only, switch to static output with demo features
    if(ARG_DEMO_STATIC)
        if(DEMO)
            set(ARG_OUTPUT_TYPE STATIC)
            set(ARG_OUTPUT_DIR ${CMAKE_BINARY_DIR})
            if(NOT ARG_BN_FEATURE)
                set(ARG_BN_FEATURE "demo")
            endif()
            if(NOT ARG_CRATE_FEATURE)
                set(ARG_CRATE_FEATURE "demo")
            endif()
        endif()
    endif()

    # OUTPUT_TYPE STATIC: Generate a static variant of the crate
    if(ARG_OUTPUT_TYPE STREQUAL "STATIC")
        if(NOT ARG_BN_FEATURE)
            set(ARG_BN_FEATURE "no_exports")
        endif()
        if(NOT ARG_CRATE_FEATURE)
            set(ARG_CRATE_FEATURE "static")
        endif()
        set(ARG_CRATE "${ARG_CRATE}-static")
        _bn_generate_static_crate(
            SOURCE_CARGO_TOML ${ARG_CRATE_PATH}/Cargo.toml
            OUTPUT_DIR ${CMAKE_BINARY_DIR}/generated-rust
            CRATE_NAME ${ARG_CRATE}
            API_PATH ${_BN_API_PATH}
            BN_FEATURE ${ARG_BN_FEATURE}
            CRATE_FEATURE ${ARG_CRATE_FEATURE}
        )
        set(ARG_CRATE_PATH ${GENERATED_CRATE_PATH})

        set(_GENERATED_FILES ${GENERATED_CRATE_PATH}/Cargo.toml)
        if(EXISTS ${GENERATED_CRATE_PATH}/build.rs)
            list(APPEND _GENERATED_FILES ${GENERATED_CRATE_PATH}/build.rs)
        endif()
    endif()

    _bn_cargo_output_name(OUTPUT_FILE_NAME ${ARG_CRATE} ${ARG_OUTPUT_TYPE})
    set(OUTPUT_FILE_PATH ${ARG_OUTPUT_DIR}/${OUTPUT_FILE_NAME})

    # Compute import library path on Windows for shared libraries
    if(WIN32 AND ARG_OUTPUT_TYPE STREQUAL "SHARED")
        get_filename_component(_OUTPUT_STEM ${OUTPUT_FILE_NAME} NAME_WE)
        set(OUTPUT_LIB_PATH ${ARG_OUTPUT_DIR}/${_OUTPUT_STEM}.lib)
    endif()

    _bn_get_cargo_profile(_unused PROFILE_DIR)
    _bn_gather_plugin_sources(PLUGIN_SOURCES
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
        EXPLICIT_SOURCES ${ARG_SOURCES})

    # Process EXTRA_SOURCES: expand directories into file lists
    if(ARG_EXTRA_SOURCES)
        foreach(_DEP IN LISTS ARG_EXTRA_SOURCES)
            if(IS_DIRECTORY "${_DEP}")
                file(GLOB_RECURSE _DEP_FILES CONFIGURE_DEPENDS "${_DEP}/*")
                list(APPEND PLUGIN_SOURCES ${_DEP_FILES})
            else()
                list(APPEND PLUGIN_SOURCES "${_DEP}")
            endif()
        endforeach()
    endif()

    set(USE_COMBINED_BUILD FALSE)
    if(BN_INTERNAL_BUILD AND NOT ARG_CARGO_ARGS)
        set(USE_COMBINED_BUILD TRUE)
    endif()

    if(USE_COMBINED_BUILD)
        if(NOT ARG_GROUP)
            message(FATAL_ERROR "bn_add_rust_crate: GROUP is required when BN_INTERNAL_BUILD is ON")
        endif()

        if(ARG_OUTPUT_TYPE STREQUAL "STATIC")
            # Static crates get combined into an umbrella crate
            # Register crate info for umbrella generation (name=path or name=path:feature)
            if(ARG_CRATE_FEATURE)
                set(_CRATE_ENTRY "${ARG_CRATE}=${ARG_CRATE_PATH}:${ARG_CRATE_FEATURE}")
            else()
                set(_CRATE_ENTRY "${ARG_CRATE}=${ARG_CRATE_PATH}")
            endif()
            set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_STATIC_CRATES "${_CRATE_ENTRY}")
            set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_STATIC_SOURCE_FILES ${PLUGIN_SOURCES} ${_GENERATED_FILES})
            if(ARG_DEPENDS)
                set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_TARGET_DEPENDS ${ARG_DEPENDS})
                # Convert target names to library paths for linking
                foreach(_DEP ${ARG_DEPENDS})
                    if(WIN32)
                        set(_LINK_EXPR "$<TARGET_PROPERTY:${_DEP},OUTPUT_LIB_PATH>")
                    else()
                        set(_LINK_EXPR "$<TARGET_PROPERTY:${_DEP},OUTPUT_FILE_PATH>")
                    endif()
                    set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_LINK_DEPS "${_LINK_EXPR}")
                endforeach()
            endif()
            if(ARG_BYPRODUCTS)
                set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_BYPRODUCTS ${ARG_BYPRODUCTS})
            endif()

            # Create a dummy target - the actual library comes from the umbrella
            add_custom_target(${TARGET_NAME} ALL)
            set_property(TARGET ${TARGET_NAME} PROPERTY OUTPUT_FILE_PATH ${OUTPUT_FILE_PATH})
            set_property(TARGET ${TARGET_NAME} PROPERTY RUST_TARGET_DIR ${BN_RUST_TARGET_DIR})
            set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_WRAPPER_TARGETS ${TARGET_NAME})
        else()
            # Shared libraries use the normal group build
            _bn_compute_cargo_paths(${BN_RUST_TARGET_DIR} ${PROFILE_DIR} ${OUTPUT_FILE_NAME})

            # Register with the group
            set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_PACKAGES ${ARG_CRATE})
            set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_OUTPUT_FILES ${OUT_CARGO_FILES})
            set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_SOURCE_FILES ${PLUGIN_SOURCES})
            if(ARG_DEPENDS)
                set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_TARGET_DEPENDS ${ARG_DEPENDS})
            endif()

            # Create copy-only command (depends on cargo output files from group)
            _bn_create_build_command(
                COPY_TO ${OUTPUT_FILE_PATH}
                COPY_FROM_FILES ${OUT_CARGO_FILES}
                OUTPUT_FILE_NAME ${OUTPUT_FILE_NAME}
                OUTPUT_TYPE ${ARG_OUTPUT_TYPE}
                TARGET_NAME ${TARGET_NAME}
            )

            add_custom_target(${TARGET_NAME} ALL DEPENDS ${OUTPUT_FILE_PATH})
            set_property(TARGET ${TARGET_NAME} PROPERTY OUTPUT_FILE_PATH ${OUTPUT_FILE_PATH})
            set_property(TARGET ${TARGET_NAME} PROPERTY RUST_TARGET_DIR ${BN_RUST_TARGET_DIR})
            if(OUTPUT_LIB_PATH)
                set_property(TARGET ${TARGET_NAME} PROPERTY OUTPUT_LIB_PATH ${OUTPUT_LIB_PATH})
            endif()
            set_property(GLOBAL APPEND PROPERTY _BN_RUST_GROUP_${ARG_GROUP}_WRAPPER_TARGETS ${TARGET_NAME})
        endif()

    else()
        set(STANDALONE_TARGET_DIR ${CMAKE_BINARY_DIR}/rust-target-${TARGET_NAME})
        _bn_get_cargo_opts(CARGO_OPTS ${STANDALONE_TARGET_DIR})
                _bn_compute_cargo_paths(${STANDALONE_TARGET_DIR} ${PROFILE_DIR} ${OUTPUT_FILE_NAME})

        if(ARG_CARGO_ARGS)
            separate_arguments(FEATURES_LIST NATIVE_COMMAND ${ARG_CARGO_ARGS})
            list(APPEND CARGO_OPTS ${FEATURES_LIST})
        endif()

        _bn_create_build_command(
            COPY_TO ${OUTPUT_FILE_PATH}
            OUTPUT_FILES ${OUT_CARGO_FILES}
            OUTPUT_FILE_NAME ${OUTPUT_FILE_NAME}
            OUTPUT_TYPE ${ARG_OUTPUT_TYPE}
            TARGET_NAME ${TARGET_NAME}
            WORKSPACE ${ARG_WORKSPACE}
            CARGO_OPTS ${CARGO_OPTS}
            PACKAGE_ARGS -p ${ARG_CRATE}
            DEPENDS ${PLUGIN_SOURCES}
            BYPRODUCTS ${ARG_BYPRODUCTS}
            TARGET_DIR ${STANDALONE_TARGET_DIR}
        )

        add_custom_target(${TARGET_NAME} ALL DEPENDS ${OUTPUT_FILE_PATH})
        set_property(TARGET ${TARGET_NAME} PROPERTY OUTPUT_FILE_PATH ${OUTPUT_FILE_PATH})
        set_property(TARGET ${TARGET_NAME} PROPERTY RUST_TARGET_DIR ${STANDALONE_TARGET_DIR})
        if(OUTPUT_LIB_PATH)
            set_property(TARGET ${TARGET_NAME} PROPERTY OUTPUT_LIB_PATH ${OUTPUT_LIB_PATH})
        endif()
        if(ARG_DEPENDS)
            add_dependencies(${TARGET_NAME} ${ARG_DEPENDS})
        endif()
    endif()
endfunction()
