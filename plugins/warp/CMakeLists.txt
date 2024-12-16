cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(warp_ninja)

if(NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    if(NOT BN_API_PATH)
        # If we have not already defined the API source directory try and find it.
        find_path(
                BN_API_PATH
                NAMES binaryninjaapi.h
                # List of paths to search for the clone of the api
                HINTS ../../.. ../../binaryninja/api/ binaryninjaapi binaryninja-api $ENV{BN_API_PATH}
                REQUIRED
        )
    endif()
    set(CARGO_STABLE_VERSION 1.83.0)
    add_subdirectory(${BN_API_PATH} binaryninjaapi)
endif()

file(GLOB_RECURSE PLUGIN_SOURCES CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/Cargo.toml
        ${PROJECT_SOURCE_DIR}/src/*.rs)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(TARGET_DIR ${PROJECT_BINARY_DIR}/target/debug)
    set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target)
else()
    set(TARGET_DIR ${PROJECT_BINARY_DIR}/target/release)
    set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target --release)
endif()

if(FORCE_COLORED_OUTPUT)
    set(CARGO_OPTS ${CARGO_OPTS} --color always)
endif()

# NOTE: --no-default-features is set to disable building artifacts used for testing
# NOTE: the linker is looking in the target dir and linking on it apparently.
set(CARGO_FEATURES "--no-default-features")
set(OUTPUT_FILE_NAME ${CMAKE_SHARED_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX})
set(OUTPUT_PDB_NAME ${CMAKE_SHARED_LIBRARY_PREFIX}${PROJECT_NAME}.pdb)
set(OUTPUT_FILE_PATH ${BN_CORE_PLUGIN_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX})
set(OUTPUT_PDB_PATH ${BN_CORE_PLUGIN_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${PROJECT_NAME}.pdb)

add_custom_target(${PROJECT_NAME} ALL DEPENDS ${OUTPUT_FILE_PATH})
add_dependencies(${PROJECT_NAME} binaryninjaapi)
get_target_property(BN_API_SOURCE_DIR binaryninjaapi SOURCE_DIR)
list(APPEND CMAKE_MODULE_PATH "${BN_API_SOURCE_DIR}/cmake")
find_package(BinaryNinjaCore REQUIRED)

set(BINJA_LIB_DIR ${BN_INSTALL_BIN_DIR})

set_property(TARGET ${PROJECT_NAME} PROPERTY OUTPUT_FILE_PATH ${OUTPUT_FILE_PATH})

# Add the whole api to the depends too
file(GLOB_RECURSE API_SOURCES CONFIGURE_DEPENDS
        ${BN_API_SOURCE_DIR}/binaryninjacore.h
        ${BN_API_SOURCE_DIR}/rust/src/*.rs
        ${BN_API_SOURCE_DIR}/rust/binaryninjacore-sys/src/*.rs)

find_program(RUSTUP_PATH rustup REQUIRED HINTS ~/.cargo/bin)
set(RUSTUP_COMMAND ${RUSTUP_PATH} run ${CARGO_STABLE_VERSION} cargo)

if(APPLE)
    if(UNIVERSAL)
        if(CMAKE_BUILD_TYPE MATCHES Debug)
            set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/debug/${OUTPUT_FILE_NAME})
            set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/debug/${OUTPUT_FILE_NAME})
        else()
            set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/release/${OUTPUT_FILE_NAME})
            set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/release/${OUTPUT_FILE_NAME})
        endif()

        add_custom_command(
                OUTPUT ${OUTPUT_FILE_PATH}
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BINJA_LIB_DIR}
                ${RUSTUP_COMMAND} clean --target=aarch64-apple-darwin ${CARGO_OPTS} --package binaryninjacore-sys
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BINJA_LIB_DIR}
                ${RUSTUP_COMMAND} clean --target=x86_64-apple-darwin ${CARGO_OPTS} --package binaryninjacore-sys
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BINJA_LIB_DIR}
                ${RUSTUP_COMMAND} build --target=aarch64-apple-darwin ${CARGO_OPTS} ${CARGO_FEATURES}
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BINJA_LIB_DIR}
                ${RUSTUP_COMMAND} build --target=x86_64-apple-darwin ${CARGO_OPTS} ${CARGO_FEATURES}
                COMMAND lipo -create ${AARCH64_LIB_PATH} ${X86_64_LIB_PATH} -output ${OUTPUT_FILE_PATH}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES}
        )
    else()
        if(CMAKE_BUILD_TYPE MATCHES Debug)
            set(LIB_PATH ${PROJECT_BINARY_DIR}/target/debug/${OUTPUT_FILE_NAME})
        else()
            set(LIB_PATH ${PROJECT_BINARY_DIR}/target/release/${OUTPUT_FILE_NAME})
        endif()

        add_custom_command(
                OUTPUT ${OUTPUT_FILE_PATH}
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BINJA_LIB_DIR}
                ${RUSTUP_COMMAND} clean ${CARGO_OPTS} --package binaryninjacore-sys
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BINJA_LIB_DIR}
                ${RUSTUP_COMMAND} build ${CARGO_OPTS} ${CARGO_FEATURES}
                COMMAND ${CMAKE_COMMAND} -E copy ${LIB_PATH} ${OUTPUT_FILE_PATH}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES}
        )
    endif()
elseif(WIN32)
    add_custom_command(
            OUTPUT ${OUTPUT_FILE_PATH}
            COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BINJA_LIB_DIR} ${RUSTUP_COMMAND} clean ${CARGO_OPTS} --package binaryninjacore-sys
            COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BINJA_LIB_DIR} ${RUSTUP_COMMAND} build ${CARGO_OPTS} ${CARGO_FEATURES}
            COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_DIR}/${OUTPUT_FILE_NAME} ${OUTPUT_FILE_PATH}
            COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_DIR}/${OUTPUT_PDB_NAME} ${OUTPUT_PDB_PATH}
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES}
    )
else()
    add_custom_command(
            OUTPUT ${OUTPUT_FILE_PATH}
            COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BINJA_LIB_DIR} ${RUSTUP_COMMAND} clean ${CARGO_OPTS} --package binaryninjacore-sys
            COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BINJA_LIB_DIR} ${RUSTUP_COMMAND} build ${CARGO_OPTS} ${CARGO_FEATURES}
            COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_DIR}/${OUTPUT_FILE_NAME} ${OUTPUT_FILE_PATH}
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES}
    )
endif()
