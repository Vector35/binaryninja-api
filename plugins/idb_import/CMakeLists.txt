cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(idb_import)

file(GLOB_RECURSE PLUGIN_SOURCES CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/Cargo.toml
        ${PROJECT_SOURCE_DIR}/src/*.rs)

file(GLOB API_SOURCES CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/../../binaryninjacore.h
        ${PROJECT_SOURCE_DIR}/../../rust/binaryninjacore-sys/build.rs
        ${PROJECT_SOURCE_DIR}/../../rust/binaryninjacore-sys/Cargo.toml
        ${PROJECT_SOURCE_DIR}/../../rust/binaryninjacore-sys/src/*
        ${PROJECT_SOURCE_DIR}/../../rust/Cargo.toml
        ${PROJECT_SOURCE_DIR}/../../rust/src/*.rs
        ${PROJECT_SOURCE_DIR}/../../rust/src/*/*.rs)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    if(DEMO)
        set(TARGET_DIR ${PROJECT_BINARY_DIR}/target/dev-demo)
        set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target --profile=dev-demo)
    else()
        set(TARGET_DIR ${PROJECT_BINARY_DIR}/target/debug)
        set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target)
    endif()
else()
    if(DEMO)
        set(TARGET_DIR ${PROJECT_BINARY_DIR}/target/release-demo)
        set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target --profile=release-demo)
    else()
        set(TARGET_DIR ${PROJECT_BINARY_DIR}/target/release)
        set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target --release)
    endif()
endif()

if(DEMO)
    set(CARGO_FEATURES --features demo --manifest-path ${PROJECT_SOURCE_DIR}/demo/Cargo.toml)

    set(OUTPUT_FILE_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}${PROJECT_NAME}_static${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(OUTPUT_PDB_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}${PROJECT_NAME}.pdb)
    set(OUTPUT_FILE_PATH ${CMAKE_BINARY_DIR}/${OUTPUT_FILE_NAME})
    set(OUTPUT_PDB_PATH ${CMAKE_BINARY_DIR}/${OUTPUT_PDB_NAME})

    set(BINJA_LIB_DIR $<TARGET_FILE_DIR:binaryninjacore>)
else()
    set(OUTPUT_FILE_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX})
    set(OUTPUT_PDB_NAME ${CMAKE_SHARED_LIBRARY_PREFIX}${PROJECT_NAME}.pdb)
    set(OUTPUT_FILE_PATH ${BN_CORE_PLUGIN_DIR}/${OUTPUT_FILE_NAME})
    set(OUTPUT_PDB_PATH ${BN_CORE_PLUGIN_DIR}/${OUTPUT_PDB_NAME})

    set(BINJA_LIB_DIR ${BN_CORE_OUTPUT_DIR})
endif()


add_custom_target(${PROJECT_NAME} ALL DEPENDS ${OUTPUT_FILE_PATH})
add_dependencies(${PROJECT_NAME} binaryninjaapi)

get_target_property(BN_API_SOURCE_DIR binaryninjaapi SOURCE_DIR)

set_property(TARGET ${PROJECT_NAME} PROPERTY OUTPUT_FILE_PATH ${OUTPUT_FILE_PATH})

find_program(RUSTUP_PATH rustup REQUIRED HINTS ~/.cargo/bin)
if(CARGO_API_VERSION)
    set(RUSTUP_COMMAND ${RUSTUP_PATH} run ${CARGO_API_VERSION} cargo)
else()
    set(RUSTUP_COMMAND ${RUSTUP_PATH} run ${CARGO_STABLE_VERSION} cargo)
endif()

if(APPLE)
    set(CARGO_DSYM_ENV)
    if(NOT DEMO)
        if(CMAKE_BUILD_TYPE MATCHES Debug)
            set(CARGO_DSYM_ENV CARGO_PROFILE_DEV_SPLIT_DEBUGINFO=packed)
        else()
            set(CARGO_DSYM_ENV CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO=packed)
        endif()
    endif()

    if(UNIVERSAL)
        if(CMAKE_BUILD_TYPE MATCHES Debug)
            if(DEMO)
                set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/dev-demo/${OUTPUT_FILE_NAME})
                set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/dev-demo/${OUTPUT_FILE_NAME})
            else()
                set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/debug/${OUTPUT_FILE_NAME})
                set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/debug/${OUTPUT_FILE_NAME})
            endif()
        else()
            if(DEMO)
                set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/release-demo/${OUTPUT_FILE_NAME})
                set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/release-demo/${OUTPUT_FILE_NAME})
            else()
                set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/release/${OUTPUT_FILE_NAME})
                set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/release/${OUTPUT_FILE_NAME})
            endif()
        endif()

        set(DSYM_BYPRODUCTS)
        set(DSYM_COMMANDS)
        if(NOT DEMO)
            set(DSYM_BYPRODUCTS BYPRODUCTS ${OUTPUT_FILE_PATH}.dSYM)
            set(DSYM_COMMANDS
                COMMAND ${CMAKE_COMMAND} -E rm -rf ${OUTPUT_FILE_PATH}.dSYM
                COMMAND ${CMAKE_COMMAND} -E copy_directory ${AARCH64_LIB_PATH}.dSYM ${OUTPUT_FILE_PATH}.dSYM
                COMMAND lipo -create
                    ${AARCH64_LIB_PATH}.dSYM/Contents/Resources/DWARF/${OUTPUT_FILE_NAME}
                    ${X86_64_LIB_PATH}.dSYM/Contents/Resources/DWARF/${OUTPUT_FILE_NAME}
                    -output ${OUTPUT_FILE_PATH}.dSYM/Contents/Resources/DWARF/${OUTPUT_FILE_NAME})
        endif()

        add_custom_command(
                OUTPUT ${OUTPUT_FILE_PATH}
                ${DSYM_BYPRODUCTS}
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BINJA_LIB_DIR} ${CARGO_DSYM_ENV}
                ${RUSTUP_COMMAND} build --target=aarch64-apple-darwin ${CARGO_OPTS} ${CARGO_FEATURES}
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BINJA_LIB_DIR} ${CARGO_DSYM_ENV}
                ${RUSTUP_COMMAND} build --target=x86_64-apple-darwin ${CARGO_OPTS} ${CARGO_FEATURES}
                COMMAND mkdir -p ${TARGET_DIR}
                COMMAND lipo -create ${AARCH64_LIB_PATH} ${X86_64_LIB_PATH} -output ${OUTPUT_FILE_PATH}
                ${DSYM_COMMANDS}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
    else()
        set(DSYM_BYPRODUCTS)
        set(DSYM_COMMANDS)
        if(NOT DEMO)
            set(DSYM_BYPRODUCTS BYPRODUCTS ${OUTPUT_FILE_PATH}.dSYM)
            set(DSYM_COMMANDS
                COMMAND ${CMAKE_COMMAND} -E rm -rf ${OUTPUT_FILE_PATH}.dSYM
                COMMAND ${CMAKE_COMMAND} -E copy_directory ${TARGET_DIR}/${OUTPUT_FILE_NAME}.dSYM ${OUTPUT_FILE_PATH}.dSYM)
        endif()

        add_custom_command(
                OUTPUT ${OUTPUT_FILE_PATH}
                ${DSYM_BYPRODUCTS}
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BINJA_LIB_DIR} ${CARGO_DSYM_ENV}
                ${RUSTUP_COMMAND} build ${CARGO_OPTS} ${CARGO_FEATURES}
                COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_DIR}/${OUTPUT_FILE_NAME} ${OUTPUT_FILE_PATH}
                ${DSYM_COMMANDS}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
    endif()
elseif(WIN32)
    if(DEMO)
        add_custom_command(
                OUTPUT ${OUTPUT_FILE_PATH}
                COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BINJA_LIB_DIR} ${RUSTUP_COMMAND} build ${CARGO_OPTS} ${CARGO_FEATURES}
                COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_DIR}/${OUTPUT_FILE_NAME} ${OUTPUT_FILE_PATH}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
    else()
        add_custom_command(
                OUTPUT ${OUTPUT_FILE_PATH}
                COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BINJA_LIB_DIR} ${RUSTUP_COMMAND} build ${CARGO_OPTS} ${CARGO_FEATURES}
                COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_DIR}/${OUTPUT_FILE_NAME} ${OUTPUT_FILE_PATH}
                COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_DIR}/${OUTPUT_PDB_NAME} ${OUTPUT_PDB_PATH}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
    endif()
else()
    if(DEMO)
        set(BN_FIX_RPATH_COMMAND ${CMAKE_COMMAND} -E true)
    else()
        set(BN_FIX_RPATH_COMMAND ${CMAKE_COMMAND} -DRPATH_KIND=plugin -DBINARY_PATH=${OUTPUT_FILE_PATH} -P "${BN_API_SOURCE_DIR}/cmake/SetElfRpath.cmake")
    endif()
    add_custom_command(
            OUTPUT ${OUTPUT_FILE_PATH}
            COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BINJA_LIB_DIR} ${RUSTUP_COMMAND} build ${CARGO_OPTS} ${CARGO_FEATURES}
            COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_DIR}/${OUTPUT_FILE_NAME} ${OUTPUT_FILE_PATH}
            COMMAND ${BN_FIX_RPATH_COMMAND}
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
endif()
