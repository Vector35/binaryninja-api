cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(sharedcacherust)

file(GLOB SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/Cargo.toml ${PROJECT_SOURCE_DIR}/src/*.rs ${PROJECT_SOURCE_DIR}/ffi.h)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(LIB_DIR ${PROJECT_BINARY_DIR}/target/debug)
    set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target)
else()
    set(LIB_DIR ${PROJECT_BINARY_DIR}/target/release)
    set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target --release)
endif()

set(LIB_PATH ${LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})

find_program(RUSTUP_PATH rustup REQUIRED HINTS ~/.cargo/bin)
set(RUSTUP_COMMAND ${RUSTUP_PATH} run ${CARGO_STABLE_VERSION} cargo)

if(APPLE)
    if(UNIVERSAL)
        if(CMAKE_BUILD_TYPE MATCHES Debug)
            set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/debug/${CMAKE_STATIC_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
            set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/debug/${CMAKE_STATIC_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
        else()
            set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/release/${CMAKE_STATIC_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
            set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/release/${CMAKE_STATIC_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
        endif()

        add_custom_command(
                OUTPUT ${LIB_PATH}
                COMMAND ${CMAKE_COMMAND} -E env MACOSX_DEPLOYMENT_TARGET=10.14
                ${RUSTUP_COMMAND} clean --target=aarch64-apple-darwin ${CARGO_OPTS}
                COMMAND ${CMAKE_COMMAND} -E env MACOSX_DEPLOYMENT_TARGET=10.14
                ${RUSTUP_COMMAND} clean --target=x86_64-apple-darwin ${CARGO_OPTS}
                COMMAND ${CMAKE_COMMAND} -E env MACOSX_DEPLOYMENT_TARGET=10.14
                ${RUSTUP_COMMAND} build --target=aarch64-apple-darwin ${CARGO_OPTS}
                COMMAND ${CMAKE_COMMAND} -E env MACOSX_DEPLOYMENT_TARGET=10.14
                ${RUSTUP_COMMAND} build --target=x86_64-apple-darwin ${CARGO_OPTS}
                COMMAND mkdir -p ${LIB_DIR}
                COMMAND lipo -create ${AARCH64_LIB_PATH} ${X86_64_LIB_PATH} -output ${LIB_PATH}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                DEPENDS ${SOURCES})
    else()
        add_custom_command(
                OUTPUT ${LIB_PATH}
                COMMAND ${CMAKE_COMMAND} -E env MACOSX_DEPLOYMENT_TARGET=10.14
                ${RUSTUP_COMMAND} clean ${CARGO_OPTS}
                COMMAND ${CMAKE_COMMAND} -E env MACOSX_DEPLOYMENT_TARGET=10.14
                ${RUSTUP_COMMAND} build ${CARGO_OPTS}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                DEPENDS ${SOURCES})
    endif()
else()
    add_custom_command(
            OUTPUT ${LIB_PATH}
            COMMAND ${RUSTUP_COMMAND} clean ${CARGO_OPTS}
            COMMAND ${RUSTUP_COMMAND} build ${CARGO_OPTS}
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            DEPENDS ${SOURCES})
endif()

add_custom_target(sharedcacherust_target ALL DEPENDS ${LIB_PATH})
add_library(sharedcacherust STATIC IMPORTED GLOBAL)
add_dependencies(sharedcacherust sharedcacherust_target)
set_target_properties(sharedcacherust PROPERTIES IMPORTED_LOCATION ${LIB_PATH})
