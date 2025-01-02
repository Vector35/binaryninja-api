cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(rust_api)

set(CARGO_API_VERSION 1.83.0)

file(GLOB RUST_API_SOURCES CONFIGURE_DEPENDS
	../binaryninjacore.h
	binaryninjacore-sys/build.rs
	binaryninjacore-sys/Cargo.toml
	binaryninjacore-sys/src/*
	Cargo.toml
	src/*.rs)

if(CMAKE_BUILD_TYPE MATCHES Debug)
	set(CARGO_CHECK_OPTS --workspace)
	# Documentation for both binaryninja and binaryninjacore-sys crates
	set(CARGO_DOC_OPTS --no-deps -p binaryninja -p binaryninjacore-sys)
else()
	set(CARGO_CHECK_OPTS --workspace --release)
	# Documentation for both binaryninja and binaryninjacore-sys crates
	set(CARGO_DOC_OPTS --no-deps --release -p binaryninja -p binaryninjacore-sys)
endif()

if (BN_BUILD_NUMBER)
	set(RUST_DOC_FLAGS "--crate-version ${BN_MAJOR_VERSION}.${BN_MINOR_VERSION}.${BN_BUILD_NUMBER}")
else()
	set(RUST_DOC_FLAGS "")
endif()

# TODO : RUSTDOCFLAGS="--theme binja-dark.css --default-theme=binja-dark"

add_custom_target(rust_api ALL DEPENDS)
add_dependencies(rust_api binaryninjaapi)

add_custom_target(rust_docs ALL DEPENDS ${PROJECT_BINARY_DIR}/target/doc)
add_dependencies(rust_docs binaryninjaapi rust_api)

# Get API source directory so we can find BinaryNinjaCore
get_target_property(BN_API_SOURCE_DIR binaryninjaapi SOURCE_DIR)
message(STATUS "${BN_API_SOURCE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${BN_API_SOURCE_DIR}/cmake")

find_program(RUSTUP_PATH rustup REQUIRED HINTS ~/.cargo/bin)
set(RUSTUP_CHECK_COMMAND ${RUSTUP_PATH} run ${CARGO_API_VERSION} cargo check)
set(RUSTUP_DOC_COMMAND ${RUSTUP_PATH} run ${CARGO_API_VERSION} cargo doc)

add_custom_command(
	TARGET rust_api
	PRE_BUILD
	COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BN_INSTALL_BIN_DIR} ${RUSTUP_CHECK_COMMAND} ${CARGO_CHECK_OPTS}
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
	DEPENDS ${RUST_API_SOURCES}
)

add_custom_command(
	OUTPUT ${PROJECT_BINARY_DIR}/target/doc
	COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BN_INSTALL_BIN_DIR} RUSTDOCFLAGS=${RUST_DOC_FLAGS} ${RUSTUP_DOC_COMMAND} ${CARGO_DOC_OPTS}
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
	DEPENDS ${RUST_API_SOURCES}
)