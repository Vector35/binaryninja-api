cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(rust_api)

set(CARGO_API_VERSION 1.91.1)

file(GLOB_RECURSE RUST_API_SOURCES CONFIGURE_DEPENDS
	../binaryninjacore.h
	binaryninjacore-sys/build.rs
	binaryninjacore-sys/Cargo.toml
	binaryninjacore-sys/src/lib.rs
	Cargo.toml
	src/*.rs)

if(CMAKE_BUILD_TYPE MATCHES Debug)
	set(CARGO_CHECK_OPTS --workspace --target-dir=${PROJECT_BINARY_DIR}/target)
	# Documentation for both binaryninja and binaryninjacore-sys crates
	set(CARGO_DOC_OPTS --no-deps -p binaryninja -p binaryninjacore-sys --target-dir=${PROJECT_BINARY_DIR}/target)
else()
	set(CARGO_CHECK_OPTS --workspace --release --target-dir=${PROJECT_BINARY_DIR}/target)
	# Documentation for both binaryninja and binaryninjacore-sys crates
	set(CARGO_DOC_OPTS --no-deps --release -p binaryninja -p binaryninjacore-sys --target-dir=${PROJECT_BINARY_DIR}/target)
endif()

if (BN_BUILD_NUMBER)
	set(RUST_DOC_FLAGS "--crate-version ${BN_MAJOR_VERSION}.${BN_MINOR_VERSION}.${BN_BUILD_NUMBER}")
else()
	set(RUST_DOC_FLAGS "")
endif()

# TODO : RUSTDOCFLAGS="--theme binja-dark.css --default-theme=binja-dark"
add_custom_target(rust_api ALL DEPENDS ${PROJECT_BINARY_DIR}/rust_api.stamp)

add_custom_target(rust_docs ALL DEPENDS ${PROJECT_BINARY_DIR}/target/doc)
add_dependencies(rust_docs binaryninjaapi rust_api)
set_property(TARGET rust_docs APPEND PROPERTY ADDITIONAL_CLEAN_FILES ${PROJECT_BINARY_DIR}/target/doc)

# Get API source directory so we can find BinaryNinjaCore
get_target_property(BN_API_SOURCE_DIR binaryninjaapi SOURCE_DIR)
message(STATUS "${BN_API_SOURCE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${BN_API_SOURCE_DIR}/cmake")

find_program(RUSTUP_PATH rustup REQUIRED HINTS ~/.cargo/bin)
set(RUSTUP_CHECK_COMMAND ${RUSTUP_PATH} run ${CARGO_API_VERSION} cargo check)
set(RUSTUP_DOC_COMMAND ${RUSTUP_PATH} run ${CARGO_API_VERSION} cargo doc)

add_custom_command(
	OUTPUT ${PROJECT_BINARY_DIR}/rust_api.stamp
	COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BN_INSTALL_BIN_DIR} ${RUSTUP_CHECK_COMMAND} ${CARGO_CHECK_OPTS}
	COMMAND ${CMAKE_COMMAND} -E touch ${PROJECT_BINARY_DIR}/rust_api.stamp
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
	DEPENDS ${RUST_API_SOURCES}
	COMMENT "Checking Rust API"
	VERBATIM
)

add_custom_command(
	OUTPUT ${PROJECT_BINARY_DIR}/target/doc
	COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BN_INSTALL_BIN_DIR} RUSTDOCFLAGS=${RUST_DOC_FLAGS} ${RUSTUP_DOC_COMMAND} ${CARGO_DOC_OPTS}
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
	DEPENDS ${RUST_API_SOURCES}
)
