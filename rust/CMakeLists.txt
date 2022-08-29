cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(rust_api)

set(CARGO_API_VERSION stable-2022-04-07)

file(GLOB RUST_API_SOURCES
	../binaryninjacore.h
	binaryninjacore-sys/build.rs
	binaryninjacore-sys/Cargo.toml
	binaryninjacore-sys/src/*
	Cargo.toml
	src/*.rs)

if(CMAKE_BUILD_TYPE MATCHES Debug)
	set(CARGO_OPTS --workspace)
else()
	set(CARGO_OPTS --workspace --release)
endif()

add_custom_target(rust_api ALL DEPENDS)
add_dependencies(rust_api binaryninjaapi)

# Get API source directory so we can find BinaryNinjaCore
get_target_property(BN_API_SOURCE_DIR binaryninjaapi SOURCE_DIR)
message(STATUS "${BN_API_SOURCE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${BN_API_SOURCE_DIR}/cmake")

find_program(RUSTUP_PATH rustup REQUIRED HINTS ~/.cargo/bin)
set(RUSTUP_COMMAND ${RUSTUP_PATH} run ${CARGO_API_VERSION} cargo check)

if(APPLE)
	if(UNIVERSAL)
		if(CMAKE_BUILD_TYPE MATCHES Debug)
			set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/debug/${OUTPUT_FILE})
			set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/debug/${OUTPUT_FILE})
		else()
			set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/release/${OUTPUT_FILE})
			set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/release/${OUTPUT_FILE})
		endif()

		add_custom_command(
      TARGET rust_api
      PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E env
				MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BN_INSTALL_BIN_DIR}
				${RUSTUP_COMMAND} --target=aarch64-apple-darwin ${CARGO_OPTS}
			COMMAND ${CMAKE_COMMAND} -E env
				MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BN_INSTALL_BIN_DIR}
				${RUSTUP_COMMAND} --target=x86_64-apple-darwin ${CARGO_OPTS}
			WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
			DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
	else()
		add_custom_command(
      TARGET rust_api
      PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E env
				MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BN_INSTALL_BIN_DIR} ${RUSTUP_COMMAND} ${CARGO_OPTS}
			WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
			DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
	endif()
elseif(WIN32)
	add_custom_command(
    TARGET rust_api
    PRE_BUILD
		COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BN_INSTALL_BIN_DIR} ${RUSTUP_COMMAND} ${CARGO_OPTS}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
else()
	add_custom_command(
    TARGET rust_api
    PRE_BUILD
		COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BN_INSTALL_BIN_DIR} ${RUSTUP_COMMAND} ${CARGO_OPTS}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
endif()


if(BN_API_BUILD_EXAMPLES)
    add_subdirectory(examples/basic_script)
endif()
