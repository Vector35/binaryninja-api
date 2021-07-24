cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(test_headless)

file(GLOB PLUGIN_SOURCES
	${PROJECT_SOURCE_DIR}/Cargo.toml
	${PROJECT_SOURCE_DIR}/src/*.rs)

file(GLOB API_SOURCES
	${PROJECT_SOURCE_DIR}/../../../binaryninjacore.h
	${PROJECT_SOURCE_DIR}/../../binaryninjacore-sys/build.rs
	${PROJECT_SOURCE_DIR}/../../binaryninjacore-sys/Cargo.toml
	${PROJECT_SOURCE_DIR}/../../binaryninjacore-sys/src/*
	${PROJECT_SOURCE_DIR}/../../Cargo.toml
	${PROJECT_SOURCE_DIR}/../../src/*.rs)

if(CMAKE_BUILD_TYPE MATCHES Debug)
	set(TARGET_DIR ${PROJECT_BINARY_DIR}/target/debug)
	set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target)
else()
	set(TARGET_DIR ${PROJECT_BINARY_DIR}/target/release)
	set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target --release)
endif()

set(OUTPUT_FILE basic_script${CMAKE_EXECUTABLE_SUFFIX})
set(OUTPUT_PATH ${CMAKE_BINARY_DIR}/out/bin/${OUTPUT_FILE})

add_custom_target(test_headless ALL DEPENDS ${OUTPUT_PATH})
add_dependencies(test_headless binaryninjaapi)

find_program(RUSTUP_PATH rustup REQUIRED HINTS ~/.cargo/bin)
set(RUSTUP_COMMAND ${RUSTUP_PATH} run ${CARGO_API_VERSION} cargo build)

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
			OUTPUT ${OUTPUT_PATH}
			COMMAND ${CMAKE_COMMAND} -E env
				MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BN_CORE_OUTPUT_DIR}
				${RUSTUP_COMMAND} --target=aarch64-apple-darwin ${CARGO_OPTS}
			COMMAND ${CMAKE_COMMAND} -E env
				MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BN_CORE_OUTPUT_DIR}
				${RUSTUP_COMMAND} --target=x86_64-apple-darwin ${CARGO_OPTS}
			COMMAND cp ${AARCH64_LIB_PATH} ${OUTPUT_PATH}-aarch
			COMMAND cp ${X86_64_LIB_PATH} ${OUTPUT_PATH}
			WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
			DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
	else()
		if(CMAKE_BUILD_TYPE MATCHES Debug)
			set(LIB_PATH ${PROJECT_BINARY_DIR}/target/debug/${OUTPUT_FILE})
		else()
			set(LIB_PATH ${PROJECT_BINARY_DIR}/target/release/${OUTPUT_FILE})
		endif()

		add_custom_command(
			OUTPUT ${OUTPUT_PATH}
			COMMAND ${CMAKE_COMMAND} -E env
				MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BN_CORE_OUTPUT_DIR}
				${RUSTUP_COMMAND} ${CARGO_OPTS}
			COMMAND cp ${LIB_PATH} ${OUTPUT_PATH}
			WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
			DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
	endif()
elseif(WIN32)
	add_custom_command(
		OUTPUT ${OUTPUT_PATH}
		COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BN_CORE_OUTPUT_DIR} ${RUSTUP_COMMAND} ${CARGO_OPTS}
		COMMAND cp ${TARGET_DIR}/${OUTPUT_FILE} ${OUTPUT_PATH}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
else()
	add_custom_command(
		OUTPUT ${OUTPUT_PATH}
		COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BN_CORE_OUTPUT_DIR} ${RUSTUP_COMMAND} ${CARGO_OPTS}
		COMMAND cp ${TARGET_DIR}/${OUTPUT_FILE} ${OUTPUT_PATH}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
endif()
