# Try to find compatible Rust toolchain
# Once done this will define
#  RUST_FOUND - If a compatible toolchain was found
#  RUST_CARGO_DIR - The path to the cargo executable
#  RUST_CARGO - The path to the cargo executable
#  RUST_VERSION - The toolchain version

set(PATH_HINTS "$ENV{USERPROFILE}" "${HOME}")
if(NOT RUST_CARGO_DIR)
    set(RUST_CARGO_DIR "${USER_HOME}/.cargo")
elseif()
    message(STATUS "Using supplied rust cargo directory: ${RUST_CARGO_DIR}")
endif()
find_program(RUST_CARGO cargo HINTS ${RUST_CARGO_DIR} PATH_SUFFIXES "bin")

set(RUST_FOUND FALSE CACHE INTERNAL "")

if(RUST_CARGO)
    set(RUST_FOUND TRUE CACHE INTERNAL "")
    execute_process(COMMAND ${RUST_CARGO} --version OUTPUT_VARIABLE RUST_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX REPLACE "cargo ([^ ]+) .*" "\\1" RUST_VERSION "${RUST_VERSION}")
endif()

if(NOT RUST_FOUND)
    message(FATAL_ERROR "Could NOT find Rust toolchain. Please configure with -RUST_CARGO_DIR=<path to cargo directory> or set the RUST_CARGO_DIR environment variable.")
endif()

message(STATUS "Found Rust: ${RUST_CARGO_DIR} (${RUST_VERSION})")