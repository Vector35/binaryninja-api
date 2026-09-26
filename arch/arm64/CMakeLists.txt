cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(arch_arm64 CXX)

file(GLOB SOURCES CONFIGURE_DEPENDS
	*.cpp
	*.h)

if(DEMO)
	add_library(${PROJECT_NAME} STATIC ${SOURCES})
else()
	add_library(${PROJECT_NAME} SHARED ${SOURCES})
endif()


target_include_directories(${PROJECT_NAME}
	PRIVATE ${PROJECT_SOURCE_DIR})

if((NOT BN_API_BUILD_EXAMPLES) AND (NOT BN_INTERNAL_BUILD))
	add_subdirectory(${PROJECT_SOURCE_DIR}/../.. ${PROJECT_BINARY_DIR}/api)
	target_link_libraries(${PROJECT_NAME} binaryninjaapi)
else()
	if(WIN32)
		target_link_directories(${PROJECT_NAME}
			PRIVATE ${BN_INSTALL_DIR})
		target_link_libraries(${PROJECT_NAME} binaryninjaapi binaryninjacore)
	else()
		target_link_libraries(${PROJECT_NAME} binaryninjaapi)
	endif()
endif()

if(NOT BN_INTERNAL_BUILD)
	get_target_property(BN_API_SOURCE_DIR binaryninjaapi SOURCE_DIR)
	list(APPEND CMAKE_MODULE_PATH "${BN_API_SOURCE_DIR}/cmake")
	include(RustBuild)
endif()

# Build exarmo, the AArch64 disassembler, from crates.io through the arm64-exarmo crate in this
# directory. Its build script copies the headers of the exarmo it links into the Rust target
# directory, where the plugin includes them from.
if(DEMO)
	bn_get_rust_target_dir(exarmo_aarch64 EXARMO_TARGET_DIR)
else()
	bn_get_rust_target_dir(exarmo_aarch64 EXARMO_TARGET_DIR STANDALONE)
endif()
set(EXARMO_INCLUDE_DIR ${EXARMO_TARGET_DIR}/arm64-exarmo/include)
set(EXARMO_HEADERS
	${EXARMO_INCLUDE_DIR}/exarmo/aarch64.h
	${EXARMO_INCLUDE_DIR}/exarmo/aarch64_generated.h)
target_include_directories(${PROJECT_NAME} PRIVATE ${EXARMO_INCLUDE_DIR})

if(DEMO)
	# arch_arm64 is linked into the core here, so exarmo goes through the umbrella
	# that holds one copy of the Rust runtime for that binary.
	bn_add_rust_crate(
		TARGET exarmo_aarch64
		CRATE arm64-exarmo
		OUTPUT_TYPE STATIC
		OUTPUT_DIR ${CMAKE_BINARY_DIR}
		GROUP plugins
		EXTRA_SOURCES ${PROJECT_SOURCE_DIR}/Cargo.lock
		BYPRODUCTS ${EXARMO_HEADERS})
else()
	bn_add_rust_crate(
		TARGET exarmo_aarch64
		CRATE arm64-exarmo
		OUTPUT_TYPE STATIC
		STANDALONE
		OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
		EXTRA_SOURCES ${PROJECT_SOURCE_DIR}/Cargo.lock
		BYPRODUCTS ${EXARMO_HEADERS})

	get_target_property(EXARMO_LIBRARY exarmo_aarch64 OUTPUT_FILE_PATH)
	add_library(exarmo_aarch64_capi STATIC IMPORTED GLOBAL)
	set_target_properties(exarmo_aarch64_capi PROPERTIES IMPORTED_LOCATION ${EXARMO_LIBRARY})
	add_dependencies(exarmo_aarch64_capi exarmo_aarch64)

	bn_rust_native_static_libs(EXARMO_NATIVE_LIBS)
	set_property(TARGET exarmo_aarch64_capi APPEND PROPERTY
		INTERFACE_LINK_LIBRARIES ${EXARMO_NATIVE_LIBS})

	target_link_libraries(${PROJECT_NAME} exarmo_aarch64_capi)
endif()

# Build exarmo first, since the plugin's sources include the headers its build script copies.
add_dependencies(${PROJECT_NAME} exarmo_aarch64)

# Keep the symbols of the static libraries linked in, exarmo and Rust's std among them, from being
# exported alongside the plugin's own.
if(UNIX AND NOT APPLE)
	target_link_options(${PROJECT_NAME} PRIVATE "LINKER:--exclude-libs,ALL")
endif()

IF(DEFINED ENV{ARM64_WARNINGS})
    MESSAGE(STATUS "ARM64 WARNINGS ON")
	target_compile_options(${PROJECT_NAME} PRIVATE -Wall)
ELSE()
    MESSAGE(STATUS "ARM64 WARNINGS OFF")
ENDIF()

set_target_properties(${PROJECT_NAME} PROPERTIES
	CXX_STANDARD 20
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(${PROJECT_NAME})
	set_target_properties(${PROJECT_NAME} PROPERTIES
	LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
	RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
	bn_install_plugin(${PROJECT_NAME})
endif()
