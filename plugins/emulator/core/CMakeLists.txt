cmake_minimum_required(VERSION 3.21 FATAL_ERROR)

project(emulatorcore)

if(NOT BN_INTERNAL_BUILD)
	# BN_API_PATH is resolved by the parent CMakeLists (api/plugins/emulator).
	add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES CONFIGURE_DEPENDS
	*.cpp
	*.h
	)

if(DEMO)
	add_library(emulatorcore STATIC ${SOURCES})
else()
	add_library(emulatorcore SHARED ${SOURCES})
endif()

target_link_libraries(emulatorcore binaryninjaapi)

set_target_properties(emulatorcore PROPERTIES
	CXX_STANDARD 20
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON
)

if(BN_INTERNAL_BUILD)
	set(LIBRARY_OUTPUT_DIRECTORY_PATH "${BN_CORE_PLUGIN_DIR}")
else()
	set(LIBRARY_OUTPUT_DIRECTORY_PATH "${CMAKE_BINARY_DIR}/out/plugins")
endif()

set_target_properties(emulatorcore PROPERTIES
	LIBRARY_OUTPUT_DIRECTORY ${LIBRARY_OUTPUT_DIRECTORY_PATH}
	RUNTIME_OUTPUT_DIRECTORY ${LIBRARY_OUTPUT_DIRECTORY_PATH}
	)

target_compile_definitions(emulatorcore PRIVATE EMULATOR_LIBRARY)
