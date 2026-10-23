cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(emulatorapi)

file(GLOB BN_EMULATOR_API_SOURCES CONFIGURE_DEPENDS *.cpp *.h)
add_library(emulatorapi STATIC ${BN_EMULATOR_API_SOURCES})

target_include_directories(emulatorapi
		PUBLIC ${PROJECT_SOURCE_DIR})

target_link_libraries(emulatorapi PUBLIC emulatorcore)

set_target_properties(emulatorapi PROPERTIES
		CXX_STANDARD 20
		CXX_VISIBILITY_PRESET hidden
		CXX_STANDARD_REQUIRED ON
		VISIBILITY_INLINES_HIDDEN ON
		POSITION_INDEPENDENT_CODE ON
		ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/out)

# Python bindings retarget (load the emulatorcore plugin dylib) is pending; wire the
# subdirectory only once api/python/CMakeLists.txt exists.
if (NOT DEMO AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/python/CMakeLists.txt)
	add_subdirectory(python)
endif()
