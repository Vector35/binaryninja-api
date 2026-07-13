cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(emulator-python-api)

if(BN_API_PATH)
	include(${BN_API_PATH}/cmake/PythonBindings.cmake)
else()
	include(${CMAKE_SOURCE_DIR}/api/cmake/PythonBindings.cmake)
endif()

file(GLOB PYTHON_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/*.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/_emulatorcore.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/emulator_enums.py)

add_executable(emulator_generator
	${PROJECT_SOURCE_DIR}/generator.cpp)
target_link_libraries(emulator_generator binaryninjaapi)

set_target_properties(emulator_generator PROPERTIES
	CXX_STANDARD 20
	CXX_STANDARD_REQUIRED ON
	BUILD_WITH_INSTALL_RPATH OFF
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

if(BN_INTERNAL_BUILD)
	set(PYTHON_OUTPUT_DIRECTORY ${BN_RESOURCE_DIR}/python/binaryninja/emulator/)
else()
	set(PYTHON_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins/emulator/)
endif()

if(WIN32)
	if (BN_INTERNAL_BUILD)
		add_custom_command(TARGET emulator_generator PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy ${BN_CORE_OUTPUT_DIR}/binaryninjacore.dll ${PROJECT_BINARY_DIR}/)
	else()
		add_custom_command(TARGET emulator_generator PRE_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy ${BN_INSTALL_DIR}/binaryninjacore.dll ${PROJECT_BINARY_DIR}/)
	endif()
endif()

generate_python_bindings(
	TARGET_NAME emulator_generator_copy
	DISPLAY_NAME "Emulator"
	GENERATOR_TARGET emulator_generator
	HEADER_FILE ${PROJECT_SOURCE_DIR}/../ffi.h
	TEMPLATE_FILE ${PROJECT_SOURCE_DIR}/_emulatorcore_template.py
	OUTPUT_DIRECTORY ${PYTHON_OUTPUT_DIRECTORY}
	CORE_OUTPUT_FILE _emulatorcore.py
	ENUMS_OUTPUT_FILE emulator_enums.py
	PYTHON_SOURCES ${PYTHON_SOURCES}
)
