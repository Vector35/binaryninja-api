cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(python-api)

set(PYTHON_PACKAGE_DIR ${PROJECT_SOURCE_DIR}/binaryninja)
file(GLOB PYTHON_SOURCES CONFIGURE_DEPENDS
	${PYTHON_PACKAGE_DIR}/*.py ${PYTHON_PACKAGE_DIR}/*.typed
	${PYTHON_PACKAGE_DIR}/collaboration/*.py ${PYTHON_PACKAGE_DIR}/collaboration/*.typed
)

list(REMOVE_ITEM PYTHON_SOURCES ${PYTHON_PACKAGE_DIR}/_binaryninjacore.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PYTHON_PACKAGE_DIR}/enums.py)

if(NOT ULTIMATE)
	list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/enterprise.py)
	list(FILTER PYTHON_SOURCES EXCLUDE REGEX ".*/collaboration/.*$")
endif()

add_executable(generator
	${PROJECT_SOURCE_DIR}/generator.cpp)
target_link_libraries(generator binaryninjaapi)

set_target_properties(generator PROPERTIES
	CXX_STANDARD 20
	CXX_STANDARD_REQUIRED ON
	BUILD_WITH_INSTALL_RPATH OFF
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

if(BN_INTERNAL_BUILD)
	if(WIN32)
		add_custom_command(TARGET generator PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy ${BN_CORE_OUTPUT_DIR}/binaryninjacore.dll ${PROJECT_BINARY_DIR}/)
	endif()

	generate_python_bindings(
		TARGET_NAME generator_copy
		DISPLAY_NAME "Binary Ninja"
		GENERATOR_TARGET generator
		HEADER_FILE ${PROJECT_SOURCE_DIR}/../binaryninjacore.h
		OUTPUT_DIRECTORY ${BN_RESOURCE_DIR}/python/binaryninja
		CORE_OUTPUT_FILE _binaryninjacore.py
		ENUMS_OUTPUT_FILE enums.py
		PYTHON_SOURCES ${PYTHON_SOURCES}
	)
endif()
