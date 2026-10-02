cmake_minimum_required(VERSION 3.28 FATAL_ERROR)

project(python-api)

file(GLOB PYTHON_SOURCES CONFIGURE_DEPENDS
	${PROJECT_SOURCE_DIR}/*.py ${PROJECT_SOURCE_DIR}/*.typed
	${PROJECT_SOURCE_DIR}/collaboration/*.py ${PROJECT_SOURCE_DIR}/collaboration/*.typed
)

list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/_binaryninjacore.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/enums.py)

if(NOT ULTIMATE)
	list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/enterprise.py)
	list(FILTER PYTHON_SOURCES EXCLUDE REGEX ".*/collaboration/.*$")
endif()

include(${PROJECT_SOURCE_DIR}/../cmake/PythonBindings.cmake)

if(BN_INTERNAL_BUILD)
	generate_python_bindings(
		TARGET_NAME generator_copy
		DISPLAY_NAME "Binary Ninja"
		HEADER_FILE ${PROJECT_SOURCE_DIR}/../binaryninjacore.h
		TEMPLATE_FILE ${PROJECT_SOURCE_DIR}/_binaryninjacore_template.py
		OUTPUT_DIRECTORY ${BN_RESOURCE_DIR}/python/binaryninja
		CORE_OUTPUT_FILE _binaryninjacore.py
		ENUMS_OUTPUT_FILE enums.py
		PYTHON_SOURCES ${PYTHON_SOURCES}
	)
endif()
