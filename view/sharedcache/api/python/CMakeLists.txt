cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(sharedcache-python-api)

include(${PROJECT_SOURCE_DIR}/../../../../cmake/PythonBindings.cmake)

file(GLOB PYTHON_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/*.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/_sharedcachecore.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/sharedcache_enums.py)

if(BN_INTERNAL_BUILD)
    set(PYTHON_OUTPUT_DIRECTORY ${BN_RESOURCE_DIR}/python/binaryninja/sharedcache/)
else()
    set(PYTHON_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins/sharedcache/)
endif()

generate_python_bindings(
        TARGET_NAME sharedcache_generator_copy
        DISPLAY_NAME "Shared Cache"
        HEADER_FILE ${PROJECT_SOURCE_DIR}/../sharedcachecore.h
        CORE_HEADER ${PROJECT_SOURCE_DIR}/../../../../binaryninjacore.h
        TEMPLATE_FILE ${PROJECT_SOURCE_DIR}/_sharedcachecore_template.py
        OUTPUT_DIRECTORY ${PYTHON_OUTPUT_DIRECTORY}
        CORE_OUTPUT_FILE _sharedcachecore.py
        ENUMS_OUTPUT_FILE sharedcache_enums.py
        PYTHON_SOURCES ${PYTHON_SOURCES}
)
