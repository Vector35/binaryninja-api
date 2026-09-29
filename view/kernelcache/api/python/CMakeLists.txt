cmake_minimum_required(VERSION 3.28 FATAL_ERROR)

project(kernelcache-python-api)

include(${PROJECT_SOURCE_DIR}/../../../../cmake/PythonBindings.cmake)

file(GLOB PYTHON_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/*.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/_kernelcachecore.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/kernelcache_enums.py)

if(BN_INTERNAL_BUILD)
    set(PYTHON_OUTPUT_DIRECTORY ${BN_RESOURCE_DIR}/python/binaryninja/kernelcache/)
else()
    set(PYTHON_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins/kernelcache/)
endif()

generate_python_bindings(
        TARGET_NAME kernelcache_generator_copy
        DISPLAY_NAME "Kernel Cache"
        HEADER_FILE ${PROJECT_SOURCE_DIR}/../kernelcachecore.h
        CORE_HEADER ${PROJECT_SOURCE_DIR}/../../../../binaryninjacore.h
        TEMPLATE_FILE ${PROJECT_SOURCE_DIR}/_kernelcachecore_template.py
        OUTPUT_DIRECTORY ${PYTHON_OUTPUT_DIRECTORY}
        CORE_OUTPUT_FILE _kernelcachecore.py
        ENUMS_OUTPUT_FILE kernelcache_enums.py
        PYTHON_SOURCES ${PYTHON_SOURCES}
)
