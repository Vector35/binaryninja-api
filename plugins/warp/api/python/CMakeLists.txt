cmake_minimum_required(VERSION 3.28 FATAL_ERROR)

project(warp-python-api)

include(${PROJECT_SOURCE_DIR}/../../../../cmake/PythonBindings.cmake)

file(GLOB PYTHON_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/*.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/_warpcore.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/warp_enums.py)

add_executable(warp_generator
        ${PROJECT_SOURCE_DIR}/generator.cpp)
target_link_libraries(warp_generator binaryninjaapi)
target_include_directories(warp_generator PUBLIC {PROJECT_SOURCE_DIR}/../../api)

set_target_properties(warp_generator PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        BUILD_WITH_INSTALL_RPATH OFF
        RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

if(BN_INTERNAL_BUILD)
    set(PYTHON_OUTPUT_DIRECTORY ${BN_RESOURCE_DIR}/python/binaryninja/warp/)
else()
    set(PYTHON_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins/warp/)
endif()

if(WIN32)
    if (BN_INTERNAL_BUILD)
        add_custom_command(TARGET warp_generator PRE_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy ${BN_CORE_OUTPUT_DIR}/binaryninjacore.dll ${PROJECT_BINARY_DIR}/)
    else()
        add_custom_command(TARGET warp_generator PRE_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy ${BN_INSTALL_DIR}/binaryninjacore.dll ${PROJECT_BINARY_DIR}/)
    endif()
endif()

generate_python_bindings(
        TARGET_NAME warp_generator_copy
        DISPLAY_NAME "WARP"
        GENERATOR_TARGET warp_generator
        HEADER_FILE ${PROJECT_SOURCE_DIR}/../warpcore.h
        TEMPLATE_FILE ${PROJECT_SOURCE_DIR}/_warpcore_template.py
        OUTPUT_DIRECTORY ${PYTHON_OUTPUT_DIRECTORY}
        CORE_OUTPUT_FILE _warpcore.py
        ENUMS_OUTPUT_FILE warp_enums.py
        PYTHON_SOURCES ${PYTHON_SOURCES}
)
