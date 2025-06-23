cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(workflow_objc)


if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
  set(BN_API_PATH $ENV{BN_API_PATH})
  if(NOT BN_API_PATH)
    message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
  endif()
endif()
if(NOT BN_INTERNAL_BUILD)
  set(HEADLESS ON CACHE BOOL "")
  add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

# Binary Ninja plugin ----------------------------------------------------------

set(PLUGIN_SOURCE
  GlobalState.h
  GlobalState.cpp
  MessageHandler.cpp
  MessageHandler.h
  Plugin.cpp
  Workflow.h
  Workflow.cpp)

add_library(workflow_objc SHARED ${PLUGIN_SOURCE})
target_link_libraries(workflow_objc binaryninjaapi)
target_compile_features(workflow_objc PRIVATE cxx_std_17 c_std_99)

# Library targets linking against the Binary Ninja API need to be compiled with
# position-independent code on Linux.
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  target_compile_options(workflow_objc PRIVATE "-fPIC")
endif()

# Configure plugin output directory for internal builds, otherwise configure
# plugin installation for public builds.
if(BN_INTERNAL_BUILD)
  set_target_properties(workflow_objc PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
  bn_install_plugin(workflow_objc)
endif()
