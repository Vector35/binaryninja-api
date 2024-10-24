cmake_minimum_required(VERSION 3.22 FATAL_ERROR)

project(efi_resolver)

option(DEBUG "DEBUG Mode" ON)

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

file(
    GLOB_RECURSE SOURCE_FILES
    CONFIGURE_DEPENDS # Automatically reconfigure if source files are added/removed.
    ${PROJECT_SOURCE_DIR}/src/*.cpp ${PROJECT_SOURCE_DIR}/include/*.h
)

add_library(efi_resolver SHARED ${SOURCE_FILES})
target_link_libraries(efi_resolver binaryninjaapi)
target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(efi_resolver PRIVATE cxx_std_17 c_std_99)

# Library targets linking against the Binary Ninja API need to be compiled with
# position-independent code on Linux.
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  target_compile_options(efi_resolver PRIVATE "-fPIC")
endif()

# Configure plugin output directory for internal builds, otherwise configure
# plugin installation for public builds.

if(BN_INTERNAL_BUILD)
  set_target_properties(efi_resolver PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
  bn_install_plugin(${PROJECT_NAME})
endif()

