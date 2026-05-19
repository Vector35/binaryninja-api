cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

file(GLOB BN_BASE_SOURCES CONFIGURE_DEPENDS *.cpp *.h unicode/*.h unicode/*.cpp)

add_library(binaryninjabase OBJECT ${BN_BASE_SOURCES})
set_target_properties(binaryninjabase PROPERTIES LINKER_LANGUAGE CXX)

get_filename_component(BN_API_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
target_include_directories(binaryninjabase PUBLIC ${BN_API_DIR})

set_target_properties(binaryninjabase PROPERTIES
    CXX_STANDARD 20
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON)

if(BN_REF_COUNT_DEBUG)
    target_compile_definitions(binaryninjabase PUBLIC BN_REF_COUNT_DEBUG)
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug OR CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
    target_compile_definitions(binaryninjabase PRIVATE BN_ENABLE_LOG_TRACE)
endif()
