cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(defaultarch)

if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${PROJECT_SOURCE_DIR}/.. ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES CONFIGURE_DEPENDS
	*.cpp
	*.h)

if(DEMO)
	add_library(defaultarch STATIC ${SOURCES})
else()
	add_library(defaultarch SHARED ${SOURCES})
endif()

target_include_directories(defaultarch
	PRIVATE ${PROJECT_SOURCE_DIR}
)

if(WIN32)
	target_link_directories(defaultarch
		PRIVATE ${BN_INSTALL_DIR})
	target_link_libraries(defaultarch binaryninjaapi)
else()
	target_link_libraries(defaultarch binaryninjaapi)
endif()

if(UNIX AND NOT APPLE)
	target_link_options(defaultarch PRIVATE "LINKER:--exclude-libs,ALL")
endif()

set_target_properties(defaultarch PROPERTIES
	CXX_STANDARD 20
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(defaultarch)
	set_target_properties(defaultarch PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
