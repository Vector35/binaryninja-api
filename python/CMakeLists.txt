cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(python-api)

file(GLOB PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/*.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/_binaryninjacore.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/enums.py)

add_executable(generator
	${PROJECT_SOURCE_DIR}/generator.cpp)
target_link_libraries(generator binaryninjaapi)

set_target_properties(generator PROPERTIES
    CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
	BUILD_WITH_INSTALL_RPATH OFF
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

if(BN_INTERNAL_BUILD)
	if(WIN32)
		add_custom_command(TARGET generator PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy ${BN_CORE_OUTPUT_DIR}/binaryninjacore.dll ${PROJECT_BINARY_DIR}/)
	endif()

	option(LICENSE_FILE "Path to license file, for compiling")
	set(LICENSE "")
	if(LICENSE_FILE)
		file(READ ${LICENSE_FILE} LICENSE_CONTS)
		message(STATUS "Using licence for build: ${LICENSE_FILE}")
		# Encode for passing through the command-line
		string(REPLACE "\n" "" LICENSE_CONTS "${LICENSE_CONTS}")
		string(REPLACE "\"" "\\\"" LICENSE_CONTS "${LICENSE_CONTS}")
		string(REPLACE "{" "\\{" LICENSE_CONTS "${LICENSE_CONTS}")
		string(REPLACE "}" "\\}" LICENSE_CONTS "${LICENSE_CONTS}")
		set(LICENSE "BN_LICENSE=${LICENSE_CONTS}")
	endif()

	add_custom_target(generator_copy ALL
		BYPRODUCTS ${PROJECT_SOURCE_DIR}/_binaryninjacore.py ${PROJECT_SOURCE_DIR}/enums.py
		DEPENDS ${PYTHON_SOURCES} ${PROJECT_SOURCE_DIR}/../binaryninjacore.h $<TARGET_FILE:generator>
		COMMAND ${CMAKE_COMMAND} -E echo "Copying Python Sources"
		COMMAND ${CMAKE_COMMAND} -E make_directory ${BN_RESOURCE_DIR}/python/binaryninja/
		COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=detect_leaks=0 ${LICENSE} $<TARGET_FILE:generator> ${PROJECT_SOURCE_DIR}/../binaryninjacore.h ${PROJECT_SOURCE_DIR}/_binaryninjacore.py ${PROJECT_SOURCE_DIR}/enums.py
		COMMAND ${CMAKE_COMMAND} -E copy ${PYTHON_SOURCES} ${BN_RESOURCE_DIR}/python/binaryninja/
		COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/_binaryninjacore.py ${BN_RESOURCE_DIR}/python/binaryninja/
		COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/enums.py ${BN_RESOURCE_DIR}/python/binaryninja/
		COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/enum ${BN_RESOURCE_DIR}/python/binaryninja/enum/)
endif()
