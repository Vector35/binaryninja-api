cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(python-api)

file(GLOB PYTHON_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/*.py ${PROJECT_SOURCE_DIR}/*.typed)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/_binaryninjacore.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/enums.py)

if(NOT ENTERPRISE)
	list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/enterprise.py)
endif()

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

	set(PYTHON_OUTPUT_DIRECTORY ${BN_RESOURCE_DIR}/python/binaryninja)
	foreach(SOURCE ${PYTHON_SOURCES})
		string(REPLACE ${PROJECT_SOURCE_DIR} ${PYTHON_OUTPUT_DIRECTORY} OUTPUT_SOURCE ${SOURCE})
		list(APPEND OUTPUT_PYTHON_SOURCES ${OUTPUT_SOURCE})
	endforeach()
	list(APPEND OUTPUT_PYTHON_SOURCES
		${PYTHON_OUTPUT_DIRECTORY}/_binaryninjacore.py
		${PYTHON_OUTPUT_DIRECTORY}/enums.py
	)

	add_custom_command(
		OUTPUT ${PROJECT_SOURCE_DIR}/_binaryninjacore.py ${PROJECT_SOURCE_DIR}/enums.py
		DEPENDS ${PROJECT_SOURCE_DIR}/../binaryninjacore.h generator
		COMMENT "Generating _binaryninjacore.py"
		COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=detect_leaks=0
			$<TARGET_FILE:generator>
			${PROJECT_SOURCE_DIR}/../binaryninjacore.h
			${PROJECT_SOURCE_DIR}/_binaryninjacore.py
			${PROJECT_SOURCE_DIR}/enums.py
	)

	add_custom_command(
		OUTPUT ${OUTPUT_PYTHON_SOURCES}
		DEPENDS ${PYTHON_SOURCES} ${PROJECT_SOURCE_DIR}/_binaryninjacore.py ${PROJECT_SOURCE_DIR}/enums.py
		COMMENT "Copying API Python sources"
		COMMAND ${CMAKE_COMMAND} -E make_directory ${PYTHON_OUTPUT_DIRECTORY}/
		COMMAND ${CMAKE_COMMAND} -E copy ${PYTHON_SOURCES} ${PYTHON_OUTPUT_DIRECTORY}/
		COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/_binaryninjacore.py ${PYTHON_OUTPUT_DIRECTORY}/
		COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/enums.py ${PYTHON_OUTPUT_DIRECTORY}/)

	add_custom_target(generator_copy DEPENDS ${OUTPUT_PYTHON_SOURCES})
endif()
