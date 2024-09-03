cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

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

	# Generate script to copy python sources with the correct paths
	file(GENERATE OUTPUT ${PROJECT_BINARY_DIR}/copy_python_sources.cmake
		CONTENT "
			foreach(PYTHON_SOURCE ${PYTHON_SOURCES})
				cmake_path(RELATIVE_PATH PYTHON_SOURCE BASE_DIRECTORY ${PROJECT_SOURCE_DIR} OUTPUT_VARIABLE OUTPUT_SUBPATH)
				cmake_path(REMOVE_FILENAME OUTPUT_SUBPATH)
				file(COPY $\{PYTHON_SOURCE\} DESTINATION ${BN_RESOURCE_DIR}/python/binaryninja/$\{OUTPUT_SUBPATH\})
			endforeach()
			"
	)

	add_custom_target(generator_copy ALL
		BYPRODUCTS ${PROJECT_SOURCE_DIR}/_binaryninjacore.py ${PROJECT_SOURCE_DIR}/enums.py
		DEPENDS ${PYTHON_SOURCES} ${PROJECT_SOURCE_DIR}/../binaryninjacore.h $<TARGET_FILE:generator>
		COMMENT "Copying API Python sources"
		COMMAND ${CMAKE_COMMAND} -E make_directory ${BN_RESOURCE_DIR}/python/binaryninja/
		COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=detect_leaks=0 $<TARGET_FILE:generator> ${PROJECT_SOURCE_DIR}/../binaryninjacore.h ${PROJECT_SOURCE_DIR}/_binaryninjacore.py ${PROJECT_SOURCE_DIR}/enums.py
		COMMAND ${CMAKE_COMMAND} -P ${PROJECT_BINARY_DIR}/copy_python_sources.cmake
		COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/_binaryninjacore.py ${BN_RESOURCE_DIR}/python/binaryninja/
		COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/enums.py ${BN_RESOURCE_DIR}/python/binaryninja/
	)
endif()
