# CMake function for generating Python bindings
#
# This function:
# 1. Creates a custom command to generate the core and enums Python modules
# 2. Creates a custom command to copy all files to the output directory
# 3. Creates a custom target that depends on all output files
#
# Usage:
#   generate_python_bindings(
#     TARGET_NAME <target_name>
#     DISPLAY_NAME <display_name>
#     GENERATOR_TARGET <generator_executable_target>
#     HEADER_FILE <path_to_header>
#     [TEMPLATE_FILE <path_to_template>]
#     OUTPUT_DIRECTORY <output_directory>
#     CORE_OUTPUT_FILE <core_output_file>
#     ENUMS_OUTPUT_FILE <enums_output_file>
#     [PYTHON_SOURCES <list_of_python_source_files>]
#   )
#
function(generate_python_bindings)
	set(options)
	set(oneValueArgs TARGET_NAME DISPLAY_NAME GENERATOR_TARGET HEADER_FILE TEMPLATE_FILE OUTPUT_DIRECTORY CORE_OUTPUT_FILE ENUMS_OUTPUT_FILE)
	set(multiValueArgs PYTHON_SOURCES)
	
	cmake_parse_arguments(PARSE_ARGV 0 ARGS "${options}" "${oneValueArgs}" "${multiValueArgs}")
	
	foreach(required_arg TARGET_NAME DISPLAY_NAME GENERATOR_TARGET HEADER_FILE OUTPUT_DIRECTORY CORE_OUTPUT_FILE ENUMS_OUTPUT_FILE)
		if(NOT ARGS_${required_arg})
			message(FATAL_ERROR "${required_arg} is required")
		endif()
	endforeach()
	
	set(CORE_SOURCE_PATH ${PROJECT_SOURCE_DIR}/${ARGS_CORE_OUTPUT_FILE})
	set(ENUMS_SOURCE_PATH ${PROJECT_SOURCE_DIR}/${ARGS_ENUMS_OUTPUT_FILE})
	
	set(GENERATOR_DEPENDS ${ARGS_HEADER_FILE} $<TARGET_FILE:${ARGS_GENERATOR_TARGET}>)
	list(APPEND GENERATOR_DEPENDS ${ARGS_TEMPLATE_FILE})

	add_custom_command(
		OUTPUT ${CORE_SOURCE_PATH} ${ENUMS_SOURCE_PATH}
		DEPENDS ${GENERATOR_DEPENDS}
		COMMENT "Generating ${ARGS_DISPLAY_NAME} Python Sources"
		COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=detect_leaks=0 $<TARGET_FILE:${ARGS_GENERATOR_TARGET}>
			${ARGS_HEADER_FILE}
			${CORE_SOURCE_PATH}
			${ARGS_TEMPLATE_FILE}
			${ENUMS_SOURCE_PATH}
		VERBATIM
	)
	
	set(PYTHON_OUTPUT_FILES)
	foreach(SOURCE_FILE ${ARGS_PYTHON_SOURCES})
		cmake_path(RELATIVE_PATH SOURCE_FILE BASE_DIRECTORY ${PROJECT_SOURCE_DIR} OUTPUT_VARIABLE REL_PATH)
		list(APPEND PYTHON_OUTPUT_FILES ${ARGS_OUTPUT_DIRECTORY}/${REL_PATH})
	endforeach()
	
	list(APPEND PYTHON_OUTPUT_FILES ${ARGS_OUTPUT_DIRECTORY}/${ARGS_CORE_OUTPUT_FILE})
	list(APPEND PYTHON_OUTPUT_FILES ${ARGS_OUTPUT_DIRECTORY}/${ARGS_ENUMS_OUTPUT_FILE})
	
	set(COPY_DEPENDENCIES ${CORE_SOURCE_PATH} ${ENUMS_SOURCE_PATH})
	list(APPEND COPY_DEPENDENCIES ${ARGS_PYTHON_SOURCES})
	
	# Generate a script to copy the generated Python files, preserving their directory structure.
	file(GENERATE OUTPUT ${PROJECT_BINARY_DIR}/copy_python_sources.cmake
		CONTENT "
			foreach(PYTHON_SOURCE ${ARGS_PYTHON_SOURCES})
				cmake_path(RELATIVE_PATH PYTHON_SOURCE BASE_DIRECTORY ${PROJECT_SOURCE_DIR} OUTPUT_VARIABLE OUTPUT_SUBPATH)
				cmake_path(REMOVE_FILENAME OUTPUT_SUBPATH)
				file(COPY $\{PYTHON_SOURCE\} DESTINATION ${ARGS_OUTPUT_DIRECTORY}/$\{OUTPUT_SUBPATH\})
			endforeach()
			"
	)
	
	add_custom_command(
		OUTPUT ${PYTHON_OUTPUT_FILES}
		DEPENDS ${COPY_DEPENDENCIES}
		COMMENT "Copying ${ARGS_DISPLAY_NAME} Python Sources"
		COMMAND ${CMAKE_COMMAND} -E make_directory ${ARGS_OUTPUT_DIRECTORY}
		COMMAND ${CMAKE_COMMAND} -P ${PROJECT_BINARY_DIR}/copy_python_sources.cmake
		COMMAND ${CMAKE_COMMAND} -E copy ${CORE_SOURCE_PATH} ${ARGS_OUTPUT_DIRECTORY}
		COMMAND ${CMAKE_COMMAND} -E copy ${ENUMS_SOURCE_PATH} ${ARGS_OUTPUT_DIRECTORY}
		VERBATIM
	)
	
	# Create target that depends on all output files. SOURCES lists the Python sources
	# so IDEs see them as belonging to a target; without it CLion treats the binding
	# directories as build I/O only and drops them from the project index.
	add_custom_target(${ARGS_TARGET_NAME} ALL
		DEPENDS ${PYTHON_OUTPUT_FILES}
		SOURCES ${ARGS_PYTHON_SOURCES})
endfunction()
