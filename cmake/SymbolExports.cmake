include_guard(GLOBAL)

# Export only the symbols matching PATTERNS, which may use * wildcards. Windows DLLs already export
# only __declspec(dllexport) symbols, and static libraries export nothing.
function(bn_target_exports TARGET)
	cmake_parse_arguments(PARSE_ARGV 1 ARG "" "" "PATTERNS")
	if(NOT ARG_PATTERNS)
		message(FATAL_ERROR "bn_target_exports: PATTERNS is required")
	endif()

	get_target_property(type ${TARGET} TYPE)
	if(NOT UNIX OR type STREQUAL "STATIC_LIBRARY")
		return()
	endif()

	if(APPLE)
		list(TRANSFORM ARG_PATTERNS PREPEND "_")
		list(JOIN ARG_PATTERNS "\n" contents)
		set(exports_file "${CMAKE_CURRENT_BINARY_DIR}/${TARGET}.exports")
		file(CONFIGURE OUTPUT "${exports_file}" CONTENT "${contents}\n")
		target_link_options(${TARGET} PRIVATE "LINKER:-exported_symbols_list,${exports_file}")
	else()
		list(JOIN ARG_PATTERNS ";\n\t\t" contents)
		set(exports_file "${CMAKE_CURRENT_BINARY_DIR}/${TARGET}.version")
		file(CONFIGURE OUTPUT "${exports_file}" CONTENT "{\n\tglobal:\n\t\t${contents};\n\tlocal: *;\n};\n")
		target_link_options(${TARGET} PRIVATE "LINKER:--version-script=${exports_file}")
	endif()

	set_property(TARGET ${TARGET} APPEND PROPERTY LINK_DEPENDS "${exports_file}")
endfunction()
