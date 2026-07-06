if(NOT DEFINED BINARY_PATH)
    message(FATAL_ERROR "BINARY_PATH is required")
endif()

if(NOT DEFINED RPATH_KIND)
    message(FATAL_ERROR "RPATH_KIND is required")
endif()

if(RPATH_KIND STREQUAL "plugin")
    set(BN_ELF_RPATH "$ORIGIN/..")
elseif(RPATH_KIND STREQUAL "plugin-with-local-deps")
    set(BN_ELF_RPATH "$ORIGIN:$ORIGIN/..")
else()
    message(FATAL_ERROR "Unsupported RPATH_KIND: ${RPATH_KIND}")
endif()

find_program(PATCHELF_EXECUTABLE patchelf REQUIRED)
execute_process(
    COMMAND "${PATCHELF_EXECUTABLE}" --set-rpath "${BN_ELF_RPATH}" "${BINARY_PATH}"
    RESULT_VARIABLE PATCHELF_RESULT
    OUTPUT_VARIABLE PATCHELF_OUTPUT
    ERROR_VARIABLE PATCHELF_ERROR)

if(NOT PATCHELF_RESULT EQUAL 0)
    message(FATAL_ERROR "patchelf failed for ${BINARY_PATH}: ${PATCHELF_ERROR}${PATCHELF_OUTPUT}")
endif()
