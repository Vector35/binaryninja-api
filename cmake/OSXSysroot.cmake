# Resolve CMAKE_OSX_SYSROOT to an absolute SDK path so every part of the build uses the same macOS SDK.
# Include this before project() in top-level CMakeLists.txt
#
# The SDK can be chosen with -DCMAKE_OSX_SYSROOT=<name or path> or the SDKROOT environment variable,
# and defaults to "macosx". SDK names are remembered so that if the resolved path stops existing
# (Xcode moved, or xcode-select switched), it is resolved again instead of using a stale path.

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
    set(_bn_osx_sysroot "${CMAKE_OSX_SYSROOT}")
    if(NOT _bn_osx_sysroot)
        if(NOT "$ENV{SDKROOT}" STREQUAL "")
            set(_bn_osx_sysroot "$ENV{SDKROOT}")
        else()
            set(_bn_osx_sysroot macosx)
        endif()
    endif()

    if(NOT IS_ABSOLUTE "${_bn_osx_sysroot}")
        set(BN_OSX_SYSROOT_NAME "${_bn_osx_sysroot}" CACHE INTERNAL "macOS SDK name CMAKE_OSX_SYSROOT was resolved from")
    elseif(NOT EXISTS "${_bn_osx_sysroot}")
        if(BN_OSX_SYSROOT_NAME)
            set(_bn_osx_sdk_name "${BN_OSX_SYSROOT_NAME}")
        else()
            set(_bn_osx_sdk_name macosx)
        endif()
        message(WARNING "macOS SDK \"${_bn_osx_sysroot}\" does not exist, resolving SDK \"${_bn_osx_sdk_name}\" instead")
        set(_bn_osx_sysroot "${_bn_osx_sdk_name}")
        unset(_bn_osx_sdk_name)
    endif()

    if(NOT IS_ABSOLUTE "${_bn_osx_sysroot}")
        execute_process(
            COMMAND xcrun --sdk "${_bn_osx_sysroot}" --show-sdk-path
            OUTPUT_VARIABLE _bn_osx_sysroot
            OUTPUT_STRIP_TRAILING_WHITESPACE
            COMMAND_ERROR_IS_FATAL ANY
        )
    endif()

    set(CMAKE_OSX_SYSROOT "${_bn_osx_sysroot}" CACHE STRING "macOS SDK path" FORCE)
    set(CMAKE_OSX_SYSROOT "${_bn_osx_sysroot}")
    unset(_bn_osx_sysroot)
endif()
