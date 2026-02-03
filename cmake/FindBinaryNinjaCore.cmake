# Try to find a Binary Ninja installation
# Once done this will define
#  BinaryNinjaCore_FOUND - If Binary Ninja Core is found
#  BinaryNinjaCore_ROOT_DIR - The installation path of Binary Ninja
#  BinaryNinjaCore_INCLUDE_DIRS - The directories to include for compiling core plugins
#  BinaryNinjaCore_LIBRARIES - The libraries for linking core plugins
#  BinaryNinjaCore_LIBRARY_DIRS - The link paths required for core plugins
#  BinaryNinjaCore_DEFINITIONS - Compiler switches required for core plugins
#  BN_USER_PLUGINS_DIR - User plugin directory (e.g. ~/.binaryninja/plugins)
#  BN_PLUGIN_OUTPUT_DIR - Plugin output directory (internal: build tree, standalone: user plugins)
#
# According to Good CMake Hygiene, we should use BinaryNinjaCore_<VAR> named variables.
# Existing plugins likely use BN_<VAR> names already, so both are provided.

cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

# User plugin directory (always available, independent of build mode)
if(WIN32)
    set(_BN_USER_PLUGINS_DEFAULT "$ENV{APPDATA}\\Binary Ninja\\plugins")
elseif(APPLE)
    set(_BN_USER_PLUGINS_DEFAULT "$ENV{HOME}/Library/Application Support/Binary Ninja/plugins")
else()
    set(_BN_USER_PLUGINS_DEFAULT "$ENV{HOME}/.binaryninja/plugins")
endif()
set(BN_USER_PLUGINS_DIR "${_BN_USER_PLUGINS_DEFAULT}" CACHE PATH "Path to Binary Ninja user plugins")

if(NOT BN_INTERNAL_BUILD)
    # For standalone builds, plugins go to the user plugins dir
    if(NOT DEFINED BN_PLUGIN_OUTPUT_DIR)
        set(BN_PLUGIN_OUTPUT_DIR "${BN_USER_PLUGINS_DIR}")
    endif()

    set(PATH_HINTS "$ENV{BN_INSTALL_DIR}" "${BN_INSTALL_DIR}")
    if(WIN32)
        # System-wide install
        list(APPEND PATH_HINTS "C:\\Program Files\\Vector35\\BinaryNinja")
        # User install
        list(APPEND PATH_HINTS "$ENV{LocalAppData}\\Vector35\\BinaryNinja")
        list(APPEND PATH_HINTS "$ENV{LocalAppData}\\Programs\\Vector35\\BinaryNinja")
    elseif(APPLE)
        list(APPEND PATH_HINTS "${BN_INSTALL_DIR}/Contents/MacOS")
        list(APPEND PATH_HINTS "$ENV{BN_INSTALL_DIR}/Contents/MacOS")
        list(APPEND PATH_HINTS "/Applications/Binary Ninja.app/Contents/MacOS")
        list(APPEND PATH_HINTS "$ENV{HOME}/Applications/Binary Ninja.app/Contents/MacOS")
    else()
        list(APPEND PATH_HINTS "$ENV{HOME}/binaryninja")
    endif()

    find_library(CORE_LIBRARY
        NAMES binaryninjacore libbinaryninjacore.so.1
        HINTS ${PATH_HINTS})

    if(NOT CORE_LIBRARY)
        set(BN_FOUND 0)
        set(BinaryNinjaCore_FOUND 0)
        return()
    endif()

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(BinaryNinjaCore
        FOUND_VAR BinaryNinjaCore_FOUND
        REQUIRED_VARS CORE_LIBRARY
        FAIL_MESSAGE "Could NOT find Binary Ninja installation. Please configure with -DBN_INSTALL_DIR=<path to Binary Ninja> or set the BN_INSTALL_DIR environment variable.")

    message(STATUS "Found Binary Ninja Core: ${CORE_LIBRARY}")

    set(BinaryNinjaCore_INCLUDE_DIRS "")
    set(BinaryNinjaCore_LIBRARIES "${CORE_LIBRARY}")
    set(BinaryNinjaCore_DEFINITIONS "")

    get_filename_component(INSTALL_BIN_DIR "${CORE_LIBRARY}" DIRECTORY)
    message(STATUS "Binary Ninja Link Dirs: ${INSTALL_BIN_DIR}")

    if(WIN32)
        set(BinaryNinjaCore_LIBRARY_DIRS "${INSTALL_BIN_DIR}")
        set(BinaryNinjaCore_ROOT_DIR "${INSTALL_BIN_DIR}")
    elseif(APPLE)
        set(BinaryNinjaCore_LIBRARY_DIRS "${INSTALL_BIN_DIR}")
        # Binary Ninja.app/Contents/MacOS/binaryninja -> Binary Ninja.app/
        get_filename_component(BinaryNinjaCore_ROOT_DIR "${INSTALL_BIN_DIR}" DIRECTORY)
        get_filename_component(BinaryNinjaCore_ROOT_DIR "${BinaryNinjaCore_ROOT_DIR}" DIRECTORY)
    else()
        set(BinaryNinjaCore_LIBRARY_DIRS "${INSTALL_BIN_DIR}")
        set(BinaryNinjaCore_ROOT_DIR "${INSTALL_BIN_DIR}")
    endif()

    message(STATUS "Binary Ninja Install Dir: ${BinaryNinjaCore_ROOT_DIR}")

    # Compatibility
    set(BN_FOUND "${BinaryNinjaCore_FOUND}")
    set(BN_INSTALL_DIR "${BinaryNinjaCore_ROOT_DIR}")
    set(BN_INSTALL_BIN_DIR "${INSTALL_BIN_DIR}")
    set(BN_CORE_LIBRARY "${CORE_LIBRARY}")
    set(BN_CORE_DEFINITIONS "${BinaryNinjaCore_DEFINITIONS}")
else()
    # Internal build
    set(INSTALL_BIN_DIR "${BN_CORE_OUTPUT_DIR}")

    if(WIN32)
        set(BinaryNinjaCore_ROOT_DIR "${INSTALL_BIN_DIR}")
    elseif(APPLE)
        # Binary Ninja.app/Contents/MacOS/binaryninja -> Binary Ninja.app/
        get_filename_component(BinaryNinjaCore_ROOT_DIR "${INSTALL_BIN_DIR}" DIRECTORY)
        get_filename_component(BinaryNinjaCore_ROOT_DIR "${BinaryNinjaCore_ROOT_DIR}" DIRECTORY)
    else()
        set(BinaryNinjaCore_ROOT_DIR "${INSTALL_BIN_DIR}")
    endif()

    set(BinaryNinjaCore_FOUND 1)
    set(BinaryNinjaCore_ROOT_DIR "${INSTALL_BIN_DIR}")
    set(BinaryNinjaCore_INCLUDE_DIRS "")
    set(BinaryNinjaCore_LIBRARIES binaryninjacore)
    set(BinaryNinjaCore_LIBRARY_DIRS "${INSTALL_BIN_DIR}")
    set(BinaryNinjaCore_DEFINITIONS "")

    message(STATUS "Found Binary Ninja Core: binaryninjacore")
    message(STATUS "Binary Ninja Link Dirs: ${INSTALL_BIN_DIR}")
    message(STATUS "Binary Ninja Install Dir: ${BinaryNinjaCore_ROOT_DIR}")

    set(BN_FOUND "${BinaryNinjaCore_FOUND}")
    set(BN_INSTALL_DIR "${BinaryNinjaCore_ROOT_DIR}")
    set(BN_INSTALL_BIN_DIR "${INSTALL_BIN_DIR}")
    set(BN_CORE_LIBRARY binaryninjacore)
    set(BN_CORE_DEFINITIONS "${BinaryNinjaCore_DEFINITIONS}")
endif()
