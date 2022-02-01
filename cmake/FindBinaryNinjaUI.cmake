# Try to find Binary Ninja UI
# Once done this will define
#  BinaryNinjaUI_FOUND - If Binary Ninja UI is found
#  BinaryNinjaUI_INCLUDE_DIRS - The directories to include for compiling UI plugins
#  BinaryNinjaUI_LIBRARIES - The libraries for linking UI plugins
#  BinaryNinjaUI_LIBRARY_DIRS - The link paths required for ui plugins
#  BinaryNinjaUI_DEFINITIONS - Compiler switches required for UI plugins

cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

find_package(BinaryNinjaCore REQUIRED)

find_library(UI_LIBRARY
    NAMES binaryninjaui libbinaryninjaui.so.1
    HINTS ${BinaryNinjaCore_LIBRARY_DIRS})

# Use qmake to find the qt6 cmake libs, if we have it in PATH
find_program(QMAKE_COMMAND qmake)
if(QMAKE_COMMAND)
    # qmake will tell us where the libs are!
    execute_process(
        COMMAND ${QMAKE_COMMAND} -query QT_INSTALL_LIBS
        OUTPUT_VARIABLE QT_LIB_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE)

    # Qt cmake files are in QT_INSTALL_LIBS/cmake
    set(QT_CMAKE_PATH "${QT_LIB_PATH}/cmake")
    message(STATUS "Found Qt CMake path: ${QT_CMAKE_PATH}")
    list(APPEND CMAKE_MODULE_PATH ${QT_CMAKE_PATH})
endif()

# Also find Qt6 which is required
find_package(Qt6 COMPONENTS Core Gui Widgets)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BinaryNinjaUI
    FOUND_VAR BinaryNinjaUI_FOUND
    REQUIRED_VARS UI_LIBRARY Qt6_FOUND
    FAIL_MESSAGE "Could NOT find Binary Ninja UI installation. Check that you are using a valid Binary Ninja, non-headless install, and qmake is in your PATH.")

if(NOT Qt6_FOUND)
    message(WARNING "Could not find Qt6! Make sure qmake is in your PATH.")
else()
    message(STATUS "Found Binary Ninja UI: ${UI_LIBRARY}")
endif()

# UI headers are added in the api cmake
set(BinaryNinjaUI_INCLUDE_DIRS "")

set(BinaryNinjaUI_LIBRARIES "${UI_LIBRARY}")
list(APPEND BinaryNinjaUI_LIBRARIES Qt6::Core)
list(APPEND BinaryNinjaUI_LIBRARIES Qt6::Gui)
list(APPEND BinaryNinjaUI_LIBRARIES Qt6::Widgets)
set(BinaryNinjaUI_DEFINITIONS "")
set(BinaryNinjaUI_LIBRARY_DIRS "${BinaryNinjaCore_LIBRARY_DIRS}")

# Compatibility
set(BN_UI_LIBRARY "${UI_LIBRARY}")
set(BN_UI_LIBRARY_DIRS "${BinaryNinjaUI_LIBRARY_DIRS}")
set(BN_UI_DEFINITIONS "${BinaryNinjaUI_DEFINITIONS}")



