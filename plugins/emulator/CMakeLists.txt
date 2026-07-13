cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(bnil-emulator)

if(NOT BN_INTERNAL_BUILD)
	# Out-of-tree build: locate the Binary Ninja API source. When this plugin is checked
	# out inside the api repo (api/plugins/emulator), the api root is two levels up.
	find_path(
		BN_API_PATH
		NAMES binaryninjaapi.h
		HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
		REQUIRED
	)
endif()

add_subdirectory(core)
add_subdirectory(api)
