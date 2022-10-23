#!/usr/bin/env python3

# =-=--
# This script builds the documentation with doxygen and runs minification routines.
# This allows shipping a few thousand fewer files in updates including C++ documentation.
#
# Usage:
# install doxygen 1.9.4 (or this script will not work. running minification on a different version can cause
# 						 real issues.)
# python3 build_min_docs.py
# =-=--

__DOXYGEN_REQUIRED_VERSION__ = "1.9.4"

import os
import sys
import json
from collections import namedtuple
from typing import List
import subprocess
import shutil


def system_with_output(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
	proc = subprocess.Popen("" + cmd,
							stdout=stdout,
							stderr=stderr,
							shell=True,
							universal_newlines=True)
	std_out, std_err = proc.communicate()
	return proc.returncode, std_out, std_err


deletion_queue = []


NavItemEntry = namedtuple("NavItemEntry", ["dName", "htmlLink", "vName"])


# Load the singular variable in a file as a list of navitems
def pop_var(filename):
	"""
	Load in the file data and entries within a file.

	File is in the format `var varName = <json valid array>`
	if <json_valid_array>[n][2] is a list, item[n][2] is a subfile, and we want to
		load the entry and return it.

	:param filename: Filename to load the entries and data from.
	:return: Tuple containing a list of NavItemEntrys and the data in the file.
	"""
	fp = open(filename)
	file_data = fp.read()
	fp.close()
	data_string = file_data.split(' =', 1)[1][:-1]
	data = json.loads(data_string)
	items = []
	for entry in data:
		if not isinstance(entry[2], list):
			items.append(NavItemEntry(entry[0], entry[1], entry[2]))
	return items, file_data


def load_items_in_file(filename):
	"""
	Recursively load in the text of file {filename} and all subfiles referenced by it.

	:param filename: Target root filename. e.g. 'modules.js'
	:return: Combined text of javascript file tree.
	"""
	items = []
	sub_items, file_data = pop_var(filename)
	items.append(file_data)
	deletion_queue.append(filename)
	for item in sub_items:
		if item.vName is not None:
			items += load_items_in_file("html/" + item.vName + ".js")
	return items


def minifier():

	# Typically, doxygen's navbar will lazy load the data in all of these variables.
	# While this has miniscule performance benefits, it generates thousands of js files.
	# Here, we take all js variables that the navbar will ever be able to load, and
	# 	add them to the top of the navbar.js file itself.

	navtree_built_data = ""
	for mod in load_items_in_file("html/modules.js"):
		navtree_built_data += mod + "\n"
	for mod in load_items_in_file("html/namespaces.js"):
		navtree_built_data += mod + "\n"
	for mod in load_items_in_file("html/annotated.js"):
		navtree_built_data += mod + "\n"

	# The navtree indices also need to be loaded in since we're modifying how navbar.js::getScript works.
	# This also saves another ~60 files.
	for nav_tree_index_file in os.listdir("html"):
		if 'navtreeindex' in nav_tree_index_file:
			with open("html/" + nav_tree_index_file, "r") as fp:
				navtree_built_data += fp.read() + "\n"
				deletion_queue.append("html/" + nav_tree_index_file)

	while "\n\n" in navtree_built_data:
		navtree_built_data = navtree_built_data.replace("\n\n", "\n")

	navtree_built_data = navtree_built_data.replace("\n", "")

	fp = open("html/navtree.js", "r")
	navtree_orig = fp.read()
	fp.close()

	# getScript(scriptName,func,show) here originally loads the js file and calls func once that is complete
	# Here, we just want to skip the whole process and immediately call the callback.
	nav_tree_fixed_get_script = "function getScript(scriptName,func,show) { func(); }"

	navtree_before_get_script = navtree_orig.split("function getScript(scriptName,func,show)")[0]
	navtree_after_get_script = navtree_orig.split("function getScript(scriptName,func,show)")[1].split('}', 1)[1]

	nav_tree_fixed = navtree_before_get_script + nav_tree_fixed_get_script + navtree_after_get_script
	navtree = navtree_built_data + "\n" + nav_tree_fixed

	fp = open("html/navtree.js", "w")
	fp.write(navtree)
	fp.close()


def build_doxygen():
	if not os.path.exists('./Doxyfile'):
		print('No Doxyfile found. Are you in the right directory?')
		sys.exit(1)
	_, vers, _ = system_with_output("doxygen -V")
	if __DOXYGEN_REQUIRED_VERSION__ not in vers.strip():
		print(f'Please use Doxygen {__DOXYGEN_REQUIRED_VERSION__} to build documentation')
		sys.exit(1)

	if os.path.exists('./html/'):
		print('Clearing ./html/')
		try:
			shutil.rmtree("./html/")
		except OSError:
			# doing it twice works (on macOS) ¯\_(ツ)_/¯
			shutil.rmtree("./html/")
	print(f'Building doxygen docs...')
	stat, out, err = system_with_output("doxygen Doxyfile")
	print(f"Built Doxygen with status code {stat}")
	print("Output dir is ./html/")


def main():
	build_doxygen()
	print("Minifying Output")
	minifier()
	for file in deletion_queue:
		file = "./" + file
		os.remove(file)
	print(f'Was able to clear {len(deletion_queue)} "redundant" files')
	print(f'Done. Output is in ./html/')


if __name__ == "__main__":
	main()
