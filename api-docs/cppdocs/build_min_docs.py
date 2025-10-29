#!/usr/bin/env python3

# =-=--
# This script builds the documentation with doxygen and runs minification routines.
# This allows shipping a few thousand fewer files in updates including C++ documentation.
#
# Usage:
# install doxygen 1.12.0
#
# make html
# OR
# make docset
# =-=--

import argparse
import os
import sys
import json
import re
from collections import namedtuple
import subprocess
import shutil

doxygen = "doxygen" #to make testing other versions easier

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

	:param filename: Target root filename. e.g. 'topics.js'
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


def convert_navtree_format(js_content):
	"""
	Fix Doxygen 1.15+ NAVTREE format.
	Doxygen 1.15 incorrectly wraps all top-level items as children of the first item.
	Instead of unwrapping (which breaks breadcrumbs), we'll just reorder items and
	use CSS to hide the wrapper node.

	Incorrect (Doxygen 1.15):
	  var NAVTREE = [ ["Root", "index.html", [["Item1",...], ["Deprecated",...], ["Item2",...]] ] ];

	We'll reorder to:
	  var NAVTREE = [ ["Root", "index.html", [["Item1",...], ["Item2",...], ["Deprecated",...]] ] ];
	"""
	# Find NAVTREE definition
	navtree_pattern = r'var NAVTREE\s*=\s*\[(.*?)\];'
	match = re.search(navtree_pattern, js_content, re.DOTALL)

	if not match:
		print("WARNING: NAVTREE not found, skipping format conversion")
		return js_content

	navtree_content = match.group(1).strip()

	print("Checking NAVTREE format...")

	# Parse the NAVTREE array
	try:
		# Wrap in array brackets to make it valid JSON
		navtree_array = json.loads('[' + navtree_content + ']')
	except json.JSONDecodeError as e:
		print(f"WARNING: Could not parse NAVTREE as JSON: {e}")
		return js_content

	# Check if this is the Doxygen 1.15 format:
	# - Single top-level item
	# - That item has an array of children as its 3rd element
	if len(navtree_array) == 1 and isinstance(navtree_array[0], list) and len(navtree_array[0]) == 3:
		root_item = navtree_array[0]
		children = root_item[2]

		if isinstance(children, list) and len(children) > 0:
			print(f"Detected Doxygen 1.15 format with wrapper containing {len(children)} items")

			# Doxygen 1.15 reorders items incorrectly
			# Correct order should be: Binary Ninja C++ API, Topics, Namespaces, Classes, Deprecated List
			# Doxygen 1.15 puts: Binary Ninja C++ API, Deprecated List, Topics, Namespaces, Classes
			# Let's reorder to put Deprecated List at the end
			deprecated_idx = None
			for i, item in enumerate(children):
				if item[0] == "Deprecated List":
					deprecated_idx = i
					break

			if deprecated_idx is not None and deprecated_idx > 0:
				# Move Deprecated List to the end
				deprecated_item = children.pop(deprecated_idx)
				children.append(deprecated_item)
				print(f"Reordered: moved 'Deprecated List' from position {deprecated_idx} to end")

			# Keep the wrapper structure, just with reordered children
			root_item[2] = children
			fixed_array = [root_item]

			# Convert back to JavaScript
			fixed_json = json.dumps(fixed_array, indent=None, separators=(',', ':'))

			# Replace in original content
			new_navtree_def = f'var NAVTREE = {fixed_json};'
			result = js_content[:match.start()] + new_navtree_def + js_content[match.end():]

			# Adjust NAVTREEINDEX breadcrumbs to account for the reordering
			result = adjust_breadcrumbs_for_reorder(result, deprecated_idx)

			print(f"Fixed NAVTREE: kept wrapper structure, reordered children")
			return result

	print("NAVTREE format appears correct, no conversion needed")
	return js_content


def adjust_breadcrumbs_for_reorder(js_content, deprecated_moved_from_idx):
	"""
	Adjust breadcrumbs in NAVTREEINDEX to account for moving Deprecated List.

	Original order (Doxygen 1.15): [0: Binary Ninja, 1: Deprecated, 2: Topics, 3: Namespaces, 4: Classes]
	New order after reorder:       [0: Binary Ninja, 1: Topics, 2: Namespaces, 3: Classes, 4: Deprecated]

	So breadcrumbs need adjustment:
	- Items at old index 1 (Deprecated) -> new index 4
	- Items at old index 2+ -> subtract 1
	"""
	if deprecated_moved_from_idx is None:
		return js_content

	print(f"Adjusting NAVTREEINDEX breadcrumbs for reordering (Deprecated moved from {deprecated_moved_from_idx} to end)...")

	result = []
	pos = 0
	adjusted_count = 0

	while True:
		# Find next NAVTREEINDEX variable
		match = re.search(r'var (NAVTREEINDEX\d*)\s*=\s*\{', js_content[pos:])
		if not match:
			result.append(js_content[pos:])
			break

		# Add everything before this match
		result.append(js_content[pos:pos + match.start()])

		var_name = match.group(1)
		obj_start = pos + match.end() - 1  # Position of the opening {

		# Find the matching closing } by counting braces
		brace_count = 1
		i = obj_start + 1
		while i < len(js_content) and brace_count > 0:
			if js_content[i] == '{':
				brace_count += 1
			elif js_content[i] == '}':
				brace_count -= 1
			i += 1

		if brace_count != 0:
			print(f"WARNING: Could not find closing brace for {var_name}")
			result.append(js_content[pos:])
			break

		obj_end = i  # Position after the closing }
		obj_content = js_content[obj_start:obj_end]

		try:
			# Parse the index object
			index_obj = json.loads(obj_content)
			adjusted_obj = {}

			for key, breadcrumbs in index_obj.items():
				if isinstance(breadcrumbs, list) and len(breadcrumbs) > 0:
					# Adjust the first breadcrumb index for the reordering
					first_idx = breadcrumbs[0]
					new_breadcrumbs = breadcrumbs.copy()

					if first_idx == deprecated_moved_from_idx:
						# This points to Deprecated List, now at the end
						new_breadcrumbs[0] = 4
					elif first_idx > deprecated_moved_from_idx:
						# This was after Deprecated, shift down by 1
						new_breadcrumbs[0] = first_idx - 1

					adjusted_obj[key] = new_breadcrumbs
				else:
					adjusted_obj[key] = breadcrumbs

			# Convert back to JavaScript
			adjusted_json = json.dumps(adjusted_obj, indent=None, separators=(',', ':'))
			result.append(f'var {var_name} = {adjusted_json};')
			adjusted_count += 1

		except json.JSONDecodeError as e:
			print(f"WARNING: Could not parse {var_name}: {e}")
			result.append(js_content[pos:obj_end])

		pos = obj_end

	print(f"Adjusted {adjusted_count} NAVTREEINDEX variables for reordering")
	return ''.join(result)




def replace_getScript_function(js_content, replacement_func):
	"""
	Robustly find and replace the getScript function definition.
	Uses brace counting to handle nested functions across different Doxygen versions.
	"""
	# Find the start of the function
	pattern = r'const getScript\s*=\s*function\s*\([^)]*\)\s*\{'
	match = re.search(pattern, js_content)

	if not match:
		print("ERROR: getScript function not found in navtree.js")
		sys.exit(1)

	start_pos = match.start()
	func_start = match.end() - 1  # Position of opening brace

	# Count braces to find the matching closing brace
	brace_count = 1
	pos = func_start + 1

	while pos < len(js_content) and brace_count > 0:
		if js_content[pos] == '{':
			brace_count += 1
		elif js_content[pos] == '}':
			brace_count -= 1
		pos += 1

	if brace_count != 0:
		print("ERROR: Could not find matching closing brace for getScript function")
		sys.exit(1)

	end_pos = pos  # Position after closing brace

	# Replace the function
	new_content = js_content[:start_pos] + replacement_func + js_content[end_pos:]

	return new_content


def minifier():

	# Typically, doxygen's navbar will lazy load the data in all of these variables.
	# While this has miniscule performance benefits, it generates thousands of js files.
	# Here, we take all js variables that the navbar will ever be able to load, and
	# 	add them to the top of the navbar.js file itself.

	navtree_built_data = ""
	for mod in load_items_in_file("html/topics.js"):
		navtree_built_data += mod + "\n"
	for mod in load_items_in_file("html/namespaces.js"):
		navtree_built_data += mod + "\n"
	for mod in load_items_in_file("html/annotated.js"):
		navtree_built_data += mod + "\n"

	# Load navtreedata.js which contains NAVTREE and NAVTREEINDEX definitions (Doxygen 1.15+)
	if os.path.exists("html/navtreedata.js"):
		with open("html/navtreedata.js", "r") as fp:
			navtree_built_data += fp.read() + "\n"
			deletion_queue.append("html/navtreedata.js")

	# The navtree indices also need to be loaded in since we're modifying how navbar.js::getScript works.
	# This also saves another ~60 files.
	for nav_tree_index_file in os.listdir("html"):
		if 'navtreeindex' in nav_tree_index_file:
			with open("html/" + nav_tree_index_file, "r") as fp:
				navtree_built_data += fp.read() + "\n"
				deletion_queue.append("html/" + nav_tree_index_file)

	while "\n\n" in navtree_built_data:
		navtree_built_data = navtree_built_data.replace("\n\n", "\n")

	# Fix Doxygen 1.15 NAVTREE format BEFORE removing newlines
	navtree_built_data = convert_navtree_format(navtree_built_data)

	navtree_built_data = navtree_built_data.replace("\n", "")

	fp = open("html/navtree.js", "r")
	navtree_orig = fp.read()
	fp.close()

	# getScript(scriptName,func,show) here originally loads the js file and calls func once that is complete
	# Here, we just want to skip the whole process and call the callback.
	# We use setTimeout(0) to make it async, which may be important for the tree sync logic
	# This replacement works across different Doxygen versions (tested with 1.12.0, 1.14.0, and 1.15.0)
	nav_tree_fixed_get_script = "function getScript(scriptName,func,show) { setTimeout(func, 0); }"

	nav_tree_fixed = replace_getScript_function(navtree_orig, nav_tree_fixed_get_script)

	navtree = navtree_built_data + "\n" + nav_tree_fixed

	fp = open("html/navtree.js", "w")
	fp.write(navtree)
	fp.close()


def build_doxygen(args):
	if not os.path.exists('./Doxyfile-HTML'):
		print('No Doxyfile found. Are you in the right directory?')
		sys.exit(1)
	_, vers, _ = system_with_output(f"{doxygen} -V")

	if args.docset:
		stat, _, _ = system_with_output("doxygen2docset --help")
		if stat != 0:
			print(f"Please install https://github.com/chinmaygarde/doxygen2docset")
			sys.exit(1)

	print(f'DOXYGEN VERSION: {vers.strip()}')

	if os.path.exists('./html/'):
		print('Clearing ./html/')
		try:
			shutil.rmtree("./html/")
		except OSError:
			# doing it twice works (on macOS) ¯\_(ツ)_/¯
			shutil.rmtree("./html/")
	print(f'Building doxygen docs...')

	if args.docset:
		stat, out, err = system_with_output(f"{doxygen} Doxyfile-Docset")
	else:
		stat, out, err = system_with_output(f"{doxygen} Doxyfile-HTML")
	print(f"Built Doxygen with status code {stat}")
	print("Output dir is ./html/")
	stat, out, err = system_with_output("cp _static/img/* html/")
	print(f"Copied images with status code {stat}")
	if args.docset:
		stat, out, err = system_with_output("doxygen2docset --doxygen html --docset docset")
		print(f"Created docset with status code {stat}")


def remove_navtreedata_references():
	"""
	Remove references to navtreedata.js from HTML files since we've inlined it into navtree.js
	"""
	import glob
	html_files = glob.glob("html/**/*.html", recursive=True)
	count = 0
	for html_file in html_files:
		with open(html_file, 'r') as f:
			content = f.read()

		# Remove the navtreedata.js script tag
		if 'navtreedata.js' in content:
			new_content = re.sub(
				r'<script type="text/javascript" src="navtreedata\.js"></script>\s*\n',
				'',
				content
			)
			with open(html_file, 'w') as f:
				f.write(new_content)
			count += 1

	print(f'Removed navtreedata.js references from {count} HTML files')


def main():
	parser = argparse.ArgumentParser(prog=sys.argv[0])
	parser.add_argument("--docset", action="store_true", default=False, help="Generate Dash docset")
	args = parser.parse_args()

	build_doxygen(args)
	print("Minifying Output")
	if os.path.exists("html/navtree.js"):
		minifier()
		remove_navtreedata_references()
	for file in deletion_queue:
		file = "./" + file
		os.remove(file)
	print(f'Was able to clear {len(deletion_queue)} "redundant" files')
	if args.docset:
		print(f'Done. Output is in ./docset/')
	else:
		print(f'Done. Output is in ./html/')


if __name__ == "__main__":
	main()
