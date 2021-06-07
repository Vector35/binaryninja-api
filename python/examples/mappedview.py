# Copyright (c) 2015-2021 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

# This is an example BinaryView plugin which demonstrates how to specify
# and generate a load settings spec. Load settings can subsequently be presented
# by the UI in the Open With Options dialog or headless when opening a
# file with options.

from binaryninja.log import log_error
from binaryninja import _binaryninjacore as core
from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.binaryview import BinaryViewType
from binaryninja.enums import SegmentFlag
from binaryninja import Settings
import json
import traceback

use_default_loader_settings = True

class MappedView(BinaryView):
	name = "Mapped (Python)"
	long_name = "Mapped (Python)"
	load_address = 0x100000

	def __init__(self, data):
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)

	@staticmethod
	def is_valid_for_data(data):
		# Insert code that looks for a magic identifier and return True if this BinaryViewType can handle/parse the binary
		return True

	@classmethod
	def get_load_settings_for_data(cls, data):
		# This method is optional. If provided this is where the Load Settings for a BinaryViewType are specified. Binary Ninja provides
		# some default read-only load settings which are:
		#		["loader.architecture", "loader.platform", "loader.entryPointOffset", "loader.imageBase", "loader.segments", "loader.sections"]
		# The default load settings are provided for consistency and convenience.
		# The default load settings are always generated with a read-only indication which is respected by the UI.
		# The read-only indication is a property that consists of a JSON name/value pair ("readOnly" : true).
		load_settings = None
		if not use_default_loader_settings:
			# Create a new named Settings container for the load settings.
			load_settings = Settings("mapped_load_settings")
		else:
			# Optionally, perform light-weight parsing of the 'Raw' BinaryView to extract required information for load settings generation.
			# This allows finer control of the settings provided as well as their default values.
			# For example, the view.relocatable property could be used to control the read-only attribute of "loader.imageBase"
			registered_view = cls.registered_view_type
			assert registered_view is not None
			view = registered_view.parse(data)
			assert view is not None
			# Populate settings container with default load settings
			# Note: `get_default_load_settings_for_data` automatically tries to parse the input if the `data` BinaryViewType name does not match the
			# cls BinaryViewType name. In this case a parsed view is already being passed.
			load_settings = registered_view.get_default_load_settings_for_data(view)

			# Specify default load settings that can be overridden (from the UI).
			overrides = ["loader.architecture", "loader.platform", "loader.entryPointOffset", "loader.imageBase", "loader.segments", "loader.sections"]
			for override in overrides:
				if load_settings.contains(override):
					load_settings.update_property(override, json.dumps({'readOnly': False}))

			# Override the default setting values.
			load_settings.update_property("loader.imageBase", json.dumps({'default': 0}))
			load_settings.update_property("loader.entryPointOffset", json.dumps({'default': 0}))

		# Specify additional custom settings.
		load_settings.register_setting("loader.my_custom_arch.customLoadSetting",
			'{"title" : "My Custom Load Setting",\
			"type" : "boolean",\
			"default" : false,\
			"description" : "My custom load setting description."}')

		return load_settings

	def init(self):
		# The BinaryView init method is invoked as part of the BinaryView creation process. This method is called under several different conditions:
		# 1) When opening a file/bndb and no load options are provided.
		# 2) When opening a file/bndb and load options are provided. e.g. 'Open with Options' in the UI, or get_view_of_file_with_options
		# 3) When parsing a file to create an ephemeral BinaryView (self.parse_only == True) for the purpose of extracting header information.
		#		Note: The get_load_settings_for_data classmethod is optional. If provided, it's used to generate load options for the BinaryViewType.
		#		If not provided, then the default load options are automatically generated by the core, extracting information automatically from a parsed BinaryView.
		#		Notice the call to get_default_load_settings_for_data above in get_load_settings_for_data. This will force parsing a file to create an ephemeral BinaryView.
		#		It is also used as a convenience method to pre-populate a Settings object with relevant, generic loader settings that are tagged as 'readOnly'. It is the responsibility,
		#		of the BinaryViewType to communicate and enforce which settings are mutable.
		if self.parse_only is True:
			# Perform light-weight parsing to extract required information for load settings generation.
			# A light-weight parsed view does not get finalized.
			print("Mapped (Python): init(): perform light-weight parsing")
		else:
			# Perform normal BinaryView initialization
			print("Mapped (Python): init(): perform normal BinaryView initialization")

		# Finish BinaryView initialization using the load settings, if they exist
		try:
			load_settings = self.get_load_settings(self.name)
			if load_settings is None:
				if self.parse_only is True:
					self.arch = Architecture['x86']  # type: ignore
					self.platform = Architecture['x86'].standalone_platform # type: ignore
					assert self.parent_view is not None
					self.add_auto_segment(0, len(self.parent_view), 0, len(self.parent_view), SegmentFlag.SegmentReadable)
					return True
				else:
					# Note: If there are no load settings and this is not a parse_only view, it's possible to call get_load_settings_for_data directly.
					# This allows us to generate default load options for the BinaryView. This step is not required but can be useful.
					load_settings = self.__class__.get_load_settings_for_data(self.parent_view)

			arch = load_settings.get_string("loader.architecture", self)
			self.arch = Architecture[arch] # type: ignore
			self.platform = Architecture[arch].standalone_platform # type: ignore
			self.load_address = load_settings.get_integer("loader.imageBase", self)
			self.add_auto_segment(self.load_address, len(self.parent_view), 0, len(self.parent_view), SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
			if load_settings.contains("loader.entryPointOffset"):
				self.entry_point_offset = load_settings.get_integer("loader.entryPointOffset", self)
				self.add_entry_point(self.load_address + self.entry_point_offset)

			# Note: This MappedView (Python) BinaryView implementation is incomplete. It ignores platform, section, and segment settings.
			# It's preferred that values saved in the settings system be imageBase agnostic.
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def perform_get_entry_point(self):
		if hasattr(self, 'entry_point_offset'):
			return self.load_address + self.entry_point_offset
		else:
			return 0

	def perform_is_executable(self):
		return True

	def perform_is_relocatable(self):
		return True

	def perform_get_address_size(self):
		return self.arch.address_size

MappedView.register()
