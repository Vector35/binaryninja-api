# Copyright (c) 2015-2020 Vector 35 Inc
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

from binaryninja import log
from binaryninja import _binaryninjacore as core
from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.binaryview import BinaryViewType
from binaryninja.enums import SegmentFlag
from binaryninja import Settings
import json

use_default_loader_settings = True

class MappedView(BinaryView):
	name = "Mapped (Python)"
	long_name = "Mapped (Python)"
	load_address = 0x100000

	def __init__(self, data):
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)

	@classmethod
	def is_valid_for_data(cls, data):
		# Insert code that looks for a magic identifier and return True if this BinaryViewType can handle/parse the binary
		return True

	@classmethod
	def get_load_settings_for_data(cls, data):
		# This method is optional. If provided this is where the Load Settings for a BinaryViewType are specified. Binary Ninja provides
		# some default read-only load settings which are:
		#		["loader.architecture", "loader.platform", "loader.entryPoint", "loader.imageBase", "loader.segments", "loader.sections"]
		# The default load settings are provided for consistency and convenience.
		# The default load settings are always generated with a read-only indication which is respected by the UI.
		# The read-only indication is a property that consists of a JSON name/value pair ("readOnly" : true).
		load_settings = None
		if not use_default_loader_settings:
			# Create a new named Settings container for the load settings.
			Settings("mapped_load_settings")
		else:
			# Optionally, perform light-weight parsing of the 'Raw' BinaryView to extract required information for load settings generation.
			# This allows finer control of the settings provided as well as their default values.
			# For example, the view.relocatable property could be used to control the read-only attribute of "loader.imageBase"
			view = cls.registered_view_type.parse(data)

			# Populate settings container with default load settings
			# Note: `get_default_load_settings_for_data` automatically tries to parse the input if the `data` BinaryViewType name does not match the
			# cls BinaryViewType name. In this case a parsed view is already being passed.
			load_settings = cls.registered_view_type.get_default_load_settings_for_data(view)

			# Specify default load settings that can be overridden (from the UI).
			overrides = ["loader.architecture", "loader.platform", "loader.entryPoint", "loader.imageBase", "loader.segments", "loader.sections"]
			for override in overrides:
				if load_settings.contains(override):
					load_settings.update_property(override, json.dumps({'readOnly': False}))

			# Override the default setting values.
			load_settings.update_property("loader.imageBase", json.dumps({'default': 0}))
			load_settings.update_property("loader.entryPoint", json.dumps({'default': 0}))

		# Specify additional custom settings.
		load_settings.register_setting("loader.my_custom_arch.customLoadSetting",
			'{"title" : "My Custom Load Setting",\
			"type" : "boolean",\
			"default" : false,\
			"description" : "My custom load setting description."}')

		return load_settings

	def init(self):
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
				self.arch = Architecture['x86']
				self.platform = Architecture['x86'].standalone_platform
				self.add_auto_segment(0, len(self.parent_view), 0, len(self.parent_view), SegmentFlag.SegmentReadable)
				return True
			arch = load_settings.get_string("loader.architecture", self)
			self.arch = Architecture[arch]
			self.platform = Architecture[arch].standalone_platform
			self.load_address = load_settings.get_integer("loader.imageBase", self)
			self.add_auto_segment(self.load_address, len(self.parent_view), 0, len(self.parent_view), SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
			entry_point = load_settings.get_integer("loader.entryPoint", self)
			self.add_entry_point(self.load_address + entry_point)
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def perform_get_entry_point(self):
		return self.load_address

	def perform_is_executable(self):
		return True

	def perform_is_relocatable(self):
		return True

	def perform_get_address_size(self):
		return self.arch.address_size

MappedView.register()
