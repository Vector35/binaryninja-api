# Copyright (c) 2015-2024 Vector 35 Inc
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

import traceback
import ctypes
import threading

from typing import Optional, Callable

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from .enums import PluginCommandType
from . import filemetadata
from . import binaryview
from . import function
from .log import log_error
from . import lowlevelil
from . import mediumlevelil
from . import highlevelil


class PluginCommandContext:
	def __init__(self, view):
		self._view = view
		self._address = 0
		self._length = 0
		self._function = None
		self._instruction = None

	def __len__(self):
		return self._length

	@property
	def view(self):
		return self._view

	@view.setter
	def view(self, value):
		self._view = value

	@property
	def address(self):
		return self._address

	@address.setter
	def address(self, value):
		self._address = value

	@property
	def length(self):
		return self._length

	@length.setter
	def length(self, value):
		self._length = value

	@property
	def function(self):
		return self._function

	@function.setter
	def function(self, value):
		self._function = value

	@property
	def instruction(self):
		return self._instruction

	@instruction.setter
	def instruction(self, value):
		self._instruction = value


class _PluginCommandMetaClass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		commands = core.BNGetAllPluginCommands(count)
		assert commands is not None, "core.BNGetAllPluginCommands returned None"
		try:
			for i in range(0, count.value):
				yield PluginCommand(commands[i])
		finally:
			core.BNFreePluginCommandList(commands)


class PluginCommand(metaclass=_PluginCommandMetaClass):
	"""
	The ``class PluginCommand`` contains all the plugin registration methods as class methods.

	You shouldn't need to create an instance of this class, instead see `register`,
	`register_for_address`, `register_for_function`, and similar class methods for examples
	on how to register your plugin.
	"""
	_registered_commands = []

	def __init__(self, cmd):
		self._command = core.BNPluginCommand()
		ctypes.memmove(ctypes.byref(self._command), ctypes.byref(cmd), ctypes.sizeof(core.BNPluginCommand))
		self._name = str(cmd.name)
		self._description = str(cmd.description)
		self._type = PluginCommandType(cmd.type)

	@staticmethod
	def _default_action(view, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			action(view_obj)
		except:
			log_error(traceback.format_exc())

	@staticmethod
	def _address_action(view, addr, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			action(view_obj, addr)
		except:
			log_error(traceback.format_exc())

	@staticmethod
	def _range_action(view, addr, length, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			action(view_obj, addr, length)
		except:
			log_error(traceback.format_exc())

	@staticmethod
	def _function_action(view, func, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			func_obj = function.Function(view_obj, core.BNNewFunctionReference(func))
			action(view_obj, func_obj)
		except:
			log_error(traceback.format_exc())

	@staticmethod
	def _low_level_il_function_action(view, func, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetLowLevelILOwnerFunction(func))
			func_obj = lowlevelil.LowLevelILFunction(owner.arch, core.BNNewLowLevelILFunctionReference(func), owner)
			action(view_obj, func_obj)
		except:
			log_error(traceback.format_exc())

	@staticmethod
	def _low_level_il_instruction_action(view, func, instr, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetLowLevelILOwnerFunction(func))
			func_obj = lowlevelil.LowLevelILFunction(owner.arch, core.BNNewLowLevelILFunctionReference(func), owner)
			action(view_obj, func_obj[instr])
		except:
			log_error(traceback.format_exc())

	@staticmethod
	def _medium_level_il_function_action(view, func, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetMediumLevelILOwnerFunction(func))
			func_obj = mediumlevelil.MediumLevelILFunction(
			    owner.arch, core.BNNewMediumLevelILFunctionReference(func), owner
			)
			action(view_obj, func_obj)
		except:
			log_error(traceback.format_exc())

	@staticmethod
	def _medium_level_il_instruction_action(view, func, instr, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetMediumLevelILOwnerFunction(func))
			func_obj = mediumlevelil.MediumLevelILFunction(
			    owner.arch, core.BNNewMediumLevelILFunctionReference(func), owner
			)
			action(view_obj, func_obj[instr])
		except:
			log_error(traceback.format_exc())

	@staticmethod
	def _high_level_il_function_action(view, func, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetHighLevelILOwnerFunction(func))
			func_obj = highlevelil.HighLevelILFunction(owner.arch, core.BNNewHighLevelILFunctionReference(func), owner)
			action(view_obj, func_obj)
		except:
			log_error(traceback.format_exc())

	@staticmethod
	def _high_level_il_instruction_action(view, func, instr, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetHighLevelILOwnerFunction(func))
			func_obj = highlevelil.HighLevelILFunction(owner.arch, core.BNNewHighLevelILFunctionReference(func), owner)
			action(view_obj, func_obj[instr])
		except:
			log_error(traceback.format_exc())

	@staticmethod
	def _default_is_valid(view, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			return is_valid(view_obj)
		except:
			log_error(traceback.format_exc())
			return False

	@staticmethod
	def _address_is_valid(view, addr, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			return is_valid(view_obj, addr)
		except:
			log_error(traceback.format_exc())
			return False

	@staticmethod
	def _range_is_valid(view, addr, length, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			return is_valid(view_obj, addr, length)
		except:
			log_error(traceback.format_exc())
			return False

	@staticmethod
	def _function_is_valid(view, func, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			func_obj = function.Function(view_obj, core.BNNewFunctionReference(func))
			return is_valid(view_obj, func_obj)
		except:
			log_error(traceback.format_exc())
			return False

	@staticmethod
	def _low_level_il_function_is_valid(view, func, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetLowLevelILOwnerFunction(func))
			func_obj = lowlevelil.LowLevelILFunction(owner.arch, core.BNNewLowLevelILFunctionReference(func), owner)
			return is_valid(view_obj, func_obj)
		except:
			log_error(traceback.format_exc())
			return False

	@staticmethod
	def _low_level_il_instruction_is_valid(view, func, instr, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetLowLevelILOwnerFunction(func))
			func_obj = lowlevelil.LowLevelILFunction(owner.arch, core.BNNewLowLevelILFunctionReference(func), owner)
			return is_valid(view_obj, func_obj[instr])
		except:
			log_error(traceback.format_exc())
			return False

	@staticmethod
	def _medium_level_il_function_is_valid(view, func, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetMediumLevelILOwnerFunction(func))
			func_obj = mediumlevelil.MediumLevelILFunction(
			    owner.arch, core.BNNewMediumLevelILFunctionReference(func), owner
			)
			return is_valid(view_obj, func_obj)
		except:
			log_error(traceback.format_exc())
			return False

	@staticmethod
	def _medium_level_il_instruction_is_valid(view, func, instr, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetMediumLevelILOwnerFunction(func))
			func_obj = mediumlevelil.MediumLevelILFunction(
			    owner.arch, core.BNNewMediumLevelILFunctionReference(func), owner
			)
			return is_valid(view_obj, func_obj[instr])
		except:
			log_error(traceback.format_exc())
			return False

	@staticmethod
	def _high_level_il_function_is_valid(view, func, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetHighLevelILOwnerFunction(func))
			func_obj = highlevelil.HighLevelILFunction(owner.arch, core.BNNewHighLevelILFunctionReference(func), owner)
			return is_valid(view_obj, func_obj)
		except:
			log_error(traceback.format_exc())
			return False

	@staticmethod
	def _high_level_il_instruction_is_valid(view, func, instr, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetHighLevelILOwnerFunction(func))
			func_obj = highlevelil.HighLevelILFunction(owner.arch, core.BNNewHighLevelILFunctionReference(func), owner)
			return is_valid(view_obj, func_obj[instr])
		except:
			log_error(traceback.format_exc())
			return False

	@classmethod
	def register(
	    cls, name: str, description: str, action: Callable[['binaryview.BinaryView'], None],
	    is_valid: Optional[Callable[['binaryview.BinaryView'], bool]] = None
	):
		r"""
		``register`` Register a plugin

		:param str name: name of the plugin (use 'Folder\\Name' to have the menu item nested in a folder)
		:param str description: description of the plugin
		:param callback action: function to call with the :class:`~binaryview.BinaryView` as an argument
		:param callback is_valid: optional argument of a function passed a :class:`~binaryview.BinaryView` to determine whether the plugin should be enabled for that view
		:rtype: None
		:Example:

			>>> def my_plugin(bv: BinaryView):
			>>> 	log_info(f"My plugin was called on bv: `{bv}`")
			>>> PluginCommand.register("My Plugin", "My plugin description (not used)", my_plugin)
			True
			>>> def is_valid(bv: BinaryView) -> bool:
			>>> 	return False
			>>> PluginCommand.register("My Plugin (With Valid Function)", "My plugin description (not used)", my_plugin, is_valid)
			True

		.. warning:: Calling ``register`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
		                              ctypes.POINTER(core.BNBinaryView
		                                             ))(lambda ctxt, view: cls._default_action(view, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
		                                ctypes.POINTER(core.BNBinaryView
		                                               ))(lambda ctxt, view: cls._default_is_valid(view, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommand(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_address(
	    cls, name: str, description: str, action: Callable[['binaryview.BinaryView', int], None],
	    is_valid: Optional[Callable[['binaryview.BinaryView', int], bool]] = None
	):
		r"""
		``register_for_address`` Register a plugin to be called with an address argument

		:param str name: name of the plugin (use 'Folder\\Name' to have the menu item nested in a folder)
		:param str description: description of the plugin
		:param callback action: function to call with the :class:`~binaryview.BinaryView` and address as arguments
		:param callback is_valid: optional argument of a function passed a :class:`~binaryview.BinaryView` and address to determine whether the plugin should be enabled for that view
		:rtype: None
		:Example:

			>>> def my_plugin(bv: BinaryView, address: int):
			>>> 	log_info(f"My plugin was called on bv: `{bv}` at address {hex(address)}")
			>>> PluginCommand.register_for_address("My Plugin", "My plugin description (not used)", my_plugin)
			True
			>>> def is_valid(bv: BinaryView, address: int) -> bool:
			>>> 	return False
			>>> PluginCommand.register_for_address("My Plugin (With Valid Function)", "My plugin description (not used)", my_plugin, is_valid)
			True

		.. warning:: Calling ``register_for_address`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(
		    core.BNBinaryView
		), ctypes.c_ulonglong)(lambda ctxt, view, addr: cls._address_action(view, addr, action))
		is_valid_obj = ctypes.CFUNCTYPE(
		    ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong
		)(lambda ctxt, view, addr: cls._address_is_valid(view, addr, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForAddress(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_range(
	    cls, name: str, description: str, action: Callable[['binaryview.BinaryView', int, int], None],
	    is_valid: Optional[Callable[['binaryview.BinaryView', int, int], bool]] = None
	):
		r"""
		``register_for_range`` Register a plugin to be called with a range argument

		:param str name: name of the plugin (use 'Folder\\Name' to have the menu item nested in a folder)
		:param str description: description of the plugin
		:param callback action: function to call with the :class:`~binaryview.BinaryView`, start address, and length as arguments
		:param callback is_valid: optional argument of a function passed a :class:`~binaryview.BinaryView`, start address, and length to determine whether the plugin should be enabled for that view
		:rtype: None
		:Example:

			>>> def my_plugin(bv: BinaryView, start: int, length: int):
			>>> 	log_info(f"My plugin was called on bv: `{bv}` at {hex(start)} of length {hex(length)}")
			>>> PluginCommand.register_for_range("My Plugin", "My plugin description (not used)", my_plugin)
			True
			>>> def is_valid(bv: BinaryView, start: int, length: int) -> bool:
			>>> 	return False
			>>> PluginCommand.register_for_range("My Plugin (With Valid Function)", "My plugin description (not used)", my_plugin, is_valid)
			True

		.. warning:: Calling ``register_for_range`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(
		    None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong, ctypes.c_ulonglong
		)(lambda ctxt, view, addr, length: cls._range_action(view, addr, length, action))
		is_valid_obj = ctypes.CFUNCTYPE(
		    ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong, ctypes.c_ulonglong
		)(lambda ctxt, view, addr, length: cls._range_is_valid(view, addr, length, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForRange(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_function(
	    cls, name: str, description: str, action: Callable[['binaryview.BinaryView', 'function.Function'], None],
	    is_valid: Optional[Callable[['binaryview.BinaryView', 'function.Function'], bool]] = None
	):
		r"""
		``register_for_function`` Register a plugin to be called with a function argument

		:param str name: name of the plugin (use 'Folder\\Name' to have the menu item nested in a folder)
		:param str description: description of the plugin
		:param callback action: function to call with the :class:`~binaryview.BinaryView` and a :class:`~function.Function` as arguments
		:param callback is_valid: optional argument of a function passed a :class:`~binaryview.BinaryView` and :class:`~function.Function` to determine whether the plugin should be enabled for that view
		:rtype: None
		:Example:

			>>> def my_plugin(bv: BinaryView, func: Function):
			>>> 	log_info(f"My plugin was called on func {func} in bv `{bv}`")
			>>> PluginCommand.register_for_function("My Plugin", "My plugin description (not used)", my_plugin)
			True
			>>> def is_valid(bv: BinaryView, func: Function) -> bool:
			>>> 	return False
			>>> PluginCommand.register_for_function("My Plugin (With Valid Function)", "My plugin description (not used)", my_plugin, is_valid)
			True

		.. warning:: Calling ``register_for_function`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(
		    None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNFunction)
		)(lambda ctxt, view, func: cls._function_action(view, func, action))
		is_valid_obj = ctypes.CFUNCTYPE(
		    ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNFunction)
		)(lambda ctxt, view, func: cls._function_is_valid(view, func, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForFunction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_low_level_il_function(
	    cls, name: str, description: str, action: Callable[['binaryview.BinaryView', 'lowlevelil.LowLevelILFunction'],
	                                                       None],
	    is_valid: Optional[Callable[['binaryview.BinaryView', 'lowlevelil.LowLevelILFunction'], bool]] = None
	):
		r"""
		``register_for_low_level_il_function`` Register a plugin to be called with a low level IL function argument

		:param str name: name of the plugin (use 'Folder\\Name' to have the menu item nested in a folder)
		:param str description: description of the plugin
		:param callback action: function to call with the :class:`~binaryview.BinaryView` and a :class:`~lowlevelil.LowLevelILFunction` as arguments
		:param callback is_valid: optional argument of a function passed a :class:`~binaryview.BinaryView` and :class:`~lowlevelil.LowLevelILFunction` to determine whether the plugin should be enabled for that view
		:rtype: None
		:Example:

			>>> def my_plugin(bv: BinaryView, func: LowLevelILFunction):
			>>> 	log_info(f"My plugin was called on func {func} in bv `{bv}`")
			>>> PluginCommand.register_for_low_level_il_function("My Plugin", "My plugin description (not used)", my_plugin)
			True
			>>> def is_valid(bv: BinaryView, func: LowLevelILFunction) -> bool:
			>>> 	return False
			>>> PluginCommand.register_for_low_level_il_function("My Plugin (With Valid Function)", "My plugin description (not used)", my_plugin, is_valid)
			True

		.. warning:: Calling ``register_for_low_level_il_function`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(
		    None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNLowLevelILFunction)
		)(lambda ctxt, view, func: cls._low_level_il_function_action(view, func, action))
		is_valid_obj = ctypes.CFUNCTYPE(
		    ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView),
		    ctypes.POINTER(core.BNLowLevelILFunction)
		)(lambda ctxt, view, func: cls._low_level_il_function_is_valid(view, func, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForLowLevelILFunction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_low_level_il_instruction(
	    cls, name: str, description: str, action: Callable[['binaryview.BinaryView', 'lowlevelil.LowLevelILInstruction'],
	                                                       None],
	    is_valid: Optional[Callable[['binaryview.BinaryView', 'lowlevelil.LowLevelILInstruction'], bool]] = None
	):
		r"""
		``register_for_low_level_il_instruction`` Register a plugin to be called with a low level IL instruction argument

		:param str name: name of the plugin (use 'Folder\\Name' to have the menu item nested in a folder)
		:param str description: description of the plugin
		:param callback action: function to call with the :class:`~binaryview.BinaryView` and a :class:`~lowlevelil.LowLevelILInstruction` as arguments
		:param callback is_valid: optional argument of a function passed a :class:`~binaryview.BinaryView` and :class:`~lowlevelil.LowLevelILInstruction` to determine whether the plugin should be enabled for that view
		:rtype: None
		:Example:

			>>> def my_plugin(bv: BinaryView, inst: LowLevelILInstruction):
			>>> 	log_info(f"My plugin was called on inst {inst} in bv `{bv}`")
			>>> PluginCommand.register_for_low_level_il_instruction("My Plugin", "My plugin description (not used)", my_plugin)
			True
			>>> def is_valid(bv: BinaryView, inst: LowLevelILInstruction) -> bool:
			>>> 	return False
			>>> PluginCommand.register_for_low_level_il_instruction("My Plugin (With Valid Function)", "My plugin description (not used)", my_plugin, is_valid)
			True

		.. warning:: Calling ``register_for_low_level_il_instruction`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(
		    None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNLowLevelILFunction),
		    ctypes.c_ulonglong
		)(lambda ctxt, view, func, instr: cls._low_level_il_instruction_action(view, func, instr, action))
		is_valid_obj = ctypes.CFUNCTYPE(
		    ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView),
		    ctypes.POINTER(core.BNLowLevelILFunction), ctypes.c_ulonglong
		)(lambda ctxt, view, func, instr: cls._low_level_il_instruction_is_valid(view, func, instr, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForLowLevelILInstruction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_medium_level_il_function(
	    cls, name: str, description: str, action: Callable[['binaryview.BinaryView', 'mediumlevelil.MediumLevelILFunction'],
	                                                       None],
	    is_valid: Optional[Callable[['binaryview.BinaryView', 'mediumlevelil.MediumLevelILFunction'], bool]] = None
	):
		r"""
		``register_for_medium_level_il_function`` Register a plugin to be called with a medium level IL function argument

		:param str name: name of the plugin (use 'Folder\\Name' to have the menu item nested in a folder)
		:param str description: description of the plugin
		:param callback action: function to call with the :class:`~binaryview.BinaryView` and a :class:`~mediumlevelil.MediumLevelILFunction` as arguments
		:param callback is_valid: optional argument of a function passed a :class:`~binaryview.BinaryView` and :class:`~mediumlevelil.MediumLevelILFunction` to determine whether the plugin should be enabled for that view
		:rtype: None
		:Example:

			>>> def my_plugin(bv: BinaryView, func: MediumLevelILFunction):
			>>> 	log_info(f"My plugin was called on func {func} in bv `{bv}`")
			>>> PluginCommand.register_for_low_level_il_function("My Plugin", "My plugin description (not used)", my_plugin)
			True
			>>> def is_valid(bv: BinaryView, func: MediumLevelILFunction) -> bool:
			>>> 	return False
			>>> PluginCommand.register_for_low_level_il_function("My Plugin (With Valid Function)", "My plugin description (not used)", my_plugin, is_valid)
			True

		.. warning:: Calling ``register_for_medium_level_il_function`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(
		    None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNMediumLevelILFunction)
		)(lambda ctxt, view, func: cls._medium_level_il_function_action(view, func, action))
		is_valid_obj = ctypes.CFUNCTYPE(
		    ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView),
		    ctypes.POINTER(core.BNMediumLevelILFunction)
		)(lambda ctxt, view, func: cls._medium_level_il_function_is_valid(view, func, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForMediumLevelILFunction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_medium_level_il_instruction(
	    cls, name: str, description: str,
	    action: Callable[['binaryview.BinaryView', 'mediumlevelil.MediumLevelILInstruction'], None],
	    is_valid: Optional[Callable[['binaryview.BinaryView', 'mediumlevelil.MediumLevelILInstruction'], bool]] = None
	):
		r"""
		``register_for_medium_level_il_instruction`` Register a plugin to be called with a medium level IL instruction argument

		:param str name: name of the plugin (use 'Folder\\Name' to have the menu item nested in a folder)
		:param str description: description of the plugin
		:param callback action: function to call with the :class:`~binaryview.BinaryView` and a :class:`~mediumlevelil.MediumLevelILInstruction` as arguments
		:param callback is_valid: optional argument of a function passed a :class:`~binaryview.BinaryView` and :class:`~mediumlevelil.MediumLevelILInstruction` to determine whether the plugin should be enabled for that view
		:rtype: None
		:Example:

			>>> def my_plugin(bv: BinaryView, inst: MediumLevelILInstruction):
			>>> 	log_info(f"My plugin was called on inst {inst} in bv `{bv}`")
			>>> PluginCommand.register_for_low_level_il_instruction("My Plugin", "My plugin description (not used)", my_plugin)
			True
			>>> def is_valid(bv: BinaryView, inst: MediumLevelILInstruction) -> bool:
			>>> 	return False
			>>> PluginCommand.register_for_low_level_il_instruction("My Plugin (With Valid Function)", "My plugin description (not used)", my_plugin, is_valid)
			True

		.. warning:: Calling ``register_for_medium_level_il_instruction`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(
		    None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNMediumLevelILFunction),
		    ctypes.c_ulonglong
		)(lambda ctxt, view, func, instr: cls._medium_level_il_instruction_action(view, func, instr, action))
		is_valid_obj = ctypes.CFUNCTYPE(
		    ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView),
		    ctypes.POINTER(core.BNMediumLevelILFunction), ctypes.c_ulonglong
		)(lambda ctxt, view, func, instr: cls._medium_level_il_instruction_is_valid(view, func, instr, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForMediumLevelILInstruction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_high_level_il_function(
	    cls, name: str, description: str, action: Callable[['binaryview.BinaryView', 'highlevelil.HighLevelILFunction'],
	                                                       None],
	    is_valid: Optional[Callable[['binaryview.BinaryView', 'highlevelil.HighLevelILFunction'], bool]] = None
	):
		r"""
		``register_for_high_level_il_function`` Register a plugin to be called with a high level IL function argument

		:param str name: name of the plugin (use 'Folder\\Name' to have the menu item nested in a folder)
		:param str description: description of the plugin
		:param callback action: function to call with the :class:`~binaryview.BinaryView` and a :class:`~highlevelil.HighLevelILFunction` as arguments
		:param callback is_valid: optional argument of a function passed a :class:`~binaryview.BinaryView` and :class:`~highlevelil.HighLevelILFunction` to determine whether the plugin should be enabled for that view
		:rtype: None
		:Example:

			>>> def my_plugin(bv: BinaryView, func: HighLevelILFunction):
			>>> 	log_info(f"My plugin was called on func {func} in bv `{bv}`")
			>>> PluginCommand.register_for_low_level_il_function("My Plugin", "My plugin description (not used)", my_plugin)
			True
			>>> def is_valid(bv: BinaryView, func: HighLevelILFunction) -> bool:
			>>> 	return False
			>>> PluginCommand.register_for_low_level_il_function("My Plugin (With Valid Function)", "My plugin description (not used)", my_plugin, is_valid)
			True

		.. warning:: Calling ``register_for_high_level_il_function`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(
		    None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNHighLevelILFunction)
		)(lambda ctxt, view, func: cls._high_level_il_function_action(view, func, action))
		is_valid_obj = ctypes.CFUNCTYPE(
		    ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView),
		    ctypes.POINTER(core.BNHighLevelILFunction)
		)(lambda ctxt, view, func: cls._high_level_il_function_is_valid(view, func, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForHighLevelILFunction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_high_level_il_instruction(
	    cls, name: str, description: str, action: Callable[['binaryview.BinaryView', 'highlevelil.HighLevelILInstruction'],
	                                                       None],
	    is_valid: Optional[Callable[['binaryview.BinaryView', 'highlevelil.HighLevelILInstruction'], bool]] = None
	):
		r"""
		``register_for_high_level_il_instruction`` Register a plugin to be called with a high level IL instruction argument

		:param str name: name of the plugin (use 'Folder\\Name' to have the menu item nested in a folder)
		:param str description: description of the plugin
		:param callback action: function to call with the :class:`~binaryview.BinaryView` and a :class:`~highlevelil.HighLevelILInstruction` as arguments
		:param callback is_valid: optional argument of a function passed a :class:`~binaryview.BinaryView` and :class:`~highlevelil.HighLevelILInstruction` to determine whether the plugin should be enabled for that view
		:rtype: None
		:Example:

			>>> def my_plugin(bv: BinaryView, inst: HighLevelILInstruction):
			>>> 	log_info(f"My plugin was called on inst {inst} in bv `{bv}`")
			>>> PluginCommand.register_for_low_level_il_instruction("My Plugin", "My plugin description (not used)", my_plugin)
			True
			>>> def is_valid(bv: BinaryView, inst: HighLevelILInstruction) -> bool:
			>>> 	return False
			>>> PluginCommand.register_for_low_level_il_instruction("My Plugin (With Valid Function)", "My plugin description (not used)", my_plugin, is_valid)
			True

		.. warning:: Calling ``register_for_high_level_il_instruction`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(
		    None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNHighLevelILFunction),
		    ctypes.c_ulonglong
		)(lambda ctxt, view, func, instr: cls._high_level_il_instruction_action(view, func, instr, action))
		is_valid_obj = ctypes.CFUNCTYPE(
		    ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView),
		    ctypes.POINTER(core.BNHighLevelILFunction), ctypes.c_ulonglong
		)(lambda ctxt, view, func, instr: cls._high_level_il_instruction_is_valid(view, func, instr, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForHighLevelILInstruction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def get_valid_list(cls, context):
		"""Dict of registered plugins"""
		commands = list(cls)
		result = {}
		for cmd in commands:
			if cmd.is_valid(context):
				result[cmd.name] = cmd
		return result

	def is_valid(self, context):
		if context.view is None:
			return False
		if self._command.type == PluginCommandType.DefaultPluginCommand:
			if not self._command.defaultIsValid:
				return True
			return self._command.defaultIsValid(self._command.context, context.view.handle)
		elif self._command.type == PluginCommandType.AddressPluginCommand:
			if not self._command.addressIsValid:
				return True
			return self._command.addressIsValid(self._command.context, context.view.handle, context.address)
		elif self._command.type == PluginCommandType.RangePluginCommand:
			if context.length == 0:
				return False
			if not self._command.rangeIsValid:
				return True
			return self._command.rangeIsValid(
			    self._command.context, context.view.handle, context.address, context.length
			)
		elif self._command.type == PluginCommandType.FunctionPluginCommand:
			if context.function is None:
				return False
			if not self._command.functionIsValid:
				return True
			return self._command.functionIsValid(self._command.context, context.view.handle, context.function.handle)
		elif self._command.type == PluginCommandType.LowLevelILFunctionPluginCommand:
			if context.function is None:
				return False
			if not self._command.lowLevelILFunctionIsValid:
				return True
			return self._command.lowLevelILFunctionIsValid(
			    self._command.context, context.view.handle, context.function.handle
			)
		elif self._command.type == PluginCommandType.LowLevelILInstructionPluginCommand:
			if context.instruction is None:
				return False
			if not isinstance(context.instruction, lowlevelil.LowLevelILInstruction):
				return False
			if not self._command.lowLevelILInstructionIsValid:
				return True
			return self._command.lowLevelILInstructionIsValid(
			    self._command.context, context.view.handle, context.instruction.function.handle,
			    context.instruction.instr_index
			)
		elif self._command.type == PluginCommandType.MediumLevelILFunctionPluginCommand:
			if context.function is None:
				return False
			if not self._command.mediumLevelILFunctionIsValid:
				return True
			return self._command.mediumLevelILFunctionIsValid(
			    self._command.context, context.view.handle, context.function.handle
			)
		elif self._command.type == PluginCommandType.MediumLevelILInstructionPluginCommand:
			if context.instruction is None:
				return False
			if not isinstance(context.instruction, mediumlevelil.MediumLevelILInstruction):
				return False
			if not self._command.mediumLevelILInstructionIsValid:
				return True
			return self._command.mediumLevelILInstructionIsValid(
			    self._command.context, context.view.handle, context.instruction.function.handle,
			    context.instruction.instr_index
			)
		elif self._command.type == PluginCommandType.HighLevelILFunctionPluginCommand:
			if context.function is None:
				return False
			if not self._command.highLevelILFunctionIsValid:
				return True
			return self._command.highLevelILFunctionIsValid(
			    self._command.context, context.view.handle, context.function.handle
			)
		elif self._command.type == PluginCommandType.HighLevelILInstructionPluginCommand:
			if context.instruction is None:
				return False
			if not isinstance(context.instruction, highlevelil.HighLevelILInstruction):
				return False
			if not self._command.highLevelILInstructionIsValid:
				return True
			return self._command.highLevelILInstructionIsValid(
			    self._command.context, context.view.handle, context.instruction.function.handle,
			    context.instruction.instr_index
			)
		return False

	def execute(self, context):
		r"""
		``execute`` Execute a Plugin

		:param str context: PluginCommandContext to pass the PluginCommand
		:rtype: None

			>>> ctx = PluginCommandContext(bv);
			>>> PluginCommand.get_valid_list(ctx)[r'PDB\Load'].execute(ctx)

		"""
		if not self.is_valid(context):
			return
		if self._command.type == PluginCommandType.DefaultPluginCommand:
			self._command.defaultCommand(self._command.context, context.view.handle)
		elif self._command.type == PluginCommandType.AddressPluginCommand:
			self._command.addressCommand(self._command.context, context.view.handle, context.address)
		elif self._command.type == PluginCommandType.RangePluginCommand:
			self._command.rangeCommand(self._command.context, context.view.handle, context.address, context.length)
		elif self._command.type == PluginCommandType.FunctionPluginCommand:
			self._command.functionCommand(self._command.context, context.view.handle, context.function.handle)
		elif self._command.type == PluginCommandType.LowLevelILFunctionPluginCommand:
			self._command.lowLevelILFunctionCommand(self._command.context, context.view.handle, context.function.handle)
		elif self._command.type == PluginCommandType.LowLevelILInstructionPluginCommand:
			self._command.lowLevelILInstructionCommand(
			    self._command.context, context.view.handle, context.instruction.function.handle,
			    context.instruction.instr_index
			)
		elif self._command.type == PluginCommandType.MediumLevelILFunctionPluginCommand:
			self._command.mediumLevelILFunctionCommand(
			    self._command.context, context.view.handle, context.function.handle
			)
		elif self._command.type == PluginCommandType.MediumLevelILInstructionPluginCommand:
			self._command.mediumLevelILInstructionCommand(
			    self._command.context, context.view.handle, context.instruction.function.handle,
			    context.instruction.instr_index
			)
		elif self._command.type == PluginCommandType.HighLevelILFunctionPluginCommand:
			self._command.highLevelILFunctionCommand(
			    self._command.context, context.view.handle, context.function.handle
			)
		elif self._command.type == PluginCommandType.HighLevelILInstructionPluginCommand:
			self._command.highLevelILInstructionCommand(
			    self._command.context, context.view.handle, context.instruction.function.handle,
			    context.instruction.instr_index
			)

	def __repr__(self):
		return "<PluginCommand: %s>" % self._name

	@property
	def command(self):
		return self._command

	@command.setter
	def command(self, value):
		self._command = value

	@property
	def name(self):
		return self._name

	@name.setter
	def name(self, value):
		self._name = value

	@property
	def description(self):
		return self._description

	@description.setter
	def description(self, value):
		self._description = value

	@property
	def type(self):
		return self._type

	@type.setter
	def type(self, value):
		self._type = value


class MainThreadAction:
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeMainThreadAction(self.handle)

	def execute(self):
		core.BNExecuteMainThreadAction(self.handle)

	@property
	def done(self):
		return core.BNIsMainThreadActionDone(self.handle)

	def wait(self):
		core.BNWaitForMainThreadAction(self.handle)


class MainThreadActionHandler:
	_main_thread = None

	def __init__(self):
		self._cb = core.BNMainThreadCallbacks()
		self._cb.context = 0
		self._cb.addAction = self._cb.addAction.__class__(self._add_action)

	def register(self):
		self.__class__._main_thread = self
		core.BNRegisterMainThread(self._cb)

	def _add_action(self, ctxt, action):
		try:
			self.add_action(MainThreadAction(action))
		except:
			log_error(traceback.format_exc())

	def add_action(self, action):
		pass


class _BackgroundTaskMetaclass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		tasks = core.BNGetRunningBackgroundTasks(count)
		assert tasks is not None, "core.BNGetRunningBackgroundTasks returned None"
		try:
			for i in range(0, count.value):
				yield BackgroundTask(handle=core.BNNewBackgroundTaskReference(tasks[i]))
		finally:
			core.BNFreeBackgroundTaskList(tasks, count.value)


class BackgroundTask(metaclass=_BackgroundTaskMetaclass):
	"""
	The ``BackgroundTask`` class provides a mechanism for reporting progress of
	an optionally cancelable task to the user via the status bar in the UI.
	If ``can_cancel`` is is `True`, then the task can be cancelled either
	programmatically (via :py:meth:`.cancel`) or by the user via the UI.

	Note this class does not provide a means to execute a task, which is
	available via the :py:class:`.BackgroundTaskThread` class.

	:param initial_progress_text: text description of the task to display in the status bar in the UI, defaults to `""`
	:param can_cancel: whether to enable cancellation of the task, defaults to `False`
	"""
	def __init__(self, initial_progress_text="", can_cancel=False, handle=None):
		if handle is None:
			self.handle = core.BNBeginBackgroundTask(initial_progress_text, can_cancel)
		else:
			self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeBackgroundTask(self.handle)

	@property
	def progress(self):
		"""Text description of the progress of the background task (displayed in status bar of the UI)"""
		return core.BNGetBackgroundTaskProgressText(self.handle)

	@progress.setter
	def progress(self, value):
		core.BNSetBackgroundTaskProgressText(self.handle, str(value))

	@property
	def can_cancel(self):
		"""Whether the task can be cancelled (read-only)"""
		return core.BNCanCancelBackgroundTask(self.handle)

	@property
	def finished(self):
		"""Whether the task has finished"""
		return core.BNIsBackgroundTaskFinished(self.handle)

	@finished.setter
	def finished(self, value):
		if value:
			self.finish()

	def finish(self):
		core.BNFinishBackgroundTask(self.handle)

	@property
	def cancelled(self):
		"""Whether the task has been cancelled"""
		return core.BNIsBackgroundTaskCancelled(self.handle)

	@cancelled.setter
	def cancelled(self, value):
		if value:
			self.cancel()

	def cancel(self):
		core.BNCancelBackgroundTask(self.handle)


class BackgroundTaskThread(BackgroundTask):
	"""
	The ``BackgroundTaskThread`` class provides an all-in-one solution for executing a :py:class:`.BackgroundTask`
	in a thread.

	See the :py:class:`.BackgroundTask` for additional information.

	:param initial_progress_text: text description of the task to display in the status bar in the UI, defaults to `""`
	:param can_cancel: whether to enable cancellation of the task, defaults to `False`
	"""
	def __init__(self, initial_progress_text: str = "", can_cancel: bool = False):
		class _Thread(threading.Thread):
			def __init__(self, task: 'BackgroundTaskThread'):
				threading.Thread.__init__(self)
				self.task = task

			def run(self):
				if self.task is None:
					raise Exception("Can not call run more than once per thread")
				try:
					self.task.run()
				finally:
					self.task.finish()
					self.task = None

		BackgroundTask.__init__(self, initial_progress_text, can_cancel)
		self.thread = _Thread(self)

	def run(self):
		pass

	def start(self):
		self.thread.start()

	def join(self, timeout=None):
		self.thread.join(timeout)
