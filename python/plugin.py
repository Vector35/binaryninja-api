# Copyright (c) 2015-2017 Vector 35 LLC
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

# Binary Ninja components
import binaryninja
from binaryninja import _binaryninjacore as core
from binaryninja.enums import PluginCommandType
from binaryninja import filemetadata
from binaryninja import binaryview
from binaryninja import function

# 2-3 compatibility
from binaryninja import range
from binaryninja import with_metaclass


class PluginCommandContext(object):
	def __init__(self, view):
		self.view = view
		self.address = 0
		self.length = 0
		self.function = None
		self.instruction = None


class _PluginCommandMetaClass(type):
	@property
	def list(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		commands = core.BNGetAllPluginCommands(count)
		result = []
		for i in range(0, count.value):
			result.append(PluginCommand(commands[i]))
		core.BNFreePluginCommandList(commands)
		return result

	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		commands = core.BNGetAllPluginCommands(count)
		try:
			for i in range(0, count.value):
				yield PluginCommand(commands[i])
		finally:
			core.BNFreePluginCommandList(commands)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class PluginCommand(with_metaclass(_PluginCommandMetaClass, object)):
	_registered_commands = []

	def __init__(self, cmd):
		self.command = core.BNPluginCommand()
		ctypes.memmove(ctypes.byref(self.command), ctypes.byref(cmd), ctypes.sizeof(core.BNPluginCommand))
		self.name = str(cmd.name)
		self.description = str(cmd.description)
		self.type = PluginCommandType(cmd.type)

	@property
	def list(self):
		"""Allow tab completion to discover metaclass list property"""
		pass

	@classmethod
	def _default_action(cls, view, action):
		try:
			file_metadata = binaryninja.filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryninja.binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			action(view_obj)
		except:
			binaryninja.log.log_error(traceback.format_exc())

	@classmethod
	def _address_action(cls, view, addr, action):
		try:
			file_metadata = binaryninja.filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryninja.binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			action(view_obj, addr)
		except:
			binaryninja.log.log_error(traceback.format_exc())

	@classmethod
	def _range_action(cls, view, addr, length, action):
		try:
			file_metadata = binaryninja.filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryninja.binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			action(view_obj, addr, length)
		except:
			binaryninja.log.log_error(traceback.format_exc())

	@classmethod
	def _function_action(cls, view, func, action):
		try:
			file_metadata = binaryninja.filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryninja.binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			func_obj = function.Function(view_obj, core.BNNewFunctionReference(func))
			action(view_obj, func_obj)
		except:
			binaryninja.log.log_error(traceback.format_exc())

	@classmethod
	def _low_level_il_function_action(cls, view, func, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetLowLevelILOwnerFunction(func))
			func_obj = binaryninja.lowlevelil.LowLevelILFunction(owner.arch, core.BNNewLowLevelILFunctionReference(func), owner)
			action(view_obj, func_obj)
		except:
			binaryninja.log.log_error(traceback.format_exc())

	@classmethod
	def _low_level_il_instruction_action(cls, view, func, instr, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetLowLevelILOwnerFunction(func))
			func_obj = binaryninja.lowlevelil.LowLevelILFunction(owner.arch, core.BNNewLowLevelILFunctionReference(func), owner)
			action(view_obj, func_obj[instr])
		except:
			binaryninja.log.log_error(traceback.format_exc())

	@classmethod
	def _medium_level_il_function_action(cls, view, func, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetMediumLevelILOwnerFunction(func))
			func_obj = binaryninja.mediumlevelil.MediumLevelILFunction(owner.arch, core.BNNewMediumLevelILFunctionReference(func), owner)
			action(view_obj, func_obj)
		except:
			binaryninja.log.log_error(traceback.format_exc())

	@classmethod
	def _medium_level_il_instruction_action(cls, view, func, instr, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetMediumLevelILOwnerFunction(func))
			func_obj = binaryninja.mediumlevelil.MediumLevelILFunction(owner.arch, core.BNNewMediumLevelILFunctionReference(func), owner)
			action(view_obj, func_obj[instr])
		except:
			binaryninja.log.log_error(traceback.format_exc())

	@classmethod
	def _default_is_valid(cls, view, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = binaryninja.filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryninja.binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			return is_valid(view_obj)
		except:
			binaryninja.log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _address_is_valid(cls, view, addr, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = binaryninja.filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryninja.binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			return is_valid(view_obj, addr)
		except:
			binaryninja.log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _range_is_valid(cls, view, addr, length, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = binaryninja.filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryninja.binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			return is_valid(view_obj, addr, length)
		except:
			binaryninja.log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _function_is_valid(cls, view, func, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = binaryninja.filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryninja.binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			func_obj = function.Function(view_obj, core.BNNewFunctionReference(func))
			return is_valid(view_obj, func_obj)
		except:
			binaryninja.log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _low_level_il_function_is_valid(cls, view, func, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetLowLevelILOwnerFunction(func))
			func_obj = binaryninja.lowlevelil.LowLevelILFunction(owner.arch, core.BNNewLowLevelILFunctionReference(func), owner)
			return is_valid(view_obj, func_obj)
		except:
			binaryninja.log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _low_level_il_instruction_is_valid(cls, view, func, instr, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetLowLevelILOwnerFunction(func))
			func_obj = binaryninja.lowlevelil.LowLevelILFunction(owner.arch, core.BNNewLowLevelILFunctionReference(func), owner)
			return is_valid(view_obj, func_obj[instr])
		except:
			binaryninja.log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _medium_level_il_function_is_valid(cls, view, func, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetMediumLevelILOwnerFunction(func))
			func_obj = binaryninja.mediumlevelil.MediumLevelILFunction(owner.arch, core.BNNewMediumLevelILFunctionReference(func), owner)
			return is_valid(view_obj, func_obj)
		except:
			binaryninja.log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _medium_level_il_instruction_is_valid(cls, view, func, instr, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			owner = function.Function(view_obj, core.BNGetMediumLevelILOwnerFunction(func))
			func_obj = binaryninja.mediumlevelil.MediumLevelILFunction(owner.arch, core.BNNewMediumLevelILFunctionReference(func), owner)
			return is_valid(view_obj, func_obj[instr])
		except:
			binaryninja.log.log_error(traceback.format_exc())
			return False

	@classmethod
	def register(cls, name, description, action, is_valid = None):
		"""
		``register`` Register a plugin

		:param str name: name of the plugin
		:param str description: description of the plugin
		:param action: function to call with the ``BinaryView`` as an argument
		:param is_valid: optional argument of a function passed a ``BinaryView`` to determine whether the plugin should be enabled for that view
		:rtype: None

		.. warning:: Calling ``register`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView))(lambda ctxt, view: cls._default_action(view, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView))(lambda ctxt, view: cls._default_is_valid(view, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommand(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_address(cls, name, description, action, is_valid = None):
		"""
		``register_for_address`` Register a plugin to be called with an address argument

		:param str name: name of the plugin
		:param str description: description of the plugin
		:param action: function to call with the ``BinaryView`` and address as arguments
		:param is_valid: optional argument of a function passed a ``BinaryView`` to determine whether the plugin should be enabled for that view
		:rtype: None

		.. warning:: Calling ``register_for_address`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong)(lambda ctxt, view, addr: cls._address_action(view, addr, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong)(lambda ctxt, view, addr: cls._address_is_valid(view, addr, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForAddress(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_range(cls, name, description, action, is_valid = None):
		"""
		``register_for_range`` Register a plugin to be called with a range argument

		:param str name: name of the plugin
		:param str description: description of the plugin
		:param action: function to call with the ``BinaryView`` and ``AddressRange`` as arguments
		:param is_valid: optional argument of a function passed a ``BinaryView`` to determine whether the plugin should be enabled for that view
		:rtype: None

		.. warning:: Calling ``register_for_range`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong, ctypes.c_ulonglong)(lambda ctxt, view, addr, length: cls._range_action(view, addr, length, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong, ctypes.c_ulonglong)(lambda ctxt, view, addr, length: cls._range_is_valid(view, addr, length, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForRange(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_function(cls, name, description, action, is_valid = None):
		"""
		``register_for_function`` Register a plugin to be called with a function argument

		:param str name: name of the plugin
		:param str description: description of the plugin
		:param action: function to call with the ``BinaryView`` and a ``Function`` as arguments
		:param is_valid: optional argument of a function passed a ``BinaryView`` to determine whether the plugin should be enabled for that view
		:rtype: None

		.. warning:: Calling ``register_for_function`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNFunction))(lambda ctxt, view, func: cls._function_action(view, func, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNFunction))(lambda ctxt, view, func: cls._function_is_valid(view, func, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForFunction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_low_level_il_function(cls, name, description, action, is_valid = None):
		"""
		``register_for_low_level_il_function`` Register a plugin to be called with a low level IL function argument

		:param str name: name of the plugin
		:param str description: description of the plugin
		:param action: function to call with the ``BinaryView`` and a ``LowLevelILFunction`` as arguments
		:param is_valid: optional argument of a function passed a ``BinaryView`` to determine whether the plugin should be enabled for that view
		:rtype: None

		.. warning:: Calling ``register_for_low_level_il_function`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNLowLevelILFunction))(lambda ctxt, view, func: cls._low_level_il_function_action(view, func, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNLowLevelILFunction))(lambda ctxt, view, func: cls._low_level_il_function_is_valid(view, func, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForLowLevelILFunction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_low_level_il_instruction(cls, name, description, action, is_valid = None):
		"""
		``register_for_low_level_il_instruction`` Register a plugin to be called with a low level IL instruction argument

		:param str name: name of the plugin
		:param str description: description of the plugin
		:param action: function to call with the ``BinaryView`` and a ``LowLevelILInstruction`` as arguments
		:param is_valid: optional argument of a function passed a ``BinaryView`` to determine whether the plugin should be enabled for that view
		:rtype: None

		.. warning:: Calling ``register_for_low_level_il_instruction`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNLowLevelILFunction), ctypes.c_ulonglong)(lambda ctxt, view, func, instr: cls._low_level_il_instruction_action(view, func, instr, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNLowLevelILFunction), ctypes.c_ulonglong)(lambda ctxt, view, func, instr: cls._low_level_il_instruction_is_valid(view, func, instr, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForLowLevelILInstruction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_medium_level_il_function(cls, name, description, action, is_valid = None):
		"""
		``register_for_medium_level_il_function`` Register a plugin to be called with a medium level IL function argument

		:param str name: name of the plugin
		:param str description: description of the plugin
		:param action: function to call with the ``BinaryView`` and a ``MediumLevelILFunction`` as arguments
		:param is_valid: optional argument of a function passed a ``BinaryView`` to determine whether the plugin should be enabled for that view
		:rtype: None

		.. warning:: Calling ``register_for_medium_level_il_function`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNMediumLevelILFunction))(lambda ctxt, view, func: cls._medium_level_il_function_action(view, func, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNMediumLevelILFunction))(lambda ctxt, view, func: cls._medium_level_il_function_is_valid(view, func, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForMediumLevelILFunction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_medium_level_il_instruction(cls, name, description, action, is_valid = None):
		"""
		``register_for_medium_level_il_instruction`` Register a plugin to be called with a medium level IL instruction argument

		:param str name: name of the plugin
		:param str description: description of the plugin
		:param action: function to call with the ``BinaryView`` and a ``MediumLevelILInstruction`` as arguments
		:param is_valid: optional argument of a function passed a ``BinaryView`` to determine whether the plugin should be enabled for that view
		:rtype: None

		.. warning:: Calling ``register_for_medium_level_il_instruction`` with the same function name will replace the existing function but will leak the memory of the original plugin.
		"""
		binaryninja._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNMediumLevelILFunction), ctypes.c_ulonglong)(lambda ctxt, view, func, instr: cls._medium_level_il_instruction_action(view, func, instr, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNMediumLevelILFunction), ctypes.c_ulonglong)(lambda ctxt, view, func, instr: cls._medium_level_il_instruction_is_valid(view, func, instr, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForMediumLevelILInstruction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def get_valid_list(cls, context):
		"""Dict of registered plugins"""
		commands = cls.list
		result = {}
		for cmd in commands:
			if cmd.is_valid(context):
				result[cmd.name] = cmd
		return result

	def is_valid(self, context):
		if context.view is None:
			return False
		if self.command.type == PluginCommandType.DefaultPluginCommand:
			if not self.command.defaultIsValid:
				return True
			return self.command.defaultIsValid(self.command.context, context.view.handle)
		elif self.command.type == PluginCommandType.AddressPluginCommand:
			if not self.command.addressIsValid:
				return True
			return self.command.addressIsValid(self.command.context, context.view.handle, context.address)
		elif self.command.type == PluginCommandType.RangePluginCommand:
			if context.length == 0:
				return False
			if not self.command.rangeIsValid:
				return True
			return self.command.rangeIsValid(self.command.context, context.view.handle, context.address, context.length)
		elif self.command.type == PluginCommandType.FunctionPluginCommand:
			if context.function is None:
				return False
			if not self.command.functionIsValid:
				return True
			return self.command.functionIsValid(self.command.context, context.view.handle, context.function.handle)
		elif self.command.type == PluginCommandType.LowLevelILFunctionPluginCommand:
			if context.function is None:
				return False
			if not self.command.lowLevelILFunctionIsValid:
				return True
			return self.command.lowLevelILFunctionIsValid(self.command.context, context.view.handle, context.function.handle)
		elif self.command.type == PluginCommandType.LowLevelILInstructionPluginCommand:
			if context.instruction is None:
				return False
			if not isinstance(context.instruction, binaryninja.lowlevelil.LowLevelILInstruction):
				return False
			if not self.command.lowLevelILInstructionIsValid:
				return True
			return self.command.lowLevelILInstructionIsValid(self.command.context, context.view.handle,
				context.instruction.function.handle, context.instruction.instr_index)
		elif self.command.type == PluginCommandType.MediumLevelILFunctionPluginCommand:
			if context.function is None:
				return False
			if not self.command.mediumLevelILFunctionIsValid:
				return True
			return self.command.mediumLevelILFunctionIsValid(self.command.context, context.view.handle, context.function.handle)
		elif self.command.type == PluginCommandType.MediumLevelILInstructionPluginCommand:
			if context.instruction is None:
				return False
			if not isinstance(context.instruction, binaryninja.mediumlevelil.MediumLevelILInstruction):
				return False
			if not self.command.mediumLevelILInstructionIsValid:
				return True
			return self.command.mediumLevelILInstructionIsValid(self.command.context, context.view.handle,
				context.instruction.function.handle, context.instruction.instr_index)
		return False

	def execute(self, context):
		if not self.is_valid(context):
			return
		if self.command.type == PluginCommandType.DefaultPluginCommand:
			self.command.defaultCommand(self.command.context, context.view.handle)
		elif self.command.type == PluginCommandType.AddressPluginCommand:
			self.command.addressCommand(self.command.context, context.view.handle, context.address)
		elif self.command.type == PluginCommandType.RangePluginCommand:
			self.command.rangeCommand(self.command.context, context.view.handle, context.address, context.length)
		elif self.command.type == PluginCommandType.FunctionPluginCommand:
			self.command.functionCommand(self.command.context, context.view.handle, context.function.handle)
		elif self.command.type == PluginCommandType.LowLevelILFunctionPluginCommand:
			self.command.lowLevelILFunctionCommand(self.command.context, context.view.handle, context.function.handle)
		elif self.command.type == PluginCommandType.LowLevelILInstructionPluginCommand:
			self.command.lowLevelILInstructionCommand(self.command.context, context.view.handle,
				context.instruction.function.handle, context.instruction.instr_index)
		elif self.command.type == PluginCommandType.MediumLevelILFunctionPluginCommand:
			self.command.mediumLevelILFunctionCommand(self.command.context, context.view.handle, context.function.handle)
		elif self.command.type == PluginCommandType.MediumLevelILInstructionPluginCommand:
			self.command.mediumLevelILInstructionCommand(self.command.context, context.view.handle,
				context.instruction.function.handle, context.instruction.instr_index)

	def __repr__(self):
		return "<PluginCommand: %s>" % self.name


class MainThreadAction(object):
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		core.BNFreeMainThreadAction(self.handle)

	def execute(self):
		core.BNExecuteMainThreadAction(self.handle)

	@property
	def done(self):
		return core.BNIsMainThreadActionDone(self.handle)

	def wait(self):
		core.BNWaitForMainThreadAction(self.handle)


class MainThreadActionHandler(object):
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
			binaryninja.log.log_error(traceback.format_exc())

	def add_action(self, action):
		pass


class _BackgroundTaskMetaclass(type):
	@property
	def list(self):
		"""List all running background tasks (read-only)"""
		count = ctypes.c_ulonglong()
		tasks = core.BNGetRunningBackgroundTasks(count)
		result = []
		for i in range(0, count.value):
			result.append(BackgroundTask(handle=core.BNNewBackgroundTaskReference(tasks[i])))
		core.BNFreeBackgroundTaskList(tasks, count.value)
		return result

	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		tasks = core.BNGetRunningBackgroundTasks(count)
		try:
			for i in range(0, count.value):
				yield BackgroundTask(handle=core.BNNewBackgroundTaskReference(tasks[i]))
		finally:
			core.BNFreeBackgroundTaskList(tasks, count.value)


class BackgroundTask(with_metaclass(_BackgroundTaskMetaclass, object)):
	def __init__(self, initial_progress_text = "", can_cancel = False, handle = None):
		if handle is None:
			self.handle = core.BNBeginBackgroundTask(initial_progress_text, can_cancel)
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeBackgroundTask(self.handle)

	@property
	def list(self):
		"""Allow tab completion to discover metaclass list property"""
		pass

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
	def __init__(self, initial_progress_text = "", can_cancel = False):
		class _Thread(threading.Thread):
			def __init__(self, task):
				threading.Thread.__init__(self)
				self.task = task

			def run(self):
				self.task.run()
				self.task.finish()
				self.task = None

		BackgroundTask.__init__(self, initial_progress_text, can_cancel)
		self.thread = _Thread(self)

	def run(self):
		pass

	def start(self):
		self.thread.start()

	def join(self):
		self.thread.join()
