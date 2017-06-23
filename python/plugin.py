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
import _binaryninjacore as core
from enums import PluginCommandType
import startup
import filemetadata
import binaryview
import function
import log


class PluginCommandContext(object):
	def __init__(self, view):
		self.view = view
		self.address = 0
		self.length = 0
		self.function = None


class _PluginCommandMetaClass(type):
	@property
	def list(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		commands = core.BNGetAllPluginCommands(count)
		result = []
		for i in xrange(0, count.value):
			result.append(PluginCommand(commands[i]))
		core.BNFreePluginCommandList(commands)
		return result

	def __iter__(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		commands = core.BNGetAllPluginCommands(count)
		try:
			for i in xrange(0, count.value):
				yield PluginCommand(commands[i])
		finally:
			core.BNFreePluginCommandList(commands)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class PluginCommand(object):
	_registered_commands = []
	__metaclass__ = _PluginCommandMetaClass

	def __init__(self, cmd):
		self.command = core.BNPluginCommand()
		ctypes.memmove(ctypes.byref(self.command), ctypes.byref(cmd), ctypes.sizeof(core.BNPluginCommand))
		self.name = str(cmd.name)
		self.description = str(cmd.description)
		self.type = PluginCommandType(cmd.type)

	@classmethod
	def _default_action(cls, view, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			action(view_obj)
		except:
			log.log_error(traceback.format_exc())

	@classmethod
	def _address_action(cls, view, addr, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			action(view_obj, addr)
		except:
			log.log_error(traceback.format_exc())

	@classmethod
	def _range_action(cls, view, addr, length, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			action(view_obj, addr, length)
		except:
			log.log_error(traceback.format_exc())

	@classmethod
	def _function_action(cls, view, func, action):
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			func_obj = function.Function(view_obj, core.BNNewFunctionReference(func))
			action(view_obj, func_obj)
		except:
			log.log_error(traceback.format_exc())

	@classmethod
	def _default_is_valid(cls, view, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			return is_valid(view_obj)
		except:
			log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _address_is_valid(cls, view, addr, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			return is_valid(view_obj, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _range_is_valid(cls, view, addr, length, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			return is_valid(view_obj, addr, length)
		except:
			log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _function_is_valid(cls, view, func, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(view))
			func_obj = function.Function(view_obj, core.BNNewFunctionReference(func))
			return is_valid(view_obj, func_obj)
		except:
			log.log_error(traceback.format_exc())
			return False

	@classmethod
	def register(cls, name, description, action, is_valid = None):
		startup._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView))(lambda ctxt, view: cls._default_action(view, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView))(lambda ctxt, view: cls._default_is_valid(view, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommand(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_address(cls, name, description, action, is_valid = None):
		startup._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong)(lambda ctxt, view, addr: cls._address_action(view, addr, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong)(lambda ctxt, view, addr: cls._address_is_valid(view, addr, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForAddress(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_range(cls, name, description, action, is_valid = None):
		startup._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong, ctypes.c_ulonglong)(lambda ctxt, view, addr, length: cls._range_action(view, addr, length, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong, ctypes.c_ulonglong)(lambda ctxt, view, addr, length: cls._range_is_valid(view, addr, length, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForRange(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_function(cls, name, description, action, is_valid = None):
		startup._init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNFunction))(lambda ctxt, view, func: cls._function_action(view, func, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNFunction))(lambda ctxt, view, func: cls._function_is_valid(view, func, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForFunction(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def get_valid_list(cls, context):
		commands = cls.list
		result = []
		for cmd in commands:
			if cmd.is_valid(context):
				result.append(cmd)
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
			log.log_error(traceback.format_exc())

	def add_action(self, action):
		pass


class _BackgroundTaskMetaclass(type):
	@property
	def list(self):
		"""List all running background tasks (read-only)"""
		count = ctypes.c_ulonglong()
		tasks = core.BNGetRunningBackgroundTasks(count)
		result = []
		for i in xrange(0, count.value):
			result.append(BackgroundTask(core.BNNewBackgroundTaskReference(tasks[i])))
		core.BNFreeBackgroundTaskList(tasks)
		return result

	def __iter__(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		tasks = core.BNGetRunningBackgroundTasks(count)
		try:
			for i in xrange(0, count.value):
				yield BackgroundTask(core.BNNewBackgroundTaskReference(tasks[i]))
		finally:
			core.BNFreeBackgroundTaskList(tasks)


class BackgroundTask(object):
	__metaclass__ = _BackgroundTaskMetaclass

	def __init__(self, initial_progress_text = "", can_cancel = False, handle = None):
		if handle is None:
			self.handle = core.BNBeginBackgroundTask(initial_progress_text, can_cancel)
		else:
			self.handle = handle

	def __del__(self):
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
