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

import abc
import code
import ctypes
import dataclasses
import importlib
import os
import re
import subprocess
import sys
import threading
import traceback

from collections.abc import Callable
from ctypes.util import find_library
from pathlib import Path
from typing import Generator, Optional, List, Tuple, Dict, Any
from typing import Type as TypeHintType

# Just windows things...
if sys.platform == "win32":
	from pydoc import help

# Binary Ninja components
import binaryninja
from . import bncompleter
from . import _binaryninjacore as core
from . import settings
from . import binaryview
from . import basicblock
from . import function
from .log import log_info, log_warn, log_error, is_output_redirected_to_log
from .pluginmanager import RepositoryManager
from .enums import ScriptingProviderExecuteResult, ScriptingProviderInputReadyState

_WARNING_REGEX = re.compile(r'^\S+:\d+: \w+Warning: ')

class _ThreadActionContext:
	_actions = []

	def __init__(self, func):
		self.func = func
		self.interpreter = None
		if hasattr(PythonScriptingInstance._interpreter, "value"):
			self.interpreter = PythonScriptingInstance._interpreter.value
		self.__class__._actions.append(self)
		self.callback = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(lambda ctxt: self.execute())

	def execute(self):
		old_interpreter = None
		if hasattr(PythonScriptingInstance._interpreter, "value"):
			old_interpreter = PythonScriptingInstance._interpreter.value
		PythonScriptingInstance._interpreter.value = self.interpreter
		try:
			self.func()
		finally:
			PythonScriptingInstance._interpreter.value = old_interpreter
			self.__class__._actions.remove(self)


class ScriptingOutputListener:
	def _register(self, handle):
		self._cb = core.BNScriptingOutputListener()
		self._cb.context = 0
		self._cb.output = self._cb.output.__class__(self._output)
		self._cb.warning = self._cb.warning.__class__(self._warning)
		self._cb.error = self._cb.error.__class__(self._error)
		self._cb.inputReadyStateChanged = self._cb.inputReadyStateChanged.__class__(self._input_ready_state_changed)
		core.BNRegisterScriptingInstanceOutputListener(handle, self._cb)

	def _unregister(self, handle):
		core.BNUnregisterScriptingInstanceOutputListener(handle, self._cb)

	def _output(self, ctxt, text):
		try:
			self.notify_output(text)
		except:
			log_error(traceback.format_exc())

	def _warning(self, ctxt, text):
		try:
			self.notify_warning(text)
		except:
			log_error(traceback.format_exc())


	def _error(self, ctxt, text):
		try:
			self.notify_error(text)
		except:
			log_error(traceback.format_exc())

	def _input_ready_state_changed(self, ctxt, state):
		try:
			self.notify_input_ready_state_changed(state)
		except:
			log_error(traceback.format_exc())

	def notify_output(self, text):
		pass

	def notify_warning(self, text):
		pass

	def notify_error(self, text):
		pass

	def notify_input_ready_state_changed(self, state):
		pass


class ScriptingInstance:
	_registered_instances = []

	def __init__(self, provider, handle=None):
		if handle is None:
			self._cb = core.BNScriptingInstanceCallbacks()
			self._cb.context = 0
			self._cb.externalRefTaken = self._cb.externalRefTaken.__class__(self._external_ref_taken)
			self._cb.externalRefReleased = self._cb.externalRefReleased.__class__(self._external_ref_released)
			self._cb.executeScriptInput = self._cb.executeScriptInput.__class__(self._execute_script_input)
			self._cb.executeScriptInputFromFilename = self._cb.executeScriptInputFromFilename.__class__(self._execute_script_input_from_filename)
			self._cb.cancelScriptInput = self._cb.cancelScriptInput.__class__(self._cancel_script_input)
			self._cb.releaseBinaryView = self._cb.releaseBinaryView.__class__(self._release_binary_view)
			self._cb.setCurrentBinaryView = self._cb.setCurrentBinaryView.__class__(self._set_current_binary_view)
			self._cb.setCurrentFunction = self._cb.setCurrentFunction.__class__(self._set_current_function)
			self._cb.setCurrentBasicBlock = self._cb.setCurrentBasicBlock.__class__(self._set_current_basic_block)
			self._cb.setCurrentAddress = self._cb.setCurrentAddress.__class__(self._set_current_address)
			self._cb.setCurrentSelection = self._cb.setCurrentSelection.__class__(self._set_current_selection)
			self._cb.completeInput = self._cb.completeInput.__class__(self._complete_input)
			self._cb.stop = self._cb.stop.__class__(self._stop)
			self._completed_input = None
			self.handle = core.BNInitScriptingInstance(provider.handle, self._cb)
			self.delimiters = ' \t\n`~!@#$%^&*()-=+{}\\|;:\'",<>/?'
		else:
			self.handle = core.handle_of_type(handle, core.BNScriptingInstance)
		self.listeners = []

	def __del__(self):
		if core is not None:
			core.BNFreeScriptingInstance(self.handle)

	def _external_ref_taken(self, ctxt):
		try:
			self.__class__._registered_instances.append(self)
		except:
			log_error(traceback.format_exc())

	def _external_ref_released(self, ctxt):
		try:
			self.__class__._registered_instances.remove(self)
		except:
			log_error(traceback.format_exc())

	def _execute_script_input(self, ctxt, text):
		try:
			return self.perform_execute_script_input(text)
		except:
			log_error(traceback.format_exc())
			return ScriptingProviderExecuteResult.InvalidScriptInput

	def _execute_script_input_from_filename(self, ctxt, filename):
		try:
			return self.perform_execute_script_input_from_filename(filename)
		except:
			log_error(traceback.format_exc())
			return ScriptingProviderExecuteResult.InvalidScriptInput

	def _cancel_script_input(self, ctxt):
		try:
			return self.perform_cancel_script_input()
		except:
			log_error(traceback.format_exc())
			return ScriptingProviderExecuteResult.ScriptExecutionCancelled

	def _release_binary_view(self, ctxt, view):
		try:
			binaryview.BinaryView._cache_remove(view)
		except:
			log_error(traceback.format_exc())

	def _set_current_binary_view(self, ctxt, view):
		try:
			if view:
				view = binaryview.BinaryView(handle=core.BNNewViewReference(view))
				binaryview.BinaryView._cache_insert(view)
			else:
				view = None
			self.perform_set_current_binary_view(view)
		except:
			log_error(traceback.format_exc())

	def _set_current_function(self, ctxt, func):
		try:
			if func:
				func = function.Function(handle=core.BNNewFunctionReference(func))
			else:
				func = None
			self.perform_set_current_function(func)
		except:
			log_error(traceback.format_exc())

	def _set_current_basic_block(self, ctxt, block):
		try:
			if block:
				func = core.BNGetBasicBlockFunction(block)
				if func is None:
					block = None
				else:
					core_block = core.BNNewBasicBlockReference(block)
					assert core_block is not None, "core.BNNewBasicBlockReference returned None"
					block = basicblock.BasicBlock(
					    core_block, binaryview.BinaryView(handle=core.BNGetFunctionData(func))
					)
					core.BNFreeFunction(func)
			else:
				block = None
			self.perform_set_current_basic_block(block)
		except:
			log_error(traceback.format_exc())

	def _set_current_address(self, ctxt, addr):
		try:
			self.perform_set_current_address(addr)
		except:
			log_error(traceback.format_exc())

	def _set_current_selection(self, ctxt, begin, end):
		try:
			self.perform_set_current_selection(begin, end)
		except:
			log_error(traceback.format_exc())

	def _complete_input(self, ctxt, text, state):
		try:
			if not isinstance(text, str):
				text = text.decode("utf-8")
			return core.BNAllocString(self.perform_complete_input(text, state))
		except:
			log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _stop(self, ctxt):
		try:
			self.perform_stop()
		except:
			log_error(traceback.format_exc())

	@abc.abstractmethod
	def perform_execute_script_input(self, text):
		return ScriptingProviderExecuteResult.InvalidScriptInput

	@abc.abstractmethod
	def perform_execute_script_input_from_filename(self, text):
		return ScriptingProviderExecuteResult.InvalidScriptInput

	@abc.abstractmethod
	def perform_cancel_script_input(self):
		return ScriptingProviderExecuteResult.ScriptExecutionCancelled

	@abc.abstractmethod
	def perform_set_current_binary_view(self, view):
		return NotImplemented

	@abc.abstractmethod
	def perform_set_current_function(self, func):
		return NotImplemented

	@abc.abstractmethod
	def perform_set_current_basic_block(self, block):
		return NotImplemented

	@abc.abstractmethod
	def perform_set_current_address(self, addr):
		return NotImplemented

	@abc.abstractmethod
	def perform_set_current_selection(self, begin, end):
		return NotImplemented

	@abc.abstractmethod
	def perform_complete_input(self, text: str, state) -> str:
		return NotImplemented

	@abc.abstractmethod
	def perform_stop(self):
		return NotImplemented

	@property
	def input_ready_state(self):
		return core.BNGetScriptingInstanceInputReadyState(self.handle)

	@input_ready_state.setter
	def input_ready_state(self, value):
		core.BNNotifyInputReadyStateForScriptingInstance(self.handle, value.value)

	def output(self, text):
		core.BNNotifyOutputForScriptingInstance(self.handle, text)

	def warning(self, text):
		core.BNNotifyWarningForScriptingInstance(self.handle, text)

	def error(self, text):
		core.BNNotifyErrorForScriptingInstance(self.handle, text)

	def execute_script_input(self, text):
		return core.BNExecuteScriptInput(self.handle, text)

	def execute_script_input_from_filename(self, filename):
		return core.BNExecuteScriptInputFromFilename(self.handle, filename)

	def cancel_script_input(self, text):
		return core.BNCancelScriptInput(self.handle)

	def set_current_binary_view(self, view):
		if view is not None:
			view = view.handle
		core.BNSetScriptingInstanceCurrentBinaryView(self.handle, view)

	def set_current_function(self, func):
		if func is not None:
			func = func.handle
		core.BNSetScriptingInstanceCurrentFunction(self.handle, func)

	def set_current_basic_block(self, block):
		if block is not None:
			block = block.handle
		core.BNSetScriptingInstanceCurrentBasicBlock(self.handle, block)

	def set_current_address(self, addr):
		core.BNSetScriptingInstanceCurrentAddress(self.handle, addr)

	def set_current_selection(self, begin, end):
		core.BNSetScriptingInstanceCurrentSelection(self.handle, begin, end)

	def complete_input(self, text, state):
		return core.BNScriptingInstanceCompleteInput(self.handle, text, state)

	def stop(self):
		core.BNStopScriptingInstance(self.handle)

	def register_output_listener(self, listener):
		listener._register(self.handle)
		self.listeners.append(listener)

	def unregister_output_listener(self, listener):
		if listener in self.listeners:
			listener._unregister(self.handle)
			self.listeners.remove(listener)

	@property
	def delimiters(self):
		return core.BNGetScriptingInstanceDelimiters(self.handle)

	@delimiters.setter
	def delimiters(self, value):
		core.BNSetScriptingInstanceDelimiters(self.handle, value)


class _ScriptingProviderMetaclass(type):
	def __iter__(self) -> Generator['ScriptingProvider', None, None]:
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetScriptingProviderList(count)
		assert types is not None, "core.BNGetScriptingProviderList returned None"
		try:
			for i in range(0, count.value):
				yield ScriptingProvider(types[i])
		finally:
			core.BNFreeScriptingProviderList(types)

	def __getitem__(self, value) -> 'ScriptingProvider':
		binaryninja._init_plugins()
		provider = core.BNGetScriptingProviderByName(str(value))
		if provider is None:
			raise KeyError("'%s' is not a valid scripting provider" % str(value))
		return ScriptingProvider(provider)


class ScriptingProvider(metaclass=_ScriptingProviderMetaclass):
	_registered_providers = []
	name = ''
	apiName = ''
	instance_class: Optional[TypeHintType[ScriptingInstance]] = None

	def __init__(self, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNScriptingProvider)
			self.__dict__["name"] = core.BNGetScriptingProviderName(handle)

	def register(self) -> None:
		self._cb = core.BNScriptingProviderCallbacks()
		self._cb.context = 0
		self._cb.createInstance = self._cb.createInstance.__class__(self._create_instance)
		self._cb.loadModule = self._cb.loadModule.__class__(self._load_module)
		self._cb.installModules = self._cb.installModules.__class__(self._install_modules)
		self._cb.moduleInstalled = self._cb.installModules.__class__(self._module_installed)
		self.handle = core.BNRegisterScriptingProvider(self.__class__.name, self.__class__.apiName, self._cb)
		self.__class__._registered_providers.append(self)

	def _create_instance(self, ctxt):
		try:
			assert self.__class__.instance_class is not None
			result = self.__class__.instance_class(self)  # type: ignore
			if result is None:
				return None
			script_instance = core.BNNewScriptingInstanceReference(result.handle)
			assert script_instance is not None, "core.BNNewScriptingInstanceReference returned None"
			return ctypes.cast(script_instance, ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	def create_instance(self) -> Optional[ScriptingInstance]:
		result = core.BNCreateScriptingProviderInstance(self.handle)
		if result is None:
			return None
		return ScriptingInstance(self, handle=result)

	def _load_module(self, ctx, repo_path: bytes, plugin_path: bytes, force: bool) -> bool:
		return False

	def _install_modules(self, ctx, modules: bytes) -> bool:
		return False

	def _module_installed(self, ctx, module: str) -> bool:
		return False


class _PythonScriptingInstanceOutput:
	def __init__(self, orig, is_error_output):
		self.orig = orig
		self.is_error_output = is_error_output
		self.buffer = ""
		self.encoding = 'UTF-8'
		self.errors = None
		self.mode = 'w'
		self.name = 'PythonScriptingInstanceOutput'
		self.newlines = None

	def close(self):
		pass

	def closed(self):
		return False

	def flush(self):
		pass

	def isatty(self):
		return False

	def next(self):
		raise IOError("File not open for reading")

	def read(self):
		raise IOError("File not open for reading")

	def readinto(self):
		raise IOError("File not open for reading")

	def readlines(self):
		raise IOError("File not open for reading")

	def seek(self):
		pass

	def softspace(self):
		return 0

	def truncate(self):
		pass

	def tell(self):
		return self.orig.tell()

	def writelines(self, lines):
		return self.write('\n'.join(lines))

	def write(self, data):
		interpreter = None
		if hasattr(PythonScriptingInstance._interpreter, "value"):
			interpreter = PythonScriptingInstance._interpreter.value

		if interpreter is None:
			if is_output_redirected_to_log():
				self.buffer += data
				while True:
					i = self.buffer.find('\n')
					if i == -1:
						break
					line = self.buffer[:i]
					self.buffer = self.buffer[i + 1:]

					if self.is_error_output:
						if _WARNING_REGEX.match(line):
							log_warn(line)
						else:
							log_error(line)
					else:
						log_info(line)
			else:
				self.orig.write(data)
		else:
			PythonScriptingInstance._interpreter.value = None
			try:
				if self.is_error_output:
					if _WARNING_REGEX.match(data):
						interpreter.instance.warning(data)
					else:
						interpreter.instance.error(data)
				else:
					interpreter.instance.output(data)
			finally:
				PythonScriptingInstance._interpreter.value = interpreter


class _PythonScriptingInstanceInput:
	def __init__(self, orig):
		self.orig = orig

	def isatty(self):
		return False

	def read(self, size):
		interpreter = None
		if hasattr(PythonScriptingInstance._interpreter, "value"):
			interpreter = PythonScriptingInstance._interpreter.value

		if interpreter is None:
			return self.orig.read(size)
		else:
			PythonScriptingInstance._interpreter.value = None
			try:
				result = interpreter.read(size)
			finally:
				PythonScriptingInstance._interpreter.value = interpreter
			return result

	def readline(self):
		interpreter = None
		if hasattr(PythonScriptingInstance._interpreter, "value"):
			interpreter = PythonScriptingInstance._interpreter.value

		if interpreter is None:
			return self.orig.readline()
		else:
			result = ""
			while True:
				data = interpreter.read(1)
				result += data
				if (len(data) == 0) or (data == "\n"):
					break
			return result


class BlacklistedDict(dict):
	def __init__(self, blacklist, *args):
		super(BlacklistedDict, self).__init__(*args)
		self.__blacklist = set(blacklist)
		self._blacklist_enabled = True

	def __setitem__(self, k, v):
		if self.blacklist_enabled and k in self.__blacklist:
			sys.stderr.write(
			    'Setting variable "{}" will have no affect as it is automatically controlled by the ScriptingProvider.\n'.
			    format(k)
			)
		super(BlacklistedDict, self).__setitem__(k, v)

	def enable_blacklist(self, enabled):
		self.__enable_blacklist = enabled

	def add_blacklist_item(self, item):
		self.__blacklist.add(item)

	def remove_blacklist_item(self, item):
		self.__blacklist.remove(item)

	def is_blacklisted_item(self, item):
		return item in self.__blacklist

	@property
	def blacklist_enabled(self):
		return self._blacklist_enabled

	@blacklist_enabled.setter
	def blacklist_enabled(self, value):
		self._blacklist_enabled = value


def bninspect(code_, globals_, locals_):
	"""
	``bninspect`` prints documentation about a command that is about to be run
	The interpreter will invoke this function if you input a line ending in `?` e.g. `bv?`

	:param str code_: Python code to be evaluated
	:param dict globals_: globals() from callsite
	:param dict locals_: locals() from callsite
	"""
	try:
		import inspect
		value = eval(code_, globals_, locals_)

		try:
			if not (inspect.ismethod(value) or inspect.isclass(value)):
				if isinstance(code_, bytes):
					code_ = code_.decode("utf-8")
				class_type_str = code_.split(".")[:-1]
				class_value = eval("type(" + ".".join(class_type_str) + ")." + code_.split(".")[-1], globals_, locals_)
				doc = inspect.getdoc(class_value)
				if doc is None:
					comments = inspect.getcomments(class_value)
					if comments is None:
						pass
					else:
						print(comments)
						return
				else:
					print(doc)
					return
		except:
			pass

		doc = inspect.getdoc(value)
		if doc is None:
			comments = inspect.getcomments(value)
			if comments is None:
				pass
			else:
				print(comments)
				return
		else:
			print(doc)
			return

		print(f"No documentation found for {code_}")
	except:
		# Hide exceptions so the normal execution can report them
		pass


class PythonScriptingInstance(ScriptingInstance):
	_interpreter = threading.local()

	class InterpreterThread(threading.Thread):
		def __init__(self, instance):
			super(PythonScriptingInstance.InterpreterThread, self).__init__()
			self.instance = instance
			blacklisted_vars = {
				"get_selected_data",
				"write_at_cursor",
			}
			self.locals = BlacklistedDict(
			    blacklisted_vars, {"__name__": "__console__", "__doc__": None, "binaryninja": sys.modules[__name__]}
			)
			self.cached_locals = {}
			self.interpreter = code.InteractiveConsole(self.locals)
			self.event = threading.Event()
			self.daemon = True

			# Latest selections from UI
			self.current_view = None
			self.current_func = None
			self.current_block = None
			self.current_addr = 0
			self.current_selection_begin = 0
			self.current_selection_end = 0
			self.current_dbg = None

			# Selections that were current as of last issued command
			self.active_view = None
			self.active_func = None
			self.active_block = None
			self.active_addr = 0
			self.active_selection_begin = 0
			self.active_selection_end = 0
			self.active_file_offset = None
			self.active_dbg = None
			self.active_il_index = 0
			self.selection_start_il_index = 0
			self.active_il_function = None

			self.update_magic_variables()

			self.locals.blacklist_enabled = False
			self.locals["get_selected_data"] = self.get_selected_data
			self.locals["write_at_cursor"] = self.write_at_cursor
			self.locals.blacklist_enabled = True

			self.exit = False
			self.code = None
			self.input = ""

			self.completer = bncompleter.Completer(namespace=self.locals)

			startup_file = os.path.join(binaryninja.user_directory(), "startup.py")
			if not os.path.isfile(startup_file):
				with open(startup_file, 'w') as f:
					f.write(
					    """# Commands in this file will be run in the interactive python console on startup
from binaryninja import *
"""
					)

			with open(startup_file, 'r') as f:
				self.interpreter.runsource(f.read(), filename="startup.py", symbol="exec")

		def update_magic_variables(self):
			for (name, var) in PythonScriptingProvider.magic_variables.items():
				if var.set_value is None:
					self.locals.add_blacklist_item(name)
				elif self.locals.is_blacklisted_item(name):
					self.locals.remove_blacklist_item(name)

		def execute(self, _code):
			self.code = _code
			self.event.set()

		def add_input(self, data):
			self.input = self.input + data.decode("utf-8")
			self.event.set()

		def end(self):
			self.exit = True
			self.event.set()

		def read(self, size):
			while not self.exit:
				if len(self.input) > size:
					result = self.input[:size]
					self.input = self.input[size:]
					return result
				elif len(self.input) > 0:
					result = self.input
					self.input = ""
					return result
				self.instance.input_ready_state = ScriptingProviderInputReadyState.ReadyForScriptProgramInput
				self.event.wait()
				self.event.clear()
			return ""

		def run(self):
			while not self.exit:
				self.event.wait()
				self.event.clear()
				if self.exit:
					break
				if self.code is not None:
					self.instance.input_ready_state = ScriptingProviderInputReadyState.NotReadyForInput
					_code = self.code
					self.code = None

					PythonScriptingInstance._interpreter.value = self
					try:
						try:
							self.update_locals()
						except:
							traceback.print_exc()

						if isinstance(_code, (lambda: 0).__code__.__class__):
							self.interpreter.runcode(_code)
							self.locals['__name__'] = '__console__'
							del self.locals['__file__']

						else:
							# If a single-line command ends in ?, show docs as well
							if _code[-2:] == b'?\n' and len(_code.split(b'\n')) < 3:
								escaped_code = repr(_code[:-2])
								self.interpreter.push(f'bninspect({escaped_code}, globals(), locals())\n')
								# Strip ? from the evaluated input
								_code = _code[:-2] + b'\n'

							for line in _code.split(b'\n'):
								self.interpreter.push(line.decode("utf-8"))

						self.apply_locals()

						if self.active_view is not None:
							self.active_view.update_analysis()
					except:
						traceback.print_exc()
					finally:
						PythonScriptingInstance._interpreter.value = None
						self.instance.input_ready_state = ScriptingProviderInputReadyState.ReadyForScriptExecution

		def update_locals(self):
			self.active_view = self.current_view
			self.active_func = self.current_func
			self.active_block = self.current_block
			self.active_addr = self.current_addr
			self.active_selection_begin = self.current_selection_begin
			self.active_selection_end = self.current_selection_end
			self.active_dbg = self.current_dbg

			self.locals.blacklist_enabled = False

			# Clear old values of magic variables first, so we don't update with stale data
			for name in PythonScriptingProvider.magic_variables.keys():
				if name in self.locals:
					del self.locals[name]

			# Apply registered magic variables
			vars = list(PythonScriptingProvider.magic_variables.items())
			used_vars = set()
			while len(vars) > 0:
				(name, var) = vars.pop(0)

				# Vars depending on others should make sure their deps have loaded first
				# TODO: Is this O(n^2)? Probably, but shouldn't be that big of a deal
				needs_deps = False
				for dep in var.depends_on:
					if dep in PythonScriptingProvider.magic_variables.keys() and dep not in used_vars:
						needs_deps = True
						break
				if needs_deps:
					# Add to the end and we'll get to it later
					vars.append((name, var))
					continue

				used_vars.add(name)

				try:
					value = var.get_value(self.instance)
				except:
					value = None
				self.locals[name] = value
				self.cached_locals[name] = value

			self.locals.blacklist_enabled = True

		def apply_locals(self):
			for (name, var) in PythonScriptingProvider.magic_variables.items():
				if var.set_value is None:
					continue

				old_value = self.cached_locals[name]
				new_value = self.locals[name]

				if old_value == new_value:
					continue

				try:
					var.set_value(self.instance, old_value, new_value)
				except:
					sys.stderr.write(f"Exception thrown trying to update variable:\n")
					traceback.print_exc(file=sys.stderr)

			self.cached_locals.clear()

		def get_selected_data(self):
			if self.active_view is None:
				return None
			length = self.active_selection_end - self.active_selection_begin
			return self.active_view.read(self.active_selection_begin, length)

		def write_at_cursor(self, data):
			if self.active_view is None:
				return 0
			selected_length = self.active_selection_end - self.active_selection_begin
			if (len(data) == selected_length) or (selected_length == 0):
				return self.active_view.write(self.active_selection_begin, data)
			else:
				self.active_view.remove(self.active_selection_begin, selected_length)
				return self.active_view.insert(self.active_selection_begin, data)

	def __init__(self, provider):
		super(PythonScriptingInstance, self).__init__(provider)
		self.interpreter = PythonScriptingInstance.InterpreterThread(self)
		self.interpreter.start()
		self.queued_input = ""
		self.input_ready_state = ScriptingProviderInputReadyState.ReadyForScriptExecution
		self.debugger_imported = False
		from binaryninja.settings import Settings
		if os.environ.get('BN_STANDALONE_DEBUGGER'):
			# By the time this scriptingprovider.py file is imported, the user plugins are not loaded yet.
			# So `from debugger import DebuggerController` would not work.
			from debugger import DebuggerController
			self.DebuggerController = DebuggerController
			self.debugger_imported = True
		else:
			settings = Settings()
			if settings.contains('corePlugins.debugger') and settings.get_bool('corePlugins.debugger') and \
				(os.environ.get('BN_DISABLE_CORE_DEBUGGER') is None):
				from .debugger import DebuggerController
				self.DebuggerController = DebuggerController
				self.debugger_imported = True

	@abc.abstractmethod
	def perform_stop(self):
		self.interpreter.end()

	@abc.abstractmethod
	def perform_execute_script_input(self, text):
		if self.input_ready_state == ScriptingProviderInputReadyState.NotReadyForInput:
			return ScriptingProviderExecuteResult.InvalidScriptInput

		if self.input_ready_state == ScriptingProviderInputReadyState.ReadyForScriptProgramInput:
			if len(text) == 0:
				return ScriptingProviderExecuteResult.SuccessfulScriptExecution
			self.input_ready_state = ScriptingProviderInputReadyState.NotReadyForInput
			self.interpreter.add_input(text)
			return ScriptingProviderExecuteResult.SuccessfulScriptExecution

		try:
			if isinstance(text, str):
				result = code.compile_command(text)
			else:
				result = code.compile_command(text.decode("utf-8"))
		except:
			result = False

		if result is None:
			# Command is not complete, ask for more input
			return ScriptingProviderExecuteResult.IncompleteScriptInput

		self.input_ready_state = ScriptingProviderInputReadyState.NotReadyForInput
		self.interpreter.execute(text)
		return ScriptingProviderExecuteResult.SuccessfulScriptExecution

	@abc.abstractmethod
	def perform_execute_script_input_from_filename(self, filename):
		if isinstance(filename, bytes):
			filename = filename.decode("utf-8")
		if not os.path.exists(filename) and os.path.isfile(filename):
			return ScriptingProviderExecuteResult.InvalidScriptInput  # TODO: maybe this isn't the best result to use?
		try:
			with open(filename, 'rb') as fp:
				file_contents = fp.read()
		except IOError:
			# File was not readable or something went horribly wrong
			return ScriptingProviderExecuteResult.InvalidScriptInput

		if len(file_contents) == 0:
			return ScriptingProviderExecuteResult.SuccessfulScriptExecution

		_code = code.compile_command(file_contents.decode('utf-8'), filename, 'exec')
		self.interpreter.locals['__file__'] = filename
		self.interpreter.locals['__name__'] = '__main__'
		self.interpreter.execute(_code)

		return ScriptingProviderExecuteResult.SuccessfulScriptExecution

	@abc.abstractmethod
	def perform_cancel_script_input(self):
		for tid, tobj in threading._active.items():  # type: ignore
			if tobj is self.interpreter:
				if ctypes.pythonapi.PyThreadState_SetAsyncExc(
				    ctypes.c_long(tid), ctypes.py_object(KeyboardInterrupt)
				) != 1:
					ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), None)
				break

	@abc.abstractmethod
	def perform_set_current_binary_view(self, view):
		self.interpreter.current_view = view
		if view is not None:
			if self.debugger_imported:
				self.interpreter.current_dbg = self.DebuggerController(view)

		else:
			self.interpreter.current_dbg = None

		# This is a workaround that allows BN to properly free up resources when the last tab of a binary view is closed.
		# Without this update, the interpreter local variables will NOT be updated until the user interacts with the
		# Python console for the next time, which means the relevant resources, e.g., the binary view is not freed until
		# then.
		# However, since perform_set_current_binary_view is called every time the user clicks in the UI, we would like
		# to avoid updating the local variables every time. So the compromise is to only do an explicit update when the
		# view is None.
		if view is None:
			try:
				self.interpreter.update_locals()
			except:
				traceback.print_exc()

	@abc.abstractmethod
	def perform_set_current_function(self, func):
		self.interpreter.current_func = func

	@abc.abstractmethod
	def perform_set_current_basic_block(self, block):
		self.interpreter.current_block = block

	@abc.abstractmethod
	def perform_set_current_address(self, addr):
		self.interpreter.current_addr = addr

	@abc.abstractmethod
	def perform_set_current_selection(self, begin, end):
		self.interpreter.current_selection_begin = begin
		self.interpreter.current_selection_end = end

	@abc.abstractmethod
	def perform_complete_input(self, text, state):
		try:
			self.interpreter.update_locals()
		except:
			traceback.print_exc()
		result = self.interpreter.completer.complete(text, state)
		if result is None:
			return ""
		return result


class PythonScriptingProvider(ScriptingProvider):
	name = "Python"
	apiName = f"python{sys.version_info.major}"  # Used for plugin compatibility testing
	instance_class: TypeHintType[PythonScriptingInstance] = PythonScriptingInstance
	magic_variables: Dict[str, 'MagicVariable'] = {}

	@dataclasses.dataclass
	class MagicVariable:
		"""
		Represents an automatically-populated (magic) variable in the python scripting console
		"""

		get_value: Callable[[PythonScriptingInstance], Any]
		"""
		Function to call, before every time a script is evaluated,
		to get the value of the variable
		"""

		set_value: Optional[Callable[[PythonScriptingInstance, Any, Any], None]]
		"""
		(Optional) function to call after a script is evaluated, if the value of the
		variable has changed during the course of the script. If None, a warning will be
		printed stating that the variable is read-only.
		Signature: (instance: PythonScriptingInstance, old_value: any, new_value: any) -> None
		"""

		depends_on: List[str]
		"""
		List of other variables whose values on which this variable's value depends
		"""

	@property
	def _python_bin(self) -> Optional[str]:
		python_lib = settings.Settings().get_string("python.interpreter")
		python_bin_override = settings.Settings().get_string("python.binaryOverride")
		python_env = self._get_python_environment(using_bundled_python=not python_lib)
		python_bin, status = self._get_executable_for_libpython(python_lib, python_bin_override, python_env=python_env)
		return python_bin

	def _load_module(self, ctx, _repo_path: bytes, _module: bytes, force: bool):
		repo_path = _repo_path.decode("utf-8")
		module = _module.decode("utf-8")
		try:
			repo = RepositoryManager()[repo_path]
			plugin = repo[module]

			if not force and self.apiName not in plugin.api:
				raise ValueError(f"Plugin API name is not {self.name}")

			if not force and core.core_platform not in plugin.install_platforms:
				raise ValueError(
				    f"Current platform {core.core_platform} isn't in list of valid platforms for this plugin {plugin.install_platforms}"
				)
			if not plugin.installed:
				plugin.installed = True

			plugin_full_path = str(Path(repo.full_path) / plugin.path)
			if repo.full_path not in sys.path:
				sys.path.append(repo.full_path)
			if plugin_full_path not in sys.path:
				sys.path.append(plugin_full_path)

			if plugin.subdir:
				__import__(module + "." + plugin.subdir.replace("/", "."))
			else:
				__import__(module)
			return True
		except KeyError:
			log_error(f"Failed to find python plugin: {repo_path}/{module}")
		except ImportError as ie:
			log_error(f"Failed to import python plugin: {repo_path}/{module}: {ie}")
		except binaryninja.UIPluginInHeadlessError:
			log_info(f"Ignored python UI plugin: {repo_path}/{module}")
		return False

	# This function can only be used to execute commands that return ASCII-only output, otherwise the decoding will fail
	def _run_args(self, args, env: Optional[Dict]=None):
		si = None
		if sys.platform == "win32":
			si = subprocess.STARTUPINFO()
			si.dwFlags |= subprocess.STARTF_USESHOWWINDOW

		try:
			return (True, subprocess.check_output(args, startupinfo=si, stderr=subprocess.STDOUT, env=env).decode("utf-8"))
		except subprocess.SubprocessError as se:
			return (False, str(se))

	def _pip_exists(self, python_bin: str, python_env: Optional[Dict]=None) -> bool:
		return self._run_args([python_bin, "-c", "import pip; pip.__version__"], env=python_env)[0]

	def _satisfied_dependencies(self, python_bin: str) -> Generator[str, None, None]:
		if python_bin is None:
			return None
		python_lib = settings.Settings().get_string("python.interpreter")
		python_env = self._get_python_environment(using_bundled_python=not python_lib)
		success, result = self._run_args([python_bin, "-m", "pip", "freeze"], env=python_env)
		if not success:
			return None
		for line in result.splitlines():
			yield line.split("==", 2)[0]

	def _bin_version(self, python_bin: str, python_env: Optional[Dict]=None):
		return self._run_args([
		    str(python_bin), "-c", "import sys; sys.stdout.write(f'{sys.version_info.major}.{sys.version_info.minor}')"
		], env=python_env)[1]

	def _get_executable_for_libpython(self, python_lib: str, python_bin: str, python_env: Optional[Dict]=None) -> Tuple[Optional[str], str]:
		python_lib_version = f"{sys.version_info.major}.{sys.version_info.minor}"
		if python_bin is not None and python_bin != "":
			python_bin_version = self._bin_version(python_bin, python_env=python_env)
			if python_lib_version != python_bin_version:
				return (
				    None,
				    f"Specified Python Binary Override is the wrong version. Expected: {python_lib_version} got: {python_bin_version}"
				)
			return (python_bin, "Success")

		using_bundled_python = not python_lib

		if sys.platform == "darwin":
			if using_bundled_python:
				python_bin = Path(binaryninja.get_install_directory()).parent / f"Frameworks/Python.framework/Versions/Current/bin/python3"
			else:
				python_bin = str(Path(python_lib).parent / f"bin/python{python_lib_version}")
		elif sys.platform == "linux":

			class Dl_info(ctypes.Structure):
				_fields_ = [("dli_fname", ctypes.c_char_p), ("dli_fbase", ctypes.c_void_p),
				            ("dli_sname", ctypes.c_char_p), ("dli_saddr", ctypes.c_void_p), ]

			def _linked_libpython():
				libdl = ctypes.CDLL(find_library("dl"))
				libdl.dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(Dl_info)]
				libdl.dladdr.restype = ctypes.c_int
				dlinfo = Dl_info()
				retcode = libdl.dladdr(
				    ctypes.cast(ctypes.pythonapi.Py_GetVersion, ctypes.c_void_p), ctypes.pointer(dlinfo)
				)
				if retcode == 0:  # means error
					return None
				return os.path.realpath(dlinfo.dli_fname.decode())

			if using_bundled_python:
				python_lib = _linked_libpython()
				if python_lib is None:
					return (
					    None,
					    "Failed: No python specified. Specify a full python installation in your 'Python Interpreter' and try again"
					)

			if python_lib == os.path.realpath(sys.executable):
				python_bin = python_lib
			else:
				python_path = Path(python_lib)
				for path in python_path.parents:
					if path.name in ["lib", "lib64"]:
						break
				else:
					return (None, f"Failed to find python binary from {python_lib}")

				python_bin = path.parent / f"bin/python{python_lib_version}"
		else:
			if using_bundled_python:
				python_bin = Path(binaryninja.get_install_directory()) / "plugins\\python\\python.exe"
			else:
				python_bin = Path(python_lib).parent / "python.exe"
		python_bin_version = self._bin_version(python_bin, python_env=python_env)
		if python_bin_version != python_lib_version:
			return (None, f"Failed: Python version not equal {python_bin_version} and {python_lib_version}")

		return (python_bin, "Success")

	def _get_python_environment(self, using_bundled_python: bool=False) -> Optional[Dict]:
		if using_bundled_python and sys.platform == "darwin":
			return {"PYTHONHOME": Path(binaryninja.get_install_directory()).parent / f"Resources/bundled-python3"}
		return None

	def _install_modules(self, ctx, _modules: bytes) -> bool:
		# This callback should not be called directly
		modules = _modules.decode("utf-8")
		if len(modules.strip()) == 0:
			return True
		python_lib = settings.Settings().get_string("python.interpreter")
		python_bin_override = settings.Settings().get_string("python.binaryOverride")
		python_env = self._get_python_environment(using_bundled_python=not python_lib)
		python_bin, status = self._get_executable_for_libpython(python_lib, python_bin_override, python_env=python_env)
		if python_bin is not None and not self._pip_exists(str(python_bin), python_env=python_env):
			log_error(
			    f"Pip not installed for configured python: {python_bin}.\n"
			    "Please install pip or switch python versions."
			)
			return False
		if python_bin is None:
			log_error(
			    f"Unable to discover python executable required for installing python modules: {status}\n"
			    "Please specify a path to a python binary in the 'Python Path Override'"
			)
			return False

		python_bin_version = subprocess.check_output([
		    python_bin, "-c", "import sys; sys.stdout.write(f'{sys.version_info.major}.{sys.version_info.minor}')"
		], env=python_env).decode("utf-8")
		python_lib_version = f"{sys.version_info.major}.{sys.version_info.minor}"
		if (python_bin_version != python_lib_version):
			log_error(
			    f"Python Binary Setting {python_bin_version} incompatible with python library {python_lib_version}"
			)
			return False

		args: List[str] = [str(python_bin), "-m", "pip", "--isolated", "--disable-pip-version-check"]
		proxy_settings = settings.Settings().get_string("network.httpsProxy")
		if proxy_settings:
			args.extend(["--proxy", proxy_settings])

		args.extend(["install", "--upgrade", "--upgrade-strategy", "only-if-needed"])
		venv = settings.Settings().get_string("python.virtualenv")
		in_virtual_env = 'VIRTUAL_ENV' in os.environ
		if venv is not None and venv.endswith("site-packages") and Path(venv).is_dir() and not in_virtual_env:
			args.extend(["--target", venv])
		else:
			user_dir = binaryninja.user_directory()
			if user_dir is None:
				raise Exception("Unable to find user directory.")
			site_package_dir = Path(
			    user_dir
			) / f"python{sys.version_info.major}{sys.version_info.minor}" / "site-packages"
			site_package_dir.mkdir(parents=True, exist_ok=True)
			args.extend(["--target", str(site_package_dir)])
		args.extend(list(filter(len, modules.split("\n"))))
		log_info(f"Running pip {args}")
		status, result = self._run_args(args, env=python_env)
		if status:
			importlib.invalidate_caches()
		else:
			log_error(f"Error while attempting to install requirements {result}")
		return status

	def _module_installed(self, ctx, module: str) -> bool:
		if self._python_bin is None:
			return False
		return re.split('>|=|,', module.strip(), 1)[0] in self._satisfied_dependencies(self._python_bin)

	@classmethod
	def register_magic_variable(
			cls,
			name: str,
			get_value: Callable[[PythonScriptingInstance], Any],
			set_value: Optional[Callable[[PythonScriptingInstance, Any, Any], None]] = None,
			depends_on: Optional[List[str]] = None
	):
		"""
		Add a magic variable to all scripting instances created by the scripting provider
		:param name: Variable name identifier to be used in the interpreter
		:param get_value: Function to call, before every time a script is evaluated,
		                  to get the value of the variable
		:param set_value: (Optional) Function to call after a script is evaluated, if the
		                  value of the variable has changed during the course of the script.
		                  If None, a warning will be printed stating that the variable is read-only.
		                  Signature:
		                  (instance: PythonScriptingInstance, old_value: any, new_value: any) -> None
		:param depends_on: List of other variables whose values on which this variable's value depends
		"""
		if depends_on is None:
			depends_on = []
		cls.magic_variables[name] = PythonScriptingProvider.MagicVariable(
			get_value=get_value,
			set_value=set_value,
			depends_on=depends_on
		)

		for inst in PythonScriptingInstance._registered_instances:
			inst.interpreter.update_magic_variables()

	@classmethod
	def unregister_magic_variable(cls, name: str):
		"""
		Remove a magic variable by name
		:param name: Variable name
		"""
		del cls.magic_variables[name]

		for inst in PythonScriptingInstance._registered_instances:
			inst.interpreter.update_magic_variables()


PythonScriptingProvider().register()
# Wrap stdin/stdout/stderr for Python scripting provider implementation
original_stdin = sys.stdin
original_stdout = sys.stdout
original_stderr = sys.stderr


def redirect_stdio():
	sys.stdin = _PythonScriptingInstanceInput(sys.stdin)
	sys.stdout = _PythonScriptingInstanceOutput(sys.stdout, False)
	sys.stderr = _PythonScriptingInstanceOutput(sys.stderr, True)
	sys.excepthook = sys.__excepthook__


def _get_here(instance: PythonScriptingInstance):
	return instance.interpreter.current_addr


def _set_here(instance: PythonScriptingInstance, old_value: Any, new_value: Any):
	if instance.interpreter.active_view is None:
		return

	if isinstance(new_value, str):
		new_value = instance.interpreter.active_view.parse_expression(
			new_value,
			instance.interpreter.active_addr
		)
	if type(new_value) is not int:
		raise ValueError("Can only replace this variable with an integer")

	if not instance.interpreter.active_view.file.navigate(
		instance.interpreter.active_view.file.view,
		new_value
	):
		binaryninja.mainthread.execute_on_main_thread(
			lambda: instance.interpreter.locals["current_ui_context"].navigateForBinaryView(
				instance.interpreter.active_view,
				new_value
			)
		)


PythonScriptingProvider.register_magic_variable(
	"here",
	_get_here,
	_set_here,
	["current_ui_context"]
)
PythonScriptingProvider.register_magic_variable(
	"current_address",
	_get_here,
	_set_here,
	["current_ui_context"]
)


def _get_current_comment(instance: PythonScriptingInstance):
	if instance.interpreter.active_view is None:
		return None

	if instance.interpreter.active_func is None:
		return instance.interpreter.active_view.get_comment_at(instance.interpreter.active_addr)
	elif instance.interpreter.active_func.get_comment_at(instance.interpreter.active_addr) != '':
		return instance.interpreter.active_func.get_comment_at(instance.interpreter.active_addr)
	else:
		return instance.interpreter.active_view.get_comment_at(instance.interpreter.active_addr)


def _set_current_comment(instance: PythonScriptingInstance, old_value: Any, new_value: Any):
	if instance.interpreter.active_view is None:
		return

	if instance.interpreter.active_func is None:
		instance.interpreter.active_view.set_comment_at(instance.interpreter.active_addr, new_value)
	else:
		if instance.interpreter.active_view.get_comment_at(instance.interpreter.active_addr) != '':
			# Prefer editing active view comment if one exists
			instance.interpreter.active_view.set_comment_at(instance.interpreter.active_addr, new_value)
		else:
			instance.interpreter.active_func.set_comment_at(instance.interpreter.active_addr, new_value)


PythonScriptingProvider.register_magic_variable(
	"current_comment",
	_get_current_comment,
	_set_current_comment
)


def _get_current_raw_offset(instance: PythonScriptingInstance):
	if instance.interpreter.active_view is not None:
		return instance.interpreter.active_view.get_data_offset_for_address(instance.interpreter.active_addr)
	else:
		return None


def _set_current_raw_offset(instance: PythonScriptingInstance, old_value: Any, new_value: Any):
	if instance.interpreter.active_view is None:
		return

	if isinstance(new_value, str):
		new_value = instance.interpreter.active_view.parse_expression(
			new_value,
			instance.interpreter.active_addr
		)
	if type(new_value) is not int:
		raise ValueError("Can only replace this variable with an integer")

	addr = instance.interpreter.active_view.get_address_for_data_offset(new_value)
	if addr is not None:
		if not instance.interpreter.active_view.file.navigate(
			instance.interpreter.active_view.file.view, addr
		):
			binaryninja.mainthread.execute_on_main_thread(
				lambda: instance.interpreter.locals["current_ui_context"].navigateForBinaryView(
					instance.interpreter.active_view,
					new_value
				)
			)


PythonScriptingProvider.register_magic_variable(
	"current_raw_offset",
	_get_current_raw_offset,
	_set_current_raw_offset,
	["current_ui_context"]
)


def _get_current_selection(instance: PythonScriptingInstance):
	return instance.interpreter.active_selection_begin, instance.interpreter.active_selection_end


def _set_current_selection(instance: PythonScriptingInstance, old_value: Any, new_value: Any):
	if not instance.interpreter.locals["current_ui_view"]:
		return

	if (not isinstance(new_value, list)) and \
			(not isinstance(new_value, tuple)):
		return
	if len(new_value) != 2:
		raise ValueError("Current selection needs to be a list or tuple of two items")

	new_value = [new_value[0], new_value[1]]

	if isinstance(new_value[0], str):
		new_value[0] = instance.interpreter.active_view.parse_expression(
			new_value[0],
			instance.interpreter.active_addr
		)

	if isinstance(new_value[1], str):
		new_value[1] = instance.interpreter.active_view.parse_expression(
			new_value[1],
			instance.interpreter.active_addr
		)

	if new_value[0] != instance.interpreter.active_selection_begin or \
			new_value[1] != instance.interpreter.active_selection_end:
		new_selection = (new_value[0], new_value[1])
		binaryninja.mainthread.execute_on_main_thread(
			lambda: instance.interpreter.locals["current_ui_view"].setSelectionOffsets(new_selection)
		)


PythonScriptingProvider.register_magic_variable(
	"current_selection",
	_get_current_selection,
	_set_current_selection,
	["current_ui_view"]
)


PythonScriptingProvider.register_magic_variable(
	"current_thread",
	lambda instance: instance.interpreter.interpreter
)


def _get_current_project(instance: PythonScriptingInstance):
	if instance.interpreter.active_view is not None:
		return instance.interpreter.active_view.project
	if instance.interpreter.locals["current_ui_context"] is not None:
		return instance.interpreter.locals["current_ui_context"].getProject()
	return None


PythonScriptingProvider.register_magic_variable(
	"current_project",
	_get_current_project,
	depends_on=["current_ui_context", "current_view"],
)


PythonScriptingProvider.register_magic_variable(
	"current_view",
	lambda instance: instance.interpreter.active_view
)
PythonScriptingProvider.register_magic_variable(
	"bv",
	lambda instance: instance.interpreter.active_view
)
PythonScriptingProvider.register_magic_variable(
	"current_function",
	lambda instance: instance.interpreter.active_func
)
PythonScriptingProvider.register_magic_variable(
	"current_basic_block",
	lambda instance: instance.interpreter.active_block
)
# todo: this is the debugger's responsibility
PythonScriptingProvider.register_magic_variable(
	"dbg",
	lambda instance: instance.interpreter.active_dbg
)


def _get_current_llil(instance: PythonScriptingInstance):
	if instance.interpreter.active_func is None:
		return None
	return instance.interpreter.active_func.llil_if_available


PythonScriptingProvider.register_magic_variable("current_llil", _get_current_llil)


def _get_current_lifted_il(instance: PythonScriptingInstance):
	if instance.interpreter.active_func is None:
		return None
	return instance.interpreter.active_func.lifted_il_if_available


PythonScriptingProvider.register_magic_variable("current_lifted_il", _get_current_lifted_il)


def _get_current_llil_ssa(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_llil"] is None:
		return None
	return instance.interpreter.locals["current_llil"].ssa_form


PythonScriptingProvider.register_magic_variable(
	"current_llil_ssa",
	_get_current_llil_ssa,
	depends_on=["current_llil"]
)


def _get_current_mapped_mlil(instance: PythonScriptingInstance):
	if instance.interpreter.active_func is None:
		return None
	return instance.interpreter.active_func.mmlil_if_available


PythonScriptingProvider.register_magic_variable("current_mapped_mlil", _get_current_mapped_mlil)


def _get_current_mapped_mlil_ssa(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_mapped_mlil"] is None:
		return None
	return instance.interpreter.locals["current_mapped_mlil"].ssa_form


PythonScriptingProvider.register_magic_variable(
	"current_mapped_mlil_ssa",
	_get_current_mapped_mlil_ssa,
	depends_on=["current_mapped_mlil"]
)


def _get_current_mlil(instance: PythonScriptingInstance):
	if instance.interpreter.active_func is None:
		return None
	return instance.interpreter.active_func.mlil_if_available


PythonScriptingProvider.register_magic_variable("current_mlil", _get_current_mlil)


def _get_current_mlil_ssa(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_mlil"] is None:
		return None
	return instance.interpreter.locals["current_mlil"].ssa_form


PythonScriptingProvider.register_magic_variable(
	"current_mlil_ssa",
	_get_current_mlil_ssa,
	depends_on=["current_mlil"]
)


def _get_current_hlil(instance: PythonScriptingInstance):
	if instance.interpreter.active_func is None:
		return None
	return instance.interpreter.active_func.hlil_if_available


PythonScriptingProvider.register_magic_variable("current_hlil", _get_current_hlil)


def _get_current_hlil_ssa(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_hlil"] is None:
		return None
	return instance.interpreter.locals["current_hlil"].ssa_form


PythonScriptingProvider.register_magic_variable(
	"current_hlil_ssa",
	_get_current_hlil_ssa,
	depends_on=["current_hlil"]
)


def _get_current_data_var(instance: PythonScriptingInstance):
	if instance.interpreter.active_view is None:
		return None
	return instance.interpreter.active_view.get_data_var_at(instance.interpreter.active_addr)


PythonScriptingProvider.register_magic_variable("current_data_var", _get_current_data_var)


def _get_current_symbol(instance: PythonScriptingInstance):
	if instance.interpreter.active_view is None:
		return None
	return instance.interpreter.active_view.get_symbol_at(instance.interpreter.active_addr)


PythonScriptingProvider.register_magic_variable("current_symbol", _get_current_symbol)


def _get_current_symbols(instance: PythonScriptingInstance):
	if instance.interpreter.active_view is None:
		return []
	return instance.interpreter.active_view.get_symbols(instance.interpreter.active_addr, 1)


PythonScriptingProvider.register_magic_variable("current_symbols", _get_current_symbols)


def _get_current_segment(instance: PythonScriptingInstance):
	if instance.interpreter.active_view is None:
		return None
	return instance.interpreter.active_view.get_segment_at(instance.interpreter.active_addr)


PythonScriptingProvider.register_magic_variable("current_segment", _get_current_segment)


def _get_current_sections(instance: PythonScriptingInstance):
	if instance.interpreter.active_view is None:
		return []
	return instance.interpreter.active_view.get_sections_at(instance.interpreter.active_addr)


PythonScriptingProvider.register_magic_variable("current_sections", _get_current_sections)


def _get_current_ui_context(instance: PythonScriptingInstance):
	if binaryninja.core_ui_enabled():
		try:
			from binaryninjaui import UIContext
			return UIContext.activeContext()
		except ImportError:
			pass
	return None


PythonScriptingProvider.register_magic_variable("current_ui_context", _get_current_ui_context)


def _get_current_ui_action_handler(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_ui_context"] is not None:
		return instance.interpreter.locals["current_ui_context"].getCurrentActionHandler()
	return None


PythonScriptingProvider.register_magic_variable(
	"current_ui_action_handler",
	_get_current_ui_action_handler,
	depends_on=["current_ui_context"]
)


def _get_current_ui_view_frame(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_ui_context"] is not None:
		return instance.interpreter.locals["current_ui_context"].getCurrentViewFrame()
	return None


PythonScriptingProvider.register_magic_variable(
	"current_ui_view_frame",
	_get_current_ui_view_frame,
	depends_on=["current_ui_context"]
)


def _get_current_ui_view(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_ui_context"] is not None:
		return instance.interpreter.locals["current_ui_context"].getCurrentView()
	return None


PythonScriptingProvider.register_magic_variable(
	"current_ui_view",
	_get_current_ui_view,
	depends_on=["current_ui_context"]
)


def _get_current_ui_view_location(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_ui_view_frame"] is not None:
		return instance.interpreter.locals["current_ui_view_frame"].getViewLocation()
	return None


PythonScriptingProvider.register_magic_variable(
	"current_ui_view_location",
	_get_current_ui_view_location,
	depends_on=["current_ui_view_frame"]
)


def _get_current_ui_action_context(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_ui_view"] is not None:
		return instance.interpreter.locals["current_ui_view"].actionContext()
	if instance.interpreter.locals["current_ui_action_handler"] is not None:
		return instance.interpreter.locals["current_ui_action_handler"].actionContext()
	return None


PythonScriptingProvider.register_magic_variable(
	"current_ui_action_context",
	_get_current_ui_action_context,
	depends_on=["current_ui_view", "current_ui_action_handler"]
)


def _get_current_ui_token_state(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_ui_action_context"] is not None:
		return instance.interpreter.locals["current_ui_action_context"].token
	return None


PythonScriptingProvider.register_magic_variable(
	"current_ui_token_state",
	_get_current_ui_token_state,
	depends_on=["current_ui_action_context"]
)


def _get_current_token(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_ui_token_state"] is not None:
		if instance.interpreter.locals["current_ui_token_state"].valid:
			return instance.interpreter.locals["current_ui_token_state"].token
	return None


PythonScriptingProvider.register_magic_variable(
	"current_token",
	_get_current_token,
	depends_on=["current_ui_token_state"]
)


def _get_current_variable(instance: PythonScriptingInstance):
	from binaryninja import Variable
	if instance.interpreter.locals["current_ui_token_state"] is not None:
		if instance.interpreter.locals["current_ui_token_state"].localVarValid:
			var = instance.interpreter.locals["current_ui_token_state"].localVar
			if var is not None and instance.interpreter.active_func:
				return Variable.from_core_variable(instance.interpreter.active_func, var)
	return None


PythonScriptingProvider.register_magic_variable(
	"current_variable",
	_get_current_variable,
	depends_on=["current_ui_token_state"]
)


def _get_current_il_index(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_ui_view_location"] is not None:
		return instance.interpreter.locals["current_ui_view_location"].getInstrIndex()
	return None


PythonScriptingProvider.register_magic_variable(
	"current_il_index",
	_get_current_il_index,
	depends_on=["current_ui_view_location"]
)


def _get_current_il_function(instance: PythonScriptingInstance):
	from binaryninja import FunctionGraphType
	if instance.interpreter.locals["current_ui_view_location"] is not None:
		ilType = instance.interpreter.locals["current_ui_view_location"].getILViewType()
		if ilType.view_type == FunctionGraphType.LowLevelILFunctionGraph:
			return instance.interpreter.locals["current_llil"]
		elif ilType.view_type == FunctionGraphType.LiftedILFunctionGraph:
			return instance.interpreter.locals["current_lifted_il"]
		elif ilType.view_type == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			return instance.interpreter.locals["current_llil_ssa"]
		elif ilType.view_type == FunctionGraphType.MappedMediumLevelILFunctionGraph:
			return instance.interpreter.locals["current_mapped_mlil"]
		elif ilType.view_type == FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph:
			return instance.interpreter.locals["current_mapped_mlil_ssa"]
		elif ilType.view_type == FunctionGraphType.MediumLevelILFunctionGraph:
			return instance.interpreter.locals["current_mlil"]
		elif ilType.view_type == FunctionGraphType.MediumLevelILSSAFormFunctionGraph:
			return instance.interpreter.locals["current_mlil_ssa"]
		elif ilType.view_type == FunctionGraphType.HighLevelILFunctionGraph:
			return instance.interpreter.locals["current_hlil"]
		elif ilType.view_type == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
			return instance.interpreter.locals["current_hlil_ssa"]
	return None


PythonScriptingProvider.register_magic_variable(
	"current_il_function",
	_get_current_il_function,
	depends_on=[
		"current_ui_view_location",
		"current_llil",
		"current_lifted_il",
		"current_llil_ssa",
		"current_mapped_mlil",
		"current_mapped_mlil_ssa",
		"current_mlil",
		"current_mlil_ssa",
		"current_hlil",
		"current_hlil_ssa",
	]
)


def _get_current_il_instruction(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_il_function"] is not None \
			and instance.interpreter.locals["current_il_index"] is not None:
		return instance.interpreter.locals["current_il_function"][
			instance.interpreter.locals["current_il_index"]
		]
	return None


PythonScriptingProvider.register_magic_variable(
	"current_il_instruction",
	_get_current_il_instruction,
	depends_on=[
		"current_il_index",
		"current_il_function"
	]
)


def _get_current_il_basic_block(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_il_instruction"] is not None:
		return instance.interpreter.locals["current_il_instruction"].il_basic_block
	return None


PythonScriptingProvider.register_magic_variable(
	"current_il_basic_block",
	_get_current_il_basic_block,
	depends_on=["current_il_instruction"]
)


def _get_current_il_instructions(instance: PythonScriptingInstance):
	if instance.interpreter.locals["current_il_index"] is not None \
			and instance.interpreter.locals["current_il_function"] is not None \
			and instance.interpreter.locals["current_ui_view"] is not None:

		start_index = instance.interpreter.locals["current_ui_view"].getSelectionStartILInstructionIndex()
		current_index = instance.interpreter.locals["current_il_index"]
		il_function = instance.interpreter.locals["current_il_function"]

		invalid_il_index = 0xffffffffffffffff
		if invalid_il_index not in (current_index, start_index):
			il_start = min(current_index, start_index)
			il_end = max(current_index, start_index)
			return (il_function[i] for i in range(il_start, il_end + 1))

	return None


PythonScriptingProvider.register_magic_variable(
	"current_il_instructions",
	_get_current_il_instructions,
	depends_on=["current_il_index", "current_il_function", "current_ui_view"]
)
