# Copyright (c) 2015-2022 Vector 35 Inc
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

import code
import traceback
import ctypes
from ctypes.util import find_library
import threading
import abc
import sys
import subprocess
from pathlib import Path
import re
import os
from typing import Generator, Optional, List, Tuple
from typing import Type as TypeHintType

# Binary Ninja components
import binaryninja
from . import bncompleter
from . import _binaryninjacore as core
from . import settings
from . import binaryview
from . import basicblock
from . import function
from .log import log_info, log_error, is_output_redirected_to_log
from .pluginmanager import RepositoryManager
from .enums import ScriptingProviderExecuteResult, ScriptingProviderInputReadyState
from .debugger import *


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
			self._cb.cancelScriptInput = self._cb.cancelScriptInput.__class__(self._cancel_script_input)
			self._cb.setCurrentBinaryView = self._cb.setCurrentBinaryView.__class__(self._set_current_binary_view)
			self._cb.setCurrentFunction = self._cb.setCurrentFunction.__class__(self._set_current_function)
			self._cb.setCurrentBasicBlock = self._cb.setCurrentBasicBlock.__class__(self._set_current_basic_block)
			self._cb.setCurrentAddress = self._cb.setCurrentAddress.__class__(self._set_current_address)
			self._cb.setCurrentSelection = self._cb.setCurrentSelection.__class__(self._set_current_selection)
			self._cb.completeInput = self._cb.completeInput.__class__(self._complete_input)
			self._cb.completeInput.restype = ctypes.c_void_p
			self._cb.stop = self._cb.stop.__class__(self._stop)
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

	def _cancel_script_input(self, ctxt):
		try:
			return self.perform_cancel_script_input()
		except:
			log_error(traceback.format_exc())
			return ScriptingProviderExecuteResult.ScriptExecutionCancelled

	def _set_current_binary_view(self, ctxt, view):
		try:
			if view:
				view = binaryview.BinaryView(handle=core.BNNewViewReference(view))
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
			return ctypes.cast(
			    self.perform_complete_input(text, state).encode("utf-8"), ctypes.c_void_p
			).value  # type: ignore
		except:
			log_error(traceback.format_exc())
			return "".encode("utf-8")

	def _stop(self, ctxt):
		try:
			self.perform_stop()
		except:
			log_error(traceback.format_exc())

	@abc.abstractmethod
	def perform_execute_script_input(self, text):
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

	def error(self, text):
		core.BNNotifyErrorForScriptingInstance(self.handle, text)

	def execute_script_input(self, text):
		return core.BNExecuteScriptInput(self.handle, text)

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
	instance_class: Optional['ScriptingInstance'] = None

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
	def __init__(self, orig, is_error):
		self.orig = orig
		self.is_error = is_error
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

					if self.is_error:
						log_error(line)
					else:
						log_info(line)
			else:
				self.orig.write(data)
		else:
			PythonScriptingInstance._interpreter.value = None
			try:
				if self.is_error:
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
			log_error(
			    'Setting variable "{}" will have no affect as it is automatically controlled by the ScriptingProvider.'.
			    format(k)
			)
		super(BlacklistedDict, self).__setitem__(k, v)

	def enable_blacklist(self, enabled):
		self.__enable_blacklist = enabled

	@property
	def blacklist_enabled(self):
		return self._blacklist_enabled

	@blacklist_enabled.setter
	def blacklist_enabled(self, value):
		self._blacklist_enabled = value


def bninspect(code, globals_, locals_):
	"""
	``bninspect`` prints documentation about a command that is about to be run
	The interpreter will invoke this function if you input a line ending in `?` e.g. `bv?`

	:param str code: Python code to be evaluated
	:param dict globals_: globals() from callsite
	:param dict locals_: locals() from callsite
	"""
	try:
		import inspect
		value = eval(code, globals_, locals_)
		doc = inspect.getdoc(value)
		if doc is None:
			comments = inspect.getcomments(value)
			if comments is None:
				print(f"No documentation found for {code}")
			else:
				print(comments)
		else:
			print(doc)
	except:
		# Hide exceptions so the normal execution can report them
		pass


class PythonScriptingInstance(ScriptingInstance):
	_interpreter = threading.local()

	class InterpreterThread(threading.Thread):
		def __init__(self, instance):
			super(PythonScriptingInstance.InterpreterThread, self).__init__()
			self.instance = instance
			# Note: "current_address" and "here" are interactive auto-variables (i.e. can be set by user and programmatically)
			blacklisted_vars = {
			    "current_view", "bv", "current_function", "current_basic_block", "current_selection", "current_llil",
			    "current_mlil", "current_hlil", "dbg"
			}
			self.locals = BlacklistedDict(
			    blacklisted_vars, {"__name__": "__console__", "__doc__": None, "binaryninja": sys.modules[__name__]}
			)
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
			self.active_dbg = None

			self.locals["get_selected_data"] = self.get_selected_data
			self.locals["write_at_cursor"] = self.write_at_cursor

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

		def execute(self, code):
			self.code = code
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
					code = self.code
					self.code = None

					PythonScriptingInstance._interpreter.value = self
					try:
						self.update_locals()

						# If a single-line command ends in ?, show docs as well
						if code[-2:] == b'?\n' and len(code.split(b'\n')) < 3:
							escaped_code = repr(code[:-2])
							self.interpreter.push(f'bninspect({escaped_code}, globals(), locals())\n')
							# Strip ? from the evaluated input
							code = code[:-2] + b'\n'

						for line in code.split(b'\n'):
							self.interpreter.push(line.decode("utf-8"))

						if self.active_view is not None:
							tryNavigate = True
							if isinstance(self.locals["here"], str) or isinstance(self.locals["current_address"], str):
								try:
									self.locals["here"] = self.active_view.parse_expression(
									    self.locals["here"], self.active_addr
									)
								except ValueError as e:
									sys.stderr.write(str(e))
									tryNavigate = False
							if tryNavigate:
								if self.locals["here"] != self.active_addr:
									if not self.active_view.file.navigate(
									    self.active_view.file.view, self.locals["here"]
									):
										sys.stderr.write(
										    "Address 0x%x is not valid for the current view\n" % self.locals["here"]
										)
								elif self.locals["current_address"] != self.active_addr:
									if not self.active_view.file.navigate(
									    self.active_view.file.view, self.locals["current_address"]
									):
										sys.stderr.write(
										    "Address 0x%x is not valid for the current view\n"
										    % self.locals["current_address"]
										)
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
			self.locals["current_thread"] = self.interpreter
			self.locals["current_view"] = self.active_view
			self.locals["bv"] = self.active_view
			self.locals["current_function"] = self.active_func
			self.locals["current_basic_block"] = self.active_block
			self.locals["current_address"] = self.active_addr
			self.locals["here"] = self.active_addr
			self.locals["current_selection"] = (self.active_selection_begin, self.active_selection_end)
			self.locals["dbg"] = self.active_dbg
			if self.active_func is None:
				self.locals["current_llil"] = None
				self.locals["current_mlil"] = None
				self.locals["current_hlil"] = None
			else:
				self.locals["current_llil"] = self.active_func.llil_if_available
				self.locals["current_mlil"] = self.active_func.mlil_if_available
				self.locals["current_hlil"] = self.active_func.hlil_if_available
			self.locals.blacklist_enabled = True

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
		if settings.Settings().get_bool('corePlugins.debugger'):
			if view is not None:
				self.interpreter.current_dbg = DebuggerController(view)
			else:
				self.interpreter.current_dbg = None

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
		self.interpreter.update_locals()
		result = self.interpreter.completer.complete(text, state)
		if result is None:
			return ""
		return result


class PythonScriptingProvider(ScriptingProvider):
	name = "Python"
	apiName = f"python{sys.version_info.major}"  # Used for plugin compatibility testing
	instance_class: TypeHintType[PythonScriptingInstance] = PythonScriptingInstance

	@property
	def _python_bin(self) -> Optional[str]:
		python_lib = settings.Settings().get_string("python.interpreter")
		python_bin_override = settings.Settings().get_string("python.binaryOverride")
		python_bin, status = self._get_executable_for_libpython(python_lib, python_bin_override)
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
		return False

	def _run_args(self, args):
		si = None
		if sys.platform == "win32":
			si = subprocess.STARTUPINFO()
			si.dwFlags |= subprocess.STARTF_USESHOWWINDOW

		try:
			return (True, subprocess.check_output(args, startupinfo=si, stderr=subprocess.STDOUT).decode("utf-8"))
		except subprocess.SubprocessError as se:
			return (False, str(se))

	def _pip_exists(self, python_bin: str) -> bool:
		return self._run_args([python_bin, "-m", "pip", "--version"])[0]

	def _satisfied_dependencies(self, python_bin: str) -> Generator[str, None, None]:
		if python_bin is None:
			return None
		success, result = self._run_args([python_bin, "-m", "pip", "freeze"])
		if not success:
			return None
		for line in result.splitlines():
			yield line.split("==", 2)[0]

	def _bin_version(self, python_bin: str):
		return self._run_args([
		    str(python_bin), "-c", "import sys; sys.stdout.write(f'{sys.version_info.major}.{sys.version_info.minor}')"
		])[1]

	def _get_executable_for_libpython(self, python_lib: str, python_bin: str) -> Tuple[Optional[str], str]:
		python_lib_version = f"{sys.version_info.major}.{sys.version_info.minor}"
		if python_bin is not None and python_bin != "":
			python_bin_version = self._bin_version(python_bin)
			if python_lib_version != python_bin_version:
				return (
				    None,
				    f"Specified Python Binary Override is the wrong version. Expected: {python_lib_version} got: {python_bin_version}"
				)
			return (python_bin, "Success")

		using_bundled_python = not python_lib

		if sys.platform == "darwin":
			if using_bundled_python:
				return (
				    None,
				    "Failed: Bundled python doesn't support dependency installation. Specify a full python installation in your 'Python Interpreter' and try again"
				)

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
		python_bin_version = self._bin_version(python_bin)
		if python_bin_version != python_lib_version:
			return (None, f"Failed: Python version not equal {python_bin_version} and {python_lib_version}")

		return (python_bin, "Success")

	def _install_modules(self, ctx, _modules: bytes) -> bool:
		# This callback should not be called directly it is indirectly
		# executed binary ninja is executed with --pip option
		modules = _modules.decode("utf-8")
		if len(modules.strip()) == 0:
			return True
		python_lib = settings.Settings().get_string("python.interpreter")
		python_bin_override = settings.Settings().get_string("python.binaryOverride")
		python_bin, status = self._get_executable_for_libpython(python_lib, python_bin_override)
		if python_bin is not None and not self._pip_exists(str(python_bin)):
			log_error(
			    f"Pip not installed for configured python: {python_bin}.\n"
			    "Please install pip or switch python versions."
			)
			return False
		if sys.platform == "darwin" and not any([python_bin, python_lib, python_bin_override]):
			log_error(
			    f"Plugin requirement installation unsupported on MacOS with bundled Python: {status}\n"
			    "Please specify a path to a python library in the 'Python Interpreter' setting"
			)
			return False
		elif python_bin is None:
			log_error(
			    f"Unable to discover python executable required for installing python modules: {status}\n"
			    "Please specify a path to a python binary in the 'Python Path Override'"
			)
			return False

		python_bin_version = subprocess.check_output([
		    python_bin, "-c", "import sys; sys.stdout.write(f'{sys.version_info.major}.{sys.version_info.minor}')"
		]).decode("utf-8")
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

		args.extend(["install", "--verbose"])
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
		status, result = self._run_args(args)
		if not status:
			log_error(f"Error while attempting to install requirements {result}")
		return status

	def _module_installed(self, ctx, module: str) -> bool:
		if self._python_bin is None:
			return False
		return re.split('>|=|,', module.strip(), 1)[0] in self._satisfied_dependencies(self._python_bin)


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
