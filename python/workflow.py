# Copyright (c) 2015-2023 Vector 35 Inc
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

import argparse
import cmd
import ctypes
import json
import traceback
from typing import List, Union, Callable, Optional, Any

# Binary Ninja components
import binaryninja
from .log import log_error
from . import _binaryninjacore as core
from .flowgraph import FlowGraph, CoreFlowGraph

from . import function as _function
from . import lowlevelil
from . import mediumlevelil
from . import highlevelil

ActivityType = Union['Activity', str]

class AnalysisContext:
	"""
	The ``AnalysisContext`` object is used to represent the current state of analysis for a given function.
	It allows direct modification of IL and other analysis information.
	"""

	def __init__(self, handle: core.BNAnalysisContextHandle):
		assert handle is not None
		self.handle = handle

	@property
	def function(self) -> '_function.Function':
		"""
		Function for the current AnalysisContext (read-only)
		"""
		result = core.BNAnalysisContextGetFunction(self.handle)
		if not result:
			return None
		return _function.Function(handle=result)

	@property
	def lifted_il(self) -> lowlevelil.LowLevelILFunction:
		"""
		LowLevelILFunction used to represent lifted IL (writable)
		"""
		return self.function.lifted_il

	@lifted_il.setter
	def lifted_il(self, lifted_il: lowlevelil.LowLevelILFunction) -> None:
		core.BNSetLiftedILFunction(self.handle, lifted_il.handle)

	@property
	def llil(self) -> lowlevelil.LowLevelILFunction:
		"""
		LowLevelILFunction used to represent Low Level IL (writeable)
		"""
		result = core.BNAnalysisContextGetLowLevelILFunction(self.handle)
		if not result:
			return None
		return lowlevelil.LowLevelILFunction(handle=result)

	@llil.setter
	def llil(self, value: lowlevelil.LowLevelILFunction) -> None:
		core.BNSetLowLevelILFunction(self.handle, value.handle)

	@property
	def mlil(self) -> mediumlevelil.MediumLevelILFunction:
		"""
		MediumLevelILFunction used to represent Medium Level IL (writeable)
		"""
		result = core.BNAnalysisContextGetMediumLevelILFunction(self.handle)
		if not result:
			return None
		return mediumlevelil.MediumLevelILFunction(handle=result)

	@mlil.setter
	def mlil(self, value: mediumlevelil.MediumLevelILFunction) -> None:
		core.BNSetMediumLevelILFunction(self.handle, value.handle)

	@property
	def hlil(self) -> highlevelil.HighLevelILFunction:
		"""
		HighLevelILFunction used to represent High Level IL (writeable)
		"""
		result = core.BNAnalysisContextGetHighLevelILFunction(self.handle)
		if not result:
			return None
		return highlevelil.HighLevelILFunction(handle=result)

	@hlil.setter
	def hlil(self, value: highlevelil.HighLevelILFunction) -> None:
		core.BNSetHighLevelILFunction(self.handle, value.handle)

	@property
	def basic_blocks(self) -> '_function.BasicBlockList':
		"""
		function.BasicBlockList of BasicBlocks in the current function (writeable)
		"""
		return _function.BasicBlockList(self.function)

	@basic_blocks.setter
	def basic_blocks(self, value: '_function.BasicBlockList') -> None:
		core.BNSetBasicBlockList(self.handle, value._blocks, value._count)

	def inform(self, request: str) -> bool:
		return core.BNAnalysisContextInform(self.handle, request)

class Activity(object):
	"""
	:class:`Activity`
	"""

	_action_callbacks = {}

	def __init__(self, configuration: str = "", handle: Optional[core.BNActivityHandle] = None, action: Optional[Callable[[Any], None]] = None):
		if handle is None:
			#cls._notify(ac, callback)
			action_callback = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNAnalysisContext))(lambda ctxt, ac: self._action(ac))
			_handle = core.BNCreateActivity(configuration, None, action_callback)
			self.action = action
			self.__class__._action_callbacks[len(self.__class__._action_callbacks)] = action_callback
		else:
			_handle = handle
		assert _handle is not None, "Activity instantiation failed"
		self.handle = _handle

	def _action(self, ac: Any):
		try:
			if self.action is not None:
				self.action(AnalysisContext(ac))
		except:
			log_error(traceback.format_exc())

	def __del__(self):
		if core is not None:
			core.BNFreeActivity(self.handle)

	def __repr__(self):
		return f"<{self.__class__.__name__}: {self.name}>"

	def __str__(self):
		return self.name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	@property
	def name(self) -> str:
		"""Activity name (read-only)"""
		return core.BNActivityGetName(self.handle)


class _WorkflowMetaclass(type):
	@property
	def list(self) -> List['Workflow']:
		"""List all Workflows (read-only)"""
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		workflows = core.BNGetWorkflowList(count)
		assert workflows is not None, "core.BNGetWorkflowList returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewWorkflowReference(workflows[i])
				assert handle is not None, "core.BNNewWorkflowReference returned None"
				result.append(Workflow(handle=handle))
			return result
		finally:
			core.BNFreeWorkflowList(workflows, count.value)

	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		workflows = core.BNGetWorkflowList(count)
		assert workflows is not None, "core.BNGetWorkflowList returned None"
		try:
			for i in range(0, count.value):
				handle = core.BNNewWorkflowReference(workflows[i])
				assert handle is not None, "core.BNNewWorkflowReference returned None"
				yield Workflow(handle=handle)
		finally:
			core.BNFreeWorkflowList(workflows, count.value)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		workflow = core.BNWorkflowInstance(str(value))
		return Workflow(handle=workflow)


class Workflow(metaclass=_WorkflowMetaclass):
	"""
	:class:`Workflow` A Binary Ninja Workflow is an abstraction of a computational binary analysis pipeline and it provides the extensibility \
	mechanism needed for tailored binary analysis and decompilation. More specifically, a Workflow is a repository of activities along with a \
	unique strategy to execute them. Binary Ninja provides two Workflows named ``core.module.defaultAnalysis`` and ``core.function.defaultAnalysis`` \
	which expose the core analysis.

	A Workflow starts in the unregistered state from either creating a new empty Workflow, or cloning an existing Workflow. While unregistered \
	it's possible to add and remove activities, as well as change the execution strategy. In order to use the Workflow on a binary it must be \
	registered. Once registered the Workflow is immutable and available for use.

	Currently, Workflows is disabled by default and can be enabled via Settings::

		>>> Settings().set_bool('workflows.enable', True)

	Retrieve the default Workflow by creating a Workflow object::

		>>> Workflow()
		<Workflow: core.module.defaultAnalysis>

	Retrieve any registered Workflow by name::

		>>> list(Workflow)
		[<Workflow: core.function.defaultAnalysis>, <Workflow: core.module.defaultAnalysis>]
		>>> Workflow('core.module.defaultAnalysis')
		<Workflow: core.module.defaultAnalysis>
		>>> Workflow('core.function.defaultAnalysis')
		<Workflow: core.function.defaultAnalysis>

	Create a new Workflow, show it in the UI, modify and then register it. Try it via Open with Options and selecting the new Workflow::

		>>> pwf = Workflow().clone("PythonLogWarnWorkflow")
		>>> pwf.show_topology()
		>>> pwf.register_activity(Activity("PythonLogWarn", action=lambda analysis_context: log_warn("PythonLogWarn Called!")))
		>>> pwf.insert("core.function.basicBlockAnalysis", ["PythonLogWarn"])
		>>> pwf.register()

	.. note:: Binary Ninja Workflows is currently under development and available as an early feature preview. For additional documentation see Help / User Guide / Developer Guide / Workflows

	"""
	def __init__(self, name: str = "", handle: core.BNWorkflowHandle = None, query_registry: bool = True, function_handle: core.BNFunctionHandle = None):
		if handle is None:
			if query_registry:
				_handle = core.BNWorkflowInstance(str(name))
			else:
				_handle = core.BNCreateWorkflow(name)
		else:
			_handle = handle
		assert _handle is not None
		self.handle = _handle
		self._name = core.BNGetWorkflowName(self.handle)
		if function_handle is not None:
			self._machine = WorkflowMachine(function_handle)

	def __del__(self):
		if core is not None:
			core.BNFreeWorkflow(self.handle)

	def __len__(self):
		return int(core.BNWorkflowSize(self.handle))

	def __repr__(self):
		if core.BNWorkflowIsRegistered(self.handle):
			return f"<Workflow: {self.name}>"
		else:
			return f"<Workflow [Unregistered]: {self.name}>"

	def __str__(self):
		return self.name

	@property
	def name(self) -> str:
		return self._name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	def register(self, configuration: str = "") -> bool:
		"""
		``register`` Register this Workflow, making it immutable and available for use.

		:param str configuration: a JSON representation of the workflow configuration
		:return: True on Success, False otherwise
		:rtype: bool
		"""
		return core.BNRegisterWorkflow(self.handle, str(configuration))

	def clone(self, name: str, activity: ActivityType = "") -> "Workflow":
		"""
		``clone`` Clone a new Workflow, copying all Activities and the execution strategy.

		:param str name: the name for the new Workflow
		:param str activity: if specified, perform the clone operation using ``activity`` as the root
		:return: a new Workflow
		:rtype: Workflow
		"""
		workflow = core.BNWorkflowClone(self.handle, str(name), str(activity))
		return Workflow(handle=workflow)

	def register_activity(self, activity: Activity, subactivities: List[ActivityType] = []) -> Optional[Activity]:
		"""
		``register_activity`` Register an Activity with this Workflow.

		:param Activity activity: the Activity to register
		:param list[str] subactivities: the list of Activities to assign
		:return: True on Success, False otherwise
		:rtype: Activity
		"""
		if activity is None:
			return None
		input_list = (ctypes.c_char_p * len(subactivities))()
		for i in range(0, len(subactivities)):
			input_list[i] = str(subactivities[i]).encode('charmap')
		return core.BNWorkflowRegisterActivity(self.handle, activity.handle, input_list, len(subactivities))

	def contains(self, activity: ActivityType) -> bool:
		"""
		``contains`` Determine if an Activity exists in this Workflow.

		:param ActivityType activity: the Activity name
		:return: True if the Activity exists, False otherwise
		:rtype: bool
		"""
		return core.BNWorkflowContains(self.handle, str(activity))

	def configuration(self, activity: ActivityType = "") -> str:
		"""
		``configuration`` Retrieve the configuration as an adjacency list in JSON for the Workflow, or if specified just for the given ``activity``.

		:param ActivityType activity: if specified, return the configuration for the ``activity``
		:return: an adjacency list representation of the configuration in JSON
		:rtype: str
		"""
		return core.BNWorkflowGetConfiguration(self.handle, str(activity))

	@property
	def registered(self) -> bool:
		"""
		``registered`` Whether this Workflow is registered or not. A Workflow becomes immutable once it is registered.

		:type: bool
		"""
		return core.BNWorkflowIsRegistered(self.handle)

	def get_activity(self, activity: ActivityType) -> Optional[Activity]:
		"""
		``get_activity`` Retrieve the Activity object for the specified ``activity``.

		:param str activity: the Activity name
		:return: the Activity object
		:rtype: Activity
		"""
		handle = core.BNWorkflowGetActivity(self.handle, str(activity))
		if handle is None:
			return None
		return Activity(str(activity), handle)

	def activity_roots(self, activity: ActivityType = "") -> List[str]:
		"""
		``activity_roots`` Retrieve the list of activity roots for the Workflow, or if specified just for the given ``activity``.

		:param str activity: if specified, return the roots for the ``activity``
		:return: list of root activity names
		:rtype: list[str]
		"""
		length = ctypes.c_ulonglong()
		result = core.BNWorkflowGetActivityRoots(self.handle, str(activity), ctypes.byref(length))
		assert result is not None, "core.BNWorkflowGetActivityRoots returned None"
		out_list = []
		try:
			for i in range(length.value):
				out_list.append(result[i].decode('utf-8'))
			return out_list
		finally:
			core.BNFreeStringList(result, length.value)

	def subactivities(self, activity: ActivityType = "", immediate: bool = True) -> List[str]:
		"""
		``subactivities`` Retrieve the list of all activities, or optionally a filtered list.

		:param str activity: if specified, return the direct children and optionally the descendants of the ``activity`` (includes ``activity``)
		:param bool immediate: whether to include only direct children of ``activity`` or all descendants
		:return: list of activity names
		:rtype: list[str]
		"""
		length = ctypes.c_ulonglong()
		result = core.BNWorkflowGetSubactivities(self.handle, str(activity), immediate, ctypes.byref(length))
		assert result is not None, "core.BNWorkflowGetSubactivities returned None"
		out_list = []
		try:
			for i in range(length.value):
				out_list.append(result[i].decode('utf-8'))
			return out_list
		finally:
			core.BNFreeStringList(result, length.value)

	def assign_subactivities(self, activity: Activity, activities: List[str]) -> bool:
		"""
		``assign_subactivities`` Assign the list of ``activities`` as the new set of children for the specified ``activity``.

		:param str activity: the Activity node to assign children
		:param list[str] activities: the list of Activities to assign
		:return: True on success, False otherwise
		:rtype: bool
		"""
		input_list = (ctypes.c_char_p * len(activities))()
		for i in range(0, len(activities)):
			input_list[i] = str(activities[i]).encode('charmap')
		return core.BNWorkflowAssignSubactivities(self.handle, str(activity), input_list, len(activities))

	def clear(self) -> bool:
		"""
		``clear`` Remove all Activity nodes from this Workflow.

		:return: True on success, False otherwise
		:rtype: bool
		"""
		return core.BNWorkflowClear(self.handle)

	def insert(self, activity: ActivityType, activities: List[str]) -> bool:
		"""
		``insert`` Insert the list of ``activities`` before the specified ``activity`` and at the same level.

		:param str activity: the Activity node for which to insert ``activities`` before
		:param list[str] activities: the list of Activities to insert
		:return: True on success, False otherwise
		:rtype: bool
		"""
		input_list = (ctypes.c_char_p * len(activities))()
		for i in range(0, len(activities)):
			input_list[i] = str(activities[i]).encode('charmap')
		return core.BNWorkflowInsert(self.handle, str(activity), input_list, len(activities))

	def remove(self, activity: ActivityType) -> bool:
		"""
		``remove`` Remove the specified ``activity``.

		:param str activity: the Activity to remove
		:return: True on success, False otherwise
		:rtype: bool
		"""
		return core.BNWorkflowRemove(self.handle, str(activity))

	def replace(self, activity: ActivityType, new_activity: List[str]) -> bool:
		"""
		``replace`` Replace the specified ``activity``.

		:param str activity: the Activity to replace
		:param list[str] new_activity: the replacement Activity
		:return: True on success, False otherwise
		:rtype: bool
		"""
		return core.BNWorkflowReplace(self.handle, str(activity), str(new_activity))

	def graph(self, activity: ActivityType = "", sequential: bool = False, show: bool = True) -> Optional[FlowGraph]:
		"""
		``graph`` Generate a FlowGraph object for the current Workflow and optionally show it in the UI.

		:param str activity: if specified, generate the Flowgraph using ``activity`` as the root
		:param bool sequential: whether to generate a **Composite** or **Sequential** style graph
		:param bool show: whether to show the graph in the UI or not
		:return: FlowGraph object on success, None on failure
		:rtype: FlowGraph
		"""
		graph = core.BNWorkflowGetGraph(self.handle, str(activity), sequential)
		if not graph:
			return None
		graph = CoreFlowGraph(graph)
		if show:
			core.BNShowGraphReport(None, f'{self.name} <{activity}>' if activity else self.name, graph.handle)
		return graph

	def show_metrics(self) -> None:
		"""
		``show_metrics`` Not yet implemented.

		:rtype: None
		"""
		core.BNWorkflowShowReport(self.handle, "metrics")

	def show_topology(self) -> None:
		"""
		``show_topology`` Show the Workflow topology in the UI.

		:rtype: None
		"""
		core.BNWorkflowShowReport(self.handle, "topology")

	def show_trace(self) -> None:
		"""
		``show_trace`` Not yet implemented.

		:rtype: None
		"""
		core.BNWorkflowShowReport(self.handle, "trace")

	@property
	def machine(self):
		if self._machine is not None:
			return self._machine
		else:
			raise AttributeError("Machine does not exist.")

class WorkflowMachine:
	def __init__(self, handle: core.BNFunctionHandle = None):
		self.handle = handle

	def log(self, enable: bool = True, is_global: bool = False):
		request = json.dumps({"command": "log", "enable": enable, "global": is_global})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def metrics(self, enable: bool = True, is_global: bool = False):
		request = json.dumps({"command": "metrics", "enable": enable, "global": is_global})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def dump(self):
		request = json.dumps({"command": "dump"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def configure(self, advanced: bool = True, incremental: bool = False):
		request = json.dumps({"command": "configure", "advanced": advanced, "incremental": incremental})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def resume(self):
		request = json.dumps({"command": "run"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def run(self):
		status = self.status()
		if 'machineState' in status and 'state' in status['machineState']:
			if status['machineState']['state'] == 'Idle':
				self.configure()
		else:
			raise AttributeError("Unknown status response!")

		request = json.dumps({"command": "run"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def abort(self):
		request = json.dumps({"command": "abort"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def halt(self):
		request = json.dumps({"command": "halt"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def reset(self):
		request = json.dumps({"command": "reset"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def enable(self):
		request = json.dumps({"command": "enable"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def disable(self):
		request = json.dumps({"command": "disable"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def step(self):
		request = json.dumps({"command": "step"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def breakpoint_delete(self, activities):
		request = json.dumps({"command": "breakpoint", "action": "delete", "activities": activities})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def breakpoint_query(self):
		request = json.dumps({"command": "breakpoint", "action": "query"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def breakpoint_set(self, activities):
		request = json.dumps({"command": "breakpoint", "action": "set", "activities": activities})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def status(self):
		request = json.dumps({"command": "status"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def override_clear(self, activity):
		request = json.dumps({"command": "override", "action": "clear", "activity": activity})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def override_query(self):
		request = json.dumps({"command": "override", "action": "query"})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def override_set(self, activity, enable):
		request = json.dumps({"command": "override", "action": "set", "activity": activity, "enable": enable})
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def request(self, request):
		return json.loads(core.BNPostWorkflowRequestForFunction(self.handle, request))

	def cli(self):
		WorkflowMachineCLI(self).cmdloop()

class WorkflowMachineCLI(cmd.Cmd):
	intro = "Welcome to the Workflow Orchestrator. Type 'help' to list available commands."
	prompt = "(dechora) "
	aliases = {
		"l": "log",
		"m": "metrics",
		"d": "dump",
		"c": "resume",
		"r": "run",
		"a": "abort",
		"h": "halt",
		"s": "step",
		"b": "breakpoint",
		"o": "override",
		"q": "quit"
	}

	def __init__(self, machine: WorkflowMachine):
		super().__init__()
		self.machine = machine

	def do_log(self, line):
		"""Control workflow logging."""
		parser = argparse.ArgumentParser(exit_on_error=False)
		parser.add_argument("--enable", action="store_true", default=None, help="Enable logging")
		parser.add_argument("--disable", action="store_true", default=False, help="Disable logging")
		parser.add_argument("--global", action="store_true", default=False, dest="is_global", help="Enable or disable logging globally")
		try:
			args = parser.parse_args(line.split())
			if args.enable is None:
				enable = not args.disable
			else:
				enable = args.enable
			status = self.machine.log(enable=enable, is_global=args.is_global)
			print(json.dumps(status, indent=4))
		except argparse.ArgumentError as e:
			print("ArgumentError:", e)
		except SystemExit:
			pass

	def do_metrics(self, line):
		"""Control workflow metrics collection."""
		parser = argparse.ArgumentParser(exit_on_error=False)
		parser.add_argument("--enable", action="store_true", default=None, help="Enable logging")
		parser.add_argument("--disable", action="store_true", default=False, help="Disable logging")
		parser.add_argument("--global", action="store_true", default=False, dest="is_global", help="Enable or disable logging globally")
		try:
			args = parser.parse_args(line.split())
			if args.enable is None:
				enable = not args.disable
			else:
				enable = args.enable
			status = self.machine.metrics(enable=enable, is_global=args.is_global)
			print(json.dumps(status, indent=4))
		except argparse.ArgumentError as e:
			print("ArgumentError:", e)
		except SystemExit:
			pass

	def do_dump(self, line):
		"""Dump metrics from the workflow system."""
		status = self.machine.dump()
		accepted = status.get('commandStatus', {}).get('accepted', False)
		if accepted:
			response = status.pop("response", None)
		print(json.dumps(status, indent=4))
		if accepted and response:
			print(json.dumps(response, indent=None))

	def do_configure(self, line):
		"""Configure the workflow machine."""
		parser = argparse.ArgumentParser(exit_on_error=False)
		parser.add_argument("--advanced", action="store_true", default=True, help="Enable advanced configuration (default: True)")
		parser.add_argument("--incremental", action="store_true", default=None, help="Enable incremental configuration (default: True if provided, False if omitted)")
		try:
			args = parser.parse_args(line.split())
			if args.incremental is None:
				args.incremental = False
			status = self.machine.configure(advanced=args.advanced, incremental=args.incremental)
			print(json.dumps(status, indent=4))
		except argparse.ArgumentError as e:
			print("ArgumentError:", e)
		except SystemExit:
			pass

	def do_resume(self, line):
		"""Continue/Resume execution of a workflow."""
		status = self.machine.resume()
		print(json.dumps(status, indent=4))

	def do_run(self, line):
		"""Run the workflow machine and generate a default configuration if the workflow is not configured."""
		status = self.machine.run()
		print(json.dumps(status, indent=4))

	def do_abort(self, line):
		"""Abort the workflow machine."""
		status = self.machine.abort()
		print(json.dumps(status, indent=4))

	def do_halt(self, line):
		"""Halt the workflow machine."""
		status = self.machine.halt()
		print(json.dumps(status, indent=4))

	def do_reset(self, line):
		"""Reset the workflow machine."""
		status = self.machine.reset()
		print(json.dumps(status, indent=4))

	def do_enable(self, line):
		"""Enable the workflow machine."""
		status = self.machine.enable()
		print(json.dumps(status, indent=4))

	def do_disable(self, line):
		"""Disable the workflow machine."""
		status = self.machine.disable()
		print(json.dumps(status, indent=4))

	def do_step(self, line):
		"""Step to the next activity in the workflow machine."""
		status = self.machine.step()
		print(json.dumps(status, indent=4))

	def do_breakpoint(self, line):
		"""Handle breakpoint commands."""
		parser = argparse.ArgumentParser(exit_on_error=False)
		parser.add_argument("action", choices=["delete", "set", "query"], help="Action to perform: delete, set, or, query.")
		parser.add_argument("activities", type=str, nargs="*", help="The breakpoint(s) to set/delete.")
		try:
			args = parser.parse_args(line.split())
			args.activities = [activity[1:-1] if activity.startswith('"') and activity.endswith('"') else activity for activity in args.activities]
			if args.action == "delete":
				status = self.machine.breakpoint_delete(args.activities)
				print(json.dumps(status, indent=4))
			elif args.action == "query":
				status = self.machine.breakpoint_query()
				accepted = status.get('commandStatus', {}).get('accepted', False)
				if accepted:
					response = status.pop("response", None)
				print(json.dumps(status, indent=4))
				if accepted and response:
					print(json.dumps(response, indent=None))
			elif args.action == "set":
				status = self.machine.breakpoint_set(args.activities)
				print(json.dumps(status, indent=4))
		except argparse.ArgumentError as e:
			print("ArgumentError:", e)
		except SystemExit:
			pass

	def do_status(self, line):
		"""Retrieve the current machine status."""
		status = self.machine.status()
		print(json.dumps(status, indent=4))

	def do_override(self, line):
		"""Handle override commands."""
		parser = argparse.ArgumentParser(exit_on_error=False)
		parser.add_argument("action", choices=["clear", "set", "query"], help="Action to perform: clear, set, or, query.")
		parser.add_argument("activity", type=str, nargs="?", default="", help="The activity to set/clear.")
		parser.add_argument("--enable", action="store_true", default=None, help="Enable the specified activity.")
		parser.add_argument("--disable", action="store_true", default=False, help="Disable the specified activity.")
		try:
			args = parser.parse_args(line.split())
			args.activity = args.activity[1:-1] if args.activity and args.activity.startswith('"') and args.activity.endswith('"') else args.activity
			if args.action == "clear":
				status = self.machine.override_clear(args.activity)
				print(json.dumps(status, indent=4))
			elif args.action == "query":
				status = self.machine.override_query()
				accepted = status.get('commandStatus', {}).get('accepted', False)
				if accepted:
					response = status.pop("response", None)
				print(json.dumps(status, indent=4))
				if accepted and response:
					print(json.dumps(response, indent=None))
			elif args.action == "set":
				if args.enable is None:
					enable = not args.disable
				else:
					enable = args.enable
				status = self.machine.override_set(args.activity, enable)
				print(json.dumps(status, indent=4))
		except argparse.ArgumentError as e:
			print("ArgumentError:", e)
		except SystemExit:
			pass

	def do_quit(self, line):
		"""Exit the WorkflowMachine CLI."""
		print("Exiting WorkflowMachine CLI...")
		return True

	def precmd(self, line):
		words = line.split()
		if words and words[0] in self.aliases:
			words[0] = self.aliases[words[0]]
			line = ' '.join(words)
		return line

	def help(self, arg):
		if arg in self.aliases:
			arg = self.aliases[arg]
		super().help(arg)
