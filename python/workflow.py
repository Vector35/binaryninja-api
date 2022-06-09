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

import ctypes
import traceback
from typing import List, Union, Callable, Optional, Any

# Binary Ninja components
import binaryninja
from .log import log_error
from . import _binaryninjacore as core
from .flowgraph import FlowGraph, CoreFlowGraph

ActivityType = Union['Activity', str]


class Activity(object):
	"""
	:class:`Activity`
	"""

	_action_callbacks = {}

	def __init__(self, name: str = "", handle: Optional[core.BNActivityHandle] = None, action: Optional[Callable[[Any], None]] = None):
		if handle is None:
			#cls._notify(ac, callback)
			action_callback = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNAnalysisContext))(lambda ctxt, ac: self._action(ac))
			_handle = core.BNCreateActivity(name, None, action_callback)
			self.action = action
			self.__class__._action_callbacks[len(self.__class__._action_callbacks)] = action_callback
		else:
			_handle = handle
		assert _handle is not None, "Activity instantiation failed"
		self.handle = _handle
		self._name = name

	def _action(self, ac: Any):
		try:
			if self.action is not None:
				self.action(ac)
		except:
			log_error(traceback.format_exc())

	def __del__(self):
		if core is not None:
			core.BNFreeActivity(self.handle)

	def __repr__(self):
		return f"<Activity: {self.name}>"

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
	def name(self):
		"""Activity name (read-only)"""
		if self._name != "":
			return self._name
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

	.. note:: Binary Ninja Workflows is currently under development and available as an early feature preview. For additional documentation::

		>>> Workflow().show_documentation()
	"""
	def __init__(self, name: str = "", handle: core.BNWorkflowHandle = None, query_registry: bool = True):
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

	def register(self, description: str = "") -> bool:
		"""
		``register`` Register this Workflow, making it immutable and available for use.

		:param str description: a JSON description of the Workflow
		:return: True on Success, False otherwise
		:rtype: bool
		"""
		return core.BNRegisterWorkflow(self.handle, str(description))

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

	def register_activity(self, activity: Activity, subactivities: List[ActivityType] = [], description: str = "") -> Optional[bool]:
		"""
		``register_activity`` Register an Activity with this Workflow.

		:param Activity activity: the Activity to register
		:param list[str] subactivities: the list of Activities to assign
		:param str description: a JSON description of the Activity
		:return: True on Success, False otherwise
		:rtype: bool
		"""
		if activity is None:
			return None
		input_list = (ctypes.c_char_p * len(subactivities))()
		for i in range(0, len(subactivities)):
			input_list[i] = str(subactivities[i]).encode('charmap')
		return core.BNWorkflowRegisterActivity(self.handle, activity.handle, input_list, len(subactivities), str(description))

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
