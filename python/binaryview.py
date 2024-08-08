# coding=utf-8
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

import struct
import threading
import queue
import traceback
import ctypes
import abc
import json
import pprint
import inspect
import os
import uuid
from typing import Callable, Generator, Optional, Union, Tuple, List, Mapping, Any, \
	Iterator, Iterable, KeysView, ItemsView, ValuesView, Dict, overload
from dataclasses import dataclass
from enum import IntFlag

import collections
from collections import defaultdict, OrderedDict, deque

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import decorators
from .enums import (
    AnalysisState, SymbolType, Endianness, ModificationStatus, StringType, SegmentFlag, SectionSemantics, FindFlag,
    TypeClass, BinaryViewEventType, FunctionGraphType, TagReferenceType, TagTypeType, RegisterValueType, DisassemblyOption
)
from .exceptions import RelocationWriteException, ILException, ExternalLinkException

from . import associateddatastore  # required for _BinaryViewAssociatedDataStore
from .log import log_warn, log_error, Logger
from . import typelibrary
from . import fileaccessor
from . import databuffer
from . import basicblock
from . import component
from . import lineardisassembly
from . import metadata
from . import highlight
from . import settings
from . import variable
from . import architecture
from . import filemetadata
from . import lowlevelil
from . import mainthread
from . import mediumlevelil
from . import highlevelil
from . import debuginfo
from . import flowgraph
from . import project
from . import typearchive
# The following are imported as such to allow the type checker disambiguate the module name
# from properties and methods of the same name
from . import workflow as _workflow
from . import function as _function
from . import types as _types
from . import platform as _platform
from . import deprecation
from . import typecontainer
from . import externallibrary
from . import project
from . import undo


PathType = Union[str, os.PathLike]
InstructionsType = Generator[Tuple[List['_function.InstructionTextToken'], int], None, None]
NotificationType = Mapping['BinaryDataNotification', 'BinaryDataNotificationCallbacks']
ProgressFuncType = Callable[[int, int], bool]
DataMatchCallbackType = Callable[[int, 'databuffer.DataBuffer'], bool]
LineMatchCallbackType = Callable[[int, 'lineardisassembly.LinearDisassemblyLine'], bool]
StringOrType = Union[str, '_types.Type', '_types.TypeBuilder']


@dataclass(frozen=True)
class ReferenceSource:
	function: Optional['_function.Function']
	arch: Optional['architecture.Architecture']
	address: int

	def __repr__(self):
		if self.arch:
			return f"<ref: {self.arch.name}@{self.address:#x}>"
		else:
			return f"<ref: {self.address:#x}>"

	@classmethod
	def _from_core_struct(cls, view: 'BinaryView', ref: core.BNReferenceSource) -> 'ReferenceSource':
		if ref.func:
			func = _function.Function(view, core.BNNewFunctionReference(ref.func))
		else:
			func = None
		if ref.arch:
			arch = architecture.CoreArchitecture._from_cache(ref.arch)
		else:
			arch = None

		return ReferenceSource(func, arch, ref.addr)

	@property
	def llil(self) -> Optional[lowlevelil.LowLevelILInstruction]:
		"""Returns the low level il instruction at the current location if one exists"""
		if self.function is None or self.arch is None:
			return None
		return self.function.get_low_level_il_at(self.address, self.arch)

	@property
	def mlil(self) -> Optional[mediumlevelil.MediumLevelILInstruction]:
		"""Returns the medium level il instruction at the current location if one exists"""
		llil = self.llil
		return llil.mlil if llil is not None else None

	@property
	def hlil(self) -> Optional[highlevelil.HighLevelILInstruction]:
		"""Returns the high level il instruction at the current location if one exists"""
		mlil = self.mlil
		return mlil.hlil if mlil is not None else None


class NotificationType(IntFlag):
	NotificationBarrier = 1 << 0
	DataWritten = 1 << 1
	DataInserted = 1 << 2
	DataRemoved = 1 << 3
	FunctionAdded = 1 << 4
	FunctionRemoved = 1 << 5
	FunctionUpdated = 1 << 6
	FunctionUpdateRequested = 1 << 7
	DataVariableAdded = 1 << 8
	DataVariableRemoved = 1 << 9
	DataVariableUpdated = 1 << 10
	DataMetadataUpdated = 1 << 11
	TagTypeUpdated = 1 << 12
	TagAdded = 1 << 13
	TagRemoved = 1 << 14
	TagUpdated = 1 << 15
	SymbolAdded = 1 << 16
	SymbolRemoved = 1 << 17
	SymbolUpdated = 1 << 18
	StringFound = 1 << 19
	StringRemoved = 1 << 20
	TypeDefined = 1 << 21
	TypeUndefined = 1 << 22
	TypeReferenceChanged = 1 << 23
	TypeFieldReferenceChanged = 1 << 24
	SegmentAdded = 1 << 25
	SegmentRemoved = 1 << 26
	SegmentUpdated = 1 << 27
	SectionAdded = 1 << 28
	SectionRemoved = 1 << 29
	SectionUpdated = 1 << 30
	ComponentNameUpdated = 1 << 31
	ComponentAdded = 1 << 32
	ComponentRemoved = 1 << 33
	ComponentMoved = 1 << 34
	ComponentFunctionAdded = 1 << 35
	ComponentFunctionRemoved = 1 << 36
	ComponentDataVariableAdded = 1 << 37
	ComponentDataVariableRemoved = 1 << 38
	ExternalLibraryAdded = 1 << 39
	ExternalLibraryRemoved = 1 << 40
	ExternalLibraryUpdated = 1 << 41
	ExternalLocationAdded = 1 << 42
	ExternalLocationRemoved = 1 << 43
	ExternalLocationUpdated = 1 << 44
	TypeArchiveAttached = 1 << 45
	TypeArchiveDetached = 1 << 46
	TypeArchiveConnected = 1 << 47
	TypeArchiveDisconnected = 1 << 48
	UndoEntryAdded = 1 << 49
	UndoEntryTaken = 1 << 50
	RedoEntryTaken = 1 << 51

	BinaryDataUpdates = DataWritten | DataInserted | DataRemoved
	FunctionLifetime = FunctionAdded | FunctionRemoved
	FunctionUpdates = FunctionLifetime | FunctionUpdated
	DataVariableLifetime = DataVariableAdded | DataVariableRemoved
	DataVariableUpdates = DataVariableLifetime | DataVariableUpdated
	TagLifetime = TagAdded | TagRemoved
	TagUpdates = TagLifetime | TagUpdated
	SymbolLifetime = SymbolAdded | SymbolRemoved
	SymbolUpdates = SymbolLifetime | SymbolUpdated
	StringUpdates = StringFound | StringRemoved
	TypeLifetime = TypeDefined | TypeUndefined
	TypeUpdates = TypeLifetime | TypeReferenceChanged | TypeFieldReferenceChanged
	SegmentLifetime = SegmentAdded | SegmentRemoved
	SegmentUpdates = SegmentLifetime | SegmentUpdated
	SectionLifetime = SectionAdded | SectionRemoved
	SectionUpdates = SectionLifetime | SectionUpdated
	ComponentUpdates = ComponentAdded | ComponentRemoved | ComponentMoved | ComponentFunctionAdded | ComponentFunctionRemoved | ComponentDataVariableAdded | ComponentDataVariableRemoved
	ExternalLibraryLifetime = ExternalLibraryAdded | ExternalLibraryRemoved
	ExternalLibraryUpdates = ExternalLibraryLifetime | ExternalLibraryUpdated
	ExternalLocationLifetime = ExternalLocationAdded | ExternalLocationRemoved
	ExternalLocationUpdates = ExternalLocationLifetime | ExternalLocationUpdated
	TypeArchiveUpdates = TypeArchiveAttached | TypeArchiveDetached | TypeArchiveConnected | TypeArchiveDisconnected
	UndoUpdates = UndoEntryAdded | UndoEntryTaken | RedoEntryTaken


class BinaryDataNotification:
	"""
	``class BinaryDataNotification`` provides an interface for receiving event notifications. Usage requires inheriting
	from this interface, overriding the relevant event handlers, and registering the `BinaryDataNotification` instance
	with a `BinaryView` using the `register_notification` method.

	By default, a `BinaryDataNotification` instance receives notifications for all available notification types. It
	is recommended for users of this interface to initialize the `BinaryDataNotification` base class with with specific
	callbacks of interest by passing the appropriate `NotificationType` flags into the `__init__` constructor.

	Handlers provided by the user should aim to limit the amount of processing within the callback. The
	callback context holds a global lock, preventing other threads from making progress during the callback phase.
	While most of the API can be used safely during this time, care must be taken when issuing a call that can block,
	as waiting for a thread requiring the global lock can result in deadlock.

	The `NotificationBarrier` is a special `NotificationType` that is disabled by default. To enable it, the
	`NotificationBarrier` flag must be passed to `__init__`. This notification is designed to facilitate efficient
	batch processing of other notification types. The idea is to collect other notifications of interest into a cache,
	which can be very efficient as it doesn't require additional locks. After some time, the core generates a
	`NotificationBarrier` event, providing a safe context to move the cache for processing by a different thread.

	To control the time of the next `NotificationBarrier` event, return the desired number of milliseconds until
	the next event from the `NotificationBarrier` callback. Returning zero quiesces future `NotificationBarrier`
	events. If the `NotificationBarrier` is quiesced, the reception of a new callback of interest automatically
	generates a new `NotificationBarrier` call after that notification is delivered. This mechanism effectively
	allows throttling and quiescing when necessary.

	.. note:: Note that the core generates a `NotificationBarrier` as part of the `BinaryDataNotification` registration \
	process. Registering the same `BinaryDataNotification` instance again results in a gratuitous `NotificationBarrier` \
	event, which can be useful in situations requiring a safe context for processing due to some other asynchronous \
	event (e.g., user interaction).

	:Example:

	>>> class NotifyTest(binaryninja.BinaryDataNotification):
	... 	def __init__(self):
	... 		super(NotifyTest, self).__init__(binaryninja.NotificationType.NotificationBarrier | binaryninja.NotificationType.FunctionLifetime | binaryninja.NotificationType.FunctionUpdated)
	... 		self.received_event = False
	... 	def notification_barrier(self, view: 'BinaryView') -> int:
	... 		has_events = self.received_event
	... 		self.received_event = False
	... 		log_info("notification_barrier")
	... 		if has_events:
	... 			return 250
	... 		else:
	... 			return 0
	... 	def function_added(self, view: 'BinaryView', func: '_function.Function') -> None:
	... 		self.received_event = True
	... 		log_info("function_added")
	... 	def function_removed(self, view: 'BinaryView', func: '_function.Function') -> None:
	... 		self.received_event = True
	... 		log_info("function_removed")
	... 	def function_updated(self, view: 'BinaryView', func: '_function.Function') -> None:
	... 		self.received_event = True
	... 		log_info("function_updated")
	...
	>>>
	>>> bv.register_notification(NotifyTest())
	>>>
	"""

	def __init__(self, notifications: NotificationType = None):
		self.notifications = notifications

	def notification_barrier(self, view: 'BinaryView') -> int:
		return 0

	def data_written(self, view: 'BinaryView', offset: int, length: int) -> None:
		pass

	def data_inserted(self, view: 'BinaryView', offset: int, length: int) -> None:
		pass

	def data_removed(self, view: 'BinaryView', offset: int, length: int) -> None:
		pass

	def function_added(self, view: 'BinaryView', func: '_function.Function') -> None:
		pass

	def function_removed(self, view: 'BinaryView', func: '_function.Function') -> None:
		pass

	def function_updated(self, view: 'BinaryView', func: '_function.Function') -> None:
		pass

	def function_update_requested(self, view: 'BinaryView', func: '_function.Function') -> None:
		pass

	def data_var_added(self, view: 'BinaryView', var: 'DataVariable') -> None:
		pass

	def data_var_removed(self, view: 'BinaryView', var: 'DataVariable') -> None:
		pass

	def data_var_updated(self, view: 'BinaryView', var: 'DataVariable') -> None:
		pass

	def data_metadata_updated(self, view: 'BinaryView', offset: int) -> None:
		pass

	def tag_type_updated(self, view: 'BinaryView', tag_type) -> None:
		pass

	def tag_added(
	    self, view: 'BinaryView', tag: 'Tag', ref_type: TagReferenceType, auto_defined: bool,
	    arch: Optional['architecture.Architecture'], func: Optional[_function.Function], addr: int
	) -> None:
		pass

	def tag_updated(
	    self, view: 'BinaryView', tag: 'Tag', ref_type: TagReferenceType, auto_defined: bool,
	    arch: Optional['architecture.Architecture'], func: Optional[_function.Function], addr: int
	) -> None:
		pass

	def tag_removed(
	    self, view: 'BinaryView', tag: 'Tag', ref_type: TagReferenceType, auto_defined: bool,
	    arch: Optional['architecture.Architecture'], func: Optional[_function.Function], addr: int
	) -> None:
		pass

	def symbol_added(self, view: 'BinaryView', sym: '_types.CoreSymbol') -> None:
		pass

	def symbol_updated(self, view: 'BinaryView', sym: '_types.CoreSymbol') -> None:
		pass

	def symbol_removed(self, view: 'BinaryView', sym: '_types.CoreSymbol') -> None:
		pass

	def string_found(self, view: 'BinaryView', string_type: StringType, offset: int, length: int) -> None:
		pass

	def string_removed(self, view: 'BinaryView', string_type: StringType, offset: int, length: int) -> None:
		pass

	def type_defined(self, view: 'BinaryView', name: '_types.QualifiedName', type: '_types.Type') -> None:
		pass

	def type_undefined(self, view: 'BinaryView', name: '_types.QualifiedName', type: '_types.Type') -> None:
		pass

	def type_ref_changed(self, view: 'BinaryView', name: '_types.QualifiedName', type: '_types.Type') -> None:
		pass

	def type_field_ref_changed(self, view: 'BinaryView', name: '_types.QualifiedName', offset: int) -> None:
		pass

	def segment_added(self, view: 'BinaryView', segment: 'Segment') -> None:
		pass

	def segment_updated(self, view: 'BinaryView', segment: 'Segment') -> None:
		pass

	def segment_removed(self, view: 'BinaryView', segment: 'Segment') -> None:
		pass

	def section_added(self, view: 'BinaryView', section: 'Section') -> None:
		pass

	def section_updated(self, view: 'BinaryView', section: 'Section') -> None:
		pass

	def section_removed(self, view: 'BinaryView', section: 'Section') -> None:
		pass

	def component_added(self,  view: 'BinaryView', _component: component.Component) -> None:
		pass

	def component_removed(self, view: 'BinaryView', formerParent: component.Component,
						  _component: component.Component) -> None:
		pass

	def component_name_updated(self,  view: 'BinaryView', previous_name: str, _component: component.Component) -> None:
		pass

	def component_moved(self, view: 'BinaryView', formerParent: component.Component, newParent: component.Component,
						_component: component.Component) -> None:
		pass

	def component_function_added(self, view: 'BinaryView', _component: component.Component, func: '_function.Function'):
		pass

	def component_function_removed(self, view: 'BinaryView', _component: component.Component,
								   func: '_function.Function'):
		pass

	def component_data_var_added(self, view: 'BinaryView', _component: component.Component, var: 'DataVariable'):
		pass

	def component_data_var_removed(self, view: 'BinaryView', _component: component.Component, var: 'DataVariable'):
		pass

	def type_archive_attached(self, view: 'BinaryView', id: str, path: str):
		pass

	def type_archive_detached(self, view: 'BinaryView', id: str, path: str):
		pass

	def type_archive_connected(self, view: 'BinaryView', archive: 'typearchive.TypeArchive'):
		pass

	def type_archive_disconnected(self, view: 'BinaryView', archive: 'typearchive.TypeArchive'):
		pass

	def undo_entry_added(self, view: 'BinaryView', entry: 'undo.UndoEntry'):
		pass

	def undo_entry_taken(self, view: 'BinaryView', entry: 'undo.UndoEntry'):
		pass

	def redo_entry_taken(self, view: 'BinaryView', entry: 'undo.UndoEntry'):
		pass


class StringReference:
	_decodings = {
	    StringType.AsciiString: "ascii", StringType.Utf8String: "utf-8", StringType.Utf16String: "utf-16",
	    StringType.Utf32String: "utf-32",
	}

	def __init__(self, bv: 'BinaryView', string_type: StringType, start: int, length: int):
		self._type = string_type
		self._start = start
		self._length = length
		self._view = bv

	def __repr__(self):
		return f"<{self._type.name}: {self._start:#x}, len {self._length:#x}>"

	def __str__(self):
		return self.value

	def __len__(self):
		return self._length

	@property
	def value(self) -> str:
		return self._view.read(self._start, self._length).decode(self._decodings[self._type])

	@property
	def raw(self) -> bytes:
		return self._view.read(self._start, self._length)

	@property
	def type(self) -> StringType:
		return self._type

	@property
	def start(self) -> int:
		return self._start

	@property
	def length(self) -> int:
		return self._length

	@property
	def view(self) -> 'BinaryView':
		return self._view


class AnalysisCompletionEvent:
	"""
	The ``AnalysisCompletionEvent`` object provides an asynchronous mechanism for receiving
	callbacks when analysis is complete. The callback runs once. A completion event must be added
	for each new analysis in order to be notified of each analysis completion. The
	AnalysisCompletionEvent class takes responsibility for keeping track of the object's lifetime.

	:Example:
		>>> def on_complete(self):
		...     print("Analysis Complete", self._view)
		...
		>>> evt = AnalysisCompletionEvent(bv, on_complete)
		>>>
	"""
	_pending_analysis_completion_events = {}

	def __init__(
	    self, view: 'BinaryView', callback: Union[Callable[['AnalysisCompletionEvent'], None], Callable[[], None]]
	):
		self._view = view
		self.callback = callback
		self._cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._notify)
		self.handle = core.BNAddAnalysisCompletionEvent(self._view.handle, None, self._cb)
		self.__class__._pending_analysis_completion_events[id(self)] = self

	def __del__(self):
		if id(self) in self.__class__._pending_analysis_completion_events:
			del self.__class__._pending_analysis_completion_events[id(self)]
		if core is not None:
			core.BNFreeAnalysisCompletionEvent(self.handle)

	def _notify(self, ctxt):
		if id(self) in self.__class__._pending_analysis_completion_events:
			del self.__class__._pending_analysis_completion_events[id(self)]
		try:
			arg_offset = inspect.ismethod(self.callback)
			callback_spec = inspect.getfullargspec(self.callback)
			if len(callback_spec.args) > arg_offset:
				self.callback(self)  # type: ignore
			else:
				self.callback()  # type: ignore
		except:
			log_error(traceback.format_exc())

	def _empty_callback(self):
		pass

	def cancel(self) -> None:
		"""
		The ``cancel`` method will cancel analysis for an :py:class:`AnalysisCompletionEvent`.

		.. warning:: This method should only be used when the system is being shut down and no further analysis should be done afterward.

		"""
		self.callback = self._empty_callback
		core.BNCancelAnalysisCompletionEvent(self.handle)
		if id(self) in self.__class__._pending_analysis_completion_events:
			del self.__class__._pending_analysis_completion_events[id(self)]

	@property
	def view(self) -> 'BinaryView':
		return self._view


class BinaryViewEvent:
	"""
	The ``BinaryViewEvent`` object provides a mechanism for receiving callbacks	when a BinaryView
	is Finalized or the initial analysis is finished. The BinaryView finalized callbacks run before the
	initial analysis starts. The callbacks run one-after-another in the same order as they get registered.
	It is a good place to modify the BinaryView to add extra information to it.

	For newly opened binaries, the initial analysis completion callbacks run after the initial analysis,
	as well as linear sweep	and signature matcher (if they are configured to run), completed. For loading
	old databases, the callbacks run after the database is loaded, as well as any automatic analysis
	update finishes.

	The callback function receives a BinaryView as its parameter. It is possible to call
	BinaryView.add_analysis_completion_event() on it to set up other callbacks for analysis completion.

	:Example:
		>>> def callback(bv):
		... 	print('start: 0x%x' % bv.start)
		...
		>>> BinaryViewType.add_binaryview_finalized_event(callback)
	"""
	BinaryViewEventCallback = Callable[['BinaryView'], None]
	# This has no functional purposes;
	# we just need it to stop Python from prematurely freeing the object
	_binaryview_events = {}

	@classmethod
	def register(cls, event_type: BinaryViewEventType, callback: BinaryViewEventCallback) -> None:
		callback_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
		                                ctypes.POINTER(core.BNBinaryView
		                                               ))(lambda ctxt, view: cls._notify(view, callback))
		core.BNRegisterBinaryViewEvent(event_type, callback_obj, None)
		cls._binaryview_events[len(cls._binaryview_events)] = callback_obj

	@staticmethod
	def _notify(view: core.BNBinaryViewHandle, callback: BinaryViewEventCallback) -> None:
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
			view_obj = BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
			callback(view_obj)
		except:
			log_error(traceback.format_exc())


@dataclass(frozen=True)
class ActiveAnalysisInfo:
	func: '_function.Function'
	analysis_time: int
	update_count: int
	submit_count: int

	def __repr__(self):
		return f"<ActiveAnalysisInfo {self.func}, analysis_time {self.analysis_time}, update_count {self.update_count}, submit_count {self.submit_count}>"


@dataclass(frozen=True)
class AnalysisInfo:
	state: AnalysisState
	analysis_time: int
	active_info: List[ActiveAnalysisInfo]

	def __repr__(self):
		return f"<AnalysisInfo {self.state}, analysis_time {self.analysis_time}, active_info {self.active_info}>"


@dataclass(frozen=True)
class AnalysisProgress:
	state: AnalysisState
	count: int
	total: int

	def __str__(self):
		if self.state == AnalysisState.InitialState:
			return "Initial"
		if self.state == AnalysisState.HoldState:
			return "Hold"
		if self.state == AnalysisState.IdleState:
			return "Idle"
		if self.state == AnalysisState.DisassembleState:
			return "Disassembling (%d/%d)" % (self.count, self.total)
		if self.state == AnalysisState.AnalyzeState:
			return "Analyzing (%d/%d)" % (self.count, self.total)
		return "Extended Analysis"

	def __repr__(self):
		return f"<progress: {self}>"


class BinaryDataNotificationCallbacks:
	def __init__(self, view: 'BinaryView', notify: 'BinaryDataNotification'):
		self._view = view
		self._notify = notify
		self._cb = core.BNBinaryDataNotification()
		self._cb.context = 0
		if (not hasattr(notify, 'notifications')) or (hasattr(notify, 'notifications') and notify.notifications is None):
			self._cb.notificationBarrier = self._cb.notificationBarrier
			self._cb.dataWritten = self._cb.dataWritten.__class__(self._data_written)
			self._cb.dataInserted = self._cb.dataInserted.__class__(self._data_inserted)
			self._cb.dataRemoved = self._cb.dataRemoved.__class__(self._data_removed)
			self._cb.functionAdded = self._cb.functionAdded.__class__(self._function_added)
			self._cb.functionRemoved = self._cb.functionRemoved.__class__(self._function_removed)
			self._cb.functionUpdated = self._cb.functionUpdated.__class__(self._function_updated)
			self._cb.functionUpdateRequested = self._cb.functionUpdateRequested.__class__(self._function_update_requested)
			self._cb.dataVariableAdded = self._cb.dataVariableAdded.__class__(self._data_var_added)
			self._cb.dataVariableRemoved = self._cb.dataVariableRemoved.__class__(self._data_var_removed)
			self._cb.dataVariableUpdated = self._cb.dataVariableUpdated.__class__(self._data_var_updated)
			self._cb.dataMetadataUpdated = self._cb.dataMetadataUpdated.__class__(self._data_metadata_updated)
			self._cb.tagTypeUpdated = self._cb.tagTypeUpdated.__class__(self._tag_type_updated)
			self._cb.tagAdded = self._cb.tagAdded.__class__(self._tag_added)
			self._cb.tagRemoved = self._cb.tagRemoved.__class__(self._tag_removed)
			self._cb.tagUpdated = self._cb.tagUpdated.__class__(self._tag_updated)

			self._cb.symbolAdded = self._cb.symbolAdded.__class__(self._symbol_added)
			self._cb.symbolRemoved = self._cb.symbolRemoved.__class__(self._symbol_removed)
			self._cb.symbolUpdated = self._cb.symbolUpdated.__class__(self._symbol_updated)
			self._cb.stringFound = self._cb.stringFound.__class__(self._string_found)
			self._cb.stringRemoved = self._cb.stringRemoved.__class__(self._string_removed)
			self._cb.typeDefined = self._cb.typeDefined.__class__(self._type_defined)
			self._cb.typeUndefined = self._cb.typeUndefined.__class__(self._type_undefined)
			self._cb.typeReferenceChanged = self._cb.typeReferenceChanged.__class__(self._type_ref_changed)
			self._cb.typeFieldReferenceChanged = self._cb.typeFieldReferenceChanged.__class__(self._type_field_ref_changed)
			self._cb.segmentAdded = self._cb.segmentAdded.__class__(self._segment_added)
			self._cb.segmentRemoved = self._cb.segmentRemoved.__class__(self._segment_removed)
			self._cb.segmentUpdated = self._cb.segmentUpdated.__class__(self._segment_updated)

			self._cb.sectionAdded = self._cb.sectionAdded.__class__(self._section_added)
			self._cb.sectionRemoved = self._cb.sectionRemoved.__class__(self._section_removed)
			self._cb.sectionUpdated = self._cb.sectionUpdated.__class__(self._section_updated)
			self._cb.componentNameUpdated = self._cb.componentNameUpdated.__class__(self._component_name_updated)
			self._cb.componentAdded = self._cb.componentAdded.__class__(self._component_added)
			self._cb.componentRemoved = self._cb.componentRemoved.__class__(self._component_removed)
			self._cb.componentMoved = self._cb.componentMoved.__class__(self._component_moved)
			self._cb.componentFunctionAdded = self._cb.componentFunctionAdded.__class__(self._component_function_added)
			self._cb.componentFunctionRemoved = self._cb.componentFunctionRemoved.__class__(self._component_function_removed)
			self._cb.componentDataVariableAdded = self._cb.componentDataVariableAdded.__class__(self._component_data_variable_added)
			self._cb.componentDataVariableRemoved = self._cb.componentDataVariableRemoved.__class__(self._component_data_variable_removed)

			self._cb.typeArchiveAttached = self._cb.typeArchiveAttached.__class__(self._type_archive_attached)
			self._cb.typeArchiveDetached = self._cb.typeArchiveDetached.__class__(self._type_archive_detached)
			self._cb.typeArchiveConnected = self._cb.typeArchiveConnected.__class__(self._type_archive_connected)
			self._cb.typeArchiveDisconnected = self._cb.typeArchiveDisconnected.__class__(self._type_archive_disconnected)

			self._cb.undoEntryAdded = self._cb.undoEntryAdded.__class__(self._undo_entry_added)
			self._cb.undoEntryTaken = self._cb.undoEntryTaken.__class__(self._undo_entry_taken)
			self._cb.redoEntryTaken = self._cb.redoEntryTaken.__class__(self._redo_entry_taken)
		else:
			if notify.notifications & NotificationType.NotificationBarrier:
				self._cb.notificationBarrier = self._cb.notificationBarrier.__class__(self._notification_barrier)
			if notify.notifications & NotificationType.DataWritten:
				self._cb.dataWritten = self._cb.dataWritten.__class__(self._data_written)
			if notify.notifications & NotificationType.DataInserted:
				self._cb.dataInserted = self._cb.dataInserted.__class__(self._data_inserted)
			if notify.notifications & NotificationType.DataRemoved:
				self._cb.dataRemoved = self._cb.dataRemoved.__class__(self._data_removed)
			if notify.notifications & NotificationType.FunctionAdded:
				self._cb.functionAdded = self._cb.functionAdded.__class__(self._function_added)
			if notify.notifications & NotificationType.FunctionRemoved:
				self._cb.functionRemoved = self._cb.functionRemoved.__class__(self._function_removed)
			if notify.notifications & NotificationType.FunctionUpdated:
				self._cb.functionUpdated = self._cb.functionUpdated.__class__(self._function_updated)
			if notify.notifications & NotificationType.FunctionUpdateRequested:
				self._cb.functionUpdateRequested = self._cb.functionUpdateRequested.__class__(self._function_update_requested)
			if notify.notifications & NotificationType.DataVariableAdded:
				self._cb.dataVariableAdded = self._cb.dataVariableAdded.__class__(self._data_var_added)
			if notify.notifications & NotificationType.DataVariableRemoved:
				self._cb.dataVariableRemoved = self._cb.dataVariableRemoved.__class__(self._data_var_removed)
			if notify.notifications & NotificationType.DataVariableUpdated:
				self._cb.dataVariableUpdated = self._cb.dataVariableUpdated.__class__(self._data_var_updated)
			if notify.notifications & NotificationType.DataMetadataUpdated:
				self._cb.dataMetadataUpdated = self._cb.dataMetadataUpdated.__class__(self._data_metadata_updated)
			if notify.notifications & NotificationType.TagTypeUpdated:
				self._cb.tagTypeUpdated = self._cb.tagTypeUpdated.__class__(self._tag_type_updated)
			if notify.notifications & NotificationType.TagAdded:
				self._cb.tagAdded = self._cb.tagAdded.__class__(self._tag_added)
			if notify.notifications & NotificationType.TagRemoved:
				self._cb.tagRemoved = self._cb.tagRemoved.__class__(self._tag_removed)
			if notify.notifications & NotificationType.TagUpdated:
				self._cb.tagUpdated = self._cb.tagUpdated.__class__(self._tag_updated)
			if notify.notifications & NotificationType.SymbolAdded:
				self._cb.symbolAdded = self._cb.symbolAdded.__class__(self._symbol_added)
			if notify.notifications & NotificationType.SymbolRemoved:
				self._cb.symbolRemoved = self._cb.symbolRemoved.__class__(self._symbol_removed)
			if notify.notifications & NotificationType.SymbolUpdated:
				self._cb.symbolUpdated = self._cb.symbolUpdated.__class__(self._symbol_updated)
			if notify.notifications & NotificationType.StringFound:
				self._cb.stringFound = self._cb.stringFound.__class__(self._string_found)
			if notify.notifications & NotificationType.StringRemoved:
				self._cb.stringRemoved = self._cb.stringRemoved.__class__(self._string_removed)
			if notify.notifications & NotificationType.TypeDefined:
				self._cb.typeDefined = self._cb.typeDefined.__class__(self._type_defined)
			if notify.notifications & NotificationType.TypeUndefined:
				self._cb.typeUndefined = self._cb.typeUndefined.__class__(self._type_undefined)
			if notify.notifications & NotificationType.TypeReferenceChanged:
				self._cb.typeReferenceChanged = self._cb.typeReferenceChanged.__class__(self._type_ref_changed)
			if notify.notifications & NotificationType.TypeFieldReferenceChanged:
				self._cb.typeFieldReferenceChanged = self._cb.typeFieldReferenceChanged.__class__(self._type_field_ref_changed)
			if notify.notifications & NotificationType.SegmentAdded:
				self._cb.segmentAdded = self._cb.segmentAdded.__class__(self._segment_added)
			if notify.notifications & NotificationType.SegmentRemoved:
				self._cb.segmentRemoved = self._cb.segmentRemoved.__class__(self._segment_removed)
			if notify.notifications & NotificationType.SegmentUpdated:
				self._cb.segmentUpdated = self._cb.segmentUpdated.__class__(self._segment_updated)
			if notify.notifications & NotificationType.SectionAdded:
				self._cb.sectionAdded = self._cb.sectionAdded.__class__(self._section_added)
			if notify.notifications & NotificationType.SectionRemoved:
				self._cb.sectionRemoved = self._cb.sectionRemoved.__class__(self._section_removed)
			if notify.notifications & NotificationType.SectionUpdated:
				self._cb.sectionUpdated = self._cb.sectionUpdated.__class__(self._section_updated)
			if notify.notifications & NotificationType.ComponentNameUpdated:
				self._cb.componentNameUpdated = self._cb.componentNameUpdated.__class__(self._component_name_updated)
			if notify.notifications & NotificationType.ComponentAdded:
				self._cb.componentAdded = self._cb.componentAdded.__class__(self._component_added)
			if notify.notifications & NotificationType.ComponentRemoved:
				self._cb.componentRemoved = self._cb.componentRemoved.__class__(self._component_removed)
			if notify.notifications & NotificationType.ComponentMoved:
				self._cb.componentMoved = self._cb.componentMoved.__class__(self._component_moved)
			if notify.notifications & NotificationType.ComponentFunctionAdded:
				self._cb.componentFunctionAdded = self._cb.componentFunctionAdded.__class__(self._component_function_added)
			if notify.notifications & NotificationType.ComponentFunctionRemoved:
				self._cb.componentFunctionRemoved = self._cb.componentFunctionRemoved.__class__(self._component_function_removed)
			if notify.notifications & NotificationType.ComponentDataVariableAdded:
				self._cb.componentDataVariableAdded = self._cb.componentDataVariableAdded.__class__(self._component_data_variable_added)
			if notify.notifications & NotificationType.ComponentDataVariableRemoved:
				self._cb.componentDataVariableRemoved = self._cb.componentDataVariableRemoved.__class__(self._component_data_variable_removed)

			if notify.notifications & NotificationType.TypeArchiveAttached:
				self._cb.typeArchiveAttached = self._cb.typeArchiveAttached.__class__(self._type_archive_attached)
			if notify.notifications & NotificationType.TypeArchiveDetached:
				self._cb.typeArchiveDetached = self._cb.typeArchiveDetached.__class__(self._type_archive_detached)
			if notify.notifications & NotificationType.TypeArchiveConnected:
				self._cb.typeArchiveConnected = self._cb.typeArchiveConnected.__class__(self._type_archive_connected)
			if notify.notifications & NotificationType.TypeArchiveDisconnected:
				self._cb.typeArchiveDisconnected = self._cb.typeArchiveDisconnected.__class__(self._type_archive_disconnected)

			if notify.notifications & NotificationType.UndoEntryAdded:
				self._cb.undoEntryAdded = self._cb.undoEntryAdded.__class__(self._undo_entry_added)
			if notify.notifications & NotificationType.UndoEntryTaken:
				self._cb.undoEntryTaken = self._cb.undoEntryTaken.__class__(self._undo_entry_taken)
			if notify.notifications & NotificationType.RedoEntryTaken:
				self._cb.redoEntryTaken = self._cb.redoEntryTaken.__class__(self._redo_entry_taken)

	def _register(self) -> None:
		core.BNRegisterDataNotification(self._view.handle, self._cb)

	def _unregister(self) -> None:
		core.BNUnregisterDataNotification(self._view.handle, self._cb)

	def _notification_barrier(self, ctxt, view: core.BNBinaryView) -> int:
		try:
			return self._notify.notification_barrier(self._view)
		except OSError:
			log_error(traceback.format_exc())

	def _data_written(self, ctxt, view: core.BNBinaryView, offset: int, length: int) -> None:
		try:
			self._notify.data_written(self._view, offset, length)
		except OSError:
			log_error(traceback.format_exc())

	def _data_inserted(self, ctxt, view: core.BNBinaryView, offset: int, length: int) -> None:
		try:
			self._notify.data_inserted(self._view, offset, length)
		except:
			log_error(traceback.format_exc())

	def _data_removed(self, ctxt, view: core.BNBinaryView, offset: int, length: int) -> None:
		try:
			self._notify.data_removed(self._view, offset, length)
		except:
			log_error(traceback.format_exc())

	def _function_added(self, ctxt, view: core.BNBinaryView, func: core.BNFunctionHandle) -> None:
		try:
			self._notify.function_added(self._view, _function.Function(self._view, core.BNNewFunctionReference(func)))
		except:
			log_error(traceback.format_exc())

	def _function_removed(self, ctxt, view: core.BNBinaryView, func: core.BNFunctionHandle) -> None:
		try:
			self._notify.function_removed(self._view, _function.Function(self._view, core.BNNewFunctionReference(func)))
		except:
			log_error(traceback.format_exc())

	def _function_updated(self, ctxt, view: core.BNBinaryView, func: core.BNFunctionHandle) -> None:
		try:
			self._notify.function_updated(self._view, _function.Function(self._view, core.BNNewFunctionReference(func)))
		except:
			log_error(traceback.format_exc())

	def _function_update_requested(self, ctxt, view: core.BNBinaryView, func: core.BNFunctionHandle) -> None:
		try:
			self._notify.function_update_requested(
			    self._view, _function.Function(self._view, core.BNNewFunctionReference(func))
			)
		except:
			log_error(traceback.format_exc())

	def _data_var_added(self, ctxt, view: core.BNBinaryView, var: core.BNDataVariableHandle) -> None:
		try:
			self._notify.data_var_added(self._view, DataVariable.from_core_struct(var[0], self._view))
		except:
			log_error(traceback.format_exc())

	def _data_var_removed(self, ctxt, view: core.BNBinaryView, var: core.BNDataVariableHandle) -> None:
		try:
			self._notify.data_var_removed(self._view, DataVariable.from_core_struct(var[0], self._view))
		except:
			log_error(traceback.format_exc())

	def _data_var_updated(self, ctxt, view: core.BNBinaryView, var: core.BNDataVariableHandle) -> None:
		try:
			self._notify.data_var_updated(self._view, DataVariable.from_core_struct(var[0], self._view))
		except:
			log_error(traceback.format_exc())

	def _data_metadata_updated(self, ctxt, view: core.BNBinaryView, offset: int) -> None:
		try:
			self._notify.data_metadata_updated(self._view, offset)
		except:
			log_error(traceback.format_exc())

	def _tag_type_updated(self, ctxt, view: core.BNBinaryView, tag_type: core.BNTagTypeHandle) -> None:
		try:
			core_tag_type = core.BNNewTagTypeReference(tag_type)
			assert core_tag_type is not None, "core.BNNewTagTypeReference returned None"
			self._notify.tag_type_updated(self._view, TagType(core_tag_type))
		except:
			log_error(traceback.format_exc())

	def _tag_added(self, ctxt, view: core.BNBinaryView, tag_ref: core.BNTagReferenceHandle) -> None:
		try:
			ref_type = tag_ref[0].refType
			auto_defined = tag_ref[0].autoDefined
			core_tag = core.BNNewTagReference(tag_ref[0].tag)
			assert core_tag is not None, "core.BNNewTagReference returned None"
			tag = Tag(core_tag)
			# Null for data tags (not in any arch or function)
			if ctypes.cast(tag_ref[0].arch, ctypes.c_void_p).value is None:
				arch = None
			else:
				arch = architecture.CoreArchitecture._from_cache(tag_ref[0].arch)
			if ctypes.cast(tag_ref[0].func, ctypes.c_void_p).value is None:
				func = None
			else:
				func = _function.Function(self._view, core.BNNewFunctionReference(tag_ref[0].func))
			addr = tag_ref[0].addr
			self._notify.tag_added(self._view, tag, ref_type, auto_defined, arch, func, addr)
		except:
			log_error(traceback.format_exc())

	def _tag_updated(self, ctxt, view: core.BNBinaryView, tag_ref: core.BNTagReferenceHandle) -> None:
		try:
			ref_type = tag_ref[0].refType
			auto_defined = tag_ref[0].autoDefined
			core_tag = core.BNNewTagReference(tag_ref[0].tag)
			assert core_tag is not None
			tag = Tag(core_tag)
			# Null for data tags (not in any arch or function)
			if ctypes.cast(tag_ref[0].arch, ctypes.c_void_p).value is None:
				arch = None
			else:
				arch = architecture.CoreArchitecture._from_cache(tag_ref[0].arch)
			if ctypes.cast(tag_ref[0].func, ctypes.c_void_p).value is None:
				func = None
			else:
				func = _function.Function(self._view, core.BNNewFunctionReference(tag_ref[0].func))
			addr = tag_ref[0].addr
			self._notify.tag_updated(self._view, tag, ref_type, auto_defined, arch, func, addr)
		except:
			log_error(traceback.format_exc())

	def _tag_removed(self, ctxt, view: core.BNBinaryView, tag_ref: core.BNTagReferenceHandle) -> None:
		try:
			ref_type = tag_ref[0].refType
			auto_defined = tag_ref[0].autoDefined
			core_tag = core.BNNewTagReference(tag_ref[0].tag)
			assert core_tag is not None, "core.BNNewTagReference returned None"
			tag = Tag(core_tag)
			# Null for data tags (not in any arch or function)
			if ctypes.cast(tag_ref[0].arch, ctypes.c_void_p).value is None:
				arch = None
			else:
				arch = architecture.CoreArchitecture._from_cache(tag_ref[0].arch)
			if ctypes.cast(tag_ref[0].func, ctypes.c_void_p).value is None:
				func = None
			else:
				func = _function.Function(self._view, core.BNNewFunctionReference(tag_ref[0].func))
			addr = tag_ref[0].addr
			self._notify.tag_removed(self._view, tag, ref_type, auto_defined, arch, func, addr)
		except:
			log_error(traceback.format_exc())

	def _symbol_added(self, ctxt, view: core.BNBinaryView, sym: core.BNSymbol) -> None:
		try:
			_handle = core.BNNewSymbolReference(sym)
			assert _handle is not None, "core.BNNewSymbolReference returned None"
			self._notify.symbol_added(self._view, _types.CoreSymbol(_handle))
		except:
			log_error(traceback.format_exc())

	def _symbol_updated(self, ctxt, view: core.BNBinaryView, sym: core.BNSymbol) -> None:
		try:
			_handle = core.BNNewSymbolReference(sym)
			assert _handle is not None, "core.BNNewSymbolReference returned None"
			self._notify.symbol_updated(self._view, _types.CoreSymbol(_handle))
		except:
			log_error(traceback.format_exc())

	def _symbol_removed(self, ctxt, view: core.BNBinaryView, sym: core.BNSymbol) -> None:
		try:
			_handle = core.BNNewSymbolReference(sym)
			assert _handle is not None, "core.BNNewSymbolReference returned None"
			self._notify.symbol_removed(self._view, _types.CoreSymbol(_handle))
		except:
			log_error(traceback.format_exc())

	def _string_found(self, ctxt, view: core.BNBinaryView, string_type: int, offset: int, length: int) -> None:
		try:
			self._notify.string_found(self._view, StringType(string_type), offset, length)
		except:
			log_error(traceback.format_exc())

	def _string_removed(self, ctxt, view: core.BNBinaryView, string_type: int, offset: int, length: int) -> None:
		try:
			self._notify.string_removed(self._view, StringType(string_type), offset, length)
		except:
			log_error(traceback.format_exc())

	def _type_defined(self, ctxt, view: core.BNBinaryView, name: str, type_obj: '_types.Type') -> None:
		try:
			qualified_name = _types.QualifiedName._from_core_struct(name[0])
			self._notify.type_defined(
			    self._view, qualified_name,
			    _types.Type.create(core.BNNewTypeReference(type_obj), platform=self._view.platform)
			)
		except:
			log_error(traceback.format_exc())

	def _type_undefined(self, ctxt, view: core.BNBinaryView, name: str, type_obj: '_types.Type') -> None:
		try:
			qualified_name = _types.QualifiedName._from_core_struct(name[0])
			self._notify.type_undefined(
			    self._view, qualified_name,
			    _types.Type.create(core.BNNewTypeReference(type_obj), platform=self._view.platform)
			)
		except:
			log_error(traceback.format_exc())

	def _type_ref_changed(self, ctxt, view: core.BNBinaryView, name: str, type_obj: '_types.Type') -> None:
		try:
			qualified_name = _types.QualifiedName._from_core_struct(name[0])
			self._notify.type_ref_changed(
			    self._view, qualified_name,
			    _types.Type.create(core.BNNewTypeReference(type_obj), platform=self._view.platform)
			)
		except:
			log_error(traceback.format_exc())

	def _type_field_ref_changed(self, ctxt, view: core.BNBinaryView, name: str, offset: int) -> None:
		try:
			qualified_name = _types.QualifiedName._from_core_struct(name[0])
			self._notify.type_field_ref_changed(self._view, qualified_name, offset)
		except:
			log_error(traceback.format_exc())

	def _segment_added(self, ctxt, view: core.BNBinaryView, segment_obj: core.BNSegment) -> None:
		try:
			segment_handle = core.BNNewSegmentReference(segment_obj)
			assert segment_handle is not None, "core.BNNewSegmentReference returned None"
			result = Segment(segment_handle)
			self._notify.segment_added(self._view, result)
		except:
			log_error(traceback.format_exc())

	def _segment_updated(self, ctxt, view: core.BNBinaryView, segment_obj: core.BNSegment) -> None:
		try:
			segment_handle = core.BNNewSegmentReference(segment_obj)
			assert segment_handle is not None, "core.BNNewSegmentReference returned None"
			result = Segment(segment_handle)
			self._notify.segment_updated(self._view, result)
		except:
			log_error(traceback.format_exc())

	def _segment_removed(self, ctxt, view: core.BNBinaryView, segment_obj: core.BNSegment) -> None:
		try:
			segment_handle = core.BNNewSegmentReference(segment_obj)
			assert segment_handle is not None, "core.BNNewSegmentReference returned None"
			result = Segment(segment_handle)
			self._notify.segment_removed(self._view, result)
		except:
			log_error(traceback.format_exc())

	def _section_added(self, ctxt, view: core.BNBinaryView, section_obj: core.BNSection) -> None:
		try:
			section_handle = core.BNNewSectionReference(section_obj)
			assert section_handle is not None, "core.BNNewSectionReference returned None"
			result = Section(section_handle)
			self._notify.section_added(self._view, result)
		except:
			log_error(traceback.format_exc())

	def _section_updated(self, ctxt, view: core.BNBinaryView, section_obj: core.BNSection) -> None:
		try:
			section_handle = core.BNNewSectionReference(section_obj)
			assert section_handle is not None, "core.BNNewSectionReference returned None"
			result = Section(section_handle)
			self._notify.section_updated(self._view, result)
		except:
			log_error(traceback.format_exc())

	def _section_removed(self, ctxt, view: core.BNBinaryView, section_obj: core.BNSection) -> None:
		try:
			section_handle = core.BNNewSectionReference(section_obj)
			assert section_handle is not None, "core.BNNewSectionReference returned None"
			result = Section(section_handle)
			self._notify.section_removed(self._view, result)
		except:
			log_error(traceback.format_exc())

	def _component_added(self, ctxt, view: core.BNBinaryView, _component: core.BNComponent):
		try:
			component_handle = core.BNNewComponentReference(_component)
			assert component_handle is not None, "core.BNNewComponentReference returned None"
			result = component.Component(component_handle)
			self._notify.component_added(self._view, result)
		except:
			log_error(traceback.format_exc())

	def _component_removed(self, ctxt, view: core.BNBinaryView, formerParent: core.BNComponent, _component: core.BNComponent):
		try:
			formerParent_handle = core.BNNewComponentReference(formerParent)
			assert formerParent_handle is not None, "core.BNNewComponentReference returned None"
			formerParentResult = component.Component(formerParent_handle)
			component_handle = core.BNNewComponentReference(_component)
			assert component_handle is not None, "core.BNNewComponentReference returned None"
			result = component.Component(component_handle)
			self._notify.component_removed(self._view, formerParentResult, result)
		except:
			log_error(traceback.format_exc())

	def _component_name_updated(self, ctxt, view: core.BNBinaryView, previous_name: str, _component: core.BNComponent):
		try:
			component_handle = core.BNNewComponentReference(_component)
			assert component_handle is not None, "core.BNNewComponentReference returned None"
			result = component.Component(component_handle)
			self._notify.component_name_updated(self._view, previous_name, result)
		except:
			log_error(traceback.format_exc())

	def _component_moved(self, ctxt, view: core.BNBinaryView, formerParent: core.BNComponent,
						 newParent: core.BNComponent, _component: core.BNComponent):
		try:
			formerParent_handle = core.BNNewComponentReference(formerParent)
			assert formerParent_handle is not None, "core.BNNewComponentReference returned None"
			formerParentResult = component.Component(formerParent_handle)
			newParent_handle = core.BNNewComponentReference(newParent)
			assert newParent_handle is not None, "core.BNNewComponentReference returned None"
			newParentResult = component.Component(newParent_handle)
			component_handle = core.BNNewComponentReference(_component)
			assert component_handle is not None, "core.BNNewComponentReference returned None"
			result = component.Component(component_handle)
			self._notify.component_moved(self._view, formerParentResult, newParentResult, result)
		except:
			log_error(traceback.format_exc())

	def _component_function_added(self, ctxt, view: core.BNBinaryView, _component: core.BNComponent,
								  func: '_function.Function'):
		try:
			component_handle = core.BNNewComponentReference(_component)
			assert component_handle is not None, "core.BNNewComponentReference returned None"
			result = component.Component(component_handle)
			function_handle = core.BNNewFunctionReference(func)
			assert function_handle is not None, "core.BNNewFunctionReference returned None"
			function = _function.Function(self._view, function_handle)
			self._notify.component_function_added(self._view, result, function)
		except:
			log_error(traceback.format_exc())

	def _component_function_removed(self, ctxt, view: core.BNBinaryView, _component: core.BNComponent,
								func: '_function.Function'):
		try:
			component_handle = core.BNNewComponentReference(_component)
			assert component_handle is not None, "core.BNNewComponentReference returned None"
			result = component.Component(component_handle)
			function_handle = core.BNNewFunctionReference(func)
			assert function_handle is not None, "core.BNNewFunctionReference returned None"
			function = _function.Function(self._view, function_handle)
			self._notify.component_function_removed(self._view, result, function)
		except:
			log_error(traceback.format_exc())

	def _component_data_variable_added(self, ctxt, view: core.BNBinaryView, _component: core.BNComponent,
									   var: core.BNDataVariable):
		try:
			component_handle = core.BNNewComponentReference(_component)
			assert component_handle is not None, "core.BNNewComponentReference returned None"
			result = component.Component(component_handle)
			self._notify.component_data_var_added(self._view, result, DataVariable.from_core_struct(var, self._view))
		except:
			log_error(traceback.format_exc())

	def _component_data_variable_removed(self, ctxt, view: core.BNBinaryView, _component: core.BNComponent,
									var: core.BNDataVariable):
		try:
			component_handle = core.BNNewComponentReference(_component)
			assert component_handle is not None, "core.BNNewComponentReference returned None"
			result = component.Component(component_handle)
			self._notify.component_data_var_removed(self._view, result, DataVariable.from_core_struct(var, self._view))
		except:
			log_error(traceback.format_exc())

	def _type_archive_attached(self, ctxt, view: core.BNBinaryView, id: ctypes.c_char_p, path: ctypes.c_char_p):
		try:
			self._notify.type_archive_attached(self._view, core.pyNativeStr(id), core.pyNativeStr(path))
		except:
			log_error(traceback.format_exc())

	def _type_archive_detached(self, ctxt, view: core.BNBinaryView, id: ctypes.c_char_p, path: ctypes.c_char_p):
		try:
			self._notify.type_archive_detached(self._view, core.pyNativeStr(id), core.pyNativeStr(path))
		except:
			log_error(traceback.format_exc())

	def _type_archive_connected(self, ctxt, view: core.BNBinaryView, archive: core.BNTypeArchive):
		try:
			py_archive = typearchive.TypeArchive(handle=core.BNNewTypeArchiveReference(archive))
			self._notify.type_archive_connected(self._view, py_archive)
		except:
			log_error(traceback.format_exc())

	def _type_archive_disconnected(self, ctxt, view: core.BNBinaryView, archive: core.BNTypeArchive):
		try:
			py_archive = typearchive.TypeArchive(handle=core.BNNewTypeArchiveReference(archive))
			self._notify.type_archive_disconnected(self._view, py_archive)
		except:
			log_error(traceback.format_exc())

	def _undo_entry_added(self, ctxt, view: core.BNBinaryView, entry: core.BNUndoEntry):
		try:
			py_entry = undo.UndoEntry(handle=core.BNNewUndoEntryReference(entry))
			self._notify.undo_entry_added(self._view, py_entry)
		except:
			log_error(traceback.format_exc())

	def _undo_entry_taken(self, ctxt, view: core.BNBinaryView, entry: core.BNUndoEntry):
		try:
			py_entry = undo.UndoEntry(handle=core.BNNewUndoEntryReference(entry))
			self._notify.undo_entry_taken(self._view, py_entry)
		except:
			log_error(traceback.format_exc())

	def _redo_entry_taken(self, ctxt, view: core.BNBinaryView, entry: core.BNUndoEntry):
		try:
			py_entry = undo.UndoEntry(handle=core.BNNewUndoEntryReference(entry))
			self._notify.redo_entry_taken(self._view, py_entry)
		except:
			log_error(traceback.format_exc())

	@property
	def view(self) -> 'BinaryView':
		return self._view

	@property
	def notify(self) -> 'BinaryDataNotification':
		return self._notify


class _BinaryViewTypeMetaclass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetBinaryViewTypes(count)
		if types is None:
			return
		try:
			for i in range(0, count.value):
				yield BinaryViewType(types[i])
		finally:
			core.BNFreeBinaryViewTypeList(types)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		view_type = core.BNGetBinaryViewTypeByName(str(value))
		if view_type is None:
			raise KeyError(f"'{value}' is not a valid view type")
		return BinaryViewType(view_type)


class BinaryViewType(metaclass=_BinaryViewTypeMetaclass):
	"""
	The ``BinaryViewType`` object is used internally and should not be directly instantiated.
	"""

	_platform_recognizers = {} # Used to force Python callback objects to not get garbage collected

	def __init__(self, handle: core.BNBinaryViewTypeHandle):
		_handle = core.BNBinaryViewTypeHandle
		self.handle = ctypes.cast(handle, _handle)

	def __repr__(self):
		return f"<view type: '{self.name}'>"

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
		"""BinaryView name (read-only)"""
		return core.BNGetBinaryViewTypeName(self.handle)

	@property
	def long_name(self) -> str:
		"""BinaryView long name (read-only)"""
		return core.BNGetBinaryViewTypeLongName(self.handle)

	@property
	def is_deprecated(self) -> bool:
		"""returns if the BinaryViewType is deprecated (read-only)"""
		return core.BNIsBinaryViewTypeDeprecated(self.handle)

	@property
	def is_force_loadable(self) -> bool:
		"""returns if the BinaryViewType is force loadable (read-only)"""
		return core.BNIsBinaryViewTypeForceLoadable(self.handle)

	def create(self, data: 'BinaryView') -> Optional['BinaryView']:
		view = core.BNCreateBinaryViewOfType(self.handle, data.handle)
		if view is None:
			return None
		return BinaryView(file_metadata=data.file, handle=view)

	def open(self, src: PathType, file_metadata: 'filemetadata.FileMetadata' = None) -> Optional['BinaryView']:
		data = BinaryView.open(src, file_metadata)
		if data is None:
			return None
		return self.create(data)

	# TODO : Check if we need binary_view_type's at all after these deprecations? (move add_binaryview_finalized_event and add_binaryview_initial_analysis_completion_event to BinaryView?)

	def parse(self, data: 'BinaryView') -> Optional['BinaryView']:
		view = core.BNParseBinaryViewOfType(self.handle, data.handle)
		if view is None:
			return None
		return BinaryView(file_metadata=data.file, handle=view)

	def is_valid_for_data(self, data: 'BinaryView') -> bool:
		return core.BNIsBinaryViewTypeValidForData(self.handle, data.handle)

	def get_load_settings_for_data(self, data: 'BinaryView') -> Optional['settings.Settings']:
		view_handle = None
		if data is not None:
			view_handle = data.handle
		load_settings = core.BNGetBinaryViewLoadSettingsForData(self.handle, view_handle)
		if load_settings is None:
			return None
		return settings.Settings(handle=load_settings)

	def register_arch(self, ident: int, endian: Endianness, arch: 'architecture.Architecture') -> None:
		core.BNRegisterArchitectureForViewType(self.handle, ident, endian, arch.handle)

	def get_arch(self, ident: int, endian: Endianness) -> Optional['architecture.Architecture']:
		arch = core.BNGetArchitectureForViewType(self.handle, ident, endian)
		if arch is None:
			return None
		return architecture.CoreArchitecture._from_cache(arch)

	def register_platform(self, ident: int, arch: 'architecture.Architecture', plat: '_platform.Platform') -> None:
		core.BNRegisterPlatformForViewType(self.handle, ident, arch.handle, plat.handle)

	def register_default_platform(self, arch: 'architecture.Architecture', plat: '_platform.Platform') -> None:
		core.BNRegisterDefaultPlatformForViewType(self.handle, arch.handle, plat.handle)

	def register_platform_recognizer(self, ident, endian, cb):
		def callback(cb, view, meta):
			try:
				file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(view))
				view_obj = BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(view))
				meta_obj = metadata.Metadata(handle=core.BNNewMetadataReference(meta))
				plat = cb(view_obj, meta_obj)
				if plat:
					handle = core.BNNewPlatformReference(plat.handle)
					assert handle is not None, "core.BNNewPlatformReference returned None"
					return ctypes.cast(handle, ctypes.c_void_p).value
			except:
				binaryninja.log_error(traceback.format_exc())
			return None

		callback_obj = ctypes.CFUNCTYPE(
		    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.POINTER(core.BNMetadata)
		)(lambda ctxt, view, meta: callback(cb, view, meta))
		core.BNRegisterPlatformRecognizerForViewType(self.handle, ident, endian, callback_obj, None)
		self.__class__._platform_recognizers[len(self.__class__._platform_recognizers)] = callback_obj

	def get_platform(self, ident: int, arch: 'architecture.Architecture') -> Optional['_platform.Platform']:
		plat = core.BNGetPlatformForViewType(self.handle, ident, arch.handle)
		if plat is None:
			return None
		return _platform.CorePlatform._from_cache(handle=plat)

	def recognize_platform(self, ident, endian: Endianness, view: 'BinaryView', metadata):
		plat = core.BNRecognizePlatformForViewType(self.handle, ident, endian, view.handle, metadata.handle)
		if plat is None:
			return None
		return _platform.CorePlatform._from_cache(handle=plat)

	@staticmethod
	def add_binaryview_finalized_event(callback: BinaryViewEvent.BinaryViewEventCallback) -> None:
		"""
		`add_binaryview_finalized_event` adds a callback that gets executed
		when new binaryview is finalized.
		For more details, please refer to the documentation of BinaryViewEvent.

		.. warning:: The callback provided **must** stay in scope for the lifetime of the process, deletion or \
		garbage collection of the callback will result in a crash.
		"""
		BinaryViewEvent.register(BinaryViewEventType.BinaryViewFinalizationEvent, callback)

	@staticmethod
	def add_binaryview_initial_analysis_completion_event(callback: BinaryViewEvent.BinaryViewEventCallback) -> None:
		"""
		`add_binaryview_initial_analysis_completion_event` adds a callback
		that gets executed after the initial analysis, as well as linear
		sweep and signature matcher (if they are configured to run) completed.
		For more details, please refer to the documentation of BinaryViewEvent.

		.. warning:: The callback provided **must** stay in scope for the lifetime of the process, deletion or \
		garbage collection of the callback will result in a crash.
		"""
		BinaryViewEvent.register(BinaryViewEventType.BinaryViewInitialAnalysisCompletionEvent, callback)


class Segment:
	"""
	The ``Segment`` object is returned during BinaryView creation and should not be directly instantiated.
	"""
	def __init__(self, handle: core.BNSegmentHandle):
		self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeSegment(self.handle)

	def __repr__(self):
		r = "r" if self.readable else "-"
		w = "w" if self.writable else "-"
		x = "x" if self.executable else "-"
		return f"<segment: {self.start:#x}-{self.end:#x}, {r}{w}{x}>"

	@classmethod
	def serialize(cls, image_base: int, start: int, length: int, data_offset: int=0, data_length: int=0, flags: 'SegmentFlag'=SegmentFlag.SegmentReadable, auto_defined=True, segments: str="[]"):
		"""
		Serialize segment parameters into a JSON string. This is useful for generating a properly formatted segment description as options when using `load`.

		:param int image_base: The base address of the image.
		:param int start: The start address of the segment.
		:param int length: The length of the segment.
		:param int data_offset: The offset of the data within the segment.
		:param int data_length: The length of the data within the segment.
		:param SegmentFlag flags: The flags of the segment.
		:param bool auto_defined: Whether the segment is auto-defined.
		:param str segments: An optional, existing array of segments to append to.
		:return: A JSON string representing the segment.
		:rtype: str

		:Example::
			>>> base = 0x400000
			>>> rom_base = 0xffff0000
			>>> segments = Segment.serialize(image_base=base, start=base, length=0x1000, data_offset=0, data_length=0x1000, flags=SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
			>>> segments = Segment.serialize(image_base=base, start=rom_base, length=0x1000, flags=SegmentFlag.SegmentReadable, segments=segments)
			>>> view = load(bytes.fromhex('5054ebfe'), options={'loader.imageBase': base, 'loader.platform': 'x86', 'loader.segments': segments})
		"""
		segments_list = json.loads(segments)
		segment_info = {
			"auto_defined": auto_defined,
			"data_length": data_length,
			"data_offset": data_offset,
			"flags": flags,
			"length": length,
			"start": start - image_base
		}
		segments_list.append(segment_info)
		return json.dumps(segments_list)

	@property
	def length(self):
		return int(core.BNSegmentGetLength(self.handle))

	def __bool__(self):
		return True

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

	def __contains__(self, i: int):
		return i >= self.start and i < self.end

	@property
	def start(self) -> int:
		return core.BNSegmentGetStart(self.handle)

	@property
	def end(self) -> int:
		return core.BNSegmentGetEnd(self.handle)

	@property
	def executable(self) -> bool:
		return (core.BNSegmentGetFlags(self.handle) & SegmentFlag.SegmentExecutable) != 0

	@property
	def writable(self) -> bool:
		return (core.BNSegmentGetFlags(self.handle) & SegmentFlag.SegmentWritable) != 0

	@property
	def readable(self) -> bool:
		return (core.BNSegmentGetFlags(self.handle) & SegmentFlag.SegmentReadable) != 0

	@property
	def data_length(self) -> int:
		return core.BNSegmentGetDataLength(self.handle)

	@property
	def data_offset(self) -> int:
		return core.BNSegmentGetDataOffset(self.handle)

	@property
	def data_end(self) -> int:
		return core.BNSegmentGetDataEnd(self.handle)

	@property
	def auto_defined(self) -> bool:
		return core.BNSegmentIsAutoDefined(self.handle)


class Section:
	"""
	The ``Section`` object is returned during BinaryView creation and should not be directly instantiated.
	"""
	def __init__(self, handle: core.BNSectionHandle):
		self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeSection(self.handle)

	def __repr__(self):
		return f"<section {self.name}: {self.start:#x}-{self.end:#x}>"

	def __bool__(self):
		return True

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

	def __contains__(self, i: int):
		return i >= self.start and i < self.end

	@classmethod
	def serialize(cls, image_base: int, name: str, start: int, length: int, semantics: SectionSemantics=SectionSemantics.DefaultSectionSemantics, type: str="", align: int=1, entry_size: int=0, link: str="", info_section: str="", info_data: int=0, auto_defined: bool=True, sections: str="[]"):
		"""
		Serialize section parameters into a JSON string. This is useful for generating a properly formatted section description as options when using `load`.

		:param int image_base: The base address of the image.
		:param str name: The name of the section.
		:param int start: The start address of the section.
		:param int length: The length of the section.
		:param SectionSemantics semantics: The semantics of the section.
		:param str type: The type of the section.
		:param int align: The alignment of the section.
		:param int entry_size: The entry size of the section.
		:param str link: The linked section of the section.
		:param str info_section: The info section of the section.
		:param int info_data: The info data of the section.
		:param bool auto_defined: Whether the section is auto-defined.
		:param str sections: An optional, existing array of sections to append to.
		:return: A JSON string representing the section.
		:rtype: str
		"""
		sections_list = json.loads(sections)
		section_info = {
			"align": align,
			"auto_defined": auto_defined,
			"entry_size": entry_size,
			"info_data": info_data,
			"info_section": info_section,
			"length": length,
			"link": link,
			"name": name,
			"semantics": semantics,
			"start": start - image_base,
			"type": type
		}
		sections_list.append(section_info)
		return json.dumps(sections_list)

	@property
	def name(self) -> str:
		return core.BNSectionGetName(self.handle)

	@property
	def type(self) -> str:
		return core.BNSectionGetType(self.handle)

	@property
	def start(self) -> int:
		return core.BNSectionGetStart(self.handle)

	@property
	def linked_section(self) -> str:
		return core.BNSectionGetLinkedSection(self.handle)

	@property
	def info_section(self) -> str:
		return core.BNSectionGetInfoSection(self.handle)

	@property
	def info_data(self) -> int:
		return core.BNSectionGetInfoData(self.handle)

	@property
	def align(self) -> int:
		return core.BNSectionGetAlign(self.handle)

	@property
	def entry_size(self) -> int:
		return core.BNSectionGetEntrySize(self.handle)

	@property
	def semantics(self) -> SectionSemantics:
		return SectionSemantics(core.BNSectionGetSemantics(self.handle))

	@property
	def auto_defined(self) -> bool:
		return core.BNSectionIsAutoDefined(self.handle)

	@property
	def length(self):
		return int(core.BNSectionGetLength(self.handle))

	@property
	def end(self) -> int:
		return self.start + self.length


class TagType:
	"""
	The ``TagType`` object is created by the create_tag_type API and should not be directly instantiated.
	"""
	def __init__(self, handle: core.BNTagTypeHandle):
		self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeTagType(self.handle)

	def __repr__(self):
		return f"<tag type {self.name}: {self.icon}>"

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
	def id(self) -> str:
		"""Unique id of the TagType"""
		return core.BNTagTypeGetId(self.handle)

	@property
	def name(self) -> str:
		"""Name of the TagType"""
		return core.BNTagTypeGetName(self.handle)

	@name.setter
	def name(self, value: str) -> None:
		core.BNTagTypeSetName(self.handle, value)

	@property
	def icon(self) -> str:
		"""Unicode str containing an emoji to be used as an icon"""
		return core.BNTagTypeGetIcon(self.handle)

	@icon.setter
	def icon(self, value: str) -> None:
		core.BNTagTypeSetIcon(self.handle, value)

	@property
	def visible(self) -> bool:
		"""Boolean for whether the tags of this type are visible"""
		return core.BNTagTypeGetVisible(self.handle)

	@visible.setter
	def visible(self, value: bool) -> None:
		core.BNTagTypeSetVisible(self.handle, value)

	@property
	def type(self) -> TagTypeType:
		"""Type from enums.TagTypeType"""
		return TagTypeType(core.BNTagTypeGetType(self.handle))

	@type.setter
	def type(self, value: TagTypeType) -> None:
		core.BNTagTypeSetType(self.handle, value)


class Tag:
	"""
	The ``Tag`` object is created by other APIs (create_*_tag) and should not be directly instantiated.
	"""
	def __init__(self, handle: core.BNTagHandle):
		self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeTag(self.handle)

	def __repr__(self):
		return f"<tag {self.type.icon} {self.type.name}: {self.data}>"

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
	def id(self) -> str:
		return core.BNTagGetId(self.handle)

	@property
	def type(self) -> TagType:
		core_tag_type = core.BNTagGetType(self.handle)
		assert core_tag_type is not None, "core.BNTagGetType returned None"
		return TagType(core_tag_type)

	@property
	def data(self) -> str:
		return core.BNTagGetData(self.handle)

	@data.setter
	def data(self, value: str) -> None:
		core.BNTagSetData(self.handle, value)


class _BinaryViewAssociatedDataStore(associateddatastore._AssociatedDataStore):
	_defaults = {}


class SymbolMapping(collections.abc.Mapping):  # type: ignore
	"""
	SymbolMapping object is used to improve performance of the `bv.symbols` API.
	This allows pythonic code like this to have reasonable performance characteristics

		>>> my_symbols = get_my_symbols()
		>>> for symbol in my_symbols:
		>>>  if bv.symbols[symbol].address == 0x41414141:
		>>>    print("Found")

	"""
	def __init__(self, view: 'BinaryView'):
		self._symbol_list = None
		self._count = None
		self._symbol_cache: Optional[Mapping[str, List[_types.CoreSymbol]]] = None
		self._view = view
		self._n = 0
		self._keys = None

	def __repr__(self):
		return f"<SymbolMapping {len(self)} symbols: {self._symbol_cache}>"

	def __del__(self):
		if core is not None and self._symbol_list is not None:
			core.BNFreeSymbolList(self._symbol_list, len(self))

	def __getitem__(self, key: str) -> Optional[List['_types.CoreSymbol']]:
		if self._symbol_cache is None:
			sym = self._view.get_symbols_by_raw_name(key)
			if len(sym) == 0:
				raise KeyError(f"'{key}': symbol not found")
			return sym
		else:
			return self._symbol_cache[key]

	def _build_symbol_cache(self):
		count = ctypes.c_ulonglong(0)
		self._symbol_list = core.BNGetSymbols(self._view.handle, count, None)
		assert self._symbol_list is not None, "core.BNGetSymbols returned None"
		self._symbol_cache = {}
		self._count = count.value
		for i in range(len(self)):
			_handle = core.BNNewSymbolReference(self._symbol_list[i])
			assert _handle is not None, "core.BNNewSymbolReference returned None"
			sym = _types.CoreSymbol(_handle)
			try:
				if sym.raw_name in self._symbol_cache:
					self._symbol_cache[sym.raw_name].append(sym)
				else:
					self._symbol_cache[sym.raw_name] = [sym]
			except UnicodeDecodeError:
				mapped_str = sym.raw_bytes.decode('charmap')
				if mapped_str in self._symbol_cache:
					self._symbol_cache[mapped_str].append(sym)
				else:
					self._symbol_cache[mapped_str] = [sym]

	def __iter__(self) -> Iterator[str]:
		if self._symbol_cache is None:
			self._build_symbol_cache()
		assert self._symbol_cache is not None
		yield from self._symbol_cache

	def __next__(self) -> List['_types.CoreSymbol']:
		if self._symbol_cache is None:
			self._build_symbol_cache()
			assert self._symbol_cache is not None
		if self._keys is None:
			self._keys = list(self._symbol_cache.keys())
		self._n += 1
		return self._symbol_cache[self._keys[self._n - 1]]

	def __len__(self):
		if self._symbol_cache is None:
			self._build_symbol_cache()
		return self._count

	def __contains__(self, value: str):
		try:
			_ = self[value]
			return True
		except KeyError:
			return False

	def keys(self) -> KeysView[str]:
		if self._symbol_cache is None:
			self._build_symbol_cache()
		assert self._symbol_cache is not None
		return self._symbol_cache.keys()

	def items(self) -> ItemsView[str, List['_types.CoreSymbol']]:
		if self._symbol_cache is None:
			self._build_symbol_cache()
		assert self._symbol_cache is not None
		return self._symbol_cache.items()

	def values(self) -> ValuesView[List['_types.CoreSymbol']]:
		if self._symbol_cache is None:
			self._build_symbol_cache()
		assert self._symbol_cache is not None
		return self._symbol_cache.values()

	def get(self, key: str, default: Optional[List['_types.CoreSymbol']] = None) -> Optional[List['_types.CoreSymbol']]:
		try:
			return self[key]
		except KeyError:
			return default


class TypeMapping(collections.abc.Mapping):  # type: ignore
	"""
	TypeMapping object is used to improve performance of the `bv.types` API.
	This allows pythonic code like this to have reasonable performance characteristics

		>>> my_types = get_my_types()
		>>> for type_name in my_types:
		>>>  if bv.types[type_name].width == 4:
		>>>    print("Found")

	"""
	def __init__(self, view: 'BinaryView', get_list_fn=core.BNGetAnalysisTypeList):
		self._type_list = None
		self._count = None
		self._type_cache: Optional[Mapping[_types.QualifiedName, _types.Type]] = None
		self._view = view
		self._get_list_fn = get_list_fn

	def __repr__(self):
		return f"<TypeMapping {len(self)} symbols: {self._type_cache}>"

	def __del__(self):
		if core is not None and self._type_list is not None:
			core.BNFreeTypeAndNameList(self._type_list, len(self))

	def __getitem__(self, key):
		if self._type_cache is None:
			result = self._view.get_type_by_name(key)
			if result is None:
				raise KeyError(key)
			return result
		else:
			return self._type_cache[key]

	def __iter__(self):
		if self._type_cache is not None:
			yield from self._type_cache

		count = ctypes.c_ulonglong(0)
		type_list = self._get_list_fn(self._view.handle, count)
		assert type_list is not None, "core.BNGetAnalysisTypeList returned None"
		self._type_list = type_list
		self._type_cache = {}
		self._count = count.value
		for i in range(len(self)):
			name = _types.QualifiedName._from_core_struct(self._type_list[i].name)
			type = _types.Type.create(core.BNNewTypeReference(self._type_list[i].type), platform=self._view.platform)
			self._type_cache[name] = type
			yield name, type

	def _build_type_cache(self):
		for _, _ in self:
			pass

	def __len__(self):
		if self._type_cache is None:
			self._build_type_cache()
		return self._count

	def __contains__(self, value):
		try:
			self[value]
			return True
		except KeyError:
			return False

	def __eq__(self, other):
		return self._view == other._view

	def __ne__(self, other):
		return not (self == other)

	def keys(self):
		if self._type_cache is None:
			self._build_type_cache()
		assert self._type_cache is not None
		return self._type_cache.keys()

	def items(self):
		if self._type_cache is None:
			self._build_type_cache()
		assert self._type_cache is not None
		return self._type_cache.items()

	def values(self):
		if self._type_cache is None:
			self._build_type_cache()
		assert self._type_cache is not None
		return self._type_cache.values()

	def get(self, value, default = None):
		try:
			return self[value]
		except KeyError:
			return default


class FunctionList:
	def __init__(self, view: 'BinaryView'):
		count = ctypes.c_ulonglong(0)
		_funcs = core.BNGetAnalysisFunctionList(view.handle, count)
		assert _funcs is not None, "core.BNGetAnalysisFunctionList returned None"
		self._funcs = _funcs
		self._count = count.value
		self._view = view
		self._n = 0

	def __iter__(self):
		for i in range(0, len(self)):
			yield _function.Function(self._view, core.BNNewFunctionReference(self._funcs[i]))

	def __next__(self):
		if self._n >= len(self):
			raise StopIteration
		func = core.BNNewFunctionReference(self._funcs[self._n])
		assert func is not None, "core.BNNewFunctionReference returned None"
		self._n += 1
		return _function.Function(self._view, func)

	@overload
	def __getitem__(self, i: int) -> '_function.Function': ...

	@overload
	def __getitem__(self, i: slice) -> List['_function.Function']: ...

	def __getitem__(self, i: Union[int, slice]) -> Union['_function.Function', List['_function.Function']]:
		if isinstance(i, int):
			if i < 0:
				i = len(self) + i
			if i >= len(self):
				raise IndexError(f"Index {i} out of bounds for FunctionList of size {len(self)}")
			return _function.Function(self._view, core.BNNewFunctionReference(self._funcs[i]))
		elif isinstance(i, slice):
			result = []
			if i.start < 0 or i.start >= len(self) or i.stop < 0 or i.stop >= len(self):
				raise IndexError(f"Slice {i} out of bounds for FunctionList of size {len(self)}")

			for j in range(i.start, i.stop, i.step if i.step is not None else 1):
				result.append(_function.Function(self._view, core.BNNewFunctionReference(self._funcs[j])))
			return result
		raise ValueError("FunctionList.__getitem__ supports argument of type integer or slice")

	def __del__(self):
		if core is not None:
			core.BNFreeFunctionList(self._funcs, len(self))

	def __len__(self) -> int:
		return self._count


class AdvancedILFunctionList:
	"""
	The purpose of this class is to generate IL functions IL function in the background
	improving the performance of iterating MediumLevelIL and HighLevelILFunctions.

	Using this class or the associated helper methods BinaryView.mlil_functions / BinaryView.hlil_functions
	can improve the performance of ILFunction iteration significantly

	The prefetch_limit property is configurable and should be modified based upon your machines hardware and RAM limitations.

	.. warning:: Setting the prefetch_limit excessively high can result in high memory utilization.

	:Example:
		>>> import timeit
		>>> len(bv.functions)
		4817
		>>> # Calculate the average time to generate hlil for all functions withing 'bv':
		>>> timeit.timeit(lambda:[f.hlil for f in bv.functions], number=1)
		21.761621682000168
		>>> t1 = _
		>>> # Now try again with the advanced analysis iterator
		>>> timeit.timeit(lambda:[f for f in bv.hlil_functions(128)], number=1)
		6.3147709989998475
		>>> t1/_
		3.4461458199270947
		>>> # This particular binary can iterate hlil functions 3.4x faster
		>>> # If you don't need IL then its still much faster to just use `bv.functions`
		>>> timeit.timeit(lambda:[f for f in bv.functions], number=1)
		0.02230275600004461
	"""
	def __init__(self, view: 'BinaryView', preload_limit: int = mainthread.get_worker_thread_count(), functions: Optional[Iterable] = None):
		self._view = view
		self._func_queue = deque()
		self._preload_limit = preload_limit
		if functions is None:
			self._functions = FunctionList(self._view)
		else:
			self._functions = iter(functions)

	def __iter__(self):
		while True:
			while len(self._func_queue) < self._preload_limit:
				try:
					self._func_queue.append(_function.AdvancedFunctionAnalysisDataRequestor(next(self._functions)))
				except StopIteration:
					break
			if not self._func_queue:
				break
			yield self._func_queue.popleft().function


class MemoryMap:
	r"""
	The MemoryMap object is used to describe a system level MemoryMap for which a BinaryView is loaded into. A loaded
	BinaryView has a view into the MemoryMap which is described by the Segments defined in that BinaryView. The MemoryMap
	object allows for the addition of multiple, arbitrary overlapping regions of memory. Segmenting of the address space is
	automatically handled when the MemoryMap is modified and in the case where a portion of the system address space has
	multiple defined regions, the default ordering gives priority to the most recently added region. This feature is
	experimental and under active development.

	:Example:

.. code-block:: python

		>>> base = 0x10000
		>>> rom_base = 0xc0000000
		>>> segments = Segment.serialize(image_base=base, start=base, length=0x1000, data_offset=0, data_length=0x1000, flags=SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
		>>> segments = Segment.serialize(image_base=base, start=rom_base, length=0x1000, flags=SegmentFlag.SegmentReadable, segments=segments)
		>>> view = load(bytes.fromhex('5054ebfe'), options={'loader.imageBase': base, 'loader.platform': 'x86', 'loader.segments': segments})
		>>> print(view.memory_map)
			<region: 0x10000 - 0x10004>
				size: 0x4
				objects:
					'origin<Mapped>@0x0' | Mapped<Absolute> | <r-x>

			<region: 0xc0000000 - 0xc0001000>
				size: 0x1000
				objects:
					'origin<Mapped>@0xbfff0000' | Unmapped | <r--> | FILL<0x0>

			<region: 0xc0001000 - 0xc0001014>
				size: 0x14
				objects:
					'origin<Mapped>@0xbfff1000' | Unmapped | <---> | FILL<0x0>
		>>> view.memory_map.add_memory_region("rom", rom_base, b'\x90' * 4096, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
		True
		>>> print(view.memory_map)
			<region: 0x10000 - 0x10004>
				size: 0x4
				objects:
					'origin<Mapped>@0x0' | Mapped<Absolute> | <r-x>

			<region: 0xc0000000 - 0xc0001000>
				size: 0x1000
				objects:
					'rom' | Mapped<Relative> | <r-x>
					'origin<Mapped>@0xbfff0000' | Unmapped | <r--> | FILL<0x0>

			<region: 0xc0001000 - 0xc0001014>
				size: 0x14
				objects:
					'origin<Mapped>@0xbfff1000' | Unmapped | <---> | FILL<0x0>
		>>> view.read(rom_base, 16)
		b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
		>>> view.memory_map.add_memory_region("pad", rom_base, b'\xa5' * 8)
		True
		>>> view.read(rom_base, 16)
		b'\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\x90\x90\x90\x90\x90\x90\x90\x90'
		>>> print(view.memory_map)
			<region: 0x10000 - 0x10004>
				size: 0x4
				objects:
					'origin<Mapped>@0x0' | Mapped<Absolute> | <r-x>

			<region: 0xc0000000 - 0xc0000008>
				size: 0x8
				objects:
					'pad' | Mapped<Relative> | <--->
					'rom' | Mapped<Relative> | <r-x>
					'origin<Mapped>@0xbfff0000' | Unmapped | <r--> | FILL<0x0>

			<region: 0xc0000008 - 0xc0001000>
				size: 0xff8
				objects:
					'rom' | Mapped<Relative> | <r-x>
					'origin<Mapped>@0xbfff0000' | Unmapped | <r--> | FILL<0x0>

			<region: 0xc0001000 - 0xc0001014>
				size: 0x14
				objects:
					'origin<Mapped>@0xbfff1000' | Unmapped | <---> | FILL<0x0>
	"""

	def __repr__(self):
		return pprint.pformat(self.description())

	def __str__(self):
		description = self.description()
		formatted_description = ""
		for entry in description['MemoryMap']:
			formatted_description += f"<region: {hex(entry['address'])} - {hex(entry['address'] + entry['length'])}>\n"
			formatted_description += f"\tsize: {hex(entry['length'])}\n"
			formatted_description += "\tobjects:\n"
			for obj in entry['objects']:
				if obj['target']:
					mapped_state = f"Mapped<{'Absolute' if obj['absolute_address_mode'] else 'Relative'}>"
				else:
					mapped_state = "Unmapped"
				formatted_description += f"\t\t'{obj['name']}' | {mapped_state}"
				r = "r" if obj['flags'] & SegmentFlag.SegmentReadable else "-"
				w = "w" if obj['flags'] & SegmentFlag.SegmentWritable else "-"
				x = "x" if obj['flags'] & SegmentFlag.SegmentExecutable else "-"
				formatted_description += f" | <{r}{w}{x}>"
				if not obj['target']:
					formatted_description += f" | FILL<{hex(obj['fill'])}>"
				if not obj['enabled']:
					formatted_description += f" | <DISABLED>"
				formatted_description += "\n"
			formatted_description += "\n"

		return formatted_description

	def __init__(self, handle: 'BinaryView'):
		self.handle = handle

	def __len__(self):
		mm_json = self.description()
		if 'MemoryMap' in mm_json:
			return len(mm_json['MemoryMap'])
		else:
			return 0

	def description(self):
		return json.loads(core.BNGetMemoryMapDescription(self.handle))

	def add_memory_region(self, name: str, start: int, source: Union['os.PathLike', str, bytes, bytearray, 'BinaryView', 'databuffer.DataBuffer', 'fileaccessor.FileAccessor'], flags: SegmentFlag = 0) -> bool:
		"""
		Adds a memory region into the memory map. There are three types of memory regions that can be added:
		- BinaryMemoryRegion(*** Unimplemented ***): Creates a memory region from a loadable binary format and provides persistence across sessions.
		- DataMemoryRegion: Creates a memory region from a flat file or bytes and provide persistence across sessions.
		- RemoteMemoryRegion: Creates a memory region from a proxy callback interface. This region is ephemeral and not saved across sessions.

		The type of memory region added depends on the source parameter:
		- `os.PathLike`, `str`, : Treats the source as a file path which is read and loaded into memory as a DataMemoryRegion.
		- `bytes`, `bytearray`: Directly loads these byte formats into memory as a DataMemoryRegion.
		- `databuffer.DataBuffer`: Directly loads a data buffer into memory as a DataMemoryRegion.
		- `fileaccessor.FileAccessor`: Utilizes a file accessor to establish a RemoteMemoryRegion, managing data fetched from a remote source.

		Parameters:
			name (str): A unique name of the memory region.
			start (int): The start address in memory where the region will be loaded.
			source (Union[os.PathLike, str, bytes, bytearray, BinaryView, databuffer.DataBuffer, fileaccessor.FileAccessor]): The source from which the memory is loaded.

		Returns:
			bool: True if the memory region was successfully added, False otherwise.

		Raises:
			NotImplementedError: If the source type is not supported.

		Notes:
			If parts of the new memory region do not overlap with existing segments, new segments will be automatically created for each non-overlapping area, each with the SegmentFlag.SegmentReadable flag set.
		"""
		if isinstance(source, os.PathLike):
			source = str(source)
		if isinstance(source, bytes) or isinstance(source, bytearray):
			source = databuffer.DataBuffer(source)
		if isinstance(source, str):
			with open(source, "rb") as f:
				source = databuffer.DataBuffer(f.read())

		if name is None:
			name = ""

		if isinstance(source, BinaryView):
			return core.BNAddBinaryMemoryRegion(self.handle, name, start, source.handle, flags)
		elif isinstance(source, databuffer.DataBuffer):
			return core.BNAddDataMemoryRegion(self.handle, name, start, source.handle, flags)
		elif isinstance(source, fileaccessor.FileAccessor):
			return core.BNAddRemoteMemoryRegion(self.handle, name, start, source._cb, flags)
		else:
			raise NotImplementedError

	def remove_memory_region(self, name: str) -> bool:
		return core.BNRemoveMemoryRegion(self.handle, name)

	def get_active_memory_region_at(self, addr: int) -> str:
		return core.BNGetActiveMemoryRegionAt(self.handle, addr)

	def get_memory_region_flags(self, name: str) -> set:
		flags = core.BNGetMemoryRegionFlags(self.handle, name)
		return {flag for flag in SegmentFlag if flags & flag}

	def set_memory_region_flags(self, name: str, flags: SegmentFlag) -> bool:
		return core.BNSetMemoryRegionFlags(self.handle, name, flags)

	def is_memory_region_enabled(self, name: str) -> bool:
		return core.BNIsMemoryRegionEnabled(self.handle, name)

	def set_memory_region_enabled(self, name: str, enabled: bool = True) -> bool:
		return core.BNSetMemoryRegionEnabled(self.handle, name, enabled)

	def is_memory_region_rebaseable(self, name: str) -> bool:
		return core.BNIsMemoryRegionRebaseable(self.handle, name)

	def set_memory_region_rebaseable(self, name: str, rebaseable: bool = True) -> bool:
		return core.BNSetMemoryRegionRebaseable(self.handle, name, rebaseable)

	def get_memory_region_fill(self, name: str) -> int:
		return core.BNGetMemoryRegionFill(self.handle, name)

	def set_memory_region_fill(self, name: str, fill: int) -> bool:
		return core.BNSetMemoryRegionFill(self.handle, name, fill)

	def reset(self):
		core.BNResetMemoryMap(self.handle)

class BinaryView:
	"""
	``class BinaryView`` implements a view on binary data, and presents a queryable interface of a binary file. One key
	job of BinaryView is file format parsing which allows Binary Ninja to read, write, insert, remove portions
	of the file given a virtual address. For the purposes of this documentation we define a virtual address as the
	memory address that the various pieces of the physical file will be loaded at.

	A binary file does not have to have just one BinaryView, thus much of the interface to manipulate disassembly exists
	within or is accessed through a BinaryView. All files are guaranteed to have at least the ``Raw`` BinaryView. The
	``Raw`` BinaryView is simply a hex editor, but is helpful for manipulating binary files via their absolute addresses.

	BinaryViews are plugins and thus registered with Binary Ninja at startup, and thus should **never** be instantiated
	directly as this is already done. The list of available BinaryViews can be seen in the BinaryViewType class which
	provides an iterator and map of the various installed BinaryViews::

		>>> list(BinaryViewType)
		[<view type: 'Raw'>, <view type: 'ELF'>, <view type: 'Mach-O'>, <view type: 'PE'>]
		>>> BinaryViewType['ELF']
		<view type: 'ELF'>

	To open a file with a given BinaryView the following code is recommended:

		>>> with load("/bin/ls") as bv:
		...   bv
		<BinaryView: '/bin/ls', start 0x100000000, len 0x142c8>

	`By convention in the rest of this document we will use bv to mean an open and, analyzed, BinaryView of an executable file.`
	When a BinaryView is open on an executable view analysis is automatically run unless specific named parameters are used
	to disable updates. If such a parameter is used, updates can be triggered using the :py:func:`update_analysis_and_wait` method
	which disassembles the executable and returns when all disassembly and analysis is complete::

		>>> bv.update_analysis_and_wait()
		>>>

	Since BinaryNinja's analysis is multi-threaded (depending on version) this can also be done in the background
	by using the :py:func:`update_analysis` method instead.

	By standard python convention methods which start with '_' should be considered private and should not
	be called externally. Additionally, methods which begin with ``perform_`` should not be called directly
	either and are used explicitly for subclassing a BinaryView.

	.. note:: An important note on the ``*_user_*()`` methods. Binary Ninja makes a distinction between edits \
	performed by the user and actions performed by auto analysis. Auto analysis actions that can quickly be recalculated \
	are not saved to the database. Auto analysis actions that take a long time and all user edits are stored in the \
	database (e.g. :py:func:`remove_user_function` rather than :py:func:`remove_function`). Thus use ``_user_`` methods if saving \
	to the database is desired.
	"""
	name: Optional[str] = None
	long_name: Optional[str] = None
	_registered = False
	_registered_cb = None
	registered_view_type = None
	_associated_data = {}
	_registered_instances = []
	_cached_instances = {}

	@classmethod
	def _cache_insert(cls, instance):
		key = ctypes.addressof(instance.handle.contents)
		if key not in cls._cached_instances:
			cls._cached_instances[ctypes.addressof(instance.handle.contents)] = instance

	@classmethod
	def _cache_remove(cls, handle):
		key = ctypes.addressof(handle.contents)
		if key in cls._cached_instances:
			cls._cached_instances.pop(key)

	@classmethod
	def _cache_contains(cls, handle):
		return ctypes.addressof(handle.contents) in cls._cached_instances

	def __new__(cls, file_metadata=None, parent_view=None, handle=None):
		if handle:
			key = ctypes.addressof(handle.contents)
			if key in cls._cached_instances:
				core.BNFreeBinaryView(handle) # release the already taken reference since we are pulling from the cache
				return cls._cached_instances[key]
		return super().__new__(cls)

	def __init__(
	    self, file_metadata: Optional['filemetadata.FileMetadata'] = None, parent_view: Optional['BinaryView'] = None,
	    handle: Optional[core.BNBinaryViewHandle] = None
	):
		if handle is not None:
			if self.__class__._cache_contains(handle):
				return
			_handle = handle
			if file_metadata is None:
				self._file = filemetadata.FileMetadata(handle=core.BNGetFileForView(handle))
			else:
				self._file = file_metadata
		elif self.__class__ is BinaryView:
			binaryninja._init_plugins()
			if file_metadata is None:
				file_metadata = filemetadata.FileMetadata()
			_handle = core.BNCreateBinaryDataView(file_metadata.handle)
			self._file = filemetadata.FileMetadata(handle=core.BNNewFileReference(file_metadata.handle))
		else:
			binaryninja._init_plugins()
			if not self.__class__._registered:
				raise TypeError("view type not registered")
			self._cb = core.BNCustomBinaryView()
			self._cb.context = 0
			self._cb.init = self._cb.init.__class__(self._init)
			self._cb.externalRefTaken = self._cb.externalRefTaken.__class__(self._external_ref_taken)
			self._cb.externalRefReleased = self._cb.externalRefReleased.__class__(self._external_ref_released)
			self._cb.read = self._cb.read.__class__(self._read)
			self._cb.write = self._cb.write.__class__(self._write)
			self._cb.insert = self._cb.insert.__class__(self._insert)
			self._cb.remove = self._cb.remove.__class__(self._remove)
			self._cb.getModification = self._cb.getModification.__class__(self._get_modification)
			self._cb.isValidOffset = self._cb.isValidOffset.__class__(self._is_valid_offset)
			self._cb.isOffsetReadable = self._cb.isOffsetReadable.__class__(self._is_offset_readable)
			self._cb.isOffsetWritable = self._cb.isOffsetWritable.__class__(self._is_offset_writable)
			self._cb.isOffsetExecutable = self._cb.isOffsetExecutable.__class__(self._is_offset_executable)
			self._cb.getNextValidOffset = self._cb.getNextValidOffset.__class__(self._get_next_valid_offset)
			self._cb.getStart = self._cb.getStart.__class__(self._get_start)
			self._cb.getLength = self._cb.getLength.__class__(self._get_length)
			self._cb.getEntryPoint = self._cb.getEntryPoint.__class__(self._get_entry_point)
			self._cb.isExecutable = self._cb.isExecutable.__class__(self._is_executable)
			self._cb.getDefaultEndianness = self._cb.getDefaultEndianness.__class__(self._get_default_endianness)
			self._cb.isRelocatable = self._cb.isRelocatable.__class__(self._is_relocatable)
			self._cb.getAddressSize = self._cb.getAddressSize.__class__(self._get_address_size)
			self._cb.save = self._cb.save.__class__(self._save)
			if file_metadata is None:
				raise Exception("Attempting to create a BinaryView with FileMetadata which is None")
			self._file = file_metadata
			_parent_view = None
			if parent_view is not None:
				_parent_view = parent_view.handle
			_handle = core.BNCreateCustomBinaryView(self.__class__.name, file_metadata.handle, _parent_view, self._cb)

		assert _handle is not None
		self.handle = _handle
		self._notifications = {}
		self._parse_only = False
		self._preload_limit = 5
		self._platform = None
		self._endianness = None

	def __enter__(self) -> 'BinaryView':
		return self

	def __exit__(self, type, value, traceback):
		self.file.close()

	def __del__(self):
		if core is None:
			return
		for i in self._notifications.values():
			i._unregister()
		core.BNFreeBinaryView(self.handle)

	def __repr__(self):
		start = self.start
		length = self.length
		if start != 0:
			size = f"start {start:#x}, len {length:#x}"
		else:
			size = f"len {length:#x}"
		filename = self._file.filename
		if len(filename) > 0:
			return f"<BinaryView: '{filename}', {size}>"
		return f"<BinaryView: {size}>"

	@property
	def length(self):
		return int(core.BNGetViewLength(self.handle))

	def __bool__(self):
		return True

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

	def __iter__(self) -> Generator['_function.Function', None, None]:
		yield from self.functions

	def __getitem__(self, i) -> bytes:
		if isinstance(i, tuple):
			result = bytes()
			for s in i:
				result += self.__getitem__(s)
			return result
		elif isinstance(i, slice):
			if i.step is not None:
				raise IndexError("step not implemented")
			i = i.indices(self.end)
			start = i[0]
			stop = i[1]
			if stop <= start:
				return b""
			return self.read(start, stop - start)
		elif i < 0:
			if i >= -self.length:
				value = self.read(self.start + int(self.length + i), 1)
				if len(value) == 0:
					raise IndexError("index not readable")
				return value
			raise IndexError("index out of range")
		elif (i >= self.start) and (i < self.end):
			value = self.read(int(i), 1)
			if len(value) == 0:
				raise IndexError("index not readable")
			return value
		else:
			raise IndexError("index out of range")

	def __setitem__(self, i, value):
		if isinstance(i, slice):
			if i.step is not None:
				raise IndexError("step not supported on assignment")
			i = i.indices(self.end)
			start = i[0]
			stop = i[1]
			if stop < start:
				stop = start
			if len(value) != (stop - start):
				self.remove(start, stop - start)
				self.insert(start, value)
			else:
				self.write(start, value)
		elif i < 0:
			if i >= -self.length:
				if len(value) != 1:
					raise ValueError("expected single byte for assignment")
				if self.write(self.start + int(self.length + i), value) != 1:
					raise IndexError("index not writable")
			else:
				raise IndexError("index out of range")
		elif (i >= self.start) and (i < self.end):
			if len(value) != 1:
				raise ValueError("expected single byte for assignment")
			if self.write(int(i), value) != 1:
				raise IndexError("index not writable")
		else:
			raise IndexError("index out of range")

	def __contains__(self, i: int):
		for s in self.segments:
			if i in s:
				return True
		return False

	@classmethod
	def register(cls) -> None:
		binaryninja._init_plugins()
		if cls.name is None:
			raise ValueError("view 'name' not defined")
		if cls.long_name is None:
			cls.long_name = cls.name
		cls._registered_cb = core.BNCustomBinaryViewType()
		cls._registered_cb.context = 0
		cls._registered_cb.create = cls._registered_cb.create.__class__(cls._create)
		cls._registered_cb.parse = cls._registered_cb.parse.__class__(cls._parse)
		cls._registered_cb.isValidForData = cls._registered_cb.isValidForData.__class__(cls._is_valid_for_data)
		cls._registered_cb.isDeprecated = cls._registered_cb.isDeprecated.__class__(cls._is_deprecated)
		cls._registered_cb.isForceLoadable = cls._registered_cb.isForceLoadable.__class__(cls._is_force_loadable)
		cls._registered_cb.getLoadSettingsForData = cls._registered_cb.getLoadSettingsForData.__class__(
		    cls._get_load_settings_for_data
		)
		view_handle = core.BNRegisterBinaryViewType(cls.name, cls.long_name, cls._registered_cb)
		assert view_handle is not None, "core.BNRegisterBinaryViewType returned None"
		cls.registered_view_type = BinaryViewType(view_handle)
		cls._registered = True

	@property
	def parse_only(self) -> bool:
		return self._parse_only

	@parse_only.setter
	def parse_only(self, value: bool) -> None:
		self._parse_only = value

	@classmethod
	def _create(cls, ctxt, data: core.BNBinaryView):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(data))
			view = cls(BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(data)))  # type: ignore
			if view is None:
				return None
			view.parse_only = False
			view_handle = core.BNNewViewReference(view.handle)
			assert view_handle is not None, "core.BNNewViewReference returned None"
			return ctypes.cast(view_handle, ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	@classmethod
	def _parse(cls, ctxt, data: core.BNBinaryView):
		try:
			file_metadata = filemetadata.FileMetadata(handle=core.BNGetFileForView(data))
			view = cls(BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(data)))  # type: ignore
			if view is None:
				return None
			view.parse_only = True
			view_handle = core.BNNewViewReference(view.handle)
			assert view_handle is not None, "core.BNNewViewReference returned None"
			return ctypes.cast(view_handle, ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	@classmethod
	def _is_valid_for_data(cls, ctxt, data):
		try:
			# I'm not sure whats going on here even so I've suppressed the linter warning
			return cls.is_valid_for_data(BinaryView(handle=core.BNNewViewReference(data)))  # type: ignore
		except:
			log_error(traceback.format_exc())
			return False

	@classmethod
	def _is_deprecated(cls, ctxt):
		# Since the is_deprecated() method is newly added, existing code may not have it at all
		# So here we do not consider it as an error
		if not callable(getattr(cls, 'is_deprecated', None)):
			return False

		try:
			return cls.is_deprecated()  # type: ignore
		except:
			log_error(traceback.format_exc())
			return False

	@classmethod
	def _is_force_loadable(cls, ctxt):
		if not callable(getattr(cls, 'is_force_loadable', None)):
			return False

		try:
			return cls.is_force_loadable()  # type: ignore
		except:
			log_error(traceback.format_exc())
			return False

	@classmethod
	def _get_load_settings_for_data(cls, ctxt, data):
		try:
			attr = getattr(cls, "get_load_settings_for_data", None)
			if callable(attr):
				result = cls.get_load_settings_for_data(
				    BinaryView(handle=core.BNNewViewReference(data))
				)  # type: ignore
				settings_handle = core.BNNewSettingsReference(result.handle)
				assert settings_handle is not None, "core.BNNewSettingsReference returned None"
				return ctypes.cast(settings_handle, ctypes.c_void_p).value
			else:
				return None
		except:
			log_error(traceback.format_exc())
			return None

	@staticmethod
	def open(src, file_metadata=None) -> Optional['BinaryView']:
		binaryninja._init_plugins()
		if isinstance(src, fileaccessor.FileAccessor):
			if file_metadata is None:
				file_metadata = filemetadata.FileMetadata()
			view = core.BNCreateBinaryDataViewFromFile(file_metadata.handle, src._cb)
		else:
			if file_metadata is None:
				file_metadata = filemetadata.FileMetadata(str(src))
			view = core.BNCreateBinaryDataViewFromFilename(file_metadata.handle, str(src))
		if view is None:
			return None
		return BinaryView(file_metadata=file_metadata, handle=view)

	@staticmethod
	def new(data: Optional[Union[bytes, bytearray, 'databuffer.DataBuffer']] = None, file_metadata: Optional['filemetadata.FileMetadata'] = None) -> Optional['BinaryView']:
		"""
		``new`` creates a new, Raw :py:class:`BinaryView` for the provided data.

		:param data: path to file/bndb, raw bytes, or raw view to load
		:type data: Union[:py:class:`str`, :py:class:`bytes`, :py:class:`bytearray`, :py:class:`~binaryninja.databuffer.DataBuffer`, :py:class:`os.PathLike`, :py:class:`BinaryView`]
		:param file_metadata: Optional FileMetadata object for this new view
		:type file_metadata: :py:class:`~binaryninja.filemetadata.FileMetadata`
		:return: returns a :py:class:`BinaryView` object for the given filename or ``None``
		:rtype: :py:class:`BinaryView` or ``None``

		:Example:

			>>> binaryninja.load('/bin/ls', options={'loader.imageBase': 0xfffffff0000, 'loader.macho.processFunctionStarts' : False})
			<BinaryView: '/bin/ls', start 0xfffffff0000, len 0xa290>
			>>>

		"""

		binaryninja._init_plugins()
		if file_metadata is None:
			file_metadata = filemetadata.FileMetadata()
		if data is None:
			view = core.BNCreateBinaryDataView(file_metadata.handle)
		elif isinstance(data, databuffer.DataBuffer):
			view = core.BNCreateBinaryDataViewFromBuffer(file_metadata.handle, data.handle)
		else:
			buf = databuffer.DataBuffer(data)
			view = core.BNCreateBinaryDataViewFromBuffer(file_metadata.handle, buf.handle)
		if view is None:
			return None
		return BinaryView(file_metadata=file_metadata, handle=view)

	@staticmethod
	def load(source: Union[str, bytes, bytearray, 'databuffer.DataBuffer', 'os.PathLike', 'BinaryView', 'project.ProjectFile'], update_analysis: Optional[bool] = True,
	    progress_func: Optional[ProgressFuncType] = None, options: Mapping[str, Any] = {}) -> Optional['BinaryView']:
		"""
		``load`` opens, generates default load options (which are overridable), and returns the first available \
		:py:class:`BinaryView`. If no :py:class:`BinaryViewType` is available, then a ``Mapped`` :py:class:`BinaryViewType` is used to load \
		the :py:class:`BinaryView` with the specified load options. The ``Mapped`` view type attempts to auto-detect the architecture of the \
		file during initialization. If no architecture is detected or specified in the load options, then the ``Mapped`` view type fails to \
		initialize and returns ``None``.

		.. note:: Although general container file support is not complete, support for Universal archives exists. It's possible to control the architecture preference \
		with the **'files.universal.architecturePreference'** setting. This setting is scoped to SettingsUserScope and can be modified as follows ::

			>>> Settings().set_string_list("files.universal.architecturePreference", ["arm64"])

		It's also possible to override the **'files.universal.architecturePreference'** user setting by specifying it directly with :py:func:`load`.
		This specific usage of this setting is experimental and may change in the future ::

			>>> bv = binaryninja.load('/bin/ls', options={'files.universal.architecturePreference': ['arm64']})

		.. warning:: The recommended code pattern for opening a BinaryView is to use the \
		:py:func:`~binaryninja.load` API as a context manager like ``with load('/bin/ls') as bv:`` \
		which will automatically clean up when done with the view. If using this API directly \
		you will need to call `bv.file.close()` before the BinaryView leaves scope to ensure the \
		reference is properly removed and prevents memory leaks.

		:param Union[str, bytes, bytearray, 'databuffer.DataBuffer', 'os.PathLike', 'BinaryView'] source: path to file/bndb, raw bytes, or raw view to load
		:param bool update_analysis: whether or not to run :py:func:`~BinaryView.update_analysis_and_wait` after opening a :py:class:`BinaryView`, defaults to ``True``
		:param callback progress_func: optional function to be called with the current progress and total count
		:param dict options: a dictionary in the form {setting identifier string : object value}
		:return: returns a :py:class:`BinaryView` object for the given filename or ``None``
		:rtype: :py:class:`BinaryView` or ``None``

		:Example:

			>>> binaryninja.load('/bin/ls', options={'loader.imageBase': 0xfffffff0000, 'loader.macho.processFunctionStarts' : False})
			<BinaryView: '/bin/ls', start 0xfffffff0000, len 0xa290>
			>>>
		"""
		binaryninja._init_plugins()

		if progress_func is None:
			progress_cfunc = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_ulonglong, ctypes.c_ulonglong)(lambda cur, total: True)
		else:
			progress_cfunc = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_ulonglong, ctypes.c_ulonglong)(lambda cur, total: progress_func(cur, total))

		if isinstance(source, os.PathLike):
			source = str(source)
		if isinstance(source, BinaryView):
			handle = core.BNLoadBinaryView(source.handle, update_analysis, json.dumps(options), progress_cfunc)
		elif isinstance(source, project.ProjectFile):
			handle = core.BNLoadProjectFile(source._handle, update_analysis, json.dumps(options), progress_cfunc)
		elif isinstance(source, str):
			handle = core.BNLoadFilename(source, update_analysis, json.dumps(options), progress_cfunc)
		elif isinstance(source, bytes) or isinstance(source, bytearray) or isinstance(source, databuffer.DataBuffer):
			raw_view = BinaryView.new(source)
			handle = core.BNLoadBinaryView(raw_view.handle, update_analysis, json.dumps(options), progress_cfunc)
		else:
			raise NotImplementedError
		return BinaryView(handle=handle) if handle else None

	@classmethod
	def _unregister(cls, view: core.BNBinaryView) -> None:
		handle = ctypes.cast(view, ctypes.c_void_p)
		if handle.value in cls._associated_data:
			del cls._associated_data[handle.value]

	@staticmethod
	def set_default_session_data(name: str, value: str) -> None:
		"""
		``set_default_session_data`` saves a variable to the BinaryView. Session data is ephemeral not saved to a database. Consider using :py:func:`store_metadata` if permanence is needed.

		:param str name: name of the variable to be saved
		:param str value: value of the variable to be saved

		:Example:
			>>> BinaryView.set_default_session_data("variable_name", "value")
			>>> bv.session_data.variable_name
			'value'
		"""
		_BinaryViewAssociatedDataStore.set_default(name, value)

	@property
	def preload_limit(self) -> int:
		return self._preload_limit

	@preload_limit.setter
	def preload_limit(self, value: int) -> None:
		self._preload_limit = value

	@property
	def basic_blocks(self) -> Generator['basicblock.BasicBlock', None, None]:
		"""A generator of all BasicBlock objects in the BinaryView"""
		for func in self:
			yield from func.basic_blocks

	@property
	def llil_basic_blocks(self) -> Generator['lowlevelil.LowLevelILBasicBlock', None, None]:
		"""A generator of all LowLevelILBasicBlock objects in the BinaryView"""
		for func in self:
			llil = func.low_level_il
			if llil is not None:
				yield from llil.basic_blocks

	@property
	def mlil_basic_blocks(self) -> Generator['mediumlevelil.MediumLevelILBasicBlock', None, None]:
		"""A generator of all MediumLevelILBasicBlock objects in the BinaryView"""
		for func in self.mlil_functions():
			yield from func.basic_blocks

	@property
	def hlil_basic_blocks(self) -> Generator['highlevelil.HighLevelILBasicBlock', None, None]:
		"""A generator of all HighLevelILBasicBlock objects in the BinaryView"""
		for func in self.hlil_functions():
			yield from func.basic_blocks

	@property
	def instructions(self) -> InstructionsType:
		"""A generator of instruction tokens and their start addresses"""
		for block in self.basic_blocks:
			start = block.start
			for i in block:
				yield (i[0], start)
				start += i[1]

	@property
	def llil_instructions(self) -> 'lowlevelil.LLILInstructionsType':
		"""A generator of llil instructions"""
		for block in self.llil_basic_blocks:
			yield from block

	@property
	def mlil_instructions(self) -> Generator['mediumlevelil.MediumLevelILInstruction', None, None]:
		"""A generator of mlil instructions"""
		for block in self.mlil_basic_blocks:
			yield from block

	@property
	def hlil_instructions(self) -> 'highlevelil.HLILInstructionsType':
		"""A generator of hlil instructions"""
		for block in self.hlil_basic_blocks:
			yield from block

	@property
	def parent_view(self) -> Optional['BinaryView']:
		"""View that contains the raw data used by this view (read-only)"""
		result = core.BNGetParentView(self.handle)
		if result is None:
			return None
		return BinaryView(handle=result)

	@property
	def modified(self) -> bool:
		"""boolean modification state of the BinaryView (read/write)"""
		return self._file.modified

	@modified.setter
	def modified(self, value: bool) -> None:
		self._file.modified = value

	@property
	def analysis_changed(self) -> bool:
		"""boolean analysis state changed of the currently running analysis (read-only)"""
		return self._file.analysis_changed

	@property
	def has_database(self) -> bool:
		"""boolean has a database been written to disk (read-only)"""
		return self._file.has_database

	@property
	def view(self) -> 'str':
		return self._file.view

	@view.setter
	def view(self, value: str) -> None:
		self._file.view = value

	@property
	def offset(self) -> int:
		return self._file.offset

	@offset.setter
	def offset(self, value: int) -> None:
		self._file.offset = value

	@property
	def file(self) -> 'filemetadata.FileMetadata':
		""":py:class:`~binaryninja.filemetadata.FileMetadata` backing the BinaryView """
		return self._file

	@property
	def image_base(self) -> int:
		"""Image base of the binary"""
		return core.BNGetImageBase(self.handle)

	@property
	def original_image_base(self) -> int:
		"""Original image base of the binary"""
		return core.BNGetOriginalImageBase(self.handle)

	@original_image_base.setter
	def original_image_base(self, image_base: int) -> None:
		"""Set original image base of the binary. Only intended for binary view implementations"""
		return core.BNSetOriginalImageBase(self.handle, image_base)

	@property
	def original_base(self) -> int:
		"""Original image base of the binary Deprecated: 4.0.xxxx Use original_image_base instead."""
		return core.BNGetOriginalImageBase(self.handle)

	@original_base.setter
	def original_base(self, base: int) -> None:
		"""Set original image base of the binary. Only intended for binary view implementations. Deprecated: 4.0.xxxx Use original_image_base instead."""
		return core.BNSetOriginalImageBase(self.handle, base)

	@property
	def start(self) -> int:
		"""Start offset of the binary (read-only)"""
		return core.BNGetStartOffset(self.handle)

	@property
	def end(self) -> int:
		"""End offset of the binary (read-only)"""
		return core.BNGetEndOffset(self.handle)

	@property
	def entry_point(self) -> int:
		"""Entry point of the binary (read-only)"""
		return core.BNGetEntryPoint(self.handle)

	@property
	def arch(self) -> Optional['architecture.Architecture']:
		"""The architecture associated with the current :py:class:`BinaryView` (read/write)"""
		arch = core.BNGetDefaultArchitecture(self.handle)
		if arch is None:
			return None
		return architecture.CoreArchitecture._from_cache(handle=arch)

	@arch.setter
	def arch(self, value: 'architecture.Architecture') -> None:
		if value is None:
			core.BNSetDefaultArchitecture(self.handle, None)
		else:
			core.BNSetDefaultArchitecture(self.handle, value.handle)

	@property
	def platform(self) -> Optional['_platform.Platform']:
		"""The platform associated with the current BinaryView (read/write)"""
		if self._platform is not None:
			return self._platform
		plat = core.BNGetDefaultPlatform(self.handle)
		if plat is None:
			return None
		self._platform = _platform.CorePlatform._from_cache(handle=plat)
		return self._platform

	@platform.setter
	def platform(self, value: Optional['_platform.Platform']) -> None:
		if value is None:
			core.BNSetDefaultPlatform(self.handle, None)
		else:
			core.BNSetDefaultPlatform(self.handle, value.handle)
		self._platform = None

	@property
	def endianness(self) -> Endianness:
		"""Endianness of the binary (read-only)"""
		if self._endianness is None:
			self._endianness = Endianness(core.BNGetDefaultEndianness(self.handle))
		return self._endianness

	@property
	def relocatable(self) -> bool:
		"""Boolean - is the binary relocatable (read-only)"""
		return core.BNIsRelocatable(self.handle)

	@property
	def address_size(self) -> int:
		"""Address size of the binary (read-only)"""
		return core.BNGetViewAddressSize(self.handle)

	@property
	def executable(self) -> bool:
		"""Whether the binary is an executable (read-only)"""
		return core.BNIsExecutableView(self.handle)

	@property
	def functions(self) -> FunctionList:
		"""returns a FunctionList object (read-only)"""
		return FunctionList(self)

	def mlil_functions(
	    self, preload_limit: Optional[int] = None,
		function_generator: Optional[Generator['_function.Function', None, None]] = None
	) -> Generator['mediumlevelil.MediumLevelILFunction', None, None]:
		"""
		Generates a list of il functions. This method should be used instead of 'functions' property if
		MLIL is needed and performance is a concern.
		"""
		for func in AdvancedILFunctionList(
		    self, self.preload_limit if preload_limit is None else preload_limit, function_generator
		):
			try:
				yield func.mlil
			except ILException:
				pass

	def hlil_functions(
	    self, preload_limit: Optional[int] = None,
		function_generator: Optional[Generator['_function.Function', None, None]] = None
	) -> Generator['highlevelil.HighLevelILFunction', None, None]:
		"""
		Generates a list of il functions. This method should be used instead of 'functions' property if
		HLIL is needed and performance is a concern.
		"""
		for func in AdvancedILFunctionList(
		    self, self.preload_limit if preload_limit is None else preload_limit, function_generator
		):
			try:
				yield func.hlil
			except ILException:
				pass

	@property
	def has_functions(self) -> bool:
		"""Boolean whether the binary has functions (read-only)"""
		return core.BNHasFunctions(self.handle)

	@property
	def has_symbols(self) -> bool:
		"""Boolean whether the binary has symbols (read-only)"""
		return core.BNHasSymbols(self.handle)

	@property
	def has_data_variables(self) -> bool:
		"""Boolean whether the binary has data variables (read-only)"""
		return core.BNHasDataVariables(self.handle)

	@property
	def entry_function(self) -> Optional['_function.Function']:
		"""Entry function (read-only)"""
		func = core.BNGetAnalysisEntryPoint(self.handle)
		if func is None:
			return None
		return _function.Function(self, func)

	@property
	def entry_functions(self) -> FunctionList:
		"""A List of entry functions (read-only)
		This list contains vanilla entry function, and functions like init_array, fini_array, and TLS callbacks etc.
		User-added entry functions(via `add_entry_point`) are also included.

		We see `entry_functions` as good starting points for analysis, these functions normally don't have internal references.
		However, note that exported functions in a dll/so file are not included.

		Note the difference with `entry_function`

		:Example:

			>>> bv.entry_function
			<func: x86@0x4014c8>
			>>> bv.entry_functions
			[<func: x86@0x4014c8>, <func: x86@0x401618>]

		:return: a list of functions, containing the vanilla entry and other platform-specific entry functions
		:rtype: list(Function)
		"""
		count = ctypes.c_ulonglong(0)
		funcs = core.BNGetAllEntryFunctions(self.handle, count)

		assert funcs is not None, "core.BNGetAllEntryFunctions returned None"
		result = []
		try:
			for i in range(0, count.value):
				result.append(_function.Function(self, core.BNNewFunctionReference(funcs[i])))
			return result
		finally:
			core.BNFreeFunctionList(funcs, count.value)

	@property
	def symbols(self) -> SymbolMapping:
		"""
		Dict of symbols (read-only)
		Items in the dict are lists of all symbols matching that name.

		:Example:

			>>> bv.symbols['_main']
			[<FunctionSymbol: "_main" @ 0x1dd0>]
			>>> list(bv.symbols)
			['_start', '_main', '_printf', '_scanf', ...]
			>>> bv.symbols['foo']
			KeyError: "'foo': symbol not found"

		:return: a dict-like generator of symbol names and values
		:rtype: Generator[str, None, None]
		"""
		return SymbolMapping(self)

	@staticmethod
	def internal_namespace() -> '_types.NameSpace':
		"""Internal namespace for the current BinaryView"""
		ns = core.BNGetInternalNameSpace()
		try:
			return _types.NameSpace._from_core_struct(ns)
		finally:
			core.BNFreeNameSpace(ns)

	@staticmethod
	def external_namespace() -> '_types.NameSpace':
		"""External namespace for the current BinaryView"""
		ns = core.BNGetExternalNameSpace()
		try:
			return _types.NameSpace._from_core_struct(ns)
		finally:
			core.BNFreeNameSpace(ns)

	@property
	def namespaces(self) -> List['_types.NameSpace']:
		"""Returns a list of namespaces for the current BinaryView"""
		count = ctypes.c_ulonglong(0)
		nameSpaceList = core.BNGetNameSpaces(self.handle, count)
		assert nameSpaceList is not None, "core.BNGetNameSpaces returned None"
		result = []
		try:
			for i in range(count.value):
				result.append(_types.NameSpace._from_core_struct(nameSpaceList[i]))
			return result
		finally:
			core.BNFreeNameSpaceList(nameSpaceList, count.value)

	@property
	def view_type(self) -> str:
		"""View type (read-only)"""
		return core.BNGetViewType(self.handle)

	@property
	def available_view_types(self) -> List[BinaryViewType]:
		"""Available view types (read-only)"""
		count = ctypes.c_ulonglong(0)
		types = core.BNGetBinaryViewTypesForData(self.handle, count)
		result = []
		if types is None:
			return result
		try:
			for i in range(0, count.value):
				result.append(BinaryViewType(types[i]))
			return result
		finally:
			core.BNFreeBinaryViewTypeList(types)

	@property
	def strings(self) -> List['StringReference']:
		"""List of strings (read-only)"""
		return self.get_strings()

	@property
	def saved(self) -> bool:
		"""boolean state of whether or not the file has been saved (read/write)"""
		return self._file.saved

	@saved.setter
	def saved(self, value: bool) -> None:
		self._file.saved = value

	@property
	def analysis_info(self) -> AnalysisInfo:
		"""Provides instantaneous analysis state information and a list of current functions under analysis (read-only).
		All times are given in units of milliseconds (ms). Per-function `analysis_time` is the aggregation of time spent
		performing incremental updates and is reset on a full function update. Per-function `update_count` tracks the
		current number of incremental updates and is reset on a full function update. Per-function `submit_count` tracks the
		current number of full updates that have completed.

		.. note:: `submit_count` is currently not reset across analysis updates.

		"""
		info_ref = core.BNGetAnalysisInfo(self.handle)
		assert info_ref is not None, "core.BNGetAnalysisInfo returned None"
		info = info_ref[0]
		active_info_list: List[ActiveAnalysisInfo] = []
		try:
			for i in range(0, info.count):
				func = _function.Function(self, core.BNNewFunctionReference(info.activeInfo[i].func))
				active_info = ActiveAnalysisInfo(
				    func, info.activeInfo[i].analysisTime, info.activeInfo[i].updateCount,
				    info.activeInfo[i].submitCount
				)
				active_info_list.append(active_info)
			return AnalysisInfo(info.state, info.analysisTime, active_info_list)
		finally:
			core.BNFreeAnalysisInfo(info_ref)

	@property
	def analysis_progress(self) -> AnalysisProgress:
		"""Status of current analysis (read-only)"""
		result = core.BNGetAnalysisProgress(self.handle)
		return AnalysisProgress(result.state, result.count, result.total)

	@property
	def linear_disassembly(self) -> Iterator['lineardisassembly.LinearDisassemblyLine']:
		"""Iterator for all lines in the linear disassembly of the view"""
		return self.get_linear_disassembly(None)

	@property
	def data_vars(self) -> Mapping[int, 'DataVariable']:
		"""List of data variables (read-only)"""
		count = ctypes.c_ulonglong(0)
		var_list = core.BNGetDataVariables(self.handle, count)
		assert var_list is not None, "core.BNGetDataVariables returned None"
		result = {}
		try:
			for i in range(0, count.value):
				result[var_list[i].address] = DataVariable.from_core_struct(var_list[i], self)
			return result
		finally:
			core.BNFreeDataVariables(var_list, count.value)

	@property
	def types(self) -> TypeMapping:
		return TypeMapping(self)

	@property
	def dependency_sorted_types(self) -> TypeMapping:
		"""
		List of all types, sorted such that types are after all types on which they depend (read-only)

		Order is guaranteed for any collection of types with no cycles. If you have cycles \
		in type dependencies, order for types in a cycle is not guaranteed.

		.. note:: Dependency order is based on named type references for all non-structure types, i.e. \
		``struct Foo m_foo`` will induce a dependency, whereas ``struct Foo* m_pFoo`` will not.

		:return: sorted types as defined above
		"""
		return TypeMapping(self, core.BNGetAnalysisDependencySortedTypeList)

	@property
	def type_names(self) -> List['_types.QualifiedName']:
		"""List of defined type names (read-only)"""
		count = ctypes.c_ulonglong(0)
		name_list = core.BNGetAnalysisTypeNames(self.handle, count, "")
		assert name_list is not None, "core.BNGetAnalysisTypeNames returned None"
		result = []
		try:
			for i in range(0, count.value):
				result.append(_types.QualifiedName._from_core_struct(name_list[i]))
			return result
		finally:
			core.BNFreeTypeNameList(name_list, count.value)

	@property
	def type_libraries(self) -> List['typelibrary.TypeLibrary']:
		"""List of imported type libraries (read-only)"""
		count = ctypes.c_ulonglong(0)
		libraries = core.BNGetBinaryViewTypeLibraries(self.handle, count)
		assert libraries is not None, "core.BNGetBinaryViewTypeLibraries returned None"
		result = []
		try:
			for i in range(0, count.value):
				result.append(typelibrary.TypeLibrary(core.BNNewTypeLibraryReference(libraries[i])))
			return result
		finally:
			core.BNFreeTypeLibraryList(libraries, count.value)

	@property
	def attached_type_archives(self) -> Mapping['str', 'str']:
		"""All attached type archive ids and paths (read-only)"""
		ids = ctypes.POINTER(ctypes.c_char_p)()
		paths = ctypes.POINTER(ctypes.c_char_p)()
		count = core.BNBinaryViewGetTypeArchives(self.handle, ids, paths)
		result = {}
		try:
			for i in range(0, count):
				result[core.pyNativeStr(ids[i])] = core.pyNativeStr(paths[i])
			return result
		finally:
			core.BNFreeStringList(ids, count)
			core.BNFreeStringList(paths, count)

	@property
	def connected_type_archives(self) -> List['typearchive.TypeArchive']:
		"""All connected type archive objects (read-only)"""
		result = []
		for (id, path) in self.attached_type_archives.items():
			archive = self.get_type_archive(id)
			if archive is not None:
				result.append(archive)
		return result

	@property
	def segments(self) -> List['Segment']:
		"""List of segments (read-only)"""
		count = ctypes.c_ulonglong(0)
		segment_list = core.BNGetSegments(self.handle, count)
		assert segment_list is not None, "core.BNGetSegments returned None"
		result = []
		try:
			for i in range(0, count.value):
				segment_handle = core.BNNewSegmentReference(segment_list[i])
				assert segment_handle is not None, "core.BNNewSegmentReference returned None"
				result.append(Segment(segment_handle))
			return result
		finally:
			core.BNFreeSegmentList(segment_list, count.value)

	@property
	def sections(self) -> Mapping[str, 'Section']:
		"""Dictionary of sections (read-only)"""
		count = ctypes.c_ulonglong(0)
		section_list = core.BNGetSections(self.handle, count)
		assert section_list is not None, "core.BNGetSections returned None"
		result = {}
		try:
			for i in range(0, count.value):
				section_handle = core.BNNewSectionReference(section_list[i])
				assert section_handle is not None, "core.BNNewSectionReference returned None"
				result[core.BNSectionGetName(section_list[i])] = Section(section_handle)
			return result
		finally:
			core.BNFreeSectionList(section_list, count.value)

	@property
	def allocated_ranges(self) -> List['variable.AddressRange']:
		"""List of valid address ranges for this view (read-only) Deprecated: 4.0.xxxx Use mapped_address_ranges instead."""
		count = ctypes.c_ulonglong(0)
		range_list = core.BNGetAllocatedRanges(self.handle, count)
		assert range_list is not None, "core.BNGetAllocatedRanges returned None"
		result = []
		try:
			for i in range(0, count.value):
				result.append(variable.AddressRange(range_list[i].start, range_list[i].end))
			return result
		finally:
			core.BNFreeAddressRanges(range_list)

	@property
	def mapped_address_ranges(self) -> List['variable.AddressRange']:
		"""List of mapped address ranges for this view (read-only)"""
		count = ctypes.c_ulonglong(0)
		range_list = core.BNGetMappedAddressRanges(self.handle, count)
		assert range_list is not None, "core.BNGetMappedAddressRanges returned None"
		result = []
		try:
			for i in range(0, count.value):
				result.append(variable.AddressRange(range_list[i].start, range_list[i].end))
			return result
		finally:
			core.BNFreeAddressRanges(range_list)

	@property
	def backed_address_ranges(self) -> List['variable.AddressRange']:
		"""List of backed address ranges for this view (read-only)"""
		count = ctypes.c_ulonglong(0)
		range_list = core.BNGetBackedAddressRanges(self.handle, count)
		assert range_list is not None, "core.BNGetBackedAddressRanges returned None"
		result = []
		try:
			for i in range(0, count.value):
				result.append(variable.AddressRange(range_list[i].start, range_list[i].end))
			return result
		finally:
			core.BNFreeAddressRanges(range_list)

	@property
	def session_data(self):  # TODO add type hint
		"""Dictionary object where plugins can store arbitrary data associated with the view. This data is ephemeral and not saved to a database. Consider using :py:func:`store_metadata` if permanence is needed."""
		handle = ctypes.cast(self.handle, ctypes.c_void_p)
		if handle.value not in BinaryView._associated_data:
			obj = _BinaryViewAssociatedDataStore()
			BinaryView._associated_data[handle.value] = obj
			return obj
		else:
			return BinaryView._associated_data[handle.value]

	@property
	def global_pointer_value(self) -> 'variable.RegisterValue':
		"""Discovered value of the global pointer register, if the binary uses one (read-only)"""
		result = core.BNGetGlobalPointerValue(self.handle)
		return variable.RegisterValue.from_BNRegisterValue(result, self.arch)

	@property
	def user_global_pointer_value_set(self) -> bool:
		"""Check whether a user global pointer value has been set"""
		return core.BNUserGlobalPointerValueSet(self.handle)

	def clear_user_global_pointer_value(self):
		"""Clear a previously set user global pointer value, so the auto-analysis can calculate a new value"""
		core.BNClearUserGlobalPointerValue(self.handle)

	def set_user_global_pointer_value(self, value: variable.RegisterValue, confidence = 255):
		"""
		Set a user global pointer value. This is useful when the auto analysis fails to find out the value of the global
		pointer, or the value is wrong. In this case, we can call `set_user_global_pointer_value` with a
		`ConstantRegisterValue` or `ConstantPointerRegisterValue`to provide a user global pointer value to assist the
		analysis.

		On the other hand, if the auto analysis figures out a global pointer value, but there should not be one, we can
		call `set_user_global_pointer_value` with an `Undetermined` value to override it.

		Whenever a user global pointer value is set/cleared, an analysis update must occur for it to take effect and
		all functions using the global pointer to be updated.

		We can use `user_global_pointer_value_set` to query whether a user global pointer value is set, and use
		`clear_user_global_pointer_value` to clear a user global pointer value. Note, `clear_user_global_pointer_value`
		is different from calling `set_user_global_pointer_value` with an `Undetermined` value. The former clears the
		user global pointer value and let the analysis decide the global pointer value, whereas the latte forces the
		global pointer value to become undetermined.

		:param variable.RegisterValue value: the user global pointer value to be set
		:param int confidence: the confidence value of the user global pointer value. In most cases this should be set
		to 255. Setting a value lower than the confidence of the global pointer value from the auto analysis will cause
		undesired effect.
		:return:
		:Example:

			>>> bv.global_pointer_value
			<const ptr 0x3fd4>
			>>> bv.set_user_global_pointer_value(ConstantPointerRegisterValue(0x12345678))
			>>> bv.global_pointer_value
			<const ptr 0x12345678>
			>>> bv.user_global_pointer_value_set
			True
			>>> bv.clear_user_global_pointer_value()
			>>> bv.global_pointer_value
			<const ptr 0x3fd4>
			>>> bv.set_user_global_pointer_value(Undetermined())
			>>> bv.global_pointer_value
			<undetermined>
		"""
		val = core.BNRegisterValueWithConfidence()
		val.value = value._to_core_struct()
		val.confidence = confidence
		core.BNSetUserGlobalPointerValue(self.handle, val)

	@property
	def parameters_for_analysis(self):
		return core.BNGetParametersForAnalysis(self.handle)

	@parameters_for_analysis.setter
	def parameters_for_analysis(self, params):
		core.BNSetParametersForAnalysis(self.handle, params)

	@property
	def max_function_size_for_analysis(self) -> int:
		"""Maximum size of function (sum of basic block sizes in bytes) for auto analysis"""
		return core.BNGetMaxFunctionSizeForAnalysis(self.handle)

	@max_function_size_for_analysis.setter
	def max_function_size_for_analysis(self, size: int) -> None:
		core.BNSetMaxFunctionSizeForAnalysis(self.handle, size)

	@property
	def relocation_ranges(self) -> List[Tuple[int, int]]:
		"""List of relocation range tuples (read-only)"""
		count = ctypes.c_ulonglong()
		ranges = core.BNGetRelocationRanges(self.handle, count)
		assert ranges is not None, "core.BNGetRelocationRanges returned None"
		try:
			return [(ranges[i].start, ranges[i].end) for i in range(count.value)]
		finally:
			core.BNFreeRelocationRanges(ranges)

	def relocation_ranges_at(self, addr: int) -> List[Tuple[int, int]]:
		"""List of relocation range tuples for a given address"""

		count = ctypes.c_ulonglong()
		ranges = core.BNGetRelocationRangesAtAddress(self.handle, addr, count)
		assert ranges is not None, "core.BNGetRelocationRangesAtAddress returned None"
		try:
			return [(ranges[i].start, ranges[i].end) for i in range(count.value)]
		finally:
			core.BNFreeRelocationRanges(ranges)

	def relocation_ranges_in_range(self, addr: int, size: int) -> List[Tuple[int, int]]:
		"""List of relocation range tuples for a given range"""

		count = ctypes.c_ulonglong()
		ranges = core.BNGetRelocationRangesInRange(self.handle, addr, size, count)
		assert ranges is not None, "core.BNGetRelocationRangesInRange returned None"
		try:
			return [(ranges[i].start, ranges[i].end) for i in range(count.value)]
		finally:
			core.BNFreeRelocationRanges(ranges)

	def range_contains_relocation(self, addr: int, size: int) -> bool:
		"""Checks if the specified range overlaps with a relocation"""
		return core.BNRangeContainsRelocation(self.handle, addr, size)

	@property
	def new_auto_function_analysis_suppressed(self) -> bool:
		"""Whether or not automatically discovered functions will be analyzed"""
		return core.BNGetNewAutoFunctionAnalysisSuppressed(self.handle)

	@new_auto_function_analysis_suppressed.setter
	def new_auto_function_analysis_suppressed(self, suppress: bool) -> None:
		core.BNSetNewAutoFunctionAnalysisSuppressed(self.handle, suppress)

	@property
	def project(self) -> Optional['project.Project']:
		return self.file.project

	@property
	def project_file(self) -> Optional['project.ProjectFile']:
		return self.file.project_file

	def _init(self, ctxt):
		try:
			return self.init()
		except:
			log_error(traceback.format_exc())
			return False

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

	def _read(self, ctxt, dest, offset, length):
		try:
			data = self.perform_read(offset, length)
			if data is None:
				return 0
			if len(data) > length:
				data = data[0:length]
			ctypes.memmove(dest, data, len(data))
			return len(data)
		except:
			log_error(traceback.format_exc())
			return 0

	def _write(self, ctxt, offset, src, length):
		try:
			data = ctypes.create_string_buffer(length)
			ctypes.memmove(data, src, length)
			return self.perform_write(offset, data.raw)
		except:
			log_error(traceback.format_exc())
			return 0

	def _insert(self, ctxt, offset, src, length):
		try:
			data = ctypes.create_string_buffer(length)
			ctypes.memmove(data, src, length)
			return self.perform_insert(offset, data.raw)
		except:
			log_error(traceback.format_exc())
			return 0

	def _remove(self, ctxt, offset, length):
		try:
			return self.perform_remove(offset, length)
		except:
			log_error(traceback.format_exc())
			return 0

	def _get_modification(self, ctxt, offset):
		try:
			return self.perform_get_modification(offset)
		except:
			log_error(traceback.format_exc())
			return ModificationStatus.Original

	def _is_valid_offset(self, ctxt, offset):
		try:
			return self.perform_is_valid_offset(offset)
		except:
			log_error(traceback.format_exc())
			return False

	def _is_offset_readable(self, ctxt, offset):
		try:
			return self.perform_is_offset_readable(offset)
		except:
			log_error(traceback.format_exc())
			return False

	def _is_offset_writable(self, ctxt, offset):
		try:
			return self.perform_is_offset_writable(offset)
		except:
			log_error(traceback.format_exc())
			return False

	def _is_offset_executable(self, ctxt, offset):
		try:
			return self.perform_is_offset_executable(offset)
		except:
			log_error(traceback.format_exc())
			return False

	def _get_next_valid_offset(self, ctxt, offset):
		try:
			return self.perform_get_next_valid_offset(offset)
		except:
			log_error(traceback.format_exc())
			return offset

	def _get_start(self, ctxt):
		try:
			return self.perform_get_start()
		except:
			log_error(traceback.format_exc())
			return 0

	def _get_length(self, ctxt):
		try:
			return self.perform_get_length()
		except:
			log_error(traceback.format_exc())
			return 0

	def _get_entry_point(self, ctxt):
		try:
			return self.perform_get_entry_point()
		except:
			log_error(traceback.format_exc())
			return 0

	def _is_executable(self, ctxt):
		try:
			return self.perform_is_executable()
		except:
			log_error(traceback.format_exc())
			return False

	def _get_default_endianness(self, ctxt):
		try:
			return self.perform_get_default_endianness()
		except:
			log_error(traceback.format_exc())
			return Endianness.LittleEndian

	def _is_relocatable(self, ctxt):
		try:
			return self.perform_is_relocatable()
		except:
			log_error(traceback.format_exc())
			return False

	def _get_address_size(self, ctxt):
		try:
			return self.perform_get_address_size()
		except:
			log_error(traceback.format_exc())
			return 8

	def _save(self, ctxt, file_accessor):
		try:
			return self.perform_save(fileaccessor.CoreFileAccessor(file_accessor))
		except:
			log_error(traceback.format_exc())
			return False

	def init(self) -> bool:
		return True

	def disassembly_tokens(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> Generator[Tuple[List['_function.InstructionTextToken'], int], None, None]:
		if arch is None:
			if self.arch is None:
				raise Exception("Can not call method disassembly with no Architecture specified")
			arch = self.arch

		size = 1
		while size != 0:
			tokens, size = arch.get_instruction_text(self.read(addr, arch.max_instr_length), addr)
			addr += size
			if size == 0 or tokens is None:
				break
			yield (tokens, size)

	def disassembly_text(self, addr: int,
	                     arch: Optional['architecture.Architecture'] = None) -> Generator[Tuple[str, int], None, None]:
		"""
		``disassembly_text`` helper function for getting disassembly of a given address

		:param int addr: virtual address of instruction
		:param Architecture arch: optional Architecture, ``self.arch`` is used if this parameter is None
		:return: a str representation of the instruction at virtual address ``addr`` or None
		:rtype: str or None
		:Example:

			>>> next(bv.disassembly_text(bv.entry_point))
			'push    ebp', 1
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Can not call method disassembly with no Architecture specified")
			arch = self.arch

		size = 1
		while size != 0:
			tokens, size = arch.get_instruction_text(self.read(addr, arch.max_instr_length), addr)
			addr += size
			if size == 0 or tokens is None:
				break
			yield (''.join(str(a) for a in tokens).strip(), size)

	def get_disassembly(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> Optional[str]:
		"""
		``get_disassembly`` simple helper function for printing disassembly of a given address

		:param int addr: virtual address of instruction
		:param Architecture arch: optional Architecture, ``self.arch`` is used if this parameter is None
		:return: a str representation of the instruction at virtual address ``addr`` or None
		:rtype: str or None
		:Example:
			>>> bv.get_disassembly(bv.entry_point)
			'push    ebp'
			>>>

		.. note:: This API is very simplistic and only returns text. See :py:func:`disassembly_text` and \
		 `instructions` for more capable APIs.
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Can not call method disassembly with no Architecture specified")
			arch = self.arch
		txt, _ = arch.get_instruction_text(self.read(addr, arch.max_instr_length), addr)
		if txt is None:
			return None
		return ''.join(str(a) for a in txt).strip()

	def perform_save(self, accessor) -> bool:
		if self.parent_view is not None:
			return self.parent_view.save(accessor)
		return False

	@abc.abstractmethod
	def perform_get_address_size(self) -> int:
		raise NotImplementedError

	def perform_get_length(self) -> int:
		"""
		``perform_get_length`` implements a query for the size of the virtual address range used by
		the BinaryView.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :py:func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:return: returns the size of the virtual address range used by the BinaryView
		:rtype: int
		"""
		return 0

	def perform_read(self, addr: int, length: int) -> bytes:
		"""
		``perform_read`` implements a mapping between a virtual address and an absolute file offset, reading
		``length`` bytes from the rebased address ``addr``.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :py:func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to attempt to read from
		:param int length: the number of bytes to be read
		:return: length bytes read from addr, should return empty string on error
		:rtype: bytes
		"""
		return b""

	def perform_write(self, addr: int, data: bytes) -> int:
		"""
		``perform_write`` implements a mapping between a virtual address and an absolute file offset, writing
		the bytes ``data`` to rebased address ``addr``.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :py:func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address
		:param bytes data: the data to be written
		:return: length of data written, should return 0 on error
		:rtype: int
		"""
		return 0

	def perform_insert(self, addr: int, data: bytes) -> int:
		"""
		``perform_insert`` implements a mapping between a virtual address and an absolute file offset, inserting
		the bytes ``data`` to rebased address ``addr``.

		.. note:: This method **may** be overridden by custom BinaryViews. If not overridden, inserting is disallowed

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address
		:param bytes data: the data to be inserted
		:return: length of data inserted, should return 0 on error
		:rtype: int
		"""
		return 0

	def perform_remove(self, addr: int, length: int) -> int:
		"""
		``perform_remove`` implements a mapping between a virtual address and an absolute file offset, removing
		``length`` bytes from the rebased address ``addr``.

		.. note:: This method **may** be overridden by custom BinaryViews. If not overridden, removing data is disallowed

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address
		:param int length: the number of bytes to be removed
		:return: length of data removed, should return 0 on error
		:rtype: int
		"""
		return 0

	def perform_get_modification(self, addr: int) -> ModificationStatus:
		"""
		``perform_get_modification`` implements query to the whether the virtual address ``addr`` is modified.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :py:func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: one of the following: Original = 0, Changed = 1, Inserted = 2
		:rtype: ModificationStatus
		"""
		return ModificationStatus.Original

	def perform_is_valid_offset(self, addr: int) -> bool:
		"""
		``perform_is_valid_offset`` implements a check if a virtual address ``addr`` is valid.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :py:func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid, false if the virtual address is invalid or error
		:rtype: bool
		"""
		data = self.read(addr, 1)
		return (data is not None) and (len(data) == 1)

	def perform_is_offset_readable(self, offset: int) -> bool:
		"""
		``perform_is_offset_readable`` implements a check if a virtual address is readable.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :py:func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int offset: a virtual address to be checked
		:return: true if the virtual address is readable, false if the virtual address is not readable or error
		:rtype: bool
		"""
		return self.is_valid_offset(offset)

	def perform_is_offset_writable(self, addr: int) -> bool:
		"""
		``perform_is_offset_writable`` implements a check if a virtual address ``addr`` is writable.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :py:func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is writable, false if the virtual address is not writable or error
		:rtype: bool
		"""
		return self.is_valid_offset(addr)

	def perform_is_offset_executable(self, addr: int) -> bool:
		"""
		``perform_is_offset_executable`` implements a check if a virtual address ``addr`` is executable.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :py:func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is executable, false if the virtual address is not executable or error
		:rtype: bool
		"""
		return self.is_valid_offset(addr)

	def perform_get_next_valid_offset(self, addr: int) -> int:
		"""
		``perform_get_next_valid_offset`` implements a query for the next valid readable, writable, or executable virtual
		memory address.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :py:func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to start checking from.
		:return: the next readable, writable, or executable virtual memory address
		:rtype: int
		"""
		if addr < self.perform_get_start():
			return self.perform_get_start()
		return addr

	def perform_get_start(self) -> int:
		"""
		``perform_get_start`` implements a query for the first readable, writable, or executable virtual address in
		the BinaryView.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :py:func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:return: returns the first virtual address in the BinaryView
		:rtype: int
		"""
		return 0

	def perform_get_entry_point(self) -> int:
		"""
		``perform_get_entry_point`` implements a query for the initial entry point for code execution.

		.. note:: This method **should** be implemented for custom BinaryViews that are executable.

		.. warning:: This method **must not** be called directly.

		:return: the virtual address of the entry point
		:rtype: int
		"""
		return 0

	def perform_is_executable(self) -> bool:
		"""
		``perform_is_executable`` implements a check which returns true if the BinaryView is executable.

		.. note:: This method **must** be implemented for custom BinaryViews that are executable.

		.. warning:: This method **must not** be called directly.

		:return: true if the current BinaryView is executable, false if it is not executable or on error
		:rtype: bool
		"""
		return False

	def perform_get_default_endianness(self) -> Endianness:
		"""
		``perform_get_default_endianness`` implements a check which returns the Endianness of the BinaryView

		.. note:: This method **may** be implemented for custom BinaryViews that are not LittleEndian.

		.. warning:: This method **must not** be called directly.

		:return: either :const:`Endianness.LittleEndian <binaryninja.enums.Endianness.LittleEndian>` or :const:`Endianness.BigEndian <binaryninja.enums.Endianness.BigEndian>`
		:rtype: Endianness
		"""
		return Endianness.LittleEndian

	def perform_is_relocatable(self) -> bool:
		"""
		``perform_is_relocatable`` implements a check which returns true if the BinaryView is relocatable. Defaults to False

		.. note:: This method **may** be implemented for custom BinaryViews that are relocatable.

		.. warning:: This method **must not** be called directly.

		:return: True if the BinaryView is relocatable, False otherwise
		:rtype: boolean
		"""
		return False

	def create_database(
	    self, filename: str, progress_func: Optional[ProgressFuncType] = None,
	    settings: Optional['filemetadata.SaveSettings'] = None
	) -> bool:
		"""
		``create_database`` writes the current database (.bndb) out to the specified file.

		:param str filename: path and filename to write the bndb to, this string `should` have ".bndb" appended to it.
		:param callback progress_func: optional function to be called with the current progress and total count.
		:param SaveSettings settings: optional argument for special save options.
		:return: True on success, False on failure
		:rtype: bool

		.. warning:: The calling thread must not hold a lock on the BinaryView instance as this action is run on the main thread which requires the lock.

		:Example:
			>>> settings = SaveSettings()
			>>> bv.create_database(f"{bv.file.filename}.bndb", None, settings)
			True
		"""
		return self._file.create_database(filename, progress_func, settings)

	def save_auto_snapshot(
	    self, progress_func: Optional[ProgressFuncType] = None, settings: Optional['filemetadata.SaveSettings'] = None
	) -> bool:
		"""
		``save_auto_snapshot`` saves the current database to the already created file.

		.. note:: :py:func:`create_database` should have been called prior to executing this method

		:param callback progress_func: optional function to be called with the current progress and total count.
		:param SaveSettings settings: optional argument for special save options.
		:return: True if it successfully saved the snapshot, False otherwise
		:rtype: bool
		"""
		return self._file.save_auto_snapshot(progress_func, settings)

	def get_view_of_type(self, name: str) -> Optional['BinaryView']:
		"""
		``get_view_of_type`` returns the BinaryView associated with the provided name if it exists.

		:param str name: Name of the view to be retrieved
		:return: BinaryView object associated with the provided name or None on failure
		:rtype: BinaryView or None
		"""
		return self._file.get_view_of_type(name)

	def undoable_transaction(self) -> Generator:
		"""
		``undoable_transaction`` gives you a context in which you can make changes to analysis,
		and creates an Undo state containing those actions. If an exception is thrown, any
		changes made to the analysis inside the transaction are reverted.

		:return: Transaction context manager, which will commit/revert actions depending on if an exception
		         is thrown when it goes out of scope.
		:rtype: Generator
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> # Actions inside the transaction will be committed to the undo state upon exit
			>>> with bv.undoable_transaction():
			>>>     bv.convert_to_nop(0x100012f1)
			True
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> # A thrown exception inside the transaction will undo all changes made inside it
			>>> with bv.undoable_transaction():
			>>>     bv.convert_to_nop(0x100012f1)  # Reverted on thrown exception
			>>>     raise RuntimeError("oh no")
			RuntimeError: oh no
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
		"""
		return self._file.undoable_transaction()

	def begin_undo_actions(self, anonymous_allowed: bool = True) -> str:
		"""
		``begin_undo_actions`` starts recording actions taken so they can be undone at some point.

		:param bool anonymous_allowed: Legacy interop: prevent empty calls to :py:func:`commit_undo_actions`` from
		                               affecting this undo state. Specifically for :py:func:`undoable_transaction``
		:return: Id of undo state, for passing to :py:func:`commit_undo_actions`` or :py:func:`revert_undo_actions`.
		:rtype: str
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> state = bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions(state)
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		return self._file.begin_undo_actions(anonymous_allowed)

	def commit_undo_actions(self, id: Optional[str] = None) -> None:
		"""
		``commit_undo_actions`` commits the actions taken since a call to :py:func:`begin_undo_actions`
		Pass as `id` the value returned by :py:func:`begin_undo_actions`. Empty values of
		`id` will commit all changes since the last call to :py:func:`begin_undo_actions`.

		:param Optional[str] id: id of undo state, from :py:func:`begin_undo_actions`
		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> state = bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions(state)
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		self._file.commit_undo_actions(id)

	def revert_undo_actions(self, id: Optional[str] = None) -> None:
		"""
		``revert_undo_actions`` reverts the actions taken since a call to :py:func:`begin_undo_actions`
		Pass as `id` the value returned by :py:func:`begin_undo_actions`. Empty values of
		`id` will revert all changes since the last call to :py:func:`begin_undo_actions`.

		:param Optional[str] id: id of undo state, from :py:func:`begin_undo_actions`
		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> state = bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.revert_undo_actions(state)
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		self._file.revert_undo_actions(id)

	def undo(self) -> None:
		"""
		``undo`` undo the last committed transaction in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> with bv.undoable_transaction():
			>>>     bv.convert_to_nop(0x100012f1)
			True
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.redo()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>>
		"""
		self._file.undo()

	def redo(self) -> None:
		"""
		``redo`` redo the last committed transaction in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> with bv.undoable_transaction():
			>>>     bv.convert_to_nop(0x100012f1)
			True
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.redo()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>>
		"""
		self._file.redo()

	def navigate(self, view_name: str, offset: int) -> bool:
		"""
		``navigate`` navigates the UI to the specified virtual address in the specified View

		The View name is created by combining a View type (e.g. "Graph") with a BinaryView type (e.g. "Mach-O"),
		separated by a colon, resulting in something like "Graph:Mach-O".

		:param str view_name: view name
		:param int offset: address to navigate to
		:return: whether navigation succeeded
		:rtype: bool
		:Example:

			>>> bv.navigate(bv.view, bv.start)
			True
			>>> bv.file.existing_views
			['Mach-O', 'Raw']
			>>> import binaryninjaui
			>>> [i.getName() for i in binaryninjaui.ViewType.getTypes()]
			['Graph', 'Hex', 'Linear', 'Strings', 'Types', 'Triage', 'Bytes']
			>>> bv.navigate('Graph:Mach-O', bv.entry_point)
			True
		"""
		return self._file.navigate(view_name, offset)

	def read(self, addr: int, length: int) -> bytes:
		r"""
		``read`` returns the data reads at most ``length`` bytes from virtual address ``addr``.

		:param int addr: virtual address to read from.
		:param int length: number of bytes to read.
		:return: at most ``length`` bytes from the virtual address ``addr``, empty string on error or no data
		:rtype: bytes
		:Example:

			>>> #Opening a x86_64 Mach-O binary
			>>> bv = BinaryView.new("/bin/ls") # note that we are using `new` instead of `load` to get the raw view
			>>> bv.read(0,4)
			b'\xcf\xfa\xed\xfe'
		"""
		if (addr < 0) or (length < 0):
			raise ValueError("length and address must both be positive")
		buf = databuffer.DataBuffer(handle=core.BNReadViewBuffer(self.handle, addr, length))
		return bytes(buf)

	def read_int(self, address: int, size: int, sign: bool = True, endian: Optional[Endianness] = None) -> int:
		_endian = self.endianness
		if endian is not None:
			_endian = endian
		data = self.read(address, size)
		if len(data) != size:
			raise ValueError(f"Couldn't read {size} bytes from address: {address:#x}")
		return TypedDataAccessor.int_from_bytes(data, size, sign, _endian)

	def read_pointer(self, address: int, size: Optional[int] = None) -> int:
		if size is None:
			if self.arch is None:
				raise ValueError("Can't read pointer for BinaryView without an architecture")
			size = self.arch.address_size
		return self.read_int(address, size, False, self.endianness)

	def read_uuid(self, address: int, ms_format: bool = True) -> uuid.UUID:
			"""
			Reads a UUID from the specified address in the binary view.

			:param address: The address to read the UUID from.
			:param ms_format: Whether to return the UUID in Microsoft format (True) or standard format (False).
			:return: A UUID object
			:raises ValueError: If 16 bytes couldn't be read from the specified address.
			"""
			data = self.read(address, 16)
			if len(data) != 16:
				raise ValueError(f"Couldn't read 16 bytes from address: {address:#x}")
			if ms_format:
				reordered = data[3::-1] + data[5:3:-1] + data[7:5:-1] + data[8:]
				return uuid.UUID(bytes=reordered)
			else:
				return uuid.UUID(bytes=data)

	def write(self, addr: int, data: bytes, except_on_relocation: bool = True) -> int:
		"""
		``write`` writes the bytes in ``data`` to the virtual address ``addr``.

		:param int addr: virtual address to write to.
		:param bytes data: data to be written at addr.
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: number of bytes written to virtual address ``addr``
		:rtype: int
		:Example:

			>>> bv.read(0,4)
			b'BBBB'
			>>> bv.write(0, b"AAAA")
			4
			>>> bv.read(0,4)
			b'AAAA'
		"""
		if not (isinstance(data, bytes) or isinstance(data, bytearray) or isinstance(data, str)):
			raise TypeError("Must be bytes, bytearray, or str")
		buf = databuffer.DataBuffer(data)
		if except_on_relocation and self.range_contains_relocation(addr, len(data)):
			raise RelocationWriteException("Attempting to write to a location which has a relocation")

		return core.BNWriteViewBuffer(self.handle, addr, buf.handle)

	def insert(self, addr: int, data: bytes) -> int:
		"""
		``insert`` inserts the bytes in ``data`` to the virtual address ``addr``.

		:param int addr: virtual address to write to.
		:param bytes data: data to be inserted at addr.
		:return: number of bytes inserted to virtual address ``addr``
		:rtype: int
		:Example:

			>>> bv.insert(0,"BBBB")
			4
			>>> bv.read(0,8)
			'BBBBAAAA'
		"""
		if not (isinstance(data, bytes) or isinstance(data, bytearray) or isinstance(data, str)):
			raise TypeError("Must be bytes, bytearray, or str")
		else:
			buf = databuffer.DataBuffer(data)
		return core.BNInsertViewBuffer(self.handle, addr, buf.handle)

	def remove(self, addr: int, length: int) -> int:
		"""
		``remove`` removes at most ``length`` bytes from virtual address ``addr``.

		:param int addr: virtual address to remove from.
		:param int length: number of bytes to remove.
		:return: number of bytes removed from virtual address ``addr``
		:rtype: int
		:Example:

			>>> bv.read(0,8)
			'BBBBAAAA'
			>>> bv.remove(0,4)
			4
			>>> bv.read(0,4)
			'AAAA'
		"""
		return core.BNRemoveViewData(self.handle, addr, length)

	def get_entropy(self, addr: int, length: int, block_size: int = 0) -> List[float]:
		"""
		``get_entropy`` returns the shannon entropy given the start ``addr``, ``length`` in bytes, and optionally in
		``block_size`` chunks.

		:param int addr: virtual address
		:param int length: total length in bytes
		:param int block_size: optional block size
		:return: list of entropy values for each chunk
		:rtype: list(float)
		"""
		result = []
		if length == 0:
			return result
		if block_size == 0:
			block_size = length
		data = (ctypes.c_float * ((length//block_size) + 1))()
		length = core.BNGetEntropy(self.handle, addr, length, block_size, data)

		for i in range(0, length):
			result.append(float(data[i]))
		return result

	def get_modification(self, addr: int, length: Optional[int] = None) -> List[ModificationStatus]:
		"""
		``get_modification`` returns the modified bytes of up to ``length`` bytes from virtual address ``addr``, or if
		``length`` is None returns the ModificationStatus.

		:param int addr: virtual address to get modification from
		:param int length: optional length of modification
		:return: List of ModificationStatus values for each byte in range
		:rtype: List[ModificationStatus]
		"""
		if length is None:
			return [ModificationStatus(core.BNGetModification(self.handle, addr))]
		data = (ctypes.c_int * length)()
		length = core.BNGetModificationArray(self.handle, addr, data, length)
		return [ModificationStatus(a) for a in data[:length]]

	def get_next_valid_offset(self, addr: int) -> int:
		"""
		``get_next_valid_offset`` returns the next valid offset in the BinaryView starting from the given virtual address ``addr``.

		:param int addr: a virtual address to start checking from.
		:return: The minimum of the next valid offset in the BinaryView and the end address of the BinaryView
		:rtype: int
		"""
		return core.BNGetNextValidOffset(self.handle, addr)

	def is_valid_offset(self, addr: int) -> bool:
		"""
		``is_valid_offset`` checks if a virtual address ``addr`` is valid .

		:param int addr: a virtual address to be checked
		:return: True if the virtual address is valid, False if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsValidOffset(self.handle, addr)

	def is_offset_readable(self, addr: int) -> bool:
		"""
		``is_offset_readable`` checks if a virtual address ``addr`` is valid for reading.

		:param int addr: a virtual address to be checked
		:return: True if the virtual address is valid for reading, False if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetReadable(self.handle, addr)

	def is_offset_writable(self, addr: int) -> bool:
		"""
		``is_offset_writable`` checks if a virtual address ``addr`` is valid for writing.

		:param int addr: a virtual address to be checked
		:return: True if the virtual address is valid for writing, False if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetWritable(self.handle, addr)

	def is_offset_executable(self, addr: int) -> bool:
		"""
		``is_offset_executable`` checks if a virtual address ``addr`` is valid for executing.

		:param int addr: a virtual address to be checked
		:return: True if the virtual address is valid for executing, False if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetExecutable(self.handle, addr)

	def is_offset_code_semantics(self, addr: int) -> bool:
		"""
		``is_offset_code_semantics`` checks if a virtual address ``addr`` is semantically valid for code.

		:param int addr: a virtual address to be checked
		:return: True if the virtual address is valid for code semantics, False if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetCodeSemantics(self.handle, addr)

	def is_offset_extern_semantics(self, addr: int) -> bool:
		"""
		``is_offset_extern_semantics`` checks if a virtual address ``addr`` is semantically valid for external references.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid for external references, false if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetExternSemantics(self.handle, addr)

	def is_offset_writable_semantics(self, addr: int) -> bool:
		"""
		``is_offset_writable_semantics`` checks if a virtual address ``addr`` is semantically writable. Some sections
		may have writable permissions for linking purposes but can be treated as read-only for the purposes of
		analysis.

		:param int addr: a virtual address to be checked
		:return: True if the virtual address is valid for writing, False if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetWritableSemantics(self.handle, addr)

	def save(self, dest: Union['fileaccessor.FileAccessor', str]) -> bool:
		"""
		``save`` saves the original binary file to the provided destination ``dest`` along with any modifications.

		:param str dest: destination path and filename of file to be written
		:return: True on success, False on failure
		:rtype: bool
		"""
		if isinstance(dest, fileaccessor.FileAccessor):
			return core.BNSaveToFile(self.handle, dest._cb)
		return core.BNSaveToFilename(self.handle, str(dest))

	def register_notification(self, notify: BinaryDataNotification) -> None:
		"""
		`register_notification` enables the receipt of callbacks for various analysis events. A full
		list of callbacks is available in the :py:class:`BinaryDataNotification` class. If the
		`notification_barrier` is enabled, then it is triggered upon the initial call to
		`register_notification`. Subsequent calls for an already registered ``notify`` instance
		also trigger a `notification_barrier` callback.

		:param BinaryDataNotification notify: notify is a subclassed instance of :py:class:`BinaryDataNotification`.
		:rtype: None
		"""
		if notify in self._notifications:
			self._notifications[notify]._register()
			return
		cb = BinaryDataNotificationCallbacks(self, notify)
		cb._register()
		self._notifications[notify] = cb

	def unregister_notification(self, notify: BinaryDataNotification) -> None:
		"""
		`unregister_notification` unregisters the :py:class:`BinaryDataNotification` object passed to
		`register_notification`

		:param BinaryDataNotification notify: notify is a subclassed instance of :py:class:`BinaryDataNotification`.
		:rtype: None
		"""
		if notify in self._notifications:
			self._notifications[notify]._unregister()
			del self._notifications[notify]

	def add_function(self, addr: int, plat: Optional['_platform.Platform'] = None, auto_discovered: bool = False, func_type: Optional['_function.Function'] = None) -> Optional['_function.Function']:
		"""
		``add_function`` add a new function of the given ``plat`` at the virtual address ``addr``

		.. warning:: This function is used to create auto functions, often used when writing loaders, etc. Most users will want to use :py:func:`create_user_function` in their scripts.

		:param int addr: virtual address of the function to be added
		:param Platform plat: Platform for the function to be added
		:param auto_discovered: True if function was automatically discovered, False if created by user
		:param func_type: optional function type
		:rtype: None
		:Example:

			>>> bv.add_function(1)
			>>> bv.functions
			[<func: x86_64@0x1>]

		"""
		if self.platform is None and plat is None:
			raise Exception("Default platform not set in BinaryView")
		if plat is None:
			plat = self.platform
		if not isinstance(plat, _platform.Platform):
			raise ValueError("Provided platform is not of type `Platform`")

		if isinstance(func_type, _types.Type):
			func_type = func_type.handle
		elif func_type is not None:
			raise ValueError("Provided type is not of type `binaryninja.Type`")

		result = core.BNAddFunctionForAnalysis(self.handle, plat.handle, addr, auto_discovered, func_type)
		if result:
			return _function.Function(self, result)
		return None

	def add_entry_point(self, addr: int, plat: Optional['_platform.Platform'] = None) -> None:
		"""
		``add_entry_point`` adds a virtual address to start analysis from for a given plat.

		:param int addr: virtual address to start analysis from
		:param Platform plat: Platform for the entry point analysis
		:rtype: None
		:Example:
			>>> bv.add_entry_point(0xdeadbeef)
			>>>
		"""
		if self.platform is None and plat is None:
			raise Exception("Default platform not set in BinaryView")
		if plat is None:
			plat = self.platform
		if not isinstance(plat, _platform.Platform):
			raise ValueError("Provided platform is not of type `Platform`")
		core.BNAddEntryPointForAnalysis(self.handle, plat.handle, addr)

	def add_to_entry_functions(self, func: '_function.Function') -> None:
		"""
		``add_to_entry_functions`` adds a function to the `entry_functions` list.

		:param Function func: a Function object
		:rtype: None
		:Example:
			>>> bv.entry_functions
			[<func: x86@0x4014c8>, <func: x86@0x401618>]
			>>> bv.add_to_entry_functions(bv.get_function_at(0x4014da))
			>>> bv.entry_functions
			[<func: x86@0x4014c8>, <func: x86@0x401618>, <func: x86@0x4014da>]
		"""
		core.BNAddToEntryFunctions(self.handle, func.handle)

	def remove_function(self, func: '_function.Function', update_refs = False) -> None:
		"""
		``remove_function`` removes the function ``func`` from the list of functions

		.. warning:: This method should only be used when the function that is removed is expected to re-appear after any other analysis executes that could re-add it. Most users will want to use :py:func:`remove_user_function` in their scripts.

		:param Function func: a Function object.
		:param bool update_refs: automatically update other functions that were referenced
		:rtype: None
		:Example:

			>>> bv.functions
			[<func: x86_64@0x1>]
			>>> bv.remove_function(next(bv.functions))
			>>> bv.functions
			[]
		"""
		core.BNRemoveAnalysisFunction(self.handle, func.handle, update_refs)

	def create_user_function(self, addr: int, plat: Optional['_platform.Platform'] = None) \
			-> Optional['_function.Function']:
		"""
		``create_user_function`` add a new *user* function of the given ``plat`` at the virtual address ``addr``

		:param int addr: virtual address of the *user* function to be added
		:param Platform plat: Platform for the function to be added
		:rtype: None
		:Example:

			>>> bv.create_user_function(1)
			>>> bv.functions
			[<func: x86_64@0x1>]

		"""
		if plat is None:
			if self.platform is None:
				raise Exception("Attempting to call create_user_function with no specified platform")
			plat = self.platform
		func = core.BNCreateUserFunction(self.handle, plat.handle, addr)
		if func is None:
			return None
		return _function.Function(self, func)

	def remove_user_function(self, func: '_function.Function') -> None:
		"""
		``remove_user_function`` removes the function ``func`` from the list of functions as a user action.

		.. note:: This API will prevent the function from being re-created if any analysis later triggers that would re-add it, unlike :py:func:`remove_function`.

		:param Function func: a Function object.
		:rtype: None
		:Example:

			>>> bv.functions
			[<func: x86_64@0x1>]
			>>> bv.remove_user_function(next(bv.functions))
			>>> bv.functions
			[]
		"""
		core.BNRemoveUserFunction(self.handle, func.handle)

	def add_analysis_option(self, name: str) -> None:
		"""
		``add_analysis_option`` adds an analysis option. Analysis options elaborate the analysis phase. The user must
		start analysis by calling either :py:func:`update_analysis` or :py:func:`update_analysis_and_wait`.

		:param str name: name of the analysis option. Available options are: "linearsweep", and "signaturematcher".

		:rtype: None
		:Example:

			>>> bv.add_analysis_option("linearsweep")
			>>> bv.update_analysis_and_wait()
		"""
		core.BNAddAnalysisOption(self.handle, name)

	def has_initial_analysis(self) -> bool:
		"""
		``has_initial_analysis`` check for the presence of an initial analysis in this BinaryView.

		:return: True if the BinaryView has a valid initial analysis, False otherwise
		:rtype: bool
		"""
		return core.BNHasInitialAnalysis(self.handle)

	def set_analysis_hold(self, enable: bool) -> None:
		"""
		``set_analysis_hold`` control the analysis hold for this BinaryView. Enabling analysis hold defers all future
		analysis updates, therefore causing :py:func:`update_analysis` or :py:func:`update_analysis_and_wait` to take no action.

		:rtype: None
		"""
		core.BNSetAnalysisHold(self.handle, enable)

	def update_analysis(self) -> None:
		"""
		``update_analysis`` asynchronously starts the analysis running and returns immediately.
		An analysis update **must** be run after changes are made which could change analysis
		results such as adding functions.

		:rtype: None
		"""
		core.BNUpdateAnalysis(self.handle)

	def update_analysis_and_wait(self) -> None:
		"""
		``update_analysis_and_wait`` blocking call to update the analysis, this call returns when the analysis is
		complete. An analysis update **must** be run after changes are made which could change analysis results such as adding functions.

		:rtype: None
		"""
		core.BNUpdateAnalysisAndWait(self.handle)

	def abort_analysis(self) -> None:
		"""
		``abort_analysis`` will abort the currently running analysis.

		.. warning:: This method should be considered non-recoverable and generally only used when shutdown is imminent after stopping.

		:rtype: None
		"""
		core.BNAbortAnalysis(self.handle)

	def define_data_var(
	    self, addr: int, var_type: StringOrType, name: Optional[Union[str, '_types.CoreSymbol']] = None
	) -> None:
		"""
		``define_data_var`` defines a non-user data variable ``var_type`` at the virtual address ``addr``.

		:param int addr: virtual address to define the given data variable
		:param StringOrType var_type: type to be defined at the given virtual address
		:param Optional[Union[str, '_types.CoreSymbol']] name: Optionally additionally define a symbol at this location
		:rtype: None
		:Example:

			>>> t = bv.parse_type_string("int foo")
			>>> t
			(<type: int32_t>, 'foo')
			>>> bv.define_data_var(bv.entry_point, t[0])
			>>> bv.define_data_var(bv.entry_point + 4, "int", "foo")
			>>> bv.get_symbol_at(bv.entry_point + 4)
			<DataSymbol: "foo" @ 0x23950>
			>>> bv.get_data_var_at(bv.entry_point + 4)
			<var 0x23950: int32_t>
		"""

		if isinstance(var_type, str):
			(var_type, _) = self.parse_type_string(var_type)
		tc = var_type._to_core_struct()
		core.BNDefineDataVariable(self.handle, addr, tc)

		if name is not None:
			if isinstance(name, str):
				name = _types.Symbol(SymbolType.DataSymbol, addr, name)
			self.define_auto_symbol(name)

	def define_user_data_var(
	    self, addr: int, var_type: StringOrType, name: Optional[Union[str, '_types.CoreSymbol']] = None
	) -> Optional['DataVariable']:
		"""
		``define_user_data_var`` defines a user data variable ``var_type`` at the virtual address ``addr``.

		:param int addr: virtual address to define the given data variable
		:param binaryninja.Type var_type: type to be defined at the given virtual address
		:param Optional[Union[str, _types.CoreSymbol]] name: Optionally, additionally define a symbol at this same address
		:rtype: Optional[DataVariable]
		:Example:

			>>> t = bv.parse_type_string("int foo")
			>>> t
			(<type: int32_t>, 'foo')
			>>> bv.define_user_data_var(bv.entry_point, t[0])
			<var 0x2394c: int32_t>
			>>> bv.define_user_data_var(bv.entry_point + 4, "int", "foo")
			<var 0x23950: int32_t>
			>>> bv.get_symbol_at(bv.entry_point + 4)
			<DataSymbol: "foo" @ 0x23950>
			>>> bv.get_data_var_at(bv.entry_point + 4)
			<var 0x23950: int32_t>
		"""

		if isinstance(var_type, str):
			(var_type, _) = self.parse_type_string(var_type)
		tc = var_type._to_core_struct()
		core.BNDefineUserDataVariable(self.handle, addr, tc)

		if name is not None:
			if isinstance(name, str):
				name = _types.Symbol(SymbolType.DataSymbol, addr, name)
			self.define_user_symbol(name)

		return self.get_data_var_at(addr)

	def undefine_data_var(self, addr: int) -> None:
		"""
		``undefine_data_var`` removes the non-user data variable at the virtual address ``addr``.

		:param int addr: virtual address to define the data variable to be removed
		:rtype: None
		:Example:

			>>> bv.undefine_data_var(bv.entry_point)
			>>>
		"""
		core.BNUndefineDataVariable(self.handle, addr)

	def undefine_user_data_var(self, addr: int) -> None:
		"""
		``undefine_user_data_var`` removes the user data variable at the virtual address ``addr``.

		:param int addr: virtual address to define the data variable to be removed
		:rtype: None
		:Example:

			>>> bv.undefine_user_data_var(bv.entry_point)
			>>>
		"""
		core.BNUndefineUserDataVariable(self.handle, addr)

	def get_data_var_at(self, addr: int) -> Optional['DataVariable']:
		"""
		``get_data_var_at`` returns the data type at a given virtual address.

		:param int addr: virtual address to get the data type from
		:return: returns the DataVariable at the given virtual address, None on error
		:rtype: DataVariable
		:Example:

			>>> t = bv.parse_type_string("int foo")
			>>> bv.define_data_var(bv.entry_point, t[0])
			>>> bv.get_data_var_at(bv.entry_point)
			<var 0x100001174: int32_t>

		"""
		var = core.BNDataVariable()
		if not core.BNGetDataVariableAtAddress(self.handle, addr, var):
			return None
		result = DataVariable.from_core_struct(var, self)
		core.BNFreeDataVariable(var)
		return result

	def get_functions_containing(self, addr: int,
	                             plat: Optional['_platform.Platform'] = None) -> List['_function.Function']:
		"""
		``get_functions_containing`` returns a list of :py:class:`~binaryninja.function.Function` objects which contain the given address.

		:param int addr: virtual address to query.
		:rtype: list of :py:class:`~binaryninja.function.Function` objects
		"""
		count = ctypes.c_ulonglong(0)
		funcs = core.BNGetAnalysisFunctionsContainingAddress(self.handle, addr, count)
		assert funcs is not None, "core.BNGetAnalysisFunctionsContainingAddress returned None"
		result = []
		try:
			for i in range(0, count.value):
				result.append(_function.Function(self, core.BNNewFunctionReference(funcs[i])))
			if plat is not None:
				result = [func for func in result if func.platform == plat]
			return result
		finally:
			core.BNFreeFunctionList(funcs, count.value)

	def get_functions_by_name(
	    self, name: str, plat: Optional['_platform.Platform'] = None, ordered_filter: Optional[List[SymbolType]] = None
	) -> List['_function.Function']:
		"""``get_functions_by_name`` returns a list of :py:class:`~binaryninja.function.Function` objects
		function with a :py:class:`~binaryninja.types.Symbol` of ``name``.

		:param str name: name of the functions
		:param Platform plat: (optional) platform
		:param list(SymbolType) ordered_filter: (optional) an ordered filter based on SymbolType
		:return: returns a list of :py:class:`~binaryninja.function.Function` objects or an empty list
		:rtype: list(Function)
		:Example:

			>>> bv.get_functions_by_name("main")
			[<func: x86_64@0x1587>]
			>>>
		"""
		if ordered_filter is None:
			ordered_filter = [
			    SymbolType.FunctionSymbol, SymbolType.ImportedFunctionSymbol, SymbolType.LibraryFunctionSymbol
			]

		fns = []
		addresses = [sym.address for sym in self.get_symbols_by_name(name, ordered_filter=ordered_filter)]
		if len(addresses) == 0 and name.startswith("sub_"):
			try:
				addresses = [int(name[4:], 16)]
			except:
				addresses = []
		for address in addresses:
			for fn in self.get_functions_at(address):
				if fn.start == address:
					if plat is not None and fn.platform != plat:
						continue
					fns.append(fn)
		return fns

	def get_function_at(self, addr: int, plat: Optional['_platform.Platform'] = None) -> Optional['_function.Function']:
		"""
		``get_function_at`` gets a Function object for the function that starts at virtual address ``addr``:

		:param int addr: starting virtual address of the desired function
		:param Platform plat: platform of the desired function
		:return: returns a Function object or None for the function at the virtual address provided
		:rtype: Function
		:Example:

			>>> bv.get_function_at(bv.entry_point)
			<func: x86_64@0x100001174>
			>>>
		"""
		if plat is None:
			funcs = self.get_functions_at(addr)
			if not funcs:
				return None
			result = [func for func in funcs if (func.platform == self.platform)]
			if not result:
				result = funcs
			return result[0]
		else:
			func = core.BNGetAnalysisFunction(self.handle, plat.handle, addr)
			if func is None:
				return None
			return _function.Function(self, func)

	def get_functions_at(self, addr: int) -> List['_function.Function']:
		"""

		``get_functions_at`` get a list of :py:class:`~binaryninja.function.Function` objects (one for each valid platform) that start at the
		given virtual address. Binary Ninja does not limit the number of platforms in a given file thus there may be
		multiple functions defined from different architectures at the same location. This API allows you to query all
		of valid platforms.

		You may also be interested in :py:func:`get_functions_containing` which is useful for requesting all function
		that contain a given address

		:param int addr: virtual address of the desired Function object list.
		:return: a list of :py:class:`~binaryninja.function.Function` objects defined at the provided virtual address
		:rtype: list(Function)
		"""
		count = ctypes.c_ulonglong(0)
		funcs = core.BNGetAnalysisFunctionsForAddress(self.handle, addr, count)
		assert funcs is not None, "core.BNGetAnalysisFunctionsForAddress returned None"
		result = []
		try:
			for i in range(0, count.value):
				result.append(_function.Function(self, core.BNNewFunctionReference(funcs[i])))
			return result
		finally:
			core.BNFreeFunctionList(funcs, count.value)

	def get_recent_function_at(self, addr: int) -> Optional['_function.Function']:
		func = core.BNGetRecentAnalysisFunctionForAddress(self.handle, addr)
		if func is None:
			return None
		return _function.Function(self, func)

	def get_basic_blocks_at(self, addr: int) -> List['basicblock.BasicBlock']:
		"""
		``get_basic_blocks_at`` get a list of :py:class:`~binaryninja.basicblock.BasicBlock` objects which exist at the provided virtual address.

		:param int addr: virtual address of BasicBlock desired
		:return: a list of :py:class:`~binaryninja.basicblock.BasicBlock` objects
		:rtype: list(BasicBlock)
		"""
		count = ctypes.c_ulonglong(0)
		blocks = core.BNGetBasicBlocksForAddress(self.handle, addr, count)
		assert blocks is not None, "core.BNGetBasicBlocksForAddress returned None"
		result = []
		try:
			for i in range(0, count.value):
				block_handle = core.BNNewBasicBlockReference(blocks[i])
				assert block_handle is not None, "core.BNNewBasicBlockReference is None"
				result.append(basicblock.BasicBlock(block_handle, self))
			return result
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def get_basic_blocks_starting_at(self, addr: int) -> List['basicblock.BasicBlock']:
		"""
		``get_basic_blocks_starting_at`` get a list of :py:class:`~binaryninja.basicblock.BasicBlock` objects which start at the provided virtual address.

		:param int addr: virtual address of BasicBlock desired
		:return: a list of :py:class:`~binaryninja.basicblock.BasicBlock` objects
		:rtype: list(BasicBlock)
		"""
		count = ctypes.c_ulonglong(0)
		blocks = core.BNGetBasicBlocksStartingAtAddress(self.handle, addr, count)
		assert blocks is not None, "core.BNGetBasicBlocksStartingAtAddress returned None"
		result = []
		try:
			for i in range(0, count.value):
				block_handle = core.BNNewBasicBlockReference(blocks[i])
				assert block_handle is not None, "core.BNNewBasicBlockReference returned None"
				result.append(basicblock.BasicBlock(block_handle, self))
			return result
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def get_recent_basic_block_at(self, addr: int) -> Optional['basicblock.BasicBlock']:
		block = core.BNGetRecentBasicBlockForAddress(self.handle, addr)
		if block is None:
			return None
		return basicblock.BasicBlock(block, self)

	def get_code_refs(self, addr: int, length: Optional[int] = None) -> Generator['ReferenceSource', None, None]:
		"""
		``get_code_refs`` returns a generator of :py:class:`~binaryninja.binaryview.ReferenceSource` objects (xrefs or cross-references) that point to the provided virtual address.
		This function returns both autoanalysis ("auto") and user-specified ("user") xrefs.
		To add a user-specified reference, see :py:func:`~binaryninja.function.Function.add_user_code_ref`.

		The related :py:func:`get_data_refs` is used to find data references to an address unlike this API which returns references that exist in code.

		.. note:: Note that `get_code_refs` returns xrefs to code that references the address being queried. \
		`get_data_refs` on the other hand returns references that exist in data (pointers in global variables for example). \
		The related :py:func:`get_code_refs_from` looks for references that are outgoing from the queried address to other locations.

		:param int addr: virtual address to query for references
		:param int length: optional length of query
		:return: A generator of References for the given virtual address
		:rtype: Generator[ReferenceSource, None, None]
		:Example:

			>>> bv.get_code_refs(here)
			[<ref: x86@0x4165ff>]
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		if length is None:
			refs = core.BNGetCodeReferences(self.handle, addr, count)
			assert refs is not None, "core.BNGetCodeReferences returned None"
		else:
			refs = core.BNGetCodeReferencesInRange(self.handle, addr, length, count)
			assert refs is not None, "core.BNGetCodeReferencesInRange returned None"

		try:
			for i in range(0, count.value):
				yield ReferenceSource._from_core_struct(self, refs[i])
		finally:
			core.BNFreeCodeReferences(refs, count.value)

	def get_code_refs_from(
	    self, addr: int, func: Optional['_function.Function'] = None,
	    arch: Optional['architecture.Architecture'] = None, length: Optional[int] = None
	) -> List[int]:
		"""
		``get_code_refs_from`` returns a list of virtual addresses referenced by code in the function ``func``,
		of the architecture ``arch``, and at the address ``addr``. If no function is specified, references from
		all functions and containing the address will be returned. If no architecture is specified, the
		architecture of the function will be used.
		This function returns both autoanalysis ("auto") and user-specified ("user") xrefs.
		To add a user-specified reference, see :py:func:`~binaryninja.function.Function.add_user_code_ref`.

		:param int addr: virtual address to query for references
		:param int length: optional length of query
		:param Architecture arch: optional architecture of query
		:return: list of integers
		:rtype: list(integer)
		"""

		result = []
		funcs = self.get_functions_containing(addr) if func is None else [func]
		if not funcs:
			return []
		for src_func in funcs:
			src_arch = src_func.arch if arch is None else arch
			assert src_arch is not None
			ref_src = core.BNReferenceSource(src_func.handle, src_arch.handle, addr)
			count = ctypes.c_ulonglong(0)
			if length is None:
				refs = core.BNGetCodeReferencesFrom(self.handle, ref_src, count)
				assert refs is not None, "core.BNGetCodeReferencesFrom returned None"
			else:
				refs = core.BNGetCodeReferencesFromInRange(self.handle, ref_src, length, count)
				assert refs is not None, "core.BNGetCodeReferencesFromInRange returned None"
			for i in range(0, count.value):
				result.append(refs[i])
			core.BNFreeAddressList(refs)
		return result

	def get_data_refs(self, addr: int, length: Optional[int] = None) -> Generator[int, None, None]:
		"""
		``get_data_refs`` returns a list of virtual addresses of _data_ (not code) which references ``addr``, optionally specifying
		a length. When ``length`` is set ``get_data_refs`` returns the data which references in the range ``addr``-``addr``+``length``.
		This function returns both autoanalysis ("auto") and user-specified ("user") xrefs. To add a user-specified
		reference, see :py:func:`add_user_data_ref`.

		.. warning:: If you're looking at this API, please double check that you don't mean to use :py:func:`get_code_refs` instead. \
		`get_code_refs` returns references from code to the specified address while this API returns references from data \
		(pointers in global variables for example). Also, note there exists :py:func:`get_data_refs_from`.

		:param int addr: virtual address to query for references
		:param int length: optional length of query
		:return: list of integers
		:rtype: list(integer)

		:Example:

			>>> bv.get_data_refs(here)
			[4203812]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		if length is None:
			refs = core.BNGetDataReferences(self.handle, addr, count)
			assert refs is not None, "core.BNGetDataReferences returned None"
		else:
			refs = core.BNGetDataReferencesInRange(self.handle, addr, length, count)
			assert refs is not None, "core.BNGetDataReferencesInRange returned None"

		try:
			for i in range(0, count.value):
				yield refs[i]
		finally:
			core.BNFreeDataReferences(refs)

	def get_data_refs_from(self, addr: int, length: Optional[int] = None) -> Generator[int, None, None]:
		"""
		``get_data_refs_from`` returns a list of virtual addresses referenced by the address ``addr``. Optionally specifying
		a length. When ``length`` is set ``get_data_refs_from`` returns the data referenced in the range ``addr``-``addr``+``length``.
		This function returns both autoanalysis ("auto") and user-specified ("user") xrefs. To add a user-specified
		reference, see :py:func:`add_user_data_ref`. Also, note there exists :py:func:`get_data_refs`.

		:param int addr: virtual address to query for references
		:param int length: optional length of query
		:return: list of integers
		:rtype: list(integer)

		:Example:

			>>> bv.get_data_refs_from(here)
			[4200327]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		if length is None:
			refs = core.BNGetDataReferencesFrom(self.handle, addr, count)
			assert refs is not None, "core.BNGetDataReferencesFrom returned None"
		else:
			refs = core.BNGetDataReferencesFromInRange(self.handle, addr, length, count)
			assert refs is not None, "core.BNGetDataReferencesFromInRange returned None"

		try:
			for i in range(0, count.value):
				yield refs[i]
		finally:
			core.BNFreeDataReferences(refs)

	def get_code_refs_for_type(self, name: str) -> Generator[ReferenceSource, None, None]:
		"""
		``get_code_refs_for_type`` returns a Generator[ReferenceSource] objects (xrefs or cross-references) that reference the provided QualifiedName.

		:param QualifiedName name: name of type to query for references
		:return: List of References for the given type
		:rtype: list(ReferenceSource)
		:Example:

			>>> bv.get_code_refs_for_type('A')
			[<ref: x86@0x4165ff>]
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetCodeReferencesForType(self.handle, _name, count)
		assert refs is not None, "core.BNGetCodeReferencesForType returned None"

		try:
			for i in range(0, count.value):
				yield ReferenceSource._from_core_struct(self, refs[i])
		finally:
			core.BNFreeCodeReferences(refs, count.value)

	def get_code_refs_for_type_field(self, name: str,
	                                 offset: int) -> Generator['_types.TypeFieldReference', None, None]:
		"""
		``get_code_refs_for_type`` returns a Generator[TypeFieldReference] objects (xrefs or cross-references) that reference the provided type field.

		:param QualifiedName name: name of type to query for references
		:param int offset: offset of the field, relative to the type
		:return: Generator of References for the given type
		:rtype: Generator[TypeFieldReference]
		:Example:

			>>> bv.get_code_refs_for_type_field('A', 0x8)
			[<ref: x86@0x4165ff>]
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetCodeReferencesForTypeField(self.handle, _name, offset, count)
		assert refs is not None, "core.BNGetCodeReferencesForTypeField returned None"

		try:
			for i in range(0, count.value):
				if refs[i].func:
					func = _function.Function(self, core.BNNewFunctionReference(refs[i].func))
				else:
					func = None
				if refs[i].arch:
					arch = architecture.CoreArchitecture._from_cache(refs[i].arch)
				else:
					arch = None
				addr = refs[i].addr
				size = refs[i].size
				typeObj = None
				if refs[i].incomingType.type:
					typeObj = _types.Type.create(
					    core.BNNewTypeReference(refs[i].incomingType.type), confidence=refs[i].incomingType.confidence
					)
				yield _types.TypeFieldReference(func, arch, addr, size, typeObj)
		finally:
			core.BNFreeTypeFieldReferences(refs, count.value)

	def get_data_refs_for_type(self, name: str) -> Generator[int, None, None]:
		"""
		``get_data_refs_for_type`` returns a list of virtual addresses of data which references the type ``name``.
		Note, the returned addresses are the actual start of the queried type. For example, suppose there is a DataVariable
		at 0x1000 that has type A, and type A contains type B at offset 0x10. Then `get_data_refs_for_type('B')` will
		return 0x1010 for it.

		:param QualifiedName name: name of type to query for references
		:return: list of integers
		:rtype: list(integer)
		:Example:

			>>> bv.get_data_refs_for_type('A')
			[4203812]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetDataReferencesForType(self.handle, _name, count)
		assert refs is not None, "core.BNGetDataReferencesForType returned None"

		try:
			for i in range(0, count.value):
				yield refs[i]
		finally:
			core.BNFreeDataReferences(refs)

	def get_data_refs_for_type_field(self, name: '_types.QualifiedNameType', offset: int) -> List[int]:
		"""
		``get_data_refs_for_type_field`` returns a list of virtual addresses of data which references the type ``name``.
		Note, the returned addresses are the actual start of the queried type field. For example, suppose there is a
		DataVariable at 0x1000 that has type A, and type A contains type B at offset 0x10.
		Then `get_data_refs_for_type_field('B', 0x8)` will return 0x1018 for it.

		:param QualifiedName name: name of type to query for references
		:param int offset: offset of the field, relative to the type
		:return: list of integers
		:rtype: list(integer)
		:Example:

			>>> bv.get_data_refs_for_type_field('A', 0x8)
			[4203812]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetDataReferencesForTypeField(self.handle, _name, offset, count)
		assert refs is not None, "core.BNGetDataReferencesForTypeField returned None"

		result = []
		try:
			for i in range(0, count.value):
				result.append(refs[i])
			return result
		finally:
			core.BNFreeDataReferences(refs)

	def get_data_refs_from_for_type_field(self, name: '_types.QualifiedNameType', offset: int) -> List[int]:
		"""
		``get_data_refs_from_for_type_field`` returns a list of virtual addresses of data which are referenced by the type ``name``.

		Only data referenced by structures with the ``__data_var_refs`` attribute are included.

		:param QualifiedName name: name of type to query for references
		:param int offset: offset of the field, relative to the type
		:return: list of integers
		:rtype: list(integer)
		:Example:

			>>> bv.get_data_refs_from_for_type_field('A', 0x8)
			[4203812]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetDataReferencesFromForTypeField(self.handle, _name, offset, count)
		assert refs is not None, "core.BNGetDataReferencesFromForTypeField returned None"

		result = []
		try:
			for i in range(0, count.value):
				result.append(refs[i])
			return result
		finally:
			core.BNFreeDataReferences(refs)

	def get_type_refs_for_type(self, name: '_types.QualifiedNameType') -> List['_types.TypeReferenceSource']:
		"""
		``get_type_refs_for_type`` returns a list of TypeReferenceSource objects (xrefs or cross-references) that reference the provided QualifiedName.

		:param QualifiedName name: name of type to query for references
		:return: List of references for the given type
		:rtype: list(TypeReferenceSource)
		:Example:

			>>> bv.get_type_refs_for_type('A')
			['<type D, offset 0x8, direct>', '<type C, offset 0x10, indirect>']
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetTypeReferencesForType(self.handle, _name, count)
		assert refs is not None, "core.BNGetTypeReferencesForType returned None"

		result = []
		try:
			for i in range(0, count.value):
				type_field = _types.TypeReferenceSource(
				    _types.QualifiedName._from_core_struct(refs[i].name), refs[i].offset, refs[i].type
				)
				result.append(type_field)
			return result
		finally:
			core.BNFreeTypeReferences(refs, count.value)

	def get_type_refs_for_type_field(self, name: '_types.QualifiedNameType',
	                                 offset: int) -> List['_types.TypeReferenceSource']:
		"""
		``get_type_refs_for_type`` returns a list of TypeReferenceSource objects (xrefs or cross-references) that reference the provided type field.

		:param QualifiedName name: name of type to query for references
		:param int offset: offset of the field, relative to the type
		:return: List of references for the given type
		:rtype: list(TypeReferenceSource)
		:Example:

			>>> bv.get_type_refs_for_type_field('A', 0x8)
			['<type D, offset 0x8, direct>', '<type C, offset 0x10, indirect>']
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetTypeReferencesForTypeField(self.handle, _name, offset, count)
		assert refs is not None, "core.BNGetTypeReferencesForTypeField returned None"

		result = []
		try:
			for i in range(0, count.value):
				type_field = _types.TypeReferenceSource(
				    _types.QualifiedName._from_core_struct(refs[i].name), refs[i].offset, refs[i].type
				)
				result.append(type_field)
			return result
		finally:
			core.BNFreeTypeReferences(refs, count.value)

	def get_code_refs_for_type_from(
	    self, addr: int, func: Optional['_function.Function'] = None,
	    arch: Optional['architecture.Architecture'] = None, length: Optional[int] = None
	) -> List['_types.TypeReferenceSource']:
		"""
		``get_code_refs_for_type_from`` returns a list of types referenced by code in the function ``func``,
		of the architecture ``arch``, and at the address ``addr``. If no function is specified, references from
		all functions and containing the address will be returned. If no architecture is specified, the
		architecture of the function will be used.

		:param int addr: virtual address to query for references
		:param int length: optional length of query
		:return: list of references
		:rtype: list(TypeReferenceSource)
		"""
		result = []
		funcs = self.get_functions_containing(addr) if func is None else [func]
		if not funcs:
			return []
		for src_func in funcs:
			src_arch = src_func.arch if arch is None else arch
			assert src_arch is not None
			ref_src = core.BNReferenceSource(src_func.handle, src_arch.handle, addr)
			count = ctypes.c_ulonglong(0)
			if length is None:
				refs = core.BNGetCodeReferencesForTypeFrom(self.handle, ref_src, count)
				assert refs is not None, "core.BNGetCodeReferencesForTypeFrom returned None"
			else:
				refs = core.BNGetCodeReferencesForTypeFromInRange(self.handle, ref_src, length, count)
				assert refs is not None, "core.BNGetCodeReferencesForTypeFromInRange returned None"
			try:
				for i in range(0, count.value):
					type_field = _types.TypeReferenceSource(
					    _types.QualifiedName._from_core_struct(refs[i].name), refs[i].offset, refs[i].type
					)
					result.append(type_field)
			finally:
				core.BNFreeTypeReferences(refs, count.value)
		return result

	def get_code_refs_for_type_fields_from(
	    self, addr: int, func: Optional['_function.Function'] = None,
	    arch: Optional['architecture.Architecture'] = None, length: Optional[int] = None
	) -> List['_types.TypeReferenceSource']:
		"""
		``get_code_refs_for_type_fields_from`` returns a list of type fields referenced by code in the function ``func``,
		of the architecture ``arch``, and at the address ``addr``. If no function is specified, references from
		all functions and containing the address will be returned. If no architecture is specified, the
		architecture of the function will be used.

		:param int addr: virtual address to query for references
		:param int length: optional length of query
		:return: list of references
		:rtype: list(TypeReferenceSource)
		"""
		result = []
		funcs = self.get_functions_containing(addr) if func is None else [func]
		if not funcs:
			return []
		for src_func in funcs:
			src_arch = src_func.arch if arch is None else arch
			assert src_arch is not None
			ref_src = core.BNReferenceSource(src_func.handle, src_arch.handle, addr)
			count = ctypes.c_ulonglong(0)
			if length is None:
				refs = core.BNGetCodeReferencesForTypeFieldsFrom(self.handle, ref_src, count)
				assert refs is not None, "core.BNGetCodeReferencesForTypeFieldsFrom returned None"
			else:
				refs = core.BNGetCodeReferencesForTypeFieldsFromInRange(self.handle, ref_src, length, count)
				assert refs is not None, "core.BNGetCodeReferencesForTypeFieldsFromInRange returned None"
			try:
				for i in range(0, count.value):
					type_field = _types.TypeReferenceSource(
					    _types.QualifiedName._from_core_struct(refs[i].name), refs[i].offset, refs[i].type
					)
					result.append(type_field)
			finally:
				core.BNFreeTypeReferences(refs, count.value)
		return result

	def add_user_data_ref(self, from_addr: int, to_addr: int) -> None:
		"""
		``add_user_data_ref`` adds a user-specified data cross-reference (xref) from the address ``from_addr`` to the address ``to_addr``.
		If the reference already exists, no action is performed. To remove the reference, use :py:func:`remove_user_data_ref`.

		:param int from_addr: the reference's source virtual address.
		:param int to_addr: the reference's destination virtual address.
		:rtype: None
		"""
		core.BNAddUserDataReference(self.handle, from_addr, to_addr)

	def remove_user_data_ref(self, from_addr: int, to_addr: int) -> None:
		"""
		``remove_user_data_ref`` removes a user-specified data cross-reference (xref) from the address ``from_addr`` to the address ``to_addr``.
		This function will only remove user-specified references, not ones generated during autoanalysis.
		If the reference does not exist, no action is performed.

		:param int from_addr: the reference's source virtual address.
		:param int to_addr: the reference's destination virtual address.
		:rtype: None
		"""
		core.BNRemoveUserDataReference(self.handle, from_addr, to_addr)

	def get_all_fields_referenced(self, name: '_types.QualifiedNameType') -> List[int]:
		"""
		``get_all_fields_referenced`` returns a list of offsets in the QualifiedName
		specified by name, which are referenced by code.

		:param QualifiedName name: name of type to query for references
		:return: List of offsets
		:rtype: list(integer)
		:Example:

			>>> bv.get_all_fields_referenced('A')
			[0, 8, 16, 24, 32, 40]
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetAllFieldsReferenced(self.handle, _name, count)
		assert refs is not None, "core.BNGetAllFieldsReferenced returned None"

		result = []
		try:
			for i in range(0, count.value):
				result.append(refs[i])
			return result
		finally:
			core.BNFreeDataReferences(refs)

	def get_all_sizes_referenced(self, name: '_types.QualifiedNameType') -> Mapping[int, List[int]]:
		"""
		``get_all_sizes_referenced`` returns a map from field offset to a list of sizes of
		the accesses to it.

		:param QualifiedName name: name of type to query for references
		:return: A map from field offset to the	size of the code accesses to it
		:rtype: map
		:Example:

			>>> bv.get_all_sizes_referenced('B')
			{0: [1, 8], 8: [8], 16: [1, 8]}
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetAllSizesReferenced(self.handle, _name, count)
		assert refs is not None, "core.BNGetAllSizesReferenced returned None"
		result: Mapping[int, List[int]] = {}
		try:
			for i in range(0, count.value):
				result[refs[i].offset] = []
				for j in range(0, refs[i].count):
					result[refs[i].offset].append(refs[i].sizes[j])
			return result
		finally:
			core.BNFreeTypeFieldReferenceSizeInfo(refs, count.value)

	def get_all_types_referenced(self, name: '_types.QualifiedNameType') -> Mapping[int, List['_types.Type']]:
		"""
		``get_all_types_referenced`` returns a map from field offset to a list of incoming types written to the specified type.

		:param QualifiedName name: name of type to query for references
		:return: A map from field offset to a list of incoming types written to it
		:rtype: map
		:Example:

			>>> bv.get_all_types_referenced('B')
			{0: [<type: char, 0% confidence>], 8: [<type: int64_t, 0% confidence>],
			16: [<type: char, 0% confidence>, <type: bool>]}
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetAllTypesReferenced(self.handle, _name, count)
		assert refs is not None, "core.BNGetAllTypesReferenced returned None"

		result: Mapping[int, List['_types.Type']] = {}
		try:
			for i in range(0, count.value):
				result[refs[i].offset] = []
				for j in range(0, refs[i].count):
					typeObj = _types.Type.create(
					    core.BNNewTypeReference(refs[i].types[j].type), self.platform, refs[i].types[j].confidence
					)
					result[refs[i].offset].append(typeObj)
			return result
		finally:
			core.BNFreeTypeFieldReferenceTypeInfo(refs, count.value)

	def get_sizes_referenced(self, name: '_types.QualifiedNameType', offset: int) -> List[int]:
		"""
		``get_sizes_referenced`` returns a list of access sizes to the specified type.

		:param QualifiedName name: name of type to query for references
		:param int offset: offset of the field
		:return: a list of sizes of the accesses to it.
		:rtype: list
		:Example:

			>>> bv.get_sizes_referenced('B', 16)
			[1, 8]
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetSizesReferenced(self.handle, _name, offset, count)
		assert refs is not None, "core.BNGetSizesReferenced returned None"

		result = []
		try:
			for i in range(0, count.value):
				result.append(refs[i])
			return result
		finally:
			core.BNFreeTypeFieldReferenceSizes(refs, count.value)

	def get_types_referenced(self, name: '_types.QualifiedName', offset: int) -> List['_types.Type']:
		"""
		``get_types_referenced`` returns a list of types related to the type field access.

		:param QualifiedName name: name of type to query for references
		:param int offset: offset of the field
		:return: a list of types related to the type field access.
		:rtype: list
		:Example:

			>>> bv.get_types_referenced('B', 0x10)
			[<type: bool>, <type: char, 0% confidence>]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		_name = _types.QualifiedName(name)._to_core_struct()
		refs = core.BNGetTypesReferenced(self.handle, _name, offset, count)
		assert refs is not None, "core.BNGetTypesReferenced returned None"
		try:
			result = []
			for i in range(0, count.value):
				typeObj = _types.Type.create(core.BNNewTypeReference(refs[i].type), confidence=refs[i].confidence)
				result.append(typeObj)
			return result
		finally:
			core.BNFreeTypeFieldReferenceTypes(refs, count.value)

	def get_outgoing_direct_type_references(self, name: '_types.QualifiedNameType') -> List['_types.QualifiedName']:
		qname = _types.QualifiedName(name)
		_qname = qname._to_core_struct()
		count = ctypes.c_ulonglong(0)
		_result = core.BNGetOutgoingDirectTypeReferences(self.handle, _qname, count)
		assert _result is not None, "core.BNGetOutgoingDirectTypeReferences returned None"
		try:
			result = []
			for i in range(0, count.value):
				result_name = _types.QualifiedName._from_core_struct(_result[i])
				result.append(result_name)
			return result
		finally:
			core.BNFreeTypeNameList(_result, count.value)

	def get_outgoing_recursive_type_references(self, names: Union['_types.QualifiedNameType', List['_types.QualifiedNameType']]) -> List['_types.QualifiedName']:
		qnames = []
		if isinstance(names, list):
			for name in names:
				qnames.append(_types.QualifiedName(name))
		else:
			qnames.append(_types.QualifiedName(names))
		_qnames = (core.BNQualifiedName * len(qnames))()
		for i, qname in enumerate(qnames):
			_qnames[i] = qname._to_core_struct()
		count = ctypes.c_ulonglong(0)
		_result = core.BNGetOutgoingRecursiveTypeReferences(self.handle, _qnames, len(qnames), count)
		assert _result is not None, "core.BNGetOutgoingRecursiveTypeReferences returned None"
		try:
			result = []
			for i in range(0, count.value):
				result_name = _types.QualifiedName._from_core_struct(_result[i])
				result.append(result_name)
			return result
		finally:
			core.BNFreeTypeNameList(_result, count.value)

	def get_incoming_direct_type_references(self, name: '_types.QualifiedNameType') -> List['_types.QualifiedName']:
		qname = _types.QualifiedName(name)
		_qname = qname._to_core_struct()
		count = ctypes.c_ulonglong(0)
		_result = core.BNGetIncomingDirectTypeReferences(self.handle, _qname, count)
		assert _result is not None, "core.BNGetIncomingDirectTypeReferences returned None"
		try:
			result = []
			for i in range(0, count.value):
				result_name = _types.QualifiedName._from_core_struct(_result[i])
				result.append(result_name)
			return result
		finally:
			core.BNFreeTypeNameList(_result, count.value)

	def get_incoming_recursive_type_references(self, names: Union['_types.QualifiedNameType', List['_types.QualifiedNameType']]) -> List['_types.QualifiedName']:
		qnames = []
		if isinstance(names, list):
			for name in names:
				qnames.append(_types.QualifiedName(name))
		else:
			qnames.append(_types.QualifiedName(names))
		_qnames = (core.BNQualifiedName * len(qnames))()
		for i, qname in enumerate(qnames):
			_qnames[i] = qname._to_core_struct()
		count = ctypes.c_ulonglong(0)
		_result = core.BNGetIncomingRecursiveTypeReferences(self.handle, _qnames, len(qnames), count)
		assert _result is not None, "core.BNGetIncomingRecursiveTypeReferences returned None"
		try:
			result = []
			for i in range(0, count.value):
				result_name = _types.QualifiedName._from_core_struct(_result[i])
				result.append(result_name)
			return result
		finally:
			core.BNFreeTypeNameList(_result, count.value)

	def create_structure_from_offset_access(self, name: '_types.QualifiedName') -> '_types.StructureType':
		newMemberAdded = ctypes.c_bool(False)
		_name = _types.QualifiedName(name)._to_core_struct()
		struct = core.BNCreateStructureFromOffsetAccess(self.handle, _name, newMemberAdded)
		if struct is None:
			raise Exception("BNCreateStructureFromOffsetAccess failed to create struct from offsets")
		return _types.StructureType.from_core_struct(struct)

	def create_structure_member_from_access(self, name: '_types.QualifiedName', offset: int) -> '_types.Type':
		_name = _types.QualifiedName(name)._to_core_struct()
		result = core.BNCreateStructureMemberFromAccess(self.handle, _name, offset)
		if not result.type:
			raise Exception("BNCreateStructureMemberFromAccess failed to create struct member offsets")

		return _types.Type.create(result.type, confidence=result.confidence)

	def add_expression_parser_magic_value(self, name: str, value: int) -> None:
		"""
		Add a magic value to the expression parser.

		If the magic value already exists, its value gets updated.
		The magic value can be used in the expression by a `$` followed by its name, e.g., `$foobar`.
		It is optional to include the `$` when calling this function, i.e., calling with `foobar` and `$foobar`
		has the same effect.

		:param str name: name for the magic value to add or update
		:param int value: value for the magic value
		:return:
		"""
		core.BNAddExpressionParserMagicValue(self.handle, name, value)

	def remove_expression_parser_magic_value(self, name: str) -> None:
		"""
		Remove a magic value from the expression parser.

		If the magic value gets referenced after removal, an error will occur during the parsing.

		:param str name: name for the magic value to remove
		:return:
		"""
		core.BNRemoveExpressionParserMagicValue(self.handle, name)

	def add_expression_parser_magic_values(self, names: List[str], values: List[int]) -> None:
		"""
		Add a list of magic value to the expression parser.

		The list `names` and `values` must have the same size. The ith name in the `names` will correspond to
		the ith value in the `values`.

		If a magic value already exists, its value gets updated.
		The magic value can be used in the expression by a `$` followed by its name, e.g., `$foobar`.
		It is optional to include the `$` when calling this function, i.e., calling with `foobar` and `$foobar`
		has the same effect.

		:param list(str) names: names for the magic values to add or update
		:param list(int) values: value for the magic values
		:return:
		"""
		if len(names) == 0 or len(values) == 0 or (not len(names) == len(values)):
			return

		names_buf = (ctypes.c_char_p * len(names))()
		for i in range(0, len(names)):
			names_buf[i] = names[i].encode('charmap')

		values_buf = (ctypes.c_ulonglong * len(values))()
		for i in range(0, len(values)):
			values_buf[i] = values[i]

		core.BNAddExpressionParserMagicValues(self.handle, names_buf, values_buf, len(names))

	def remove_expression_parser_magic_values(self, names: List[str]) -> None:
		"""
		Remove a list of magic value from the expression parser

		If any of the magic values gets referenced after removal, an error will occur during the parsing.

		:param list(str) names: names for the magic value to remove
		:return:
		"""
		if len(names) == 0:
			return

		names_buf = (ctypes.c_char_p * len(names))()
		for i in range(0, len(names)):
			names_buf[i] = names[i].encode('charmap')

		core.BNRemoveExpressionParserMagicValues(self.handle, names_buf, len(names))

	def get_expression_parser_magic_value(self, name: str) -> Optional[int]:
		"""
		Get the value of an expression parser magic value

		If the queried magic value exists, the function returns true and the magic value is returned in `value`.
		If the queried magic value does not exist, the function returns None.

		:param name: name for the magic value to query
		:return:
		"""
		result = ctypes.c_ulonglong()
		if not core.BNGetExpressionParserMagicValue(self.handle, name, result):
			return None

		return result.value

	def get_callers(self, addr: int) -> Generator[ReferenceSource, None, None]:
		"""
		``get_callers`` returns a list of ReferenceSource objects (xrefs or cross-references) that call the provided virtual address.
		In this case, tail calls, jumps, and ordinary calls are considered.

		:param int addr: virtual address of callee to query for callers
		:return: List of References that call the given virtual address
		:rtype: list(ReferenceSource)
		:Example:

			>>> bv.get_callers(here)
			[<ref: x86@0x4165ff>]
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		refs = core.BNGetCallers(self.handle, addr, count)
		assert refs is not None, "core.BNGetCallers returned None"
		try:
			for i in range(0, count.value):
				yield ReferenceSource._from_core_struct(self, refs[i])
		finally:
			core.BNFreeCodeReferences(refs, count.value)

	def get_callees(self, addr: int, func: Optional['_function.Function'] = None,
	                arch: Optional['architecture.Architecture'] = None) -> List[int]:
		"""
		``get_callees`` returns a list of virtual addresses called by the call site in the function ``func``,
		of the architecture ``arch``, and at the address ``addr``. If no function is specified, call sites from
		all functions and containing the address will be considered. If no architecture is specified, the
		architecture of the function will be used.

		:param int addr: virtual address of the call site to query for callees
		:param Function func: (optional) the function that the call site belongs to
		:param Architecture func: (optional) the architecture of the call site
		:return: list of integers
		:rtype: list(integer)
		"""

		result = []
		funcs = self.get_functions_containing(addr) if func is None else [func]
		if not funcs:
			return []
		for src_func in funcs:
			src_arch = src_func.arch if arch is None else arch
			assert src_arch is not None
			ref_src = core.BNReferenceSource(src_func.handle, src_arch.handle, addr)
			count = ctypes.c_ulonglong(0)
			refs = core.BNGetCallees(self.handle, ref_src, count)
			assert refs is not None, "core.BNGetCallees returned None"
			try:
				for i in range(0, count.value):
					result.append(refs[i])
			finally:
				core.BNFreeAddressList(refs)
		return result

	def get_symbol_at(self, addr: int, namespace: '_types.NameSpaceType' = None) -> Optional['_types.CoreSymbol']:
		"""
		``get_symbol_at`` returns the Symbol at the provided virtual address.

		:param addr: virtual address to query for symbol
		:param namespace: (optional) the namespace of the symbols to retrieve
		:return: CoreSymbol for the given virtual address
		:rtype: CoreSymbol
		:Example:

			>>> bv.get_symbol_at(bv.entry_point)
			<FunctionSymbol: "_start" @ 0x100001174>
			>>>
		"""
		_namespace = _types.NameSpace.get_core_struct(namespace)
		sym = core.BNGetSymbolByAddress(self.handle, addr, _namespace)
		if sym is None:
			return None
		return _types.CoreSymbol(sym)

	def get_symbols_by_raw_name(self, name: str, namespace: '_types.NameSpaceType' = None) -> List['_types.CoreSymbol']:
		_namespace = _types.NameSpace.get_core_struct(namespace)
		count = ctypes.c_ulonglong(0)
		syms = core.BNGetSymbolsByRawName(self.handle, name, count, _namespace)
		assert syms is not None, "core.BNGetSymbolsByRawName returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewSymbolReference(syms[i])
				assert handle is not None, "core.BNNewSymbolReference returned None"
				result.append(_types.CoreSymbol(handle))
			return result
		finally:
			core.BNFreeSymbolList(syms, count.value)

	def get_symbol_by_raw_name(self, name: str,
	                           namespace: '_types.NameSpaceType' = None) -> Optional['_types.CoreSymbol']:
		"""
		``get_symbol_by_raw_name`` retrieves a Symbol object for the given raw (mangled) name.

		:param name: raw (mangled) name of Symbol to be retrieved
		:param namespace: (optional) the namespace to search for the given symbol
		:return: CoreSymbol object corresponding to the provided raw name
		:rtype: CoreSymbol
		:Example:

			>>> bv.get_symbol_by_raw_name('?testf@Foobar@@SA?AW4foo@1@W421@@Z')
			<FunctionSymbol: "public: static enum Foobar::foo __cdecl Foobar::testf(enum Foobar::foo)" @ 0x10001100>
			>>>
		"""
		_namespace = _types.NameSpace.get_core_struct(namespace)
		sym = core.BNGetSymbolByRawName(self.handle, name, _namespace)
		if sym is None:
			return None
		return _types.CoreSymbol(sym)

	def get_symbols_by_name(
	    self, name: str, namespace: '_types.NameSpaceType' = None, ordered_filter: Optional[List[SymbolType]] = None
	) -> List['_types.CoreSymbol']:
		"""
		``get_symbols_by_name`` retrieves a list of Symbol objects for the given symbol name and ordered filter

		:param name: name of Symbol object to be retrieved
		:param namespace: (optional) the namespace to search for the given symbol
		:param namespace: (optional) the namespace to search for the given symbol
		:param ordered_filter: (optional) an ordered filter based on SymbolType
		:return: Symbol object corresponding to the provided name
		:rtype: Symbol
		:Example:

			>>> bv.get_symbols_by_name('?testf@Foobar@@SA?AW4foo@1@W421@@Z')
			[<FunctionSymbol: "public: static enum Foobar::foo __cdecl Foobar::testf(enum Foobar::foo)" @ 0x10001100>]
			>>>
		"""
		if ordered_filter is None:
			ordered_filter = [
			    SymbolType.FunctionSymbol, SymbolType.ImportedFunctionSymbol, SymbolType.LibraryFunctionSymbol, SymbolType.SymbolicFunctionSymbol,
			    SymbolType.DataSymbol, SymbolType.ImportedDataSymbol, SymbolType.ImportAddressSymbol,
			    SymbolType.ExternalSymbol, SymbolType.LocalLabelSymbol
			]

		_namespace = _types.NameSpace.get_core_struct(namespace)
		count = ctypes.c_ulonglong(0)
		syms = core.BNGetSymbolsByName(self.handle, name, count, _namespace)
		assert syms is not None, "core.BNGetSymbolsByName returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewSymbolReference(syms[i])
				assert handle is not None, "core.BNNewSymbolReference returned None"
				result.append(_types.CoreSymbol(handle))
			result = sorted(
			    filter(lambda sym: sym.type in ordered_filter, result), key=lambda sym: ordered_filter.index(sym.type)
			)
			return result
		finally:
			core.BNFreeSymbolList(syms, count.value)

	def get_symbols(
	    self, start: Optional[int] = None, length: Optional[int] = None, namespace: '_types.NameSpaceType' = None
	) -> List['_types.CoreSymbol']:
		"""
		``get_symbols`` retrieves the list of all Symbol objects in the optionally provided range.

		:param start: optional start virtual address
		:param length: optional length
		:return: list of all Symbol objects, or those Symbol objects in the range of ``start``-``start+length``
		:rtype: list(Symbol)
		:Example:

			>>> bv.get_symbols(0x1000200c, 1)
			[<ImportAddressSymbol: "KERNEL32!IsProcessorFeaturePresent" @ 0x1000200c>]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		_namespace = _types.NameSpace.get_core_struct(namespace)
		if start is None:
			syms = core.BNGetSymbols(self.handle, count, _namespace)
			assert syms is not None, "core.BNGetSymbols returned None"
		else:
			if length is None:
				length = 1
			syms = core.BNGetSymbolsInRange(self.handle, start, length, count, namespace)
			assert syms is not None, "core.BNGetSymbolsInRange returned None"
		result = []
		try:
			for i in range(0, count.value):
				sym_handle = core.BNNewSymbolReference(syms[i])
				assert sym_handle is not None, "core.BNNewSymbolReference returned None"
				result.append(_types.CoreSymbol(sym_handle))
			return result
		finally:
			core.BNFreeSymbolList(syms, count.value)

	def get_symbols_of_type(
	    self, sym_type: SymbolType, start: Optional[int] = None, length: Optional[int] = None,
	    namespace: '_types.NameSpaceType' = None
	) -> List['_types.CoreSymbol']:
		"""
		``get_symbols_of_type`` retrieves a list of all :py:class:`~binaryninja.types.Symbol` objects of the provided symbol type in the optionally
		 provided range.

		:param sym_type: A Symbol type: :py:class:`~binaryninja.enums.SymbolType`
		:param start: optional start virtual address
		:param length: optional length
		:return: list of all :py:class:`~binaryninja.types.Symbol` objects of type ``sym_type``, or those :py:class:`~binaryninja.types.Symbol` objects in the range of ``start``-``start+length``
		:rtype: list(CoreSymbol)
		:Example:

			>>> bv.get_symbols_of_type(SymbolType.ImportAddressSymbol, 0x10002028, 1)
			[<ImportAddressSymbol: "KERNEL32!GetCurrentThreadId" @ 0x10002028>]
			>>>
		"""
		if isinstance(sym_type, str):
			sym_type = SymbolType[sym_type]
		_namespace = _types.NameSpace.get_core_struct(namespace)

		count = ctypes.c_ulonglong(0)
		if start is None:
			syms = core.BNGetSymbolsOfType(self.handle, sym_type, count, _namespace)
			assert syms is not None, "core.BNGetSymbolsOfType returned None"
		else:
			if length is None:
				raise Exception("Length must be provided if start is present")
			syms = core.BNGetSymbolsOfTypeInRange(self.handle, sym_type, start, length, count, _namespace)
			assert syms is not None, "core.BNGetSymbolsOfTypeInRange returned None"
		result = []
		try:
			for i in range(0, count.value):
				sym_handle = core.BNNewSymbolReference(syms[i])
				assert sym_handle is not None, "core.BNNewSymbolReference returned None"
				result.append(_types.CoreSymbol(sym_handle))
			return result
		finally:
			core.BNFreeSymbolList(syms, count.value)

	def define_auto_symbol(self, sym: '_types.CoreSymbol') -> None:
		"""
		``define_auto_symbol`` adds a symbol to the internal list of automatically discovered Symbol objects in a given
		namespace.

		.. warning:: If multiple symbols for the same address are defined, only the most recent symbol will ever be used.

		:param sym: the symbol to define
		:rtype: None
		"""
		core.BNDefineAutoSymbol(self.handle, sym.handle)

	def define_auto_symbol_and_var_or_function(
	    self, sym: '_types.CoreSymbol', type: '_types.Type', plat: Optional['_platform.Platform'] = None
	) -> Optional['_types.CoreSymbol']:
		"""
		``define_auto_symbol_and_var_or_function`` Defines an "Auto" symbol, and a Variable/Function alongside it.

		.. warning:: If multiple symbols for the same address are defined, only the most recent symbol will ever be used.

		:param sym: Symbol to define
		:param type: Type for the function/variable being defined (can be None)
		:param plat: Platform (optional)
		:rtype: Optional[CoreSymbol]
		"""
		if plat is None:
			if self.platform is None:
				raise Exception("Attempting to call define_auto_symbol_and_var_or_function without Platform specified")
			plat = self.platform
		elif not isinstance(plat, _platform.Platform):
			raise ValueError("Provided platform is not of type `Platform`")

		if isinstance(type, _types.Type):
			type = type.handle
		elif type is not None:
			raise ValueError("Provided type is not of type `binaryninja.Type`")

		_sym = core.BNDefineAutoSymbolAndVariableOrFunction(self.handle, plat.handle, sym.handle, type)
		if _sym is None:
			return None
		return _types.CoreSymbol(_sym)

	def undefine_auto_symbol(self, sym: '_types.CoreSymbol') -> None:
		"""
		``undefine_auto_symbol`` removes a symbol from the internal list of automatically discovered Symbol objects.

		:param Symbol sym: the symbol to undefine
		:rtype: None
		"""
		core.BNUndefineAutoSymbol(self.handle, sym.handle)

	def define_user_symbol(self, sym: '_types.CoreSymbol') -> None:
		"""
		``define_user_symbol`` adds a symbol to the internal list of user added Symbol objects.

		.. warning:: If multiple symbols for the same address are defined, only the most recent symbol will ever be used.

		:param Symbol sym: the symbol to define
		:rtype: None
		"""
		core.BNDefineUserSymbol(self.handle, sym.handle)

	def undefine_user_symbol(self, sym: '_types.CoreSymbol') -> None:
		"""
		``undefine_user_symbol`` removes a symbol from the internal list of user added Symbol objects.

		:param sym: the symbol to undefine
		:rtype: None
		"""
		core.BNUndefineUserSymbol(self.handle, sym.handle)

	def define_imported_function(
	    self, import_addr_sym: '_types.CoreSymbol', func: '_function.Function', type: Optional['_types.Type'] = None
	) -> None:
		"""
		``define_imported_function`` defines an imported Function ``func`` with a ImportedFunctionSymbol type.

		:param import_addr_sym: A Symbol object with type ImportedFunctionSymbol
		:param func: A Function object to define as an imported function
		:param type: Optional type for the function
		:rtype: None
		"""
		core.BNDefineImportedFunction(
		    self.handle, import_addr_sym.handle, func.handle, None if type is None else type.handle
		)

	def bulk_modify_symbols(self):
		"""
		``bulk_modify_symbols`` returns a context manager that improves performance when adding or
		removing a large number of symbols. Symbols added within the Python `with` keyword will
		defer processing until the end of the block. Many symbol getter APIs will return stale
		results inside the `with` block, so this function should only be used when symbol
		queries are not needed at the same time as the modifications.
		"""
		class BulkModify:
			def __init__(self, view: 'BinaryView'):
				self._view = view

			def __enter__(self) -> None:
				core.BNBeginBulkModifySymbols(self._view.handle)

			def __exit__(self, type, value, traceback):
				core.BNEndBulkModifySymbols(self._view.handle)

		return BulkModify(self)

	def create_tag_type(self, name: str, icon: str) -> 'TagType':
		"""
		``create_tag_type`` creates a new :py:class:`TagType` and adds it to the view

		:param str name: The name for the tag
		:param str icon: The icon (recommended 1 emoji or 2 chars) for the tag
		:return: The created tag type
		:rtype: TagType
		:Example:

			>>> bv.create_tag_type("Crabby Functions", "🦀")
			>>>
		"""
		tag_handle = core.BNCreateTagType(self.handle)
		assert tag_handle is not None, "core.BNCreateTagType returned None"
		tag_type = TagType(tag_handle)
		tag_type.name = name
		tag_type.icon = icon
		core.BNAddTagType(self.handle, tag_type.handle)
		return tag_type

	def remove_tag_type(self, tag_type: str):
		"""
		``remove_tag_type`` removes a :py:class:`TagType` and all tags that use it

		:param str tag_type: The name of the tag type to remove
		:rtype: None
		"""
		tag_type = self.get_tag_type(tag_type)
		if tag_type is not None:
			core.BNRemoveTagType(self.handle, tag_type.handle)

	@property
	def tag_types(self) -> Mapping[str, Union['TagType', List['TagType']]]:
		"""
		``tag_types`` gets a dictionary of all Tag Types present for the view,
		structured as {Tag Type Name => Tag Type}.

		.. warning:: This method inconsistently returns a list of :py:class:`TagType` objects or a single \
		 :py:class:`TagType` this behavior will change in future revisions

		:rtype: dict of (str, TagType)
		"""
		count = ctypes.c_ulonglong(0)
		types = core.BNGetTagTypes(self.handle, count)
		assert types is not None, "core.BNGetTagTypes returned None"
		result: Mapping[str, Union['TagType', List['TagType']]] = {}
		try:
			for i in range(0, count.value):
				tag_handle = core.BNNewTagTypeReference(types[i])
				assert tag_handle is not None, "core.BNNewTagTypeReference returned None"
				tag = TagType(tag_handle)
				if tag.name in result:
					cur_item = result[tag.name]
					if isinstance(cur_item, list):
						cur_item.append(tag)
						result[tag.name] = cur_item
					else:
						result[tag.name] = [cur_item, tag]
				else:
					result[tag.name] = tag
			return result
		finally:
			core.BNFreeTagTypeList(types, count.value)

	def get_tag_type(self, name: str) -> Optional['TagType']:
		"""
		Get a tag type by its name.

		:param name: Name of the tag type
		:return: The relevant tag type, if it exists
		:rtype: TagType
		"""

		if isinstance(name, TagType):
			log_warn("Accessing tag types by type is deprecated. Please use the name instead.")
			return name
		else:
			tag_type = core.BNGetTagType(self.handle, name)
			if tag_type is not None:
				return TagType(tag_type)
			else:
				return None

	def add_tag(self, addr: int, tag_type_name: str, data: str, user: bool = True):
		"""
		``add_tag`` creates and adds a :py:class:`Tag` object at a data address.

		This API is appropriate for generic data tags. For functions,
		consider using :py:func:`~binaryninja.function.Function.add_tag`.

		:param int addr: address at which to add the tag
		:param str tag_type_name: The name of the tag type for this Tag
		:param str data: additional data for the Tag
		:param bool user: Whether or not a user tag

		:Example:

			>>> bv.add_tag(here, "Crashes", "Null pointer dereference")
			>>>
		"""
		tag_type = self.get_tag_type(tag_type_name)
		if tag_type is None:
			return

		tag_handle = core.BNCreateTag(tag_type.handle, data)
		assert tag_handle is not None, "core.BNCreateTag returned None"
		tag = Tag(tag_handle)
		core.BNAddTag(self.handle, tag.handle, user)
		core.BNAddUserDataTag(self.handle, addr, tag.handle)

	@property
	def tags(self) -> List[Tuple[int, 'Tag']]:
		"""
		``tags`` gets a list of all data :py:class:`Tag` objects in the view.
		Tags are returned as a list of (address, :py:class:`Tag`) pairs.

		:rtype: list(int, Tag)
		"""
		return self.get_tags()

	def get_tags(self, auto: Optional[bool] = None) -> List[Tuple[int, 'Tag']]:
		"""
		``tags`` gets a list of all data :py:class:`Tag` objects in the view.
		Tags are returned as a list of (address, :py:class:`Tag`) pairs.

		:rtype: list(int, Tag)
		"""
		count = ctypes.c_ulonglong()

		if auto is None:
			tags = core.BNGetDataTagReferences(self.handle, count)
			assert tags is not None, "core.BNGetDataTagReferences returned None"
		elif auto:
			tags = core.BNGetAutoDataTagReferences(self.handle, count)
			assert tags is not None, "core.BNGetAutoDataTagReferences return None"
		else:
			tags = core.BNGetUserDataTagReferences(self.handle, count)
			assert tags is not None, "core.BNGetUserDataTagReferences returned None"

		result = []
		try:
			for i in range(0, count.value):
				tag_handle = core.BNNewTagReference(tags[i].tag)
				assert tag_handle is not None, "core.BNNewTagReference is not None"
				tag = Tag(tag_handle)
				result.append((tags[i].addr, tag))
			return result
		finally:
			core.BNFreeTagReferences(tags, count.value)


	def get_tags_at(self, addr: int, auto: Optional[bool] = None) -> List['Tag']:
		"""
		``get_data_tags_at`` gets a list of :py:class:`Tag` objects for a data address.

		:param int addr: address to get tags at
		:param bool auto: If None, gets all tags, if True, gets auto tags, if False, gets user tags
		:return: A list of data :py:class:`Tag` objects
		:rtype: list(Tag)
		"""
		count = ctypes.c_ulonglong()
		if auto is None:
			tags = core.BNGetDataTags(self.handle, addr, count)
			assert tags is not None, "core.BNGetDataTags returned None"
		elif auto:
			tags = core.BNGetAutoDataTags(self.handle, addr, count)
			assert tags is not None, "core.BNGetAutoDataTags returned None"
		else:
			tags = core.BNGetUserDataTags(self.handle, addr, count)
			assert tags is not None, "core.BNGetUserDataTags returned None"

		result = []
		try:
			for i in range(0, count.value):
				tag_handle = core.BNNewTagReference(tags[i])
				assert tag_handle is not None, "core.BNNewTagReference is not None"
				result.append(Tag(tag_handle))
			return result
		finally:
			core.BNFreeTagList(tags, count.value)

	def get_tags_in_range(self, address_range: 'variable.AddressRange', auto: Optional[bool] = None) -> List[Tuple[int, 'Tag']]:
		"""
		``get_data_tags_in_range`` gets a list of all data :py:class:`Tag` objects in a given range.
		Range is inclusive at the start, exclusive at the end.

		:param AddressRange address_range: address range from which to get tags
		:param bool auto: If None, gets all tags, if True, gets auto tags, if False, gets auto tags
		:return: A list of (address, data tag) tuples
		:rtype: list((int, Tag))
		"""
		count = ctypes.c_ulonglong()
		if auto is None:
			refs = core.BNGetDataTagsInRange(self.handle, address_range.start, address_range.end, count)
			assert refs is not None, "BNGetDataTagsInRange returned None"
		elif auto:
			refs = core.BNGetAutoDataTagsInRange(self.handle, address_range.start, address_range.end, count)
			assert refs is not None, "BNGetAutoDataTagsInRange returned None"
		else:
			refs = core.BNGetUserDataTagsInRange(self.handle, address_range.start, address_range.end, count)
			assert refs is not None, "BNGetUserDataTagsInRange returned None"

		result = []
		try:
			for i in range(0, count.value):
				tag_ref = core.BNNewTagReference(refs[i].tag)
				assert tag_ref is not None, "BNNewTagReference returned None"
				tag = Tag(tag_ref)
				result.append((refs[i].addr, tag))
			return result
		finally:
			core.BNFreeTagReferences(refs, count.value)

	def remove_user_data_tag(self, addr: int, tag: Tag):
		"""
		``remove_user_data_tag`` removes a :py:class:`Tag` object at a data address.
		Since this removes a user tag, it will be added to the current undo buffer.

		:param int addr: address at which to remove the tag
		:param Tag tag: :py:class:`Tag` object to be removed
		:rtype: None
		"""
		core.BNRemoveUserDataTag(self.handle, addr, tag.handle)

	def remove_user_data_tags_of_type(self, addr: int, tag_type: str):
		"""
		``remove_user_data_tags_of_type`` removes all data tags at the given address of the given type.
		Since this removes user tags, it will be added to the current undo buffer.

		:param int addr: address at which to add the tags
		:param str tag_type: Tag type name to match for removing
		:rtype: None
		"""
		tag_type = self.get_tag_type(tag_type)
		if tag_type is not None:
			core.BNRemoveUserDataTagsOfType(self.handle, addr, tag_type.handle)

	def remove_auto_data_tag(self, addr: int, tag: 'Tag'):
		"""
		``remove_auto_data_tag`` removes a Tag object at a data address.

		:param int addr: address at which to remove the tag
		:param Tag tag: Tag object to be removed
		:rtype: None
		"""
		core.BNRemoveAutoDataTag(self.handle, addr, tag.handle)

	def remove_auto_data_tags_of_type(self, addr: int, tag_type: str):
		"""
		``remove_auto_data_tags_of_type`` removes all data tags at the given address of the given type.

		:param int addr: address at which to add the tags
		:param str tag_type: Tag type name to match for removing
		:rtype: None
		"""
		tag_type = self.get_tag_type(tag_type)
		if tag_type is not None:
			core.BNRemoveAutoDataTagsOfType(self.handle, addr, tag_type.handle)

	def check_for_string_annotation_type(self, addr: int, allow_short_strings: bool = False, allow_large_strings: bool = False, child_width: int = 0) -> Optional[Tuple[str, StringType]]:
		"""
		Check for string annotation at a given address. This returns the string (and type of the string) as annotated in the UI at a given address. If there's no annotation, this function returns `None`.

		:param int addr: address at which to check for string annotation
		:param bool allow_short_strings: Allow string shorter than the `analysis.limits.minStringLength` setting
		:param bool allow_large_strings: Allow strings longer than the `rendering.strings.maxAnnotationLength` setting (up to `analysis.limits.maxStringLength`)
		:param int child_width: What width of strings to look for, 1 for ASCII/UTF8, 2 for UTF16, 4 for UTF32, 0 to check for all
		:rtype: None
		"""
		value = ctypes.c_char_p()
		string_type = ctypes.c_int()
		result = core.BNCheckForStringAnnotationType(self.handle, addr, value, string_type, allow_short_strings, allow_large_strings, child_width)
		if result:
			result = value.value.decode("utf-8")
			core.free_string(value)
			return (result, StringType(string_type.value))
		return None

	def can_assemble(self, arch: Optional['architecture.Architecture'] = None) -> bool:
		"""
		``can_assemble`` queries the architecture plugin to determine if the architecture can assemble instructions.

		:return: True if the architecture can assemble, False otherwise
		:rtype: bool
		:Example:

			>>> bv.can_assemble()
			True
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNCanAssemble(self.handle, arch.handle)

	def is_never_branch_patch_available(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> bool:
		"""
		``is_never_branch_patch_available`` queries the architecture plugin to determine if the instruction at the
		instruction at ``addr`` can be made to **never branch**. The actual logic of which is implemented in the
		``perform_is_never_branch_patch_available`` in the corresponding architecture.

		:param int addr: the virtual address of the instruction to be patched
		:param Architecture arch: (optional) the architecture of the instructions if different from the default
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012ed)
			'test    eax, eax'
			>>> bv.is_never_branch_patch_available(0x100012ed)
			False
			>>> bv.get_disassembly(0x100012ef)
			'jg      0x100012f5'
			>>> bv.is_never_branch_patch_available(0x100012ef)
			True
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNIsNeverBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_always_branch_patch_available(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> bool:
		"""
		``is_always_branch_patch_available`` queries the architecture plugin to determine if the
		instruction at ``addr`` can be made to **always branch**. The actual logic of which is implemented in the
		``perform_is_always_branch_patch_available`` in the corresponding architecture.

		:param int addr: the virtual address of the instruction to be patched
		:param Architecture arch: (optional) the architecture for the current view
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012ed)
			'test    eax, eax'
			>>> bv.is_always_branch_patch_available(0x100012ed)
			False
			>>> bv.get_disassembly(0x100012ef)
			'jg      0x100012f5'
			>>> bv.is_always_branch_patch_available(0x100012ef)
			True
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNIsAlwaysBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_invert_branch_patch_available(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> bool:
		"""
		``is_invert_branch_patch_available`` queries the architecture plugin to determine if the instruction at ``addr``
		is a branch that can be inverted. The actual logic of which is implemented in the
		``perform_is_invert_branch_patch_available`` in the corresponding architecture.

		:param int addr: the virtual address of the instruction to be patched
		:param Architecture arch: (optional) the architecture of the instructions if different from the default
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012ed)
			'test    eax, eax'
			>>> bv.is_invert_branch_patch_available(0x100012ed)
			False
			>>> bv.get_disassembly(0x100012ef)
			'jg      0x100012f5'
			>>> bv.is_invert_branch_patch_available(0x100012ef)
			True
			>>>

		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNIsInvertBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_skip_and_return_zero_patch_available(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> bool:
		"""
		``is_skip_and_return_zero_patch_available`` queries the architecture plugin to determine if the
		instruction at ``addr`` is similar to an x86 "call" instruction which can be made to return zero. The actual
		logic of which is implemented in the ``perform_is_skip_and_return_zero_patch_available`` in the corresponding
		architecture.

		:param int addr: the virtual address of the instruction to be patched
		:param Architecture arch: (optional) the architecture of the instructions if different from the default
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012f6)
			'mov     dword [0x10003020], eax'
			>>> bv.is_skip_and_return_zero_patch_available(0x100012f6)
			False
			>>> bv.get_disassembly(0x100012fb)
			'call    0x10001629'
			>>> bv.is_skip_and_return_zero_patch_available(0x100012fb)
			True
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNIsSkipAndReturnZeroPatchAvailable(self.handle, arch.handle, addr)

	def is_skip_and_return_value_patch_available(
	    self, addr: int, arch: Optional['architecture.Architecture'] = None
	) -> bool:
		"""
		``is_skip_and_return_value_patch_available`` queries the architecture plugin to determine if the
		instruction at ``addr`` is similar to an x86 "call" instruction which can be made to return a value. The actual
		logic of which is implemented in the ``perform_is_skip_and_return_value_patch_available`` in the corresponding
		architecture.

		:param int addr: the virtual address of the instruction to be patched
		:param Architecture arch: (optional) the architecture of the instructions if different from the default
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012f6)
			'mov     dword [0x10003020], eax'
			>>> bv.is_skip_and_return_value_patch_available(0x100012f6)
			False
			>>> bv.get_disassembly(0x100012fb)
			'call    0x10001629'
			>>> bv.is_skip_and_return_value_patch_available(0x100012fb)
			True
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNIsSkipAndReturnValuePatchAvailable(self.handle, arch.handle, addr)

	def convert_to_nop(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> bool:
		"""
		``convert_to_nop`` converts the instruction at virtual address ``addr`` to a nop of the provided architecture.

		.. note:: This API performs a binary patch, analysis may need to be updated afterward. Additionally the binary \
		file must be saved in order to preserve the changes made.

		:param int addr: virtual address of the instruction to convert to nops
		:param Architecture arch: (optional) the architecture of the instructions if different from the default
		:return: True on success, False on failure.
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012fb)
			'call    0x10001629'
			>>> bv.convert_to_nop(0x100012fb)
			True
			>>> #The above 'call' instruction is 5 bytes, a nop in x86 is 1 byte,
			>>> # thus 5 nops are used:
			>>> bv.get_disassembly(0x100012fb)
			'nop'
			>>> bv.get_disassembly(0x100012fb + 1)
			'nop'
			>>> bv.get_disassembly(0x100012fb + 2)
			'nop'
			>>> bv.get_disassembly(0x100012fb + 3)
			'nop'
			>>> bv.get_disassembly(0x100012fb + 4)
			'nop'
			>>> bv.get_disassembly(0x100012fb + 5)
			'mov     byte [ebp-0x1c], al'
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNConvertToNop(self.handle, arch.handle, addr)

	def always_branch(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> bool:
		"""
		``always_branch`` convert the instruction of architecture ``arch`` at the virtual address ``addr`` to an
		unconditional branch.

		.. note:: This API performs a binary patch, analysis may need to be updated afterward. Additionally the binary \
		file must be saved in order to preserve the changes made.

		:param int addr: virtual address of the instruction to be modified
		:param Architecture arch: (optional) the architecture of the instructions if different from the default
		:return: True on success, False on failure.
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012ef)
			'jg      0x100012f5'
			>>> bv.always_branch(0x100012ef)
			True
			>>> bv.get_disassembly(0x100012ef)
			'jmp     0x100012f5'
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNAlwaysBranch(self.handle, arch.handle, addr)

	def never_branch(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> bool:
		"""
		``never_branch`` convert the branch instruction of architecture ``arch`` at the virtual address ``addr`` to
		a fall through.

		.. note:: This API performs a binary patch, analysis may need to be updated afterward. Additionally the binary\
		file must be saved in order to preserve the changes made.

		:param int addr: virtual address of the instruction to be modified
		:param Architecture arch: (optional) the architecture of the instructions if different from the default
		:return: True on success, False on failure.
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x1000130e)
			'jne     0x10001317'
			>>> bv.never_branch(0x1000130e)
			True
			>>> bv.get_disassembly(0x1000130e)
			'nop'
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNConvertToNop(self.handle, arch.handle, addr)

	def invert_branch(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> bool:
		"""
		``invert_branch`` convert the branch instruction of architecture ``arch`` at the virtual address ``addr`` to the
		inverse branch.

		.. note:: This API performs a binary patch, analysis may need to be updated afterward. Additionally the binary \
		file must be saved in order to preserve the changes made.

		:param int addr: virtual address of the instruction to be modified
		:param Architecture arch: (optional) the architecture of the instructions if different from the default
		:return: True on success, False on failure.
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x1000130e)
			'je      0x10001317'
			>>> bv.invert_branch(0x1000130e)
			True
			>>>
			>>> bv.get_disassembly(0x1000130e)
			'jne     0x10001317'
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNInvertBranch(self.handle, arch.handle, addr)

	def skip_and_return_value(self, addr: int, value: int, arch: Optional['architecture.Architecture'] = None) -> bool:
		"""
		``skip_and_return_value`` convert the ``call`` instruction of architecture ``arch`` at the virtual address
		``addr`` to the equivalent of returning a value.

		:param int addr: virtual address of the instruction to be modified
		:param int value: value to make the instruction *return*
		:param Architecture arch: (optional) the architecture of the instructions if different from the default
		:return: True on success, False on failure.
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x1000132a)
			'call    0x1000134a'
			>>> bv.skip_and_return_value(0x1000132a, 42)
			True
			>>> #The return value from x86 functions is stored in eax thus:
			>>> bv.get_disassembly(0x1000132a)
			'mov     eax, 0x2a'
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNSkipAndReturnValue(self.handle, arch.handle, addr, value)

	def get_instruction_length(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> int:
		"""
		``get_instruction_length`` returns the number of bytes in the instruction of Architecture ``arch`` at the virtual
		address ``addr``

		:param int addr: virtual address of the instruction query
		:param Architecture arch: (optional) the architecture of the instructions if different from the default
		:return: Number of bytes in instruction
		:rtype: int
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.get_instruction_length(0x100012f1)
			2L
			>>>
		"""
		if arch is None:
			if self.arch is None:
				raise Exception("Attempting to call can_assemble without an Architecture specified")
			arch = self.arch
		return core.BNGetInstructionLength(self.handle, arch.handle, addr)

	def notify_data_written(self, offset: int, length: int) -> None:
		core.BNNotifyDataWritten(self.handle, offset, length)

	def notify_data_inserted(self, offset: int, length: int) -> None:
		core.BNNotifyDataInserted(self.handle, offset, length)

	def notify_data_removed(self, offset: int, length: int) -> None:
		core.BNNotifyDataRemoved(self.handle, offset, length)

	def get_component(self, guid: str) -> Optional[component.Component]:
		"""
		Lookup a Component by its GUID

		:param guid: GUID of the component to look up
		:return: The Component with that Guid
		"""
		bn_component = core.BNGetComponentByGuid(self.handle, guid)
		if bn_component is None:
			return None
		return component.Component(bn_component)

	def get_component_by_path(self, path: str) -> Optional[component.Component]:
		"""
		Lookup a Component by its pathname

		:note: This is a convenience method, and for performance-sensitive lookups, GetComponentByGuid is very highly recommended.

		Lookups are done based on the .display_name of the Component.

		All lookups are absolute from the root component, and are case-sensitive. Pathnames are delimited with "/"

		:param path: Pathname of the desired Component
		:return: The Component at that pathname

		:Example:

			>>> c = bv.create_component(name="MyComponent")
			>>> c2 = bv.create_component(name="MySubComponent", parent=c)
			>>> bv.get_component_by_path("/MyComponent/MySubComponent") == c2
			True
			>>> c3 = bv.create_component(name="MySubComponent", parent=c)
			>>> c3
			<Component "MySubComponent (1)" "(20712aff...")>
			>>> bv.get_component_by_path("/MyComponent/MySubComponent (1)") == c3
			True
		"""
		if not isinstance(path, str):
			raise TypeError("Pathname must be a string")
		bn_component = core.BNGetComponentByPath(self.handle, path)
		if bn_component is None:
			return None
		return component.Component(bn_component)

	@property
	def root_component(self) -> component.Component:
		"""
		The root component for the BinaryView (read-only)

		This Component cannot be removed, and houses all unparented Components.

		:return: The root component
		"""
		return component.Component(core.BNGetRootComponent(self.handle))

	def create_component(self, name: Optional[str] = None, parent: Union[component.Component, str, None] = None) -> component.Component:
		"""
		Create a new component with an optional name and parent.

		The `parent` argument can be either a Component or the Guid of a component that the created component will be
			added as a child of

		:param name: Optional name to create the component with
		:param parent: Optional parent to which the component will be added
		:return: The created component
		"""

		if parent:
			if isinstance(parent, component.Component):
				if name:
					return component.Component(core.BNCreateComponentWithParentAndName(self.handle, parent.guid, name))
				else:
					return component.Component(core.BNCreateComponentWithParent(self.handle, parent.guid))
			elif isinstance(parent, str):
				if name:
					return component.Component(core.BNCreateComponentWithParentAndName(self.handle, parent, name))
				else:
					return component.Component(core.BNCreateComponentWithParent(self.handle, parent))
			else:
				raise TypeError("parent can only be a Component object or string GUID representing one")
		else:
			if name:
				return component.Component(core.BNCreateComponentWithName(self.handle, name))
			else:
				return component.Component(core.BNCreateComponent(self.handle))

	def remove_component(self, _component: Union[component.Component, str]) -> bool:
		"""
		Remove a component from the tree entirely.

		:param _component: Component to remove
		:return: Whether the removal was successful
		"""
		if isinstance(_component, component.Component):
			return core.BNRemoveComponent(self.handle, _component.handle)
		elif isinstance(_component, str):
			return core.BNRemoveComponentByGuid(self.handle, _component)

		raise TypeError("Removal is only supported with a Component or string representing its Guid")

	def get_function_parent_components(self, function: 'function.Function') -> List['component.Component']:
		_components = []
		count = ctypes.c_ulonglong(0)
		bn_components = core.BNGetFunctionParentComponents(self.handle, function.handle, count)
		try:
			for i in range(count.value):
				_components.append(component.Component(core.BNNewComponentReference(bn_components[i])))
		finally:
			core.BNFreeComponents(bn_components, count.value)
		return _components

	def get_data_variable_parent_components(self, data_variable: 'DataVariable') -> List['component.Component']:
		_components = []
		count = ctypes.c_ulonglong(0)
		bn_components = core.BNGetDataVariableParentComponents(self.handle, data_variable.address, count)
		try:
			for i in range(count.value):
				_components.append(component.Component(core.BNNewComponentReference(bn_components[i])))
		finally:
			core.BNFreeComponents(bn_components, count.value)
		return _components

	def get_strings(self, start: Optional[int] = None, length: Optional[int] = None) -> List['StringReference']:
		"""
		``get_strings`` returns a list of strings defined in the binary in the optional virtual address range:
		``start-(start+length)``

		Note that this API will only return strings that have been identified by the string-analysis and thus governed by the minimum and maximum length settings and unrelated to the type system.

		:param int start: optional virtual address to start the string list from, defaults to start of the binary
		:param int length: optional length range to return strings from, defaults to length of the binary
		:return: a list of all strings or a list of strings defined between ``start`` and ``start+length``
		:rtype: list(StringReference)
		:Example:

			>>> bv.get_strings(0x1000004d, 1)
			[<AsciiString: 0x1000004d, len 0x2c>]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		if start is None:
			strings = core.BNGetStrings(self.handle, count)
			assert strings is not None, "core.BNGetStrings returned None"
		else:
			if length is None:
				length = self.end - start
			strings = core.BNGetStringsInRange(self.handle, start, length, count)
			assert strings is not None, "core.BNGetStringsInRange returned None"
		result = []
		try:
			for i in range(0, count.value):
				result.append(StringReference(self, StringType(strings[i].type), strings[i].start, strings[i].length))
			return result
		finally:
			core.BNFreeStringReferenceList(strings)

	def get_string_at(self, addr: int, partial: bool = False) -> Optional['StringReference']:
		"""
		``get_string_at`` returns the string that falls on given virtual address.

		.. note:: This returns discovered strings and is therefore governed by `analysis.limits.minStringLength` and other settings. For an alternative API that simply returns any potential c-string at a given location, use :py:func:`get_ascii_string_at`.

		:param int addr: virtual address to get the string from
		:param bool partial: whether to return a partial string reference or not
		:return: returns the StringReference at the given virtual address, otherwise None.
		:rtype: StringReference
		:Example:

			>>> bv.get_string_at(0x40302f)
			<StringType.AsciiString: 0x403028, len 0x12>

		"""
		str_ref = core.BNStringReference()
		if not core.BNGetStringAtAddress(self.handle, addr, str_ref):
			return None
		if partial and (addr != str_ref.start) and (str_ref.type != StringType.AsciiString):
			partial = False
			log_warn("Partial string not supported at {}".format(hex(addr)))
		start = addr if partial else str_ref.start
		length = str_ref.length - (addr - str_ref.start) if partial else str_ref.length
		return StringReference(self, StringType(str_ref.type), start, length)

	def get_ascii_string_at(self, addr: int, min_length: int = 4, max_length: Optional[int] = None,
	                        require_cstring: bool = True) -> Optional['StringReference']:
		"""
		``get_ascii_string_at`` returns an ascii string found at ``addr``.

		.. note:: This returns an ascii string irrespective of whether the core analysis identified a string at that location. For an alternative API that uses existing identified strings, use :py:func:`get_string_at`.

		:param int addr: virtual address to start the string
		:param int min_length: minimum length to define a string
		:param int max_length: max length string to return
		:param bool require_cstring: only return 0x0-terminated strings
		:return: the string found at ``addr`` or None if a string does not exist
		:rtype: StringReference or None
		:Example:

			>>> s1 = bv.get_ascii_string_at(0x70d0)
			>>> s1
			<AsciiString: 0x70d0, len 0xb>
			>>> s1.value
			'AWAVAUATUSH'
			>>> s2 = bv.get_ascii_string_at(0x70d1)
			>>> s2
			<AsciiString: 0x70d1, len 0xa>
			>>> s2.value
			'WAVAUATUSH'
		"""
		if not isinstance(addr, int):
			raise ValueError("Input address (" + str(addr) + ") is not a number.")
		if addr < self.start or addr >= self.end:
			return None

		br = BinaryReader(self)
		br.seek(addr)
		length = 0
		c = br.read8()
		while c is not None and c > 0 and c <= 0x7f:
			if length == max_length:
				break
			length += 1
			c = br.read8()
		if length < min_length:
			return None
		if require_cstring and c != 0:
			return None
		return StringReference(self, StringType.AsciiString, addr, length)

	def add_analysis_completion_event(self, callback: Callable[[], None]) -> 'AnalysisCompletionEvent':
		"""
		``add_analysis_completion_event`` sets up a call back function to be called when analysis has been completed.
		This is helpful when using :py:func:`update_analysis` which does not wait for analysis completion before returning.

		The callee of this function is not responsible for maintaining the lifetime of the returned AnalysisCompletionEvent object.

		.. note:: The lock held by the callback thread on the BinaryView instance ensures that other BinaryView actions can be safely performed in the callback thread.
		.. warning:: The built-in python console automatically updates analysis after every command is run, which means this call back may not behave as expected if entered interactively.

		:param callback callback: A function to be called with no parameters when analysis has completed.
		:return: An initialized AnalysisCompletionEvent object
		:rtype: AnalysisCompletionEvent
		:Example:

			>>> def completionEvent():
			...   print("done")
			...
			>>> bv.add_analysis_completion_event(completionEvent)
			<binaryninja.AnalysisCompletionEvent object at 0x10a2c9f10>
			>>> bv.update_analysis()
			done
			>>>
		"""
		return AnalysisCompletionEvent(self, callback)

	def get_next_function_start_after(self, addr: int) -> int:
		"""
		``get_next_function_start_after`` returns the virtual address of the Function that occurs after the virtual address
		``addr``

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the next Function
		:rtype: int
		:Example:

			>>> bv.get_next_function_start_after(bv.entry_point)
			268441061L
			>>> hex(bv.get_next_function_start_after(bv.entry_point))
			'0x100015e5L'
			>>> hex(bv.get_next_function_start_after(0x100015e5))
			'0x10001629L'
			>>> hex(bv.get_next_function_start_after(0x10001629))
			'0x1000165eL'
			>>>
		"""
		return core.BNGetNextFunctionStartAfterAddress(self.handle, addr)

	def get_next_basic_block_start_after(self, addr: int) -> int:
		"""
		``get_next_basic_block_start_after`` returns the virtual address of the BasicBlock that occurs after the virtual
		 address ``addr``

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the next BasicBlock
		:rtype: int
		:Example:

			>>> hex(bv.get_next_basic_block_start_after(bv.entry_point))
			'0x100014a8L'
			>>> hex(bv.get_next_basic_block_start_after(0x100014a8))
			'0x100014adL'
			>>>
		"""
		return core.BNGetNextBasicBlockStartAfterAddress(self.handle, addr)

	def get_next_data_after(self, addr: int) -> int:
		"""
		``get_next_data_after`` retrieves the virtual address of the next non-code byte.

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the next data byte which is data, not code
		:rtype: int
		:Example:

			>>> hex(bv.get_next_data_after(0x10000000))
			'0x10000001L'
		"""
		return core.BNGetNextDataAfterAddress(self.handle, addr)

	def get_next_data_var_after(self, addr: int) -> Optional['DataVariable']:
		"""
		``get_next_data_var_after`` retrieves the next :py:class:`DataVariable`, or None.

		:param int addr: the virtual address to start looking from.
		:return: the next :py:class:`DataVariable`
		:rtype: DataVariable
		:Example:

			>>> bv.get_next_data_var_after(0x10000000)
			<var 0x1000003c: int32_t>
			>>>
		"""
		while True:
			next_data_var_start = core.BNGetNextDataVariableStartAfterAddress(self.handle, addr)
			if next_data_var_start == self.end:
				return None
			var = core.BNDataVariable()
			if not core.BNGetDataVariableAtAddress(self.handle, next_data_var_start, var):
				return None
			if var.address < next_data_var_start:
				addr = var.address + core.BNGetTypeWidth(var.type)
				continue
			break
		result = DataVariable.from_core_struct(var, self)
		core.BNFreeDataVariable(var)
		return result

	def get_next_data_var_start_after(self, addr: int) -> int:
		"""
		``get_next_data_var_start_after`` retrieves the next virtual address of the next :py:class:`DataVariable`

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the next :py:class:`DataVariable`
		:rtype: int
		:Example:

			>>> hex(bv.get_next_data_var_start_after(0x10000000))
			'0x1000003cL'
			>>> bv.get_data_var_at(0x1000003c)
			<var 0x1000003c: int32_t>
			>>>
		"""
		return core.BNGetNextDataVariableStartAfterAddress(self.handle, addr)

	def get_previous_function_start_before(self, addr: int) -> int:
		"""
		``get_previous_function_start_before`` returns the virtual address of the Function that occurs prior to the
		virtual address provided

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the previous Function
		:rtype: int
		:Example:

			>>> hex(bv.entry_point)
			'0x1000149fL'
			>>> hex(bv.get_next_function_start_after(bv.entry_point))
			'0x100015e5L'
			>>> hex(bv.get_previous_function_start_before(0x100015e5))
			'0x1000149fL'
			>>>
		"""
		return core.BNGetPreviousFunctionStartBeforeAddress(self.handle, addr)

	def get_previous_basic_block_start_before(self, addr: int) -> int:
		"""
		``get_previous_basic_block_start_before`` returns the virtual address of the BasicBlock that occurs prior to the
		provided virtual address

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the previous BasicBlock
		:rtype: int
		:Example:

			>>> hex(bv.entry_point)
			'0x1000149fL'
			>>> hex(bv.get_next_basic_block_start_after(bv.entry_point))
			'0x100014a8L'
			>>> hex(bv.get_previous_basic_block_start_before(0x100014a8))
			'0x1000149fL'
			>>>
		"""
		return core.BNGetPreviousBasicBlockStartBeforeAddress(self.handle, addr)

	def get_previous_basic_block_end_before(self, addr: int) -> int:
		"""
		``get_previous_basic_block_end_before``

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the previous BasicBlock end
		:rtype: int
		:Example:
			>>> hex(bv.entry_point)
			'0x1000149fL'
			>>> hex(bv.get_next_basic_block_start_after(bv.entry_point))
			'0x100014a8L'
			>>> hex(bv.get_previous_basic_block_end_before(0x100014a8))
			'0x100014a8L'
		"""
		return core.BNGetPreviousBasicBlockEndBeforeAddress(self.handle, addr)

	def get_previous_data_before(self, addr: int) -> int:
		"""
		``get_previous_data_before``

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the previous data (non-code) byte
		:rtype: int
		:Example:

			>>> hex(bv.get_previous_data_before(0x1000001))
			'0x1000000L'
			>>>
		"""
		return core.BNGetPreviousDataBeforeAddress(self.handle, addr)

	def get_previous_data_var_before(self, addr: int) -> Optional['DataVariable']:
		"""
		``get_previous_data_var_before`` retrieves the previous :py:class:`DataVariable`, or None.

		:param int addr: the virtual address to start looking from.
		:return: the previous :py:class:`DataVariable`
		:rtype: DataVariable
		:Example:

			>>> bv.get_previous_data_var_before(0x1000003c)
			<var 0x10000000: int16_t>
			>>>
		"""
		prev_data_var_start = core.BNGetPreviousDataVariableStartBeforeAddress(self.handle, addr)
		if prev_data_var_start == addr:
			return None
		var = core.BNDataVariable()
		if not core.BNGetDataVariableAtAddress(self.handle, prev_data_var_start, var):
			return None
		result = DataVariable.from_core_struct(var, self)
		core.BNFreeDataVariable(var)
		return result

	def get_previous_data_var_start_before(self, addr: int) -> int:
		"""
		``get_previous_data_var_start_before``

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the previous :py:class:`DataVariable`
		:rtype: int
		:Example:

			>>> hex(bv.get_previous_data_var_start_before(0x1000003c))
			'0x10000000L'
			>>> bv.get_data_var_at(0x10000000)
			<var 0x10000000: int16_t>
			>>>
		"""
		return core.BNGetPreviousDataVariableStartBeforeAddress(self.handle, addr)

	def get_linear_disassembly_position_at(
	    self, addr: int, settings: Optional['_function.DisassemblySettings'] = None
	) -> 'lineardisassembly.LinearViewCursor':
		"""
		``get_linear_disassembly_position_at`` instantiates a :py:class:`~binaryninja.lineardisassembly.LinearViewCursor` object for use in
		:py:func:`get_previous_linear_disassembly_lines` or :py:func:`get_next_linear_disassembly_lines`.

		:param int addr: virtual address of linear disassembly position
		:param DisassemblySettings settings: an instantiated :py:class:`~binaryninja.function.DisassemblySettings` object, defaults to None which will use default settings
		:return: An instantiated :py:class:`~binaryninja.lineardisassembly.LinearViewCursor` object for the provided virtual address
		:rtype: LinearViewCursor
		:Example:

			>>> settings = DisassemblySettings()
			>>> pos = bv.get_linear_disassembly_position_at(0x1000149f, settings)
			>>> lines = bv.get_previous_linear_disassembly_lines(pos)
			>>> lines
			[<0x1000149a: pop     esi>, <0x1000149b: pop     ebp>,
			<0x1000149c: retn    0xc>, <0x1000149f: >]
		"""
		pos = lineardisassembly.LinearViewCursor(lineardisassembly.LinearViewObject.disassembly(self, settings))
		pos.seek_to_address(addr)
		return pos

	def get_previous_linear_disassembly_lines(
	    self, pos: 'lineardisassembly.LinearViewCursor'
	) -> List['lineardisassembly.LinearDisassemblyLine']:
		"""
		``get_previous_linear_disassembly_lines`` retrieves a list of :py:class:`~binaryninja.lineardisassembly.LinearDisassemblyLine` objects for the
		previous disassembly lines, and updates the LinearViewCursor passed in. This function can be called
		repeatedly to get more lines of linear disassembly.

		:param LinearViewCursor pos: Position to start retrieving linear disassembly lines from
		:return: a list of :py:class:`~binaryninja.lineardisassembly.LinearDisassemblyLine` objects for the previous lines.

		:Example:

			>>> settings = DisassemblySettings()
			>>> pos = bv.get_linear_disassembly_position_at(0x1000149a, settings)
			>>> bv.get_previous_linear_disassembly_lines(pos)
			[<0x10001488: push    dword [ebp+0x10 {arg_c}]>, ... , <0x1000149a: >]
			>>> bv.get_previous_linear_disassembly_lines(pos)
			[<0x10001483: xor     eax, eax  {0x0}>, ... , <0x10001488: >]
		"""
		result = []
		while len(result) == 0:
			if not pos.previous():
				return result
			result = pos.lines
		return result

	def get_next_linear_disassembly_lines(
	    self, pos: 'lineardisassembly.LinearViewCursor'
	) -> List['lineardisassembly.LinearDisassemblyLine']:
		"""
		``get_next_linear_disassembly_lines`` retrieves a list of :py:class:`~binaryninja.lineardisassembly.LinearDisassemblyLine` objects for the
		next disassembly lines, and updates the LinearViewCursor passed in. This function can be called
		repeatedly to get more lines of linear disassembly.

		:param LinearViewCursor pos: Position to start retrieving linear disassembly lines from
		:return: a list of :py:class:`~binaryninja.lineardisassembly.LinearDisassemblyLine` objects for the next lines.
		:Example:

			>>> settings = DisassemblySettings()
			>>> pos = bv.get_linear_disassembly_position_at(0x10001483, settings)
			>>> bv.get_next_linear_disassembly_lines(pos)
			[<0x10001483: xor     eax, eax  {0x0}>, <0x10001485: inc     eax  {0x1}>, ... , <0x10001488: >]
			>>> bv.get_next_linear_disassembly_lines(pos)
			[<0x10001488: push    dword [ebp+0x10 {arg_c}]>, ... , <0x1000149a: >]
			>>>
		"""
		result = []
		while len(result) == 0:
			result = pos.lines
			if not pos.next():
				return result
		return result

	def get_linear_disassembly(
	    self, settings: Optional['_function.DisassemblySettings'] = None
	) -> Iterator['lineardisassembly.LinearDisassemblyLine']:
		"""
		``get_linear_disassembly`` gets an iterator for all lines in the linear disassembly of the view for the given
		disassembly settings.

		.. note:: linear_disassembly doesn't just return disassembly; it will return a single line from the linear view,\
		 and thus will contain both data views, and disassembly.

		:param DisassemblySettings settings: instance specifying the desired output formatting. Defaults to None which will use default settings.
		:return: An iterator containing formatted disassembly lines.
		:rtype: LinearDisassemblyIterator
		:Example:

			>>> settings = DisassemblySettings()
			>>> lines = bv.get_linear_disassembly(settings)
			>>> for line in lines:
			...  print(line)
			...  break
			...
			cf fa ed fe 07 00 00 01  ........
		"""
		@dataclass
		class LinearDisassemblyIterator:
			view: 'BinaryView'
			settings: Optional['_function.DisassemblySettings'] = None

			def __iter__(self):
				pos = lineardisassembly.LinearViewCursor(
				    lineardisassembly.LinearViewObject.disassembly(self.view, self.settings)
				)
				while True:
					lines = self.view.get_next_linear_disassembly_lines(pos)
					if len(lines) == 0:
						break
					for line in lines:
						yield line

		return iter(LinearDisassemblyIterator(self, settings))

	def parse_type_string(self, text: str, import_dependencies: bool = True) -> Tuple['_types.Type', '_types.QualifiedName']:
		"""
		``parse_type_string`` parses string containing C into a single type :py:class:`Type`.
		In contrast to the :py:func:`~binaryninja.platform.Platform.parse_types_from_source` or :py:func:`~binaryninja.platform.Platform.parse_types_from_source_file`, ``parse_type_string``
		can only load a single type, though it can take advantage of existing type information in the binary
		view, while those two APIs do not.

		:param str text: C source code string of type to create
		:param import_dependencies: If Type Library / Type Archive types should be imported during parsing
		:return: A tuple of a :py:class:`Type` and type name
		:rtype: tuple(Type, QualifiedName)
		:Example:

			>>> bv.parse_type_string("int foo")
			(<type: int32_t>, 'foo')
			>>>
		"""
		if not isinstance(text, str):
			raise ValueError("Source must be a string")
		result = core.BNQualifiedNameAndType()
		assert result is not None, "core.BNQualifiedNameAndType returned None"
		try:
			errors = ctypes.c_char_p()
			type_list = core.BNQualifiedNameList()
			type_list.count = 0
			if not core.BNParseTypeString(self.handle, text, result, errors, type_list, import_dependencies):
				assert errors.value is not None, "core.BNParseTypeString returned 'errors' set to None"
				error_str = errors.value.decode("utf-8")
				core.free_string(errors)
				raise SyntaxError(error_str)
			type_obj = _types.Type.create(core.BNNewTypeReference(result.type), platform=self.platform)
			name = _types.QualifiedName._from_core_struct(result.name)
			return type_obj, name
		finally:
			core.BNFreeQualifiedNameAndType(result)

	def parse_types_from_string(self, text: str, options: Optional[List[str]] = None, include_dirs: Optional[List[str]] = None, import_dependencies: bool = True) -> '_types.TypeParserResult':
		"""
		``parse_types_from_string`` parses string containing C into a :py:class:`TypeParserResult` objects. This API
		unlike the :py:func:`~binaryninja.platform.Platform.parse_types_from_source` allows the reference of types already defined
		in the BinaryView.

		:param str text: C source code string of types, variables, and function types, to create
		:param options: Optional list of string options to be passed into the type parser
		:param include_dirs: Optional list of header search directories
		:param import_dependencies: If Type Library / Type Archive types should be imported during parsing
		:return: :py:class:`~binaryninja.typeparser.TypeParserResult` (a SyntaxError is thrown on parse error)
		:rtype: TypeParserResult
		:Example:

			>>> bv.parse_types_from_string('int foo;\\nint bar(int x);\\nstruct bas{int x,y;};\\n')
			({types: {'bas': <type: struct bas>}, variables: {'foo': <type: int32_t>}, functions:{'bar':
			<type: int32_t(int32_t x)>}}, '')
			>>>
		"""
		if not isinstance(text, str):
			raise ValueError("Source must be a string")

		if options is None:
			options = []
		if include_dirs is None:
			include_dirs = []

		parse = core.BNTypeParserResult()
		try:
			options_cpp = (ctypes.c_char_p * len(options))()
			for (i, s) in enumerate(options):
				options_cpp[i] = core.cstr(s)

			include_dirs_cpp = (ctypes.c_char_p * len(include_dirs))()
			for (i, s) in enumerate(include_dirs):
				include_dirs_cpp[i] = core.cstr(s)

			errors = ctypes.c_char_p()
			type_list = core.BNQualifiedNameList()
			type_list.count = 0
			if not core.BNParseTypesString(
					self.handle, text, options_cpp, len(options), include_dirs_cpp,
					len(include_dirs), parse, errors, type_list, import_dependencies):
				assert errors.value is not None, "core.BNParseTypesString returned errors set to None"
				error_str = errors.value.decode("utf-8")
				core.free_string(errors)
				raise SyntaxError(error_str)

			type_dict: Mapping[_types.QualifiedName, _types.Type] = {}
			variables: Mapping[_types.QualifiedName, _types.Type] = {}
			functions: Mapping[_types.QualifiedName, _types.Type] = {}
			for i in range(0, parse.typeCount):
				name = _types.QualifiedName._from_core_struct(parse.types[i].name)
				type_dict[name] = _types.Type.create(
				    core.BNNewTypeReference(parse.types[i].type), platform=self.platform
				)
			for i in range(0, parse.variableCount):
				name = _types.QualifiedName._from_core_struct(parse.variables[i].name)
				variables[name] = _types.Type.create(
				    core.BNNewTypeReference(parse.variables[i].type), platform=self.platform
				)
			for i in range(0, parse.functionCount):
				name = _types.QualifiedName._from_core_struct(parse.functions[i].name)
				functions[name] = _types.Type.create(
				    core.BNNewTypeReference(parse.functions[i].type), platform=self.platform
				)
			return _types.TypeParserResult(type_dict, variables, functions)
		finally:
			core.BNFreeTypeParserResult(parse)

	def parse_possiblevalueset(
	    self, value: str, state: RegisterValueType, here: int = 0
	) -> 'variable.PossibleValueSet':
		"""
		Evaluates a string representation of a PossibleValueSet into an instance of the ``PossibleValueSet`` value.

		.. note:: Values are evaluated based on the rules as specified for :py:func:`parse_expression` API. This implies that a ``ConstantValue [0x4000].d`` can be provided given that 4 bytes can be read at ``0x4000``. All constants are considered to be in hexadecimal form by default.

		The parser uses the following rules:
			- ConstantValue - ``<value>``
			- ConstantPointerValue - ``<value>``
			- StackFrameOffset - ``<value>``
			- SignedRangeValue - ``<value>:<value>:<value>{,<value>:<value>:<value>}*`` (Multiple ValueRanges can be provided by separating them by commas)
			- UnsignedRangeValue - ``<value>:<value>:<value>{,<value>:<value>:<value>}*`` (Multiple ValueRanges can be provided by separating them by commas)
			- InSetOfValues - ``<value>{,<value>}*``
			- NotInSetOfValues - ``<value>{,<value>}*``

		:param str value: PossibleValueSet value to be parsed
		:param RegisterValueType state: State for which the value is to be parsed
		:param int here: (optional) Base address for relative expressions, defaults to zero
		:rtype: PossibleValueSet
		:Example:

			>>> psv_c = bv.parse_possiblevalueset("400", RegisterValueType.ConstantValue)
			>>> psv_c
			<const 0x400>
			>>> psv_ur = bv.parse_possiblevalueset("1:10:1", RegisterValueType.UnsignedRangeValue)
			>>> psv_ur
			<unsigned ranges: [<range: 0x1 to 0x10>]>
			>>> psv_is = bv.parse_possiblevalueset("1,2,3", RegisterValueType.InSetOfValues)
			>>> psv_is
			<in set([0x1, 0x2, 0x3])>
			>>>
		"""
		result = core.BNPossibleValueSet()
		errors = ctypes.c_char_p()
		if value == None:
			value = ''
		if not core.BNParsePossibleValueSet(self.handle, value, state, result, here, errors):
			if errors:
				assert errors.value is not None, "core.BNParsePossibleValueSet returned errors set to None"
				error_str = errors.value.decode("utf-8")
			else:
				error_str = "Error parsing specified PossibleValueSet"
			core.BNFreePossibleValueSet(result)
			core.free_string(errors)
			raise ValueError(error_str)
		return variable.PossibleValueSet(self.arch, result)

	@property
	def type_container(self) -> 'typecontainer.TypeContainer':
		"""
		Type Container for all types (user and auto) in the BinaryView. Any auto types
		modified through the Type Container will be converted into user types.
		:return: Full view Type Container
		"""
		container = core.BNGetAnalysisTypeContainer(self.handle)
		return typecontainer.TypeContainer(handle=container)

	@property
	def auto_type_container(self) -> 'typecontainer.TypeContainer':
		"""
		Type Container for ONLY auto types in the BinaryView. Any changes to types will
		NOT promote auto types to user types.
		:return: Auto types only Type Container
		"""
		container = core.BNGetAnalysisAutoTypeContainer(self.handle)
		return typecontainer.TypeContainer(handle=container)

	@property
	def user_type_container(self) -> 'typecontainer.TypeContainer':
		"""
		Type Container for ONLY user types in the BinaryView.
		:return: User types only Type Container
		"""
		container = core.BNGetAnalysisUserTypeContainer(self.handle)
		return typecontainer.TypeContainer(handle=container)

	def get_type_by_name(self, name: '_types.QualifiedNameType') -> Optional['_types.Type']:
		"""
		``get_type_by_name`` returns the defined type whose name corresponds with the provided ``name``

		:param QualifiedName name: Type name to lookup
		:return: A :py:class:`Type` or None if the type does not exist
		:rtype: Type or None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_user_type(name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
			>>>
		"""
		_name = _types.QualifiedName(name)._to_core_struct()
		obj = core.BNGetAnalysisTypeByName(self.handle, _name)
		if not obj:
			return None
		return _types.Type.create(obj, platform=self.platform)

	def get_type_by_id(self, id: str) -> Optional['_types.Type']:
		"""
		``get_type_by_id`` returns the defined type whose unique identifier corresponds with the provided ``id``

		:param str id: Unique identifier to lookup
		:return: A :py:class:`Type` or None if the type does not exist
		:rtype: Type or None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> type_id = Type.generate_auto_type_id("source", name)
			>>> bv.define_type(type_id, name, type)
			>>> bv.get_type_by_id(type_id)
			<type: int32_t>
			>>>
		"""
		obj = core.BNGetAnalysisTypeById(self.handle, id)
		if not obj:
			return None
		return _types.Type.create(obj, platform=self.platform)

	def get_type_name_by_id(self, id: str) -> Optional['_types.QualifiedName']:
		"""
		``get_type_name_by_id`` returns the defined type name whose unique identifier corresponds with the provided ``id``

		:param str id: Unique identifier to lookup
		:return: A QualifiedName or None if the type does not exist
		:rtype: QualifiedName or None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> type_id = Type.generate_auto_type_id("source", name)
			>>> bv.define_type(type_id, name, type)
			'foo'
			>>> bv.get_type_name_by_id(type_id)
			'foo'
			>>>
		"""
		name = core.BNGetAnalysisTypeNameById(self.handle, id)
		result = _types.QualifiedName._from_core_struct(name)
		core.BNFreeQualifiedName(name)
		if len(result) == 0:
			return None
		return result

	def get_type_id(self, name: '_types.QualifiedNameType') -> str:
		"""
		``get_type_id`` returns the unique identifier of the defined type whose name corresponds with the
		provided ``name``

		:param QualifiedName name: Type name to lookup
		:return: The unique identifier of the type
		:rtype: str
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> type_id = Type.generate_auto_type_id("source", name)
			>>> registered_name = bv.define_type(type_id, name, type)
			>>> bv.get_type_id(registered_name) == type_id
			True
			>>>
		"""
		_name = _types.QualifiedName(name)._to_core_struct()
		return core.BNGetAnalysisTypeId(self.handle, _name)

	def add_type_library(self, lib: 'typelibrary.TypeLibrary') -> None:
		"""
		``add_type_library`` make the contents of a type library available for type/import resolution

		:param TypeLibrary lib: library to register with the view
		:rtype: None
		"""
		if not isinstance(lib, typelibrary.TypeLibrary):
			raise ValueError("must pass in a TypeLibrary object")
		core.BNAddBinaryViewTypeLibrary(self.handle, lib.handle)

	def get_type_library(self, name: str) -> Optional['typelibrary.TypeLibrary']:
		"""
		``get_type_library`` returns the TypeLibrary

		:param str name: Library name to lookup
		:return: The Type Library object, if any
		:rtype: TypeLibrary or None
		:Example:

		"""
		handle = core.BNGetBinaryViewTypeLibrary(self.handle, name)
		if handle is None:
			return None
		return typelibrary.TypeLibrary(handle)

	def is_type_auto_defined(self, name: '_types.QualifiedNameType') -> bool:
		"""
		``is_type_auto_defined`` queries the user type list of name. If name is not in the *user* type list then the name
		is considered an *auto* type.

		:param QualifiedName name: Name of type to query
		:return: True if the type is not a *user* type. False if the type is a *user* type.
		:Example:
			>>> bv.is_type_auto_defined("foo")
			True
			>>> bv.define_user_type("foo", bv.parse_type_string("struct {int x,y;}")[0])
			>>> bv.is_type_auto_defined("foo")
			False
			>>>
		"""
		_name = _types.QualifiedName(name)._to_core_struct()
		return core.BNIsAnalysisTypeAutoDefined(self.handle, _name)

	def define_type(
	    self, type_id: str, default_name: Optional['_types.QualifiedNameType'], type_obj: StringOrType
	) -> '_types.QualifiedName':
		"""
		``define_type`` registers a :py:class:`Type` ``type_obj`` of the given ``name`` in the global list of types for
		the current :py:class:`BinaryView`. This method should only be used for automatically generated types.

		:param str type_id: Unique identifier for the automatically generated type
		:param QualifiedName default_name: Name of the type to be registered
		:param StringOrType type_obj: Type object to be registered
		:return: Registered name of the type. May not be the same as the requested name if the user has renamed types.
		:rtype: QualifiedName
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> registered_name = bv.define_type(Type.generate_auto_type_id("source", name), name, type)
			>>> bv.get_type_by_name(registered_name)
			<type: int32_t>
			>>> registered_name = bv.define_type("mytypeid", None, "int bar")
			>>> bv.get_type_by_name(registered_name)
			<type: int32_t>
		"""

		if isinstance(type_obj, str):
			(type_obj, new_name) = self.parse_type_string(type_obj)
			if default_name is None:
				default_name = new_name
		assert default_name is not None, "default_name can only be None if named type is derived from string passed to type_obj"
		name = _types.QualifiedName(default_name)._to_core_struct()
		reg_name = core.BNDefineAnalysisType(self.handle, type_id, name, type_obj.handle)
		result = _types.QualifiedName._from_core_struct(reg_name)
		core.BNFreeQualifiedName(reg_name)
		return result

	def define_user_type(self, name: Optional['_types.QualifiedNameType'], type_obj: StringOrType) -> None:
		"""
		``define_user_type`` registers a :py:class:`Type` ``type_obj`` of the given ``name`` in the global list of user
		types for the current :py:class:`BinaryView`.

		:param QualifiedName name: Name of the user type to be registered
		:param StringOrType type_obj: Type object to be registered
		:rtype: None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_user_type(name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
			>>> bv.define_user_type(None, "int bas")
			>>> bv.get_type_by_name("bas")
			<type: int32_t>
		"""
		if isinstance(type_obj, str):
			(type_obj, new_name) = self.parse_type_string(type_obj)
			if name is None:
				name = new_name
		if name is None:
			raise ValueError("name can only be None if named type is derived from string passed to type_obj")
		_name = _types.QualifiedName(name)._to_core_struct()
		core.BNDefineUserAnalysisType(self.handle, _name, type_obj.handle)

	def define_types(self, types: List[Tuple[str, Optional['_types.QualifiedNameType'], StringOrType]], progress_func: Optional[ProgressFuncType]) -> Mapping[str, '_types.QualifiedName']:
		"""
		``define_types`` registers multiple types as though calling :py:func:`define_type` multiple times.
		The difference with this plural version is that it is optimized for adding many types
		at the same time, using knowledge of all types at add-time to improve runtime.
		There is an optional ``progress_func`` callback function in case you want updates for a long-running call.

		.. warning:: This method should only be used for automatically generated types, see :py:func:`define_user_types` for interactive plugin uses.

		The return values of this function provide a map of each type id and which name was chosen for that type
		(which may be different from the requested name).

		:param types: List of type ids/names/definitions for the new types. Check :py:func:`define_type` for more details.
		:param progress: Function to call for progress updates
		:return: A map of all the chosen names for the defined types with their ids.
		"""
		api_types = (core.BNQualifiedNameTypeAndId * len(types))()
		for i, (type_id, default_name, type_obj) in enumerate(types):
			if isinstance(type_obj, str):
				(type_obj, new_name) = self.parse_type_string(type_obj)
				if default_name is None:
					default_name = new_name
			assert default_name is not None, "default_name can only be None if named type is derived from string passed to type_obj"
			api_types[i].name = _types.QualifiedName(default_name)._to_core_struct()
			api_types[i].id = core.cstr(type_id)
			api_types[i].type = type_obj.handle

		if progress_func:
			progress_func_obj = ctypes.CFUNCTYPE(
				ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: progress_func(cur, total))
		else:
			progress_func_obj = ctypes.CFUNCTYPE(
				ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: True)

		result_ids = ctypes.POINTER(ctypes.c_char_p)()
		result_names = ctypes.POINTER(core.BNQualifiedName)()

		result_count = core.BNDefineAnalysisTypes(self.handle, api_types, len(types), progress_func_obj, None, result_ids, result_names)

		try:
			result = {}
			for i in range(result_count):
				id = core.pyNativeStr(result_ids[i])
				name = _types.QualifiedName._from_core_struct(result_names[i])
				result[id] = name
			return result
		finally:
			core.BNFreeStringList(result_ids, result_count)
			core.BNFreeTypeNameList(result_names, result_count)

	def define_user_types(self, types: List[Tuple[Optional['_types.QualifiedNameType'], StringOrType]], progress_func: Optional[ProgressFuncType]):
		"""
		``define_user_types`` registers multiple types as though calling :py:func:`define_user_type` multiple times.
		The difference with this plural version is that it is optimized for adding many types
		at the same time, using knowledge of all types at add-time to improve runtime.
		There is an optional ``progress_func`` callback function in case you want updates for a long-running call.

		:param types: List of type names/definitions for the new types. Check :py:func:`define_user_type` for more details.
		:param progress: Function to call for progress updates
		"""
		api_types = (core.BNQualifiedNameAndType * len(types))()
		for i, (default_name, type_obj) in enumerate(types):
			if isinstance(type_obj, str):
				(type_obj, new_name) = self.parse_type_string(type_obj)
				if default_name is None:
					default_name = new_name
			assert default_name is not None, "default_name can only be None if named type is derived from string passed to type_obj"
			api_types[i].name = _types.QualifiedName(default_name)._to_core_struct()
			api_types[i].type = type_obj.handle

		if progress_func:
			progress_func_obj = ctypes.CFUNCTYPE(
				ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: progress_func(cur, total))
		else:
			progress_func_obj = ctypes.CFUNCTYPE(
				ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: True)

		core.BNDefineUserAnalysisTypes(self.handle, api_types, len(types), progress_func_obj, None)

	def undefine_type(self, type_id: str) -> None:
		"""
		``undefine_type`` removes a :py:class:`Type` from the global list of types for the current :py:class:`BinaryView`

		:param str type_id: Unique identifier of type to be undefined
		:rtype: None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> type_id = Type.generate_auto_type_id("source", name)
			>>> bv.define_type(type_id, name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
			>>> bv.undefine_type(type_id)
			>>> bv.get_type_by_name(name)
			>>>
		"""
		core.BNUndefineAnalysisType(self.handle, type_id)

	def undefine_user_type(self, name: '_types.QualifiedNameType') -> None:
		"""
		``undefine_user_type`` removes a :py:class:`Type` from the global list of user types for the current
		:py:class:`BinaryView`

		:param QualifiedName name: Name of user type to be undefined
		:rtype: None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_user_type(name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
			>>> bv.undefine_user_type(name)
			>>> bv.get_type_by_name(name)
			>>>
		"""
		_name = _types.QualifiedName(name)._to_core_struct()
		core.BNUndefineUserAnalysisType(self.handle, _name)

	def rename_type(self, old_name: '_types.QualifiedNameType', new_name: '_types.QualifiedNameType') -> None:
		"""
		``rename_type`` renames a type in the global list of types for the current :py:class:`BinaryView`

		:param QualifiedName old_name: Existing name of type to be renamed
		:param QualifiedName new_name: New name of type to be renamed
		:rtype: None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_user_type(name, type)
			>>> bv.get_type_by_name("foo")
			<type: int32_t>
			>>> bv.rename_type("foo", "bar")
			>>> bv.get_type_by_name("bar")
			<type: int32_t>
			>>>
		"""
		_old_name = _types.QualifiedName(old_name)._to_core_struct()
		_new_name = _types.QualifiedName(new_name)._to_core_struct()
		core.BNRenameAnalysisType(self.handle, _old_name, _new_name)

	def import_library_type(self, name: str, lib: Optional[typelibrary.TypeLibrary] = None) -> Optional['_types.Type']:
		"""
		``import_library_type`` recursively imports a type from the specified type library, or, if
		no library was explicitly provided, the first type library associated with the current :py:class:`BinaryView`
		that provides the name requested.

		This may have the impact of loading other type libraries as dependencies on other type libraries are lazily resolved
		when references to types provided by them are first encountered.

		Note that the name actually inserted into the view may not match the name as it exists in the type library in
		the event of a name conflict. To aid in this, the :py:class:`Type` object returned is a `NamedTypeReference` to
		the deconflicted name used.

		:param QualifiedName name:
		:param TypeLibrary lib:
		:return: a `NamedTypeReference` to the type, taking into account any renaming performed
		:rtype: Type
		"""
		_name = _types.QualifiedName(name)
		_lib = ctypes.POINTER(ctypes.POINTER(core.BNTypeLibrary))()
		if lib is not None:
			_lib.contents = lib.handle
		else:
			_lib.contents = ctypes.POINTER(core.BNTypeLibrary)()

		handle = core.BNBinaryViewImportTypeLibraryType(
		    self.handle, _lib, _name._to_core_struct()
		)
		if handle is None:
			return None
		return _types.Type.create(handle, platform=self.platform)

	def import_type_by_guid(self, guid: Union[str, uuid.UUID]) -> Optional['_types.Type']:
		"""
		``import_type_by_guid`` recursively imports a type interface given its GUID.

		.. note:: To support this type of lookup a type library must have
			contain a metadata key called "type_guids" which is a map
			Dict[string_guid, string_type_name] or
			Dict[string_guid, Tuple[string_type_name, type_library_name]]

		:param str guid: GUID of the COM interface to import
		:return: the object type, with any interior `NamedTypeReferences` renamed as necessary to be appropriate for the current view
		:rtype: Type
		"""
		if not isinstance(guid, str):
			guid = str(guid)

		if self.arch is None:
			return None

		if type_handle := core.BNBinaryViewImportTypeLibraryTypeByGuid(self.handle, guid):
			return _types.Type.create(type_handle, platform=self.platform)

		return None

	def import_library_object(self, name: str, lib: Optional[typelibrary.TypeLibrary] = None) -> Optional[Tuple['typelibrary.TypeLibrary', '_types.Type']]:
		"""
		``import_library_object`` recursively imports an object from the specified type library, or, if \
		no library was explicitly provided, the first type library associated with the current :py:class:`BinaryView` \
		that provides the name requested.

		This may have the impact of loading other type libraries as dependencies on other type libraries are lazily resolved \
		when references to types provided by them are first encountered.

		.. note:: If you are implementing a custom BinaryView and use this method to import object types, \
		you should then call ``record_imported_object`` with the details of where the object is located.

		:param QualifiedName name:
		:param TypeLibrary lib:
		:return: the object type, with any interior `NamedTypeReferences` renamed as necessary to be appropriate for the current view
		:rtype: Type
		"""
		_name = _types.QualifiedName(name)
		_lib = ctypes.POINTER(ctypes.POINTER(core.BNTypeLibrary))()
		if lib is not None:
			_lib.contents = lib.handle
		else:
			_lib.contents = ctypes.POINTER(core.BNTypeLibrary)()

		handle = core.BNBinaryViewImportTypeLibraryObject(
		    self.handle, _lib, _name._to_core_struct()
		)
		if handle is None:
			return None
		return _types.Type.create(handle, platform=self.platform)

	def export_type_to_library(self, lib: typelibrary.TypeLibrary, name: Optional[str], type_obj: StringOrType) -> None:
		"""
		``export_type_to_library`` recursively exports ``type_obj`` into ``lib`` as a type with name ``name``

		As other referenced types are encountered, they are either copied into the destination type library or
		else the type library that provided the referenced type is added as a dependency for the destination library.

		:param TypeLibrary lib:
		:param QualifiedName name:
		:param StringOrType type_obj:
		:rtype: None
		"""
		_name = None
		if name is not None:
			_name = _types.QualifiedName(name)
		if not isinstance(lib, typelibrary.TypeLibrary):
			raise TypeError("lib must be a TypeLibrary object")
		if isinstance(type_obj, str):
			(type_obj, new_name) = self.parse_type_string(type_obj)
			if name is None:
				_name = new_name
		if not isinstance(type_obj, (_types.Type, _types.TypeBuilder)):
			raise TypeError("type_obj must be a Type object")
		if _name is None:
			raise ValueError("name can only be None if named type is derived from string passed to type_obj")
		core.BNBinaryViewExportTypeToTypeLibrary(self.handle, lib.handle, _name._to_core_struct(), type_obj.handle)

	def export_object_to_library(
	    self, lib: typelibrary.TypeLibrary, name: Optional[str], type_obj: StringOrType
	) -> None:
		"""
		``export_object_to_library`` recursively exports ``type_obj`` into ``lib`` as an object with name ``name``

		As other referenced types are encountered, they are either copied into the destination type library or
		else the type library that provided the referenced type is added as a dependency for the destination library.

		:param TypeLibrary lib:
		:param QualifiedName name:
		:param StringOrType type_obj:
		:rtype: None
		"""

		_name = None
		if name is not None:
			_name = _types.QualifiedName(name)
		if not isinstance(lib, typelibrary.TypeLibrary):
			raise TypeError("lib must be a TypeLibrary object")
		if isinstance(type_obj, str):
			(type_obj, new_name) = self.parse_type_string(type_obj)
			if name is None:
				_name = new_name
		if not isinstance(type_obj, (_types.Type, _types.TypeBuilder)):
			raise TypeError("type_obj must be a Type object")
		if _name is None:
			raise ValueError("name can only be None if named type is derived from string passed to type_obj")
		core.BNBinaryViewExportObjectToTypeLibrary(self.handle, lib.handle, _name._to_core_struct(), type_obj.handle)

	def set_manual_type_source_override(self, entries: Mapping['_types.QualifiedName', Tuple['_types.QualifiedName', str]]):
		"""
		This allows for fine-grained control over how types from this BinaryView are exported to a TypeLibrary
		by `export_type_to_library` and `export_object_to_library`. Types identified by the keys of the dict
		will NOT be exported to the destination TypeLibrary, but will instead be treated as a type that had
		come from the string component of the value tuple. This results in the destination TypeLibrary gaining
		a new dependency.

		This is useful if a BinaryView was automatically marked up with a lot of debug information but you
		want to export only a subset of that information into a new TypeLibrary. By creating a description of
		which local types correspond to types in other already extant libraries, those types will be avoided
		during the recursive export.

		This data is not persisted and does not impact analysis.

		For example, if a BinaryView contains the following types:

.. code-block:: c

			struct RECT { ... }; // omitted
			struct ContrivedExample { RECT rect; };

Then the following python:

.. code-block:: python

			overrides = {"RECT": ("tagRECT", "winX64common")}
			bv.set_manual_type_source_override(overrides)
			bv.export_type_to_library(dest_new_typelib, "ContrivedExample", bv.get_type_by_name("ContrivedExample"))

Results in dest_new_typelib only having ContrivedExample added, and "RECT" being inserted as a dependency
to a the type "tagRECT" found in the typelibrary "winX64common"

		"""
		count = len(entries)
		src_names = (core.BNQualifiedName * count)()
		dst_names = (core.BNQualifiedName * count)()
		lib_names = (ctypes.c_char_p * count)()
		for (i, src, (dst, lib)) in enumerate(entries.items()):
			src_names[i] = src._to_core_struct()
			dst_names[i] = dst._to_core_struct()
			lib_names[i] = lib.encode("utf-8")
		core.BNBinaryViewSetManualDependencies(self.handle, src_names, dst_names, lib_names, count)

	def record_imported_object_library(
		self, lib: typelibrary.TypeLibrary, name: str, addr: int, platform: Optional['_platform.Platform'] = None
	) -> None:
		"""
		``record_imported_object_library`` should be called by custom py:py:class:`BinaryView` implementations
		when they have successfully imported an object from a type library (e.g. a symbol's type).
		Values recorded with this function will then be queryable via ``lookup_imported_object_library``.

		:param lib: Type Library containing the imported type
		:param name: Name of the object in the type library
		:param addr: address of symbol at import site
		:param platform: Platform of symbol at import site
		:rtype: None
		"""

		if platform is None:
			platform = self.platform

		if platform is None:
			raise Exception("Unable to record imported object library without a platform")

		core.BNBinaryViewRecordImportedObjectLibrary(self.handle, platform.handle, addr, lib.handle, _types.QualifiedName(name)._to_core_struct())

	def lookup_imported_object_library(
		self, addr: int, platform: Optional['_platform.Platform'] = None
	) -> Optional[Tuple[typelibrary.TypeLibrary, '_types.QualifiedName']]:
		"""
		``lookup_imported_object_library`` gives you details of which type library and name was used to determine
		the type of a symbol at a given address

		:param addr: address of symbol at import site
		:param platform: Platform of symbol at import site
		:return: A tuple of [TypeLibrary, QualifiedName] with the library and name used, or None if it was not imported
		:rtype: Tuple[TypeLibrary, QualifiedName]
		"""

		if platform is None:
			platform = self.platform

		result_lib = (ctypes.POINTER(core.BNTypeLibrary) * 1)()
		result_name = (core.BNQualifiedName * 1)()
		if not core.BNBinaryViewLookupImportedObjectLibrary(self.handle, platform.handle, addr, result_lib, result_name):
			return None
		lib = typelibrary.TypeLibrary(result_lib[0])
		name = _types.QualifiedName._from_core_struct(result_name[0])
		core.BNFreeQualifiedName(result_name)
		return lib, name

	def lookup_imported_type_library(
		self, name: '_types.QualifiedNameType'
	) -> Optional[Tuple[typelibrary.TypeLibrary, '_types.QualifiedName']]:
		"""
		``lookup_imported_type_library`` gives you details of from which type library and name
		a given type in the analysis was imported.

		:param name: Name of type in analysis
		:return: A tuple of [TypeLibrary, QualifiedName] with the library and name used, or None if it was not imported
		:rtype: Optional[Tuple[TypeLibrary, QualifiedName]]
		"""
		name = _types.QualifiedName(name)
		result_lib = (ctypes.POINTER(core.BNTypeLibrary) * 1)()
		result_name = (core.BNQualifiedName * 1)()
		if not core.BNBinaryViewLookupImportedTypeLibrary(self.handle, name._to_core_struct(), result_lib, result_name):
			return None
		lib = typelibrary.TypeLibrary(result_lib[0])
		name = _types.QualifiedName._from_core_struct(result_name[0])
		core.BNFreeQualifiedName(result_name)
		return lib, name

	def attach_type_archive(self, archive: 'typearchive.TypeArchive'):
		"""
		Attach a given type archive to the analysis and try to connect to it.
		If attaching was successful, names from that archive will become available to pull,
		but no types will actually be associated by calling this.

		:param archive: New archive
		"""
		attached = self.attach_type_archive_by_id(archive.id, archive.path)
		assert attached == archive

	def attach_type_archive_by_id(self, id: str, path: str) -> Optional['typearchive.TypeArchive']:
		"""
		Attach a type archive to the owned analysis and try to connect to it.
		If attaching was successful, names from that archive will become available to pull,
		but no types will actually be associated by calling this.

		The behavior of this function is rather complicated, in an attempt to enable the
		ability to have attached, but disconnected Type Archives.

		Normal operation:

		If there was no previously connected Type Archive whose id matches `id`, and the
		file at `path` contains a Type Archive whose id matches `id`, it will be
		attached and connected.

		Edge-cases:

		If there was a previously connected Type Archive whose id matches `id`, nothing
		will happen, and it will simply be returned.
		If the file at `path` does not exist, nothing will happen and None will be returned.
		If the file at `path` exists but does not contain a Type Archive whose id matches `id`,
		nothing will happen and None will be returned.
		If there was a previously attached but disconnected Type Archive whose id matches `id`,
		and the file at `path` contains a Type Archive whose id matches `id`, the
		previously attached Type Archive will have its saved path updated to point
		to `path`. The Type Archive at `path` will be connected and returned.

		:param id: Id of Type Archive to attach
		:param path: Path to file of Type Archive to attach
		:return: Attached archive object, if it could be connected.
		"""
		archive = core.BNBinaryViewAttachTypeArchive(self.handle, id, path)
		if not archive:
			return None
		return typearchive.TypeArchive(handle=archive)

	def detach_type_archive(self, archive: 'typearchive.TypeArchive'):
		"""
		Detach from a type archive, breaking all associations to types within the archive

		:param archive: Type archive to detach
		"""
		self.detach_type_archive_by_id(archive.id)

	def detach_type_archive_by_id(self, id: str):
		"""
		Detach from a type archive, breaking all associations to types within the archive

		:param id: Id of archive to detach
		"""
		if not core.BNBinaryViewDetachTypeArchive(self.handle, id):
			raise RuntimeError("BNBinaryViewDetachTypeArchive")

	def get_type_archive(self, id: str) -> Optional['typearchive.TypeArchive']:
		"""
		Look up a connected archive by its id

		:param id: Id of archive
		:return: Archive, if one exists with that id. Otherwise None
		"""
		result = core.BNBinaryViewGetTypeArchive(self.handle, id)
		if result is None:
			return None
		return typearchive.TypeArchive(result)

	def get_type_archive_path(self, id: str) -> Optional[str]:
		"""
		Look up the path for an attached (but not necessarily connected) type archive by its id

		:param id: Id of archive
		:return: Archive path, if it is attached. Otherwise None.
		"""
		result = core.BNBinaryViewGetTypeArchivePath(self.handle, id)
		if result is None:
			return None
		return result

	@property
	def type_archive_type_names(self) -> Mapping['_types.QualifiedName', List[Tuple['typearchive.TypeArchive', str]]]:
		"""
		Get a list of all available type names in all connected archives, and their archive/type id pair

		:return: name <-> [(archive, archive type id)] for all type names
		"""
		result = {}

		archives = self.connected_type_archives
		for archive in archives:
			for (id, name) in archive.type_names_and_ids.items():
				if name in result:
					result[name].append((archive, id))
				else:
					result[name] = [(archive, id)]
		return result

	def get_type_archives_for_type_name(self, name: '_types.QualifiedNameType') -> List[Tuple['typearchive.TypeArchive', str]]:
		"""
		Get a list of all connected type archives that have a given type name

		:return: (archive, archive type id) for all archives
		"""
		name = _types.QualifiedName(name)
		archive_ids = ctypes.POINTER(ctypes.c_char_p)()
		type_ids = ctypes.POINTER(ctypes.c_char_p)()
		id_count = core.BNBinaryViewGetTypeArchiveTypeNames(self.handle, name._to_core_struct(), archive_ids, type_ids)
		ids = []

		type_archives = self.connected_type_archives
		type_archives_by_id = {}
		for archive in type_archives:
			type_archives_by_id[archive.id] = archive
		try:
			for j in range(0, id_count):
				ids.append((type_archives_by_id[core.pyNativeStr(archive_ids[j])], core.pyNativeStr(type_ids[j])))
			return ids
		finally:
			core.BNFreeStringList(archive_ids, id_count)
			core.BNFreeStringList(type_ids, id_count)

	@property
	def associated_type_archive_types(self) -> Mapping['_types.QualifiedName', Tuple[Optional['typearchive.TypeArchive'], str]]:
		"""
		Get a list of all types in the analysis that are associated with attached type archives

		:return: Map of all analysis types to their corresponding archive / id. If a type is associated with a disconnected type archive, the archive will be None.
		"""
		result = {}

		type_archives = self.attached_type_archives
		type_archives_by_id = {}
		for (archive_id, _) in type_archives.items():
			type_archives_by_id[archive_id] = self.get_type_archive(archive_id)

		for type_id, (archive_id, archive_type_id) in self.associated_type_archive_type_ids.items():
			name = self.get_type_name_by_id(type_id)
			if name is None:
				continue
			result[name] = (type_archives_by_id.get(archive_id, None), archive_type_id)
		return result

	@property
	def associated_type_archive_type_ids(self) -> Mapping[str, Tuple[str, str]]:
		"""
		Get a list of all types in the analysis that are associated with type archives

		:return: Map of all analysis types to their corresponding archive / id
		"""

		type_ids = ctypes.POINTER(ctypes.c_char_p)()
		archive_ids = ctypes.POINTER(ctypes.c_char_p)()
		archive_type_ids = ctypes.POINTER(ctypes.c_char_p)()
		count = core.BNBinaryViewGetAssociatedTypeArchiveTypes(self.handle, type_ids, archive_ids, archive_type_ids)

		result = {}
		try:
			for i in range(0, count):
				type_id = core.pyNativeStr(type_ids[i])
				archive_id = core.pyNativeStr(archive_ids[i])
				archive_type_id = core.pyNativeStr(archive_type_ids[i])
				result[type_id] = (archive_id, archive_type_id)
			return result
		finally:
			core.BNFreeStringList(type_ids, count)
			core.BNFreeStringList(archive_ids, count)
			core.BNFreeStringList(archive_type_ids, count)

	def get_associated_types_from_archive(self, archive: 'typearchive.TypeArchive') -> Mapping['_types.QualifiedName', str]:
		"""
		Get a list of all types in the analysis that are associated with a specific type archive

		:return: Map of all analysis types to their corresponding archive id
		"""
		result = {}

		for type_id, archive_type_id in self.get_associated_types_from_archive_by_id(archive.id).items():
			name = self.get_type_name_by_id(type_id)
			if name is None:
				continue
			result[name] = archive_type_id
		return result

	def get_associated_types_from_archive_by_id(self, archive_id: str) -> Mapping[str, str]:
		"""
		Get a list of all types in the analysis that are associated with a specific type archive
		:return: Map of all analysis types to their corresponding archive id
		"""

		type_ids = ctypes.POINTER(ctypes.c_char_p)()
		archive_type_ids = ctypes.POINTER(ctypes.c_char_p)()
		count = core.BNBinaryViewGetAssociatedTypesFromArchive(self.handle, archive_id, type_ids, archive_type_ids)

		result = {}
		try:
			for i in range(0, count):
				type_id = core.pyNativeStr(type_ids[i])
				archive_type_id = core.pyNativeStr(archive_type_ids[i])
				result[type_id] = archive_type_id
			return result
		finally:
			core.BNFreeStringList(type_ids, count)
			core.BNFreeStringList(archive_type_ids, count)

	def get_associated_type_archive_type_target(self, name: '_types.QualifiedNameType') -> Optional[Tuple[Optional['typearchive.TypeArchive'], str]]:
		"""
		Determine the target archive / type id of a given analysis type

		:param name: Analysis type
		:return: (archive, archive type id) if the type is associated. None otherwise.
		"""
		type_id = self.get_type_id(name)
		if type_id == '':
			return None
		result = self.get_associated_type_archive_type_target_by_id(type_id)
		if result is None:
			return None
		archive_id, type_id = result
		archive = self.get_type_archive(archive_id)
		return archive, type_id

	def get_associated_type_archive_type_target_by_id(self, type_id: str) -> Optional[Tuple[str, str]]:
		"""
		Determine the target archive / type id of a given analysis type

		:param type_id: Analysis type id
		:return: (archive id, archive type id) if the type is associated. None otherwise.
		"""
		archive_id = ctypes.c_char_p()
		archive_type_id = ctypes.c_char_p()
		if not core.BNBinaryViewGetAssociatedTypeArchiveTypeTarget(self.handle, type_id, archive_id, archive_type_id):
			return None
		result = (core.pyNativeStr(archive_id.value), core.pyNativeStr(archive_type_id.value))
		core.free_string(archive_id)
		core.free_string(archive_type_id)
		return result

	def get_associated_type_archive_type_source(self, archive: 'typearchive.TypeArchive', archive_type: '_types.QualifiedNameType') -> Optional['_types.QualifiedName']:
		"""
		Determine the local source type name for a given archive type

		:param archive: Target type archive
		:param archive_type: Name of target archive type
		:return: Name of source analysis type, if this type is associated. None otherwise.
		"""
		archive_type_id = archive.get_type_id(archive_type)
		if archive_type_id is None:
			return None
		result = self.get_associated_type_archive_type_source_by_id(archive.id, archive_type_id)
		if result is None:
			return None
		return self.get_type_name_by_id(result)

	def get_associated_type_archive_type_source_by_id(self, archive_id: str, archive_type_id: str) -> Optional[str]:
		"""
		Determine the local source type id for a given archive type

		:param archive_id: Id of target type archive
		:param archive_type_id: Id of target archive type
		:return: Id of source analysis type, if this type is associated. None otherwise.
		"""
		type_id = ctypes.c_char_p()
		if not core.BNBinaryViewGetAssociatedTypeArchiveTypeSource(self.handle, archive_id, archive_type_id, type_id):
			return None
		result = core.pyNativeStr(type_id.value)
		core.free_string(type_id)
		return result

	def disassociate_type_archive_type(self, type: '_types.QualifiedNameType') -> bool:
		"""
		Disassociate an associated type, so that it will no longer receive updates from its connected type archive

		:param type: Name of type in analysis
		:return: True if successful
		"""
		type_id = self.get_type_id(type)
		if type_id == '':
			return False
		return self.disassociate_type_archive_type_by_id(type_id)

	def disassociate_type_archive_type_by_id(self, type_id: str) -> bool:
		"""
		Disassociate an associated type id, so that it will no longer receive updates from its connected type archive

		:param type_id: Id of type in analysis
		:return: True if successful
		"""
		return core.BNBinaryViewDisassociateTypeArchiveType(self.handle, type_id)

	def pull_types_from_archive(self, archive: 'typearchive.TypeArchive', names: List['_types.QualifiedNameType']) \
			-> Optional[Mapping['_types.QualifiedName', Tuple['_types.QualifiedName', '_types.Type']]]:
		"""
		Pull types from a type archive, updating them and any dependencies

		:param archive: Target type archive
		:param names: Names of desired types in type archive
		:return: { name: (name, type) } Mapping from archive name to (analysis name, definition), None on error
		"""
		archive_type_ids = []
		for name in names:
			archive_type_id = archive.get_type_id(name)
			if archive_type_id is None:
				return None
			archive_type_ids.append(archive_type_id)
		result = self.pull_types_from_archive_by_id(archive.id, archive_type_ids)
		if result is None:
			return None

		results = {}
		for (archive_type_id, analysis_type_id) in result.items():
			results[archive.get_type_name_by_id(archive_type_id)] = (self.get_type_name_by_id(analysis_type_id), self.get_type_by_id(analysis_type_id))

		return results

	def pull_types_from_archive_by_id(self, archive_id: str, archive_type_ids: List[str]) \
			-> Optional[Mapping[str, str]]:
		"""
		Pull types from a type archive by id, updating them and any dependencies

		:param archive_id: Target type archive id
		:param archive_type_ids: Ids of desired types in type archive
		:return: { id: id } Mapping from archive type id to analysis type id, None on error
		"""
		api_ids = (ctypes.c_char_p * len(archive_type_ids))()
		for i, id in enumerate(archive_type_ids):
			api_ids[i] = core.cstr(id)

		updated_archive_type_strs = ctypes.POINTER(ctypes.c_char_p)()
		updated_analysis_type_strs = ctypes.POINTER(ctypes.c_char_p)()
		updated_type_count = ctypes.c_size_t(0)
		try:
			if not core.BNBinaryViewPullTypeArchiveTypes(self.handle, archive_id, api_ids, len(archive_type_ids), updated_archive_type_strs, updated_analysis_type_strs, updated_type_count):
				return None

			results = {}
			for i in range(0, updated_type_count.value):
				results[core.pyNativeStr(updated_archive_type_strs[i])] = core.pyNativeStr(updated_analysis_type_strs[i])
			return results
		finally:
			core.BNFreeStringList(updated_archive_type_strs, updated_type_count.value)
			core.BNFreeStringList(updated_analysis_type_strs, updated_type_count.value)

	def push_types_to_archive(self, archive: 'typearchive.TypeArchive', names: List['_types.QualifiedNameType']) \
			-> Optional[Mapping['_types.QualifiedName', Tuple['_types.QualifiedName', '_types.Type']]]:
		"""
		Push a collection of types, and all their dependencies, into a type archive

		:param archive: Target type archive
		:param names: Names of types in analysis
		:return: { name: (name, type) } Mapping from analysis name to (archive name, definition), None on error
		"""
		analysis_type_ids = []
		for name in names:
			analysis_type_id = self.get_type_id(name)
			if analysis_type_id is None:
				return None
			analysis_type_ids.append(analysis_type_id)
		result = self.push_types_to_archive_by_id(archive.id, analysis_type_ids)
		if result is None:
			return None

		results = {}
		for (analysis_type_id, archive_type_id) in result.items():
			results[self.get_type_name_by_id(analysis_type_id)] = (archive.get_type_name_by_id(archive_type_id), archive.get_type_by_id(archive_type_id))

		return results

	def push_types_to_archive_by_id(self, archive_id: str, type_ids: List[str]) \
			-> Optional[Mapping[str, str]]:
		"""
		Push a collection of types, and all their dependencies, into a type archive

		:param archive_id: Id of target type archive
		:param type_ids: Ids of types in analysis
		:return: True if successful
		"""
		api_ids = (ctypes.c_char_p * len(type_ids))()
		for i, id in enumerate(type_ids):
			api_ids[i] = core.cstr(id)

		updated_analysis_type_strs = ctypes.POINTER(ctypes.c_char_p)()
		updated_archive_type_strs = ctypes.POINTER(ctypes.c_char_p)()
		updated_type_count = ctypes.c_size_t(0)
		try:
			if not core.BNBinaryViewPushTypeArchiveTypes(self.handle, archive_id, api_ids, len(type_ids), updated_analysis_type_strs, updated_archive_type_strs, updated_type_count):
				return None

			results = {}
			for i in range(0, updated_type_count.value):
				results[core.pyNativeStr(updated_analysis_type_strs[i])] = core.pyNativeStr(updated_archive_type_strs[i])
			return results
		finally:
			core.BNFreeStringList(updated_analysis_type_strs, updated_type_count.value)
			core.BNFreeStringList(updated_archive_type_strs, updated_type_count.value)

	def register_platform_types(self, platform: '_platform.Platform') -> None:
		"""
		``register_platform_types`` ensures that the platform-specific types for a :py:class:`Platform` are available
		for the current :py:class:`BinaryView`. This is automatically performed when adding a new function or setting
		the default platform.

		:param Platform platform: Platform containing types to be registered
		:rtype: None
		:Example:

			>>> platform = Platform["linux-x86"]
			>>> bv.register_platform_types(platform)
			>>>
		"""
		core.BNRegisterPlatformTypes(self.handle, platform.handle)

	def lookup_imported_type_platform(
		self, name: '_types.QualifiedNameType'
	) -> Optional[Tuple['_platform.Platform', '_types.QualifiedName']]:
		"""
		``lookup_imported_type_platform`` gives you details of from which platform and name
		a given type in the analysis was imported.

		:param name: Name of type in analysis
		:return: A tuple of [Platform, QualifiedName] with the platform and name used, or None if it was not imported
		:rtype: Optional[Tuple[Platform, QualifiedName]]
		"""
		name = _types.QualifiedName(name)
		result_platform = (ctypes.POINTER(core.BNPlatform) * 1)()
		result_name = (core.BNQualifiedName * 1)()
		if not core.BNLookupImportedTypePlatform(self.handle, name._to_core_struct(), result_platform, result_name):
			return None
		platform = _platform.CorePlatform._from_cache(handle=result_platform[0])
		name = _types.QualifiedName._from_core_struct(result_name[0])
		core.BNFreeQualifiedName(result_name)
		return platform, name

	def find_next_data(self, start: int, data: bytes, flags: FindFlag = FindFlag.FindCaseSensitive) -> Optional[int]:
		"""
		``find_next_data`` searches for the bytes ``data`` starting at the virtual address ``start`` until the end of the BinaryView.

		:param int start: virtual address to start searching from.
		:param Union[bytes, bytearray, str] data: data to search for
		:param FindFlag flags: (optional) defaults to case-insensitive data search

			==================== ============================
			FindFlag             Description
			==================== ============================
			FindCaseSensitive    Case-sensitive search
			FindCaseInsensitive  Case-insensitive search
			==================== ============================
		"""
		if not isinstance(data, bytes):
			raise TypeError("Must be bytes, bytearray, or str")
		else:
			buf = databuffer.DataBuffer(data)
		result = ctypes.c_ulonglong()
		if not core.BNFindNextData(self.handle, start, buf.handle, result, flags):
			return None
		return result.value

	def find_next_text(
	    self, start: int, text: str, settings: Optional[_function.DisassemblySettings] = None,
	    flags: FindFlag = FindFlag.FindCaseSensitive,
	    graph_type: FunctionGraphType = FunctionGraphType.NormalFunctionGraph
	) -> Optional[int]:
		"""
		``find_next_text`` searches for string ``text`` occurring in the linear view output starting at the virtual
		address ``start`` until the end of the BinaryView.

		:param int start: virtual address to start searching from.
		:param str text: text to search for
		:param DisassemblySettings settings: disassembly settings
		:param FindFlag flags: (optional) defaults to case-insensitive data search

			==================== ============================
			FindFlag             Description
			==================== ============================
			FindCaseSensitive    Case-sensitive search
			FindCaseInsensitive  Case-insensitive search
			==================== ============================
		:param FunctionGraphType graph_type: the IL to search within
		"""
		if not isinstance(text, str):
			raise TypeError("text parameter is not str type")
		if settings is None:
			settings = _function.DisassemblySettings()
		if not isinstance(settings, _function.DisassemblySettings):
			raise TypeError("settings parameter is not DisassemblySettings type")

		result = ctypes.c_ulonglong()
		if not core.BNFindNextText(self.handle, start, text, result, settings.handle, flags, graph_type):
			return None
		return result.value

	def find_next_constant(
	    self, start: int, constant: int, settings: Optional[_function.DisassemblySettings] = None,
	    graph_type: FunctionGraphType = FunctionGraphType.NormalFunctionGraph
	) -> Optional[int]:
		"""
		``find_next_constant`` searches for integer constant ``constant`` occurring in the linear view output starting at the virtual
		address ``start`` until the end of the BinaryView.

		:param int start: virtual address to start searching from.
		:param int constant: constant to search for
		:param DisassemblySettings settings: disassembly settings
		:param FunctionGraphType graph_type: the IL to search within
		"""
		if not isinstance(constant, int):
			raise TypeError("constant parameter is not integral type")
		if settings is None:
			settings = _function.DisassemblySettings()
		if not isinstance(settings, _function.DisassemblySettings):
			raise TypeError("settings parameter is not DisassemblySettings type")

		result = ctypes.c_ulonglong()
		if not core.BNFindNextConstant(self.handle, start, constant, result, settings.handle, graph_type):
			return None
		return result.value

	class QueueGenerator:
		def __init__(self, t, results):
			self.thread = t
			self.results = results
			t.start()

		def __iter__(self):
			return self

		def __next__(self):
			while True:
				if not self.results.empty():
					return self.results.get()

				if (not self.thread.is_alive()) and self.results.empty():
					raise StopIteration

	def find_all_data(
	    self, start: int, end: int, data: bytes, flags: FindFlag = FindFlag.FindCaseSensitive,
	    progress_func: Optional[ProgressFuncType] = None, match_callback: Optional[DataMatchCallbackType] = None
	) -> QueueGenerator:
		"""
		``find_all_data`` searches for the bytes ``data`` starting at the virtual address ``start``
		until the virtual address ``end``. Once a match is found, the ``match_callback`` is called.

		:param int start: virtual address to start searching from.
		:param int end: virtual address to end the search.
		:param Union[bytes, bytearray, str] data: data to search for
		:param FindFlag flags: (optional) defaults to case-insensitive data search

			==================== ============================
			FindFlag             Description
			==================== ============================
			FindCaseSensitive    Case-sensitive search
			FindCaseInsensitive  Case-insensitive search
			==================== ============================
		:param callback progress_func: optional function to be called with the current progress \
		and total count. This function should return a boolean value that decides whether the \
		search should continue or stop
		:param callback match_callback: function that gets called when a match is found. The \
		callback takes two parameters, i.e., the address of the match, and the actual DataBuffer \
		that satisfies the search. If this parameter is None, this function becomes a generator \
		and yields a tuple of the matching address and the matched DataBuffer. This function \
		can return a boolean value that decides whether the search should continue or stop.
		:rtype QueueGenerator: A generator object that will yield all the found results
		"""
		if not isinstance(data, bytes):
			raise TypeError("data parameter must be bytes, bytearray, or str")

		buf = databuffer.DataBuffer(data)
		if not isinstance(flags, FindFlag):
			raise TypeError('flag parameter must have type FindFlag')

		if progress_func:
			progress_func_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: progress_func(cur, total))
		else:
			progress_func_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: True)

		if match_callback:
			# the `not match_callback(...) is False` tolerates the users who forget to return
			# `True` from inside the callback
			match_callback_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.POINTER(core.BNDataBuffer)
			)(lambda ctxt, addr, match: not match_callback(addr, databuffer.DataBuffer(handle=match)) is False)
			return core.BNFindAllDataWithProgress(
			    self.handle, start, end, buf.handle, flags, None, progress_func_obj, None, match_callback_obj
			)
		else:
			results = queue.Queue()
			match_callback_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.POINTER(core.BNDataBuffer)
			)(lambda ctxt, addr, match: results.put((addr, databuffer.DataBuffer(handle=match))) or True)

			t = threading.Thread(
			    target=lambda: core.BNFindAllDataWithProgress(
			        self.handle, start, end, buf.handle, flags, None, progress_func_obj, None, match_callback_obj
			    )
			)

			return self.QueueGenerator(t, results)

	def _LinearDisassemblyLine_convertor(
	    self, lines: core.BNLinearDisassemblyLineHandle
	) -> 'lineardisassembly.LinearDisassemblyLine':
		func = None
		block = None
		line = lines[0]
		if line.function:
			func = _function.Function(self, core.BNNewFunctionReference(line.function))
		if line.block:
			block_handle = core.BNNewBasicBlockReference(line.block)
			assert block_handle is not None, "core.BNNewBasicBlockReference returned None"
			block = basicblock.BasicBlock(block_handle, self)
		color = highlight.HighlightColor._from_core_struct(line.contents.highlight)
		addr = line.contents.addr
		tokens = _function.InstructionTextToken._from_core_struct(line.contents.tokens, line.contents.count)
		contents = _function.DisassemblyTextLine(tokens, addr, color=color)
		return lineardisassembly.LinearDisassemblyLine(line.type, func, block, contents)

	def find_all_text(
	    self, start: int, end: int, text: str, settings: Optional[_function.DisassemblySettings] = None,
	    flags=FindFlag.FindCaseSensitive, graph_type=FunctionGraphType.NormalFunctionGraph, progress_func=None,
	    match_callback=None
	) -> QueueGenerator:
		"""
		``find_all_text`` searches for string ``text`` occurring in the linear view output starting
		at the virtual address ``start`` until the virtual address ``end``. Once a match is found,
		the ``match_callback`` is called.

		:param int start: virtual address to start searching from.
		:param int end: virtual address to end the search.
		:param str text: text to search for
		:param DisassemblySettings settings: DisassemblySettings object used to render the text \
		to be searched
		:param FindFlag flags: (optional) defaults to case-insensitive data search

			==================== ============================
			FindFlag             Description
			==================== ============================
			FindCaseSensitive    Case-sensitive search
			FindCaseInsensitive  Case-insensitive search
			==================== ============================
		:param FunctionGraphType graph_type: the IL to search within
		:param callback progress_func: optional function to be called with the current progress \
		and total count. This function should return a boolean value that decides whether the \
		search should continue or stop
		:param callback match_callback: function that gets called when a match is found. The \
		callback takes three parameters, i.e., the address of the match, and the actual string \
		that satisfies the search, and the LinearDisassemblyLine that contains the matching \
		line. If this parameter is None, this function becomes a generator \
		and yields a tuple of the matching address, the matched string, and the matching \
		LinearDisassemblyLine. This function can return a boolean value that decides whether \
		the search should continue or stop
		:rtype QueueGenerator: A generator object that will yield all the found results
		"""
		if not isinstance(text, str):
			raise TypeError("text parameter is not str type")
		if settings is None:
			settings = _function.DisassemblySettings()
			settings.set_option(DisassemblyOption.ShowAddress, False)
			settings.set_option(DisassemblyOption.ShowOpcode, False)
			settings.set_option(DisassemblyOption.ShowVariableTypesWhenAssigned, True)
			settings.set_option(DisassemblyOption.WaitForIL, True)
		if not isinstance(settings, _function.DisassemblySettings):
			raise TypeError("settings parameter is not DisassemblySettings type")
		if not isinstance(flags, FindFlag):
			raise TypeError('flag parameter must have type FindFlag')

		if progress_func:
			progress_func_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: progress_func(cur, total))
		else:
			progress_func_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: True)

		if match_callback:
			# The reason we use `not match_callback(...) is False` is the user tends to happily
			# deal with the returned data, but forget to return True at the end of the callback.
			# Then only the first result will be returned.
			match_callback_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_char_p,
			    ctypes.POINTER(core.BNLinearDisassemblyLine)
			)(
			    lambda ctxt, addr, match, line:
			    not match_callback(addr, match, self._LinearDisassemblyLine_convertor(line)) is False
			)

			return core.BNFindAllTextWithProgress(
			    self.handle, start, end, text, settings.handle, flags, graph_type, None, progress_func_obj, None,
			    match_callback_obj
			)
		else:
			results = queue.Queue()
			match_callback_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_char_p,
			    ctypes.POINTER(core.BNLinearDisassemblyLine)
			)(
			    lambda ctxt, addr, match, line: results.put((addr, match, self._LinearDisassemblyLine_convertor(line)))
			    or True
			)

			t = threading.Thread(
			    target=lambda: core.BNFindAllTextWithProgress(
			        self.handle, start, end, text, settings.handle, flags, graph_type, None, progress_func_obj, None,
			        match_callback_obj
			    )
			)

			return self.QueueGenerator(t, results)

	def find_all_constant(
	    self, start: int, end: int, constant: int, settings: Optional[_function.DisassemblySettings] = None,
	    graph_type: FunctionGraphType = FunctionGraphType.NormalFunctionGraph, progress_func: Optional[ProgressFuncType] = None,
	    match_callback: Optional[LineMatchCallbackType] = None
	) -> QueueGenerator:
		"""
		``find_all_constant`` searches for the integer constant ``constant`` starting at the
		virtual address ``start`` until the virtual address ``end``. Once a match is found,
		the ``match_callback`` is called.

		.. note:: A ``constant`` is considered used if a line in the linear view expansion of the given \
		function graph type contains a token with a value that matches that constant. \
		This does not search for raw bytes/data in the binary, for that you want to use \
		:py:func:`find_all_data`.

		:param int start: virtual address to start searching from.
		:param int end: virtual address to end the search.
		:param int constant: constant to search for
		:param DisassemblySettings settings: DisassemblySettings object used to render the text \
		to be searched
		:param FunctionGraphType graph_type: the IL to search within
		:param callback progress_func: optional function to be called with the current progress \
		and total count. This function should return a boolean value that decides whether the \
		search should continue or stop
		:param callback match_callback: function that gets called when a match is found. The \
		callback takes two parameters, i.e., the address of the match, and the \
		LinearDisassemblyLine that contains the matching line. If this parameter is None, \
		this function becomes a generator and yields the matching address and the \
		matching LinearDisassemblyLine. This function can return a boolean value that \
		decides whether the search should continue or stop
		:rtype QueueGenerator: A generator object that will yield all the found results
		"""
		if not isinstance(constant, int):
			raise TypeError("constant parameter is not integral type")
		if settings is None:
			settings = _function.DisassemblySettings()
			settings.set_option(DisassemblyOption.ShowAddress, False)
			settings.set_option(DisassemblyOption.ShowOpcode, False)
			settings.set_option(DisassemblyOption.ShowVariableTypesWhenAssigned, True)
			settings.set_option(DisassemblyOption.WaitForIL, True)
		if not isinstance(settings, _function.DisassemblySettings):
			raise TypeError("settings parameter is not DisassemblySettings type")

		if progress_func:
			progress_func_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: progress_func(cur, total))
		else:
			progress_func_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong
			)(lambda ctxt, cur, total: True)

		if match_callback:
			match_callback_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.POINTER(core.BNLinearDisassemblyLine)
			)(lambda ctxt, addr, line: not match_callback(addr, self._LinearDisassemblyLine_convertor(line)) is False)

			return core.BNFindAllConstantWithProgress(
			    self.handle, start, end, constant, settings.handle, graph_type, None, progress_func_obj, None,
			    match_callback_obj
			)
		else:
			results = queue.Queue()
			match_callback_obj = ctypes.CFUNCTYPE(
			    ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.POINTER(core.BNLinearDisassemblyLine)
			)(lambda ctxt, addr, line: results.put((addr, self._LinearDisassemblyLine_convertor(line))) or True)

			t = threading.Thread(
			    target=lambda: core.BNFindAllConstantWithProgress(
			        self.handle, start, end, constant, settings.handle, graph_type, None, progress_func_obj, None,
			        match_callback_obj
			    )
			)

			return self.QueueGenerator(t, results)

	def search(self, pattern: str, start: int = None, end: int = None, raw: bool = False, ignore_case: bool = False, overlap: bool = False, align: int = 1) -> QueueGenerator:
		r"""
		Searches for matches of the specified `pattern` within this BinaryView with an optionally provided address range specified by `start` and `end`.
		The search pattern can be interpreted in various ways:

			- specified as a string of hexadecimal digits where whitespace is ignored, and the '?' character acts as a wildcard
			- a regular expression suitable for working with bytes
			- or if the `raw` option is enabled, the pattern is interpreted as a raw string, and any special characters are escaped and interpreted literally

		:param pattern: The pattern to search for.
		:type pattern: :py:class:`str`
		:param start: The address to start the search from. (default: None)
		:type start: :py:class:`int`
		:param end: The address to end the search (inclusive). (default: None)
		:type end: :py:class:`int`
		:param bool raw: Whether to interpret the pattern as a raw string (default: False).
		:param bool ignore_case: Whether to perform case-insensitive matching (default: False).
		:param bool overlap: Whether to allow matches to overlap (default: False).
		:param int align: The alignment of matches, must be a power of 2 (default: 1).

		:return: A generator object that yields the offset and matched DataBuffer for each match found.
		:rtype: QueueGenerator
		:Example:
			>>> from binaryninja import load
			>>> bv = load('/bin/ls')
			>>> print(bv)
			<BinaryView: '/bin/ls', start 0x100000000, len 0x182f8>
			>>> bytes(list(bv.search("50 ?4"))[0][1]).hex()
			'5004'
			>>> bytes(list(bv.search("[\x20-\x25][\x60-\x67]"))[0][1]).hex()
			'2062'
		"""
		if start is None:
			start = self.start
		if end is None:
			end = self.end
			if end != 0xffffffffffffffff:
				end = end - 1
		if start > end:
			raise ValueError("The start address must be less than or equal to end address!")
		query = {
			"pattern": pattern,
			"start": start,
			"end": end,
			"raw": raw,
			"ignoreCase": ignore_case,
			"overlap": overlap,
			"align": align
		}
		results = queue.Queue()
		match_callback_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.POINTER(core.BNDataBuffer)
		)(lambda ctxt, offset, match: results.put((offset, databuffer.DataBuffer(handle=match))) or True)
		t = threading.Thread(target=lambda: core.BNSearch(self.handle, json.dumps(query), None, match_callback_obj))
		return self.QueueGenerator(t, results)

	def reanalyze(self) -> None:
		"""
		``reanalyze`` causes all functions to be reanalyzed. This function does not wait for the analysis to finish.

		:rtype: None
		"""
		core.BNReanalyzeAllFunctions(self.handle)

	@property
	def workflow(self) -> Optional['_workflow.Workflow']:
		handle = core.BNGetWorkflowForBinaryView(self.handle)
		if handle is None:
			return None
		return _workflow.Workflow(handle=handle)

	def rebase(self, address: int, force: Optional[bool] = False,
	           progress_func: Optional[ProgressFuncType] = None) -> Optional['BinaryView']:
		"""
		``rebase`` rebase the existing :py:class:`BinaryView` into a new :py:class:`BinaryView` at the specified virtual address

		.. note:: This method does not update corresponding UI components. If the `BinaryView` is associated with \
		UI components then initiate the rebase operation within the UI, e.g. using the command palette. If working with views that \
		are not associated with UI components while the UI is active, then set ``force`` to ``True`` to enable rebasing.

		:param int address: virtual address of the start of the :py:class:`BinaryView`
		:param bool force: enable rebasing while the UI is active
		:return: the new :py:class:`BinaryView` object or ``None`` on failure
		:rtype: :py:class:`BinaryView` or ``None``
		:Example:
			>>> from binaryninja import load
			>>> bv = load('/bin/ls')
			>>> print(bv)
			<BinaryView: '/bin/ls', start 0x100000000, len 0x182f8>
			>>> newbv = bv.rebase(0x400000)
			>>> print(newbv)
			<BinaryView: '/bin/ls', start 0x400000, len 0x182f8>
		"""
		result = False
		if core.BNIsUIEnabled() and not force:
			log_warn(
			    "The BinaryView rebase API does not update corresponding UI components. If the BinaryView is not associated with the UI rerun with 'force = True'."
			)
			return None
		if progress_func is None:
			result = core.BNRebase(self.handle, address)
		else:
			result = core.BNRebaseWithProgress(
			    self.handle, address, None,
			    ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong,
			                     ctypes.c_ulonglong)(lambda ctxt, cur, total: progress_func(cur, total))
			)
		if result:
			return self.get_view_of_type(self.view_type)
		else:
			return None

	def show_plain_text_report(self, title: str, contents: str) -> None:
		core.BNShowPlainTextReport(self.handle, title, contents)

	def show_markdown_report(self, title: str, contents: str, plaintext: str = "") -> None:
		"""
		``show_markdown_report`` displays the markdown contents in UI applications and plaintext in command-line
		applications. Markdown reports support hyperlinking into the BinaryView. Hyperlinks can be specified as follows:
		``binaryninja://?expr=_start`` Where ``expr=`` specifies an expression parsable by the :py:func:`parse_expression` API.

		.. note:: This API functions differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line \
		a simple text prompt is used.

		:param str contents: markdown contents to display
		:param str plaintext: Plain text version to display (used on the command-line)
		:rtype: None
		:Example:
			>>> bv.show_markdown_report("title", "##Contents", "Plain text contents")
			Plain text contents
		"""
		core.BNShowMarkdownReport(self.handle, title, contents, plaintext)

	def show_html_report(self, title: str, contents: str, plaintext: str = "") -> None:
		"""
		``show_html_report`` displays the HTML contents in UI applications and plaintext in command-line
		applications. HTML reports support hyperlinking into the BinaryView. Hyperlinks can be specified as follows:
		``binaryninja://?expr=_start`` Where ``expr=`` specifies an expression parsable by the :py:func:`parse_expression` API.

		.. note:: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line \
			a simple text prompt is used.

		:param str contents: HTML contents to display
		:param str plaintext: Plain text version to display (used on the command-line)
		:rtype: None
		:Example:
			>>> bv.show_html_report("title", "<h1>Contents</h1>", "Plain text contents")
			Plain text contents
		"""
		core.BNShowHTMLReport(self.handle, title, contents, plaintext)

	def show_graph_report(self, title: str, graph: flowgraph.FlowGraph) -> None:
		"""
		``show_graph_report`` displays a :py:class:`FlowGraph` object `graph` in a new tab with ``title``.

		:param title: Title of the graph
		:type title: Text string title of the tab
		:param graph: The graph you wish to display
		:type graph: :py:class:`FlowGraph` object
		"""
		core.BNShowGraphReport(self.handle, title, graph.handle)

	def get_address_input(self, prompt: str, title: str, current_address: Optional[int] = None) -> Optional[int]:
		"""
		``get_address_input`` Gets a virtual address via a prompt displayed to the user

		:param prompt: Prompt for the dialog
		:param title: Window title, if used in the UI
		:param current_address: Optional current address, for relative inputs
		:return: The value entered by the user, if one was entered
		"""
		if current_address is None:
			current_address = self._file.offset
		value = ctypes.c_ulonglong()
		if not core.BNGetAddressInput(value, prompt, title, self.handle, current_address):
			return None
		return value.value

	def add_auto_segment(self, start: int, length: int, data_offset: int, data_length: int, flags: SegmentFlag) -> None:
		core.BNAddAutoSegment(self.handle, start, length, data_offset, data_length, flags)

	def remove_auto_segment(self, start: int, length: int) -> None:
		"""
		``remove_auto_segment`` removes an automatically generated segment from the current segment mapping.

		:param int start: virtual address of the start of the segment
		:param int length: length of the segment
		:rtype: None

		.. warning:: This action is not persistent across saving of a BNDB and must be re-applied each time a BNDB is loaded.

		"""
		core.BNRemoveAutoSegment(self.handle, start, length)

	def add_user_segment(self, start: int, length: int, data_offset: int, data_length: int, flags: SegmentFlag) -> None:
		"""
		``add_user_segment`` creates a user-defined segment that specifies how data from the raw file is mapped into a virtual address space.

		:param int start: virtual address of the start of the segment
		:param int length: length of the segment (may be larger than the source data)
		:param int data_offset: offset from the parent view
		:param int data_length: length of the data from the parent view
		:param enums.SegmentFlag flags: SegmentFlags
		:rtype: None
		"""
		core.BNAddUserSegment(self.handle, start, length, data_offset, data_length, flags)

	def remove_user_segment(self, start: int, length: int) -> None:
		core.BNRemoveUserSegment(self.handle, start, length)

	def get_segment_at(self, addr: int) -> Optional[Segment]:
		"""
		``get_segment_at`` gets the Segment a given virtual address is located in

		:param addr: A virtual address
		:return: The segment, if it was found
		"""
		seg = core.BNGetSegmentAt(self.handle, addr)
		if not seg:
			return None
		segment_handle = core.BNNewSegmentReference(seg)
		assert segment_handle is not None, "core.BNNewSegmentReference returned None"
		return Segment(segment_handle)

	def get_address_for_data_offset(self, offset: int) -> Optional[int]:
		"""
		``get_address_for_data_offset`` returns the virtual address that maps to the specific file offset.

		:param int offset: file offset
		:return: the virtual address of the first segment that contains that file location
		:rtype: Int
		"""
		address = ctypes.c_ulonglong()
		if not core.BNGetAddressForDataOffset(self.handle, offset, address):
			return None
		return address.value

	def get_data_offset_for_address(self, address: int) -> Optional[int]:
		"""
		``get_data_offset_for_address`` returns the file offset that maps to the given virtual address, if possible.

		If `address` falls within a bss segment or an external segment, for example, no mapping is possible, and `None` will be returned.

		:param int address: virtual address
		:return: the file location that is mapped to the given virtual address, or None if no such mapping is possible
		:rtype: Int
		"""
		segment = self.get_segment_at(address)
		if segment is not None and segment.start <= address < segment.end:
			offset = address - segment.start
			if offset < segment.data_length:
				return offset + segment.data_offset
		return None

	def add_auto_section(
	    self, name: str, start: int, length: int,
	    semantics: SectionSemantics = SectionSemantics.DefaultSectionSemantics, type: str = "", align: int = 1,
	    entry_size: int = 1, linked_section: str = "", info_section: str = "", info_data: int = 0
	) -> None:
		core.BNAddAutoSection(
		    self.handle, name, start, length, semantics, type, align, entry_size, linked_section, info_section,
		    info_data
		)

	def remove_auto_section(self, name: str) -> None:
		core.BNRemoveAutoSection(self.handle, name)

	def add_user_section(
	    self, name: str, start: int, length: int,
	    semantics: SectionSemantics = SectionSemantics.DefaultSectionSemantics, type: str = "", align: int = 1,
	    entry_size: int = 1, linked_section: str = "", info_section: str = "", info_data: int = 0
	) -> None:
		"""
		``add_user_section`` creates a user-defined section that can help inform analysis by clarifying what types of
		data exist in what ranges. Note that all data specified must already be mapped by an existing segment.

		:param str name: name of the section
		:param int start: virtual address of the start of the section
		:param int length: length of the section
		:param enums.SectionSemantics semantics: SectionSemantics of the section
		:param str type: optional type
		:param int align: optional byte alignment
		:param int entry_size: optional entry size
		:param str linked_section: optional name of a linked section
		:param str info_section: optional name of an associated informational section
		:param int info_data: optional info data
		:rtype: None
		"""
		core.BNAddUserSection(
		    self.handle, name, start, length, semantics, type, align, entry_size, linked_section, info_section,
		    info_data
		)

	def remove_user_section(self, name: str) -> None:
		core.BNRemoveUserSection(self.handle, name)

	def get_sections_at(self, addr: int) -> List[Section]:
		count = ctypes.c_ulonglong(0)
		section_list = core.BNGetSectionsAt(self.handle, addr, count)
		assert section_list is not None, "core.BNGetSectionsAt returned None"
		result = []
		try:
			for i in range(0, count.value):
				section_handle = core.BNNewSectionReference(section_list[i])
				assert section_handle is not None, "core.BNNewSectionReference returned None"
				result.append(Section(section_handle))
			return result
		finally:
			core.BNFreeSectionList(section_list, count.value)

	def get_section_by_name(self, name: str) -> Optional[Section]:
		section = core.BNGetSectionByName(self.handle, name)
		if section is None:
			return None
		section_handle = core.BNNewSectionReference(section)
		assert section_handle is not None, "core.BNNewSectionReference returned None"
		result = Section(section_handle)
		return result

	def get_unique_section_names(self, name_list: List[str]) -> List[str]:
		incoming_names = (ctypes.c_char_p * len(name_list))()
		for i in range(0, len(name_list)):
			incoming_names[i] = name_list[i].encode("utf-8")
		outgoing_names = core.BNGetUniqueSectionNames(self.handle, incoming_names, len(name_list))
		assert outgoing_names is not None, "core.BNGetUniqueSectionNames returned None"
		result = []
		try:
			for i in range(0, len(name_list)):
				result.append(outgoing_names[i].decode("utf-8"))
			return result
		finally:
			core.BNFreeStringList(outgoing_names, len(name_list))

	@property
	def address_comments(self) -> Mapping[int, str]:
		"""
		Returns a read-only dict of the address comments attached to this BinaryView

		Note that these are different from function-level comments which are specific to each :py:class:`Function`.
		For annotating code, it is recommended to use comments attached to functions rather than address
		comments attached to the BinaryView. On the other hand, BinaryView comments can be attached to data
		whereas function comments cannot.

		To create a function-level comment, use :py:func:`~binaryninja.function.Function.set_comment_at`.
		"""
		count = ctypes.c_ulonglong()
		addrs = core.BNGetGlobalCommentedAddresses(self.handle, count)
		assert addrs is not None, "core.BNGetGlobalCommentedAddresses returned None"
		result = {}
		try:
			for i in range(0, count.value):
				result[addrs[i]] = self.get_comment_at(addrs[i])
			return result
		finally:
			core.BNFreeAddressList(addrs)

	def get_comment_at(self, addr: int) -> str:
		"""
		``get_comment_at`` returns the address-based comment attached to the given address in this BinaryView
		Note that address-based comments are different from function-level comments which are specific to each :py:class:`~binaryninja.function.Function`.
		For more information, see :py:func:`address_comments`.

		:param int addr: virtual address within the current BinaryView to apply the comment to
		:rtype: str

		"""
		return core.BNGetGlobalCommentForAddress(self.handle, addr)

	def set_comment_at(self, addr: int, comment: str) -> None:
		"""
		``set_comment_at`` sets a comment for the BinaryView at the address specified

		Note that these are different from function-level comments which are specific to each :py:class:`~binaryninja.function.Function`. \
		For more information, see :py:func:`address_comments`.

		:param int addr: virtual address within the current BinaryView to apply the comment to
		:param str comment: string comment to apply
		:rtype: None
		:Example:

			>>> bv.set_comment_at(here, "hi")

		"""
		core.BNSetGlobalCommentForAddress(self.handle, addr, comment)

	@property
	def debug_info(self) -> "debuginfo.DebugInfo":
		"""The current debug info object for this binary view"""
		debug_handle = core.BNGetDebugInfo(self.handle)
		debug_ref = core.BNNewDebugInfoReference(debug_handle)
		assert debug_ref is not None, "core.BNNewDebugInfoReference returned None"
		return debuginfo.DebugInfo(debug_ref)

	@debug_info.setter
	def debug_info(self, value: "debuginfo.DebugInfo") -> None:
		"""Sets the debug info for the current binary view"""
		if not isinstance(value, debuginfo.DebugInfo):
			raise ValueError("Attempting to set debug_info to something which isn't and instance of 'DebugInfo'")
		core.BNSetDebugInfo(self.handle, value.handle)

	def apply_debug_info(self, value: "debuginfo.DebugInfo") -> None:
		"""Sets the debug info and applies its contents to the current binary view"""
		if not isinstance(value, debuginfo.DebugInfo):
			raise ValueError("Attempting to apply_debug_info with something which isn't and instance of 'DebugInfo'")
		core.BNApplyDebugInfo(self.handle, value.handle)

	def query_metadata(self, key: str) -> 'metadata.MetadataValueType':
		"""
		`query_metadata` retrieves a metadata associated with the given key stored in the current BinaryView.

		:param str key: key to query
		:rtype: metadata associated with the key
		:Example:

			>>> bv.store_metadata("integer", 1337)
			>>> bv.query_metadata("integer")
			1337L
			>>> bv.store_metadata("list", [1,2,3])
			>>> bv.query_metadata("list")
			[1L, 2L, 3L]
			>>> bv.store_metadata("string", "my_data")
			>>> bv.query_metadata("string")
			'my_data'
		"""
		md_handle = core.BNBinaryViewQueryMetadata(self.handle, key)
		if md_handle is None:
			raise KeyError(key)
		return metadata.Metadata(handle=md_handle).value

	def store_metadata(self, key: str, md: metadata.MetadataValueType, isAuto: bool = False) -> None:
		"""
		`store_metadata` stores an object for the given key in the current BinaryView. Objects stored using
		`store_metadata` can be retrieved when the database is reopened. Objects stored are not arbitrary python
		objects! The values stored must be able to be held in a Metadata object. See :py:class:`~binaryninja.metadata.Metadata`
		for more information. Python objects could obviously be serialized using pickle but this intentionally
		a task left to the user since there is the potential security issues.

		:param str key: key value to associate the Metadata object with
		:param Varies md: object to store.
		:param bool isAuto: whether the metadata is an auto metadata. Most metadata should \
		keep this as False. Only those automatically generated metadata should have this set \
		to True. Auto metadata is not saved into the database and is presumably re-generated \
		when re-opening the database.
		:rtype: None

		:Example:

			>>> bv.store_metadata("integer", 1337)
			>>> bv.query_metadata("integer")
			1337L
			>>> bv.store_metadata("list", [1,2,3])
			>>> bv.query_metadata("list")
			[1L, 2L, 3L]
			>>> bv.store_metadata("string", "my_data")
			>>> bv.query_metadata("string")
			'my_data'
		"""
		_md = md
		if not isinstance(_md, metadata.Metadata):
			_md = metadata.Metadata(_md)
		core.BNBinaryViewStoreMetadata(self.handle, key, _md.handle, isAuto)

	def remove_metadata(self, key: str) -> None:
		"""
		`remove_metadata` removes the metadata associated with key from the current BinaryView.

		:param str key: key associated with metadata to remove from the BinaryView
		:rtype: None
		:Example:

			>>> bv.store_metadata("integer", 1337)
			>>> bv.remove_metadata("integer")
		"""
		core.BNBinaryViewRemoveMetadata(self.handle, key)

	@property
	def metadata(self) -> Dict[str, 'metadata.MetadataValueType']:
		"""
		`metadata` retrieves the metadata associated with the current BinaryView.

		:rtype: metadata associated with the BinaryView
		:Example:

			>>> bv.metadata
			<metadata: {}>
		"""
		md_handle = core.BNBinaryViewGetMetadata(self.handle)
		assert md_handle is not None, "core.BNBinaryViewGetMetadata returned None"
		value = metadata.Metadata(handle=md_handle).value
		assert isinstance(value, dict), "core.BNBinaryViewGetMetadata did not return a dict"
		return value

	@property
	def auto_metadata(self) -> Dict[str, 'metadata.MetadataValueType']:
		"""
		`metadata` retrieves the metadata associated with the current BinaryView.

		:rtype: metadata associated with the BinaryView
		:Example:

			>>> bv.metadata
			<metadata: {}>
		"""
		md_handle = core.BNBinaryViewGetAutoMetadata(self.handle)
		assert md_handle is not None, "core.BNBinaryViewGetAutoMetadata returned None"
		value = metadata.Metadata(handle=md_handle).value
		assert isinstance(value, dict), "core.BNBinaryViewGetAutoMetadata did not return a dict"
		return value

	def get_load_settings_type_names(self) -> List[str]:
		"""
		``get_load_settings_type_names`` retrieve a list :py:class:`BinaryViewType` names for which load settings exist in \
		this :py:class:`BinaryView` context

		:return: list of :py:class:`BinaryViewType` names
		:rtype: list(str)
		"""
		result = []
		count = ctypes.c_ulonglong(0)
		names = core.BNBinaryViewGetLoadSettingsTypeNames(self.handle, count)
		assert names is not None, "core.BNBinaryViewGetLoadSettingsTypeNames returned None"
		try:
			for i in range(count.value):
				result.append(names[i])
			return result
		finally:
			core.BNFreeStringList(names, count.value)

	def get_load_settings(self, type_name: str) -> Optional[settings.Settings]:
		"""
		``get_load_settings`` retrieve a :py:class:`~binaryninja.settings.Settings` object which defines the load settings for the given :py:class:`BinaryViewType` ``type_name``

		:param str type_name: the :py:class:`BinaryViewType` name
		:return: the load settings
		:rtype: :py:class:`~binaryninja.settings.Settings`, or ``None``
		"""
		settings_handle = core.BNBinaryViewGetLoadSettings(self.handle, type_name)
		if settings_handle is None:
			return None
		return settings.Settings(handle=settings_handle)

	def set_load_settings(self, type_name: str, settings: settings.Settings) -> None:
		"""
		``set_load_settings`` set a :py:class:`~binaryninja.settings.Settings` object which defines the load settings for the given :py:class:`BinaryViewType` ``type_name``

		:param str type_name: the :py:class:`BinaryViewType` name
		:param Settings settings: the load settings
		:rtype: None
		"""
		if settings is not None:
			settings = settings.handle
		core.BNBinaryViewSetLoadSettings(self.handle, type_name, settings)

	def parse_expression(self, expression: str, here: int = 0) -> int:
		r"""
		Evaluates a string expression to an integer value.

		The parser uses the following rules:

			- Symbols are defined by the lexer as ``[A-Za-z0-9_:<>][A-Za-z0-9_:$\-<>]+`` or anything enclosed in either single or double quotes
			- Symbols are everything in ``bv.symbols``, unnamed DataVariables (i.e. ``data_00005000``), unnamed functions (i.e. ``sub_00005000``), or section names (i.e. ``.text``)
			- Numbers are defaulted to hexadecimal thus `_printf + 10` is equivalent to `printf + 0x10` If decimal numbers required use the decimal prefix.
			- Since numbers and symbols can be ambiguous its recommended that you prefix your numbers with the following:

				- ``0x`` - Hexadecimal
				- ``0n`` - Decimal
				- ``0`` - Octal

			- In the case of an ambiguous number/symbol (one with no prefix) for instance ``12345`` we will first attempt
			  to look up the string as a symbol, if a symbol is found its address is used, otherwise we attempt to convert
			  it to a hexadecimal number.
			- The following operations are valid: ``+, -, \*, /, %, (), &, \|, ^, ~, ==, !=, >, <, >=, <=``

				- Comparison operators return 1 if the condition is true, 0 otherwise.

			- In addition to the above operators there are dereference operators similar to BNIL style IL:

				- ``[<expression>]`` - read the `current address size` at ``<expression>``
				- ``[<expression>].b`` - read the byte at ``<expression>``
				- ``[<expression>].w`` - read the word (2 bytes) at ``<expression>``
				- ``[<expression>].d`` - read the dword (4 bytes) at ``<expression>``
				- ``[<expression>].q`` - read the quadword (8 bytes) at ``<expression>``

			- The ``$here`` (or more succinctly: ``$``) keyword can be used in calculations and is defined as the ``here`` parameter, or the currently selected address
			- The ``$start``/``$end`` keyword represents the address of the first/last bytes in the file respectively
			- Arbitrary magic values (name-value-pairs) can be added to the expression parser via the
			  :py:func:`add_expression_parser_magic_value` API. Notably, the debugger adds all register values into the
			  expression parser so they can be used directly when navigating. The register values can be referenced like
			  `$rbp`, `$x0`, etc. For more details, refer to the related
			  `debugger docs <https://docs.binary.ninja/guide/debugger/index.html#navigating-the-binary>`_.

		:param str expression: Arithmetic expression to be evaluated
		:param int here: (optional) Base address for relative expressions, defaults to zero
		:rtype: int
		"""
		offset = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		if not core.BNParseExpression(self.handle, expression, offset, here, errors):
			assert errors.value is not None, "core.BNParseExpression returned errors set to None"
			error_str = errors.value.decode("utf-8")
			core.free_string(errors)
			raise ValueError(error_str)
		return offset.value

	def eval(self, expression: str, here: int = 0) -> int:
		"""
		Evaluates a string expression to an integer value. This is a more concise alias for the :py:func:`parse_expression` API
		"""
		return self.parse_expression(expression, here)

	def reader(self, address: Optional[int] = None) -> 'BinaryReader':
		return BinaryReader(self, address=address)

	def writer(self, address: Optional[int] = None) -> 'BinaryWriter':
		return BinaryWriter(self, address=address)

	@property
	def libraries(self) -> List[str]:
		try:
			result: List[str] = []
			libs = self.query_metadata("Libraries")
			assert isinstance(libs, list)
			for s in libs:
				assert isinstance(s, str)
				result.append(s)
			return result
		except KeyError:
			return []

	def typed_data_accessor(self, address: int, type: '_types.Type') -> 'TypedDataAccessor':
		return TypedDataAccessor(type, address, self, self.endianness)

	def create_logger(self, logger_name:str) -> Logger:
		return Logger(self.file.session_id, logger_name)

	def add_external_library(self, name: str, backing_file: Optional['project.ProjectFile'] = None, auto: bool = False) -> externallibrary.ExternalLibrary:
		"""
		Add an ExternalLibrary to this BinaryView

		:param name: Name of the external library
		:param backing_file: Optional ProjectFile that backs the external library
		:param auto: Whether or not this action is the result of automated analysis
		:return: The created ExternalLibrary
		"""
		file_handle = None
		if backing_file is not None:
			file_handle = backing_file._handle
		handle = core.BNBinaryViewAddExternalLibrary(self.handle, name, file_handle, auto)
		assert handle is not None, "core.BNBinaryViewAddExternalLibrary returned None"
		return externallibrary.ExternalLibrary(handle)

	def remove_external_library(self, name: str):
		"""
		Remove an ExternalLibrary from this BinaryView by name.
		Any associated ExternalLocations will be unassociated from the ExternalLibrary

		:param name: Name of the external library to remove
		"""
		core.BNBinaryViewRemoveExternalLibrary(self.handle, name)

	def get_external_library(self, name: str) -> Optional[externallibrary.ExternalLibrary]:
		"""
		Get an ExternalLibrary in this BinaryView by name

		:param name: Name of the external library
		:return: An ExternalLibrary with the given name, or None
		"""
		handle = core.BNBinaryViewGetExternalLibrary(self.handle, name)
		if handle is None:
			return None
		return externallibrary.ExternalLibrary(handle)

	def get_external_libraries(self) -> List[externallibrary.ExternalLibrary]:
		"""
		Get a list of all ExternalLibrary in this BinaryView

		:return: A list of ExternalLibraries in this BinaryView
		"""
		count = ctypes.c_ulonglong(0)
		handles = core.BNBinaryViewGetExternalLibraries(self.handle, count)
		assert handles is not None, "core.BNBinaryViewGetExternalLibraries returned None"
		result = []
		try:
			for i in range(count.value):
				new_handle = core.BNNewExternalLibraryReference(handles[i])
				assert new_handle is not None, "core.BNNewExternalLibraryReference returned None"
				result.append(externallibrary.ExternalLibrary(new_handle))
			return result
		finally:
			core.BNFreeExternalLibraryList(handles, count.value)

	def add_external_location(self, source_symbol: '_types.CoreSymbol', library: Optional[externallibrary.ExternalLibrary], target_symbol: Optional[str], target_address: Optional[int], auto: bool = False) -> externallibrary.ExternalLocation:
		"""
		Add an ExternalLocation with its source in this BinaryView.
		ExternalLocations must have a target address and/or symbol.

		:param source_symbol: Symbol that the association is from
		:param library: Library that the ExternalLocation belongs to
		:param target_symbol: Symbol that the ExternalLocation points to
		:param target_address: Address that the ExternalLocation points to
		:param auto: Whether or not this action is the result of automated analysis
		:return: The created ExternalLocation
		"""
		c_addr = None
		if target_address is not None:
			c_addr = ctypes.c_ulonglong(target_address)
		elif target_symbol is None:
			raise ExternalLinkException("External locations must have a target address and/or symbol")

		handle = core.BNBinaryViewAddExternalLocation(self.handle, source_symbol.handle, library._handle if library else None, target_symbol, c_addr, auto)
		assert handle is not None, "core.BNBinaryViewAddExternalLocation returned None"
		return externallibrary.ExternalLocation(handle)

	def remove_external_location(self, source_symbol: '_types.CoreSymbol'):
		"""
		Remove the ExternalLocation with the given source symbol from this BinaryView

		:param source_symbol: Source symbol that will be used to determine the ExternalLocation to remove
		"""
		core.BNBinaryViewRemoveExternalLocation(self.handle, source_symbol._handle)

	def get_external_location(self, source_symbol: '_types.CoreSymbol') -> Optional[externallibrary.ExternalLocation]:
		"""
		Get the ExternalLocation with the given source symbol in this BinaryView

		:param source_symbol: The source symbol of the ExternalLocation
		:return: An ExternalLocation with the given source symbol, or None
		"""
		handle = core.BNBinaryViewGetExternalLocation(self.handle, source_symbol.handle)
		if handle is None:
			return None
		return externallibrary.ExternalLocation(handle)

	def get_external_locations(self) -> List[externallibrary.ExternalLocation]:
		"""
		Get a list of ExternalLocations in this BinaryView

		:return: A list of ExternalLocations in this BinaryView
		"""
		count = ctypes.c_ulonglong(0)
		handles = core.BNBinaryViewGetExternalLocations(self.handle, count)
		assert handles is not None, "core.BNBinaryViewGetExternalLocations returned None"
		result = []
		try:
			for i in range(count.value):
				new_handle = core.BNNewExternalLocationReference(handles[i])
				assert new_handle is not None, "core.BNNewExternalLocationReference returned None"
				result.append(externallibrary.ExternalLocation(new_handle))
			return result
		finally:
			core.BNFreeExternalLocationList(handles, count.value)

	@property
	def memory_map(self):
		return MemoryMap(handle=self.handle)

class BinaryReader:
	"""
	``class BinaryReader`` is a convenience class for reading binary data.

	BinaryReader can be instantiated as follows and the rest of the document will start from this context ::

		>>> from binaryninja import *
		>>> bv = load("/bin/ls")
		>>> br = BinaryReader(bv)
		>>> hex(br.read32())
		'0xfeedfacfL'
		>>>

	Or using the optional endian parameter ::

		>>> from binaryninja import *
		>>> br = BinaryReader(bv, Endianness.BigEndian)
		>>> hex(br.read32())
		'0xcffaedfeL'
		>>>
	"""
	def __init__(self, view: 'BinaryView', endian: Optional[Endianness] = None, address: Optional[int] = None):
		_handle = core.BNCreateBinaryReader(view.handle)
		assert _handle is not None, "core.BNCreateBinaryReader returned None"
		self._handle = _handle
		if endian is None:
			core.BNSetBinaryReaderEndianness(self._handle, view.endianness)
		else:
			core.BNSetBinaryReaderEndianness(self._handle, endian)

		if address is not None:
			self.seek(address)

	def __del__(self):
		if core is not None:
			core.BNFreeBinaryReader(self._handle)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self._handle.contents) == ctypes.addressof(other._handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self._handle.contents))

	@property
	def endianness(self) -> Endianness:
		"""
		The Endianness to read data. (read/write)

		:getter: returns the endianness of the reader
		:setter: sets the endianness of the reader (BigEndian or LittleEndian)
		:type: Endianness
		"""
		return Endianness(core.BNGetBinaryReaderEndianness(self._handle))

	@endianness.setter
	def endianness(self, value: Endianness) -> None:
		core.BNSetBinaryReaderEndianness(self._handle, value)

	@property
	def offset(self) -> int:
		"""
		The current read offset (read/write).

		:getter: returns the current internal offset
		:setter: sets the internal offset
		:type: int
		"""
		return core.BNGetReaderPosition(self._handle)

	@offset.setter
	def offset(self, value: int) -> None:
		core.BNSeekBinaryReader(self._handle, value)

	@property
	def virtual_base(self) -> int:
		"""
		The current virtual base offset for the stream (read/write).

		:getter: returns the current virtual base
		:setter: sets the virtual base
		:type: int
		"""
		return core.BNGetBinaryReaderVirtualBase(self._handle)

	@virtual_base.setter
	def virtual_base(self, value: int) -> None:
		core.BNSetBinaryReaderVirtualBase(self._handle, value)

	@property
	def eof(self) -> bool:
		"""
		Is end of file (read-only)

		:getter: returns boolean, true if end of file, false otherwise
		:type: bool
		"""
		return core.BNIsEndOfFile(self._handle)

	def read(self, length: int, address: Optional[int] = None) -> Optional[bytes]:
		r"""
		``read`` returns ``length`` bytes read from the current offset, adding ``length`` to offset.

		:param int length: number of bytes to read.
		:param int address: offset to set the internal offset before reading
		:return: ``length`` bytes from current offset
		:rtype: str, or None on failure
		:Example:

			>>> br.read(8)
			'\xcf\xfa\xed\xfe\x07\x00\x00\x01'
			>>>
		"""
		if address is not None:
			self.seek(address)

		dest = ctypes.create_string_buffer(length)
		if not core.BNReadData(self._handle, dest, length):
			return None
		return dest.raw

	def read8(self, address: Optional[int] = None) -> Optional[int]:
		"""
		``read8`` returns a one byte integer from offset incrementing the offset.

		:param int address: offset to set the internal offset before reading
		:return: byte at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> br.read8()
			207
			>>>
		"""
		if address is not None:
			self.seek(address)

		result = ctypes.c_ubyte()
		if not core.BNRead8(self._handle, result):
			return None
		return result.value

	def read16(self, address: Optional[int] = None) -> Optional[int]:
		"""
		``read16`` returns a two byte integer from offset incrementing the offset by two, using specified endianness.

		:param int address: offset to set the internal offset before reading
		:return: a two byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read16())
			'0xfacf'
			>>>
		"""
		if address is not None:
			self.seek(address)

		result = ctypes.c_ushort()
		if not core.BNRead16(self._handle, result):
			return None
		return result.value

	def read32(self, address: Optional[int] = None) -> Optional[int]:
		"""
		``read32`` returns a four byte integer from offset incrementing the offset by four, using specified endianness.

		:param int address: offset to set the internal offset before reading
		:return: a four byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read32())
			'0xfeedfacfL'
			>>>
		"""
		if address is not None:
			self.seek(address)

		result = ctypes.c_uint()
		if not core.BNRead32(self._handle, result):
			return None
		return result.value

	def read64(self, address: Optional[int] = None) -> Optional[int]:
		"""
		``read64`` returns an eight byte integer from offset incrementing the offset by eight, using specified endianness.

		:param int address: offset to set the internal offset before reading
		:return: an eight byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read64())
			'0x1000007feedfacfL'
			>>>
		"""
		if address is not None:
			self.seek(address)

		result = ctypes.c_ulonglong()
		if not core.BNRead64(self._handle, result):
			return None
		return result.value

	def read16le(self, address: Optional[int] = None) -> Optional[int]:
		"""
		``read16le`` returns a two byte little endian integer from offset incrementing the offset by two.

		:param int address: offset to set the internal offset before reading
		:return: a two byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read16le())
			'0xfacf'
			>>>
		"""
		if address is not None:
			self.seek(address)

		result = self.read(2)
		if (result is None) or (len(result) != 2):
			return None
		return struct.unpack("<H", result)[0]

	def read32le(self, address: Optional[int] = None) -> Optional[int]:
		"""
		``read32le`` returns a four byte little endian integer from offset incrementing the offset by four.

		:param int address: offset to set the internal offset before reading
		:return: a four byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read32le())
			'0xfeedfacf'
			>>>
		"""
		if address is not None:
			self.seek(address)

		result = self.read(4)
		if (result is None) or (len(result) != 4):
			return None
		return struct.unpack("<I", result)[0]

	def read64le(self, address: Optional[int] = None) -> Optional[int]:
		"""
		``read64le`` returns an eight byte little endian integer from offset incrementing the offset by eight.

		:param int address: offset to set the internal offset before reading
		:return: a eight byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read64le())
			'0x1000007feedfacf'
			>>>
		"""
		if address is not None:
			self.seek(address)

		result = self.read(8)
		if (result is None) or (len(result) != 8):
			return None
		return struct.unpack("<Q", result)[0]

	def read16be(self, address: Optional[int] = None) -> Optional[int]:
		"""
		``read16be`` returns a two byte big endian integer from offset incrementing the offset by two.

		:param int address: offset to set the internal offset before reading
		:return: a two byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read16be())
			'0xcffa'
			>>>
		"""
		if address is not None:
			self.seek(address)

		result = self.read(2)
		if (result is None) or (len(result) != 2):
			return None
		return struct.unpack(">H", result)[0]

	def read32be(self, address: Optional[int] = None) -> Optional[int]:
		"""
		``read32be`` returns a four byte big endian integer from offset incrementing the offset by four.

		:param int address: offset to set the internal offset before reading
		:return: a four byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read32be())
			'0xcffaedfe'
		"""
		if address is not None:
			self.seek(address)

		result = self.read(4)
		if (result is None) or (len(result) != 4):
			return None
		return struct.unpack(">I", result)[0]

	def read64be(self, address: Optional[int] = None) -> Optional[int]:
		"""
		``read64be`` returns an eight byte big endian integer from offset incrementing the offset by eight.

		:param int address: offset to set the internal offset before reading
		:return: a eight byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read64be())
			'0xcffaedfe07000001L'
		"""
		if address is not None:
			self.seek(address)

		result = self.read(8)
		if (result is None) or (len(result) != 8):
			return None
		return struct.unpack(">Q", result)[0]

	def seek(self, offset: int, whence: Optional[int] = 0) -> None:
		"""
		``seek`` update internal offset to ``offset``.

		:param int offset: offset to set the internal offset to
		:param int whence: optional, defaults to 0 for absolute file positioning, or 1 for relative to current location
		:rtype: None
		:Example:

			>>> hex(br.offset)
			'0x100000008L'
			>>> br.seek(0x100000000)
			>>> hex(br.offset)
			'0x100000000L'
			>>>
		"""
		if whence:
			self.seek_relative(offset)
			return
		core.BNSeekBinaryReader(self._handle, offset)

	def seek_relative(self, offset: int) -> None:
		"""
		``seek_relative`` updates the internal offset by ``offset``.

		:param int offset: offset to add to the internal offset
		:rtype: None
		:Example:

			>>> hex(br.offset)
			'0x100000008L'
			>>> br.seek_relative(-8)
			>>> hex(br.offset)
			'0x100000000L'
			>>>
		"""
		core.BNSeekBinaryReaderRelative(self._handle, offset)


class BinaryWriter:
	"""
	``class BinaryWriter`` is a convenience class for writing binary data.

	BinaryWriter can be instantiated as follows and the rest of the document will start from this context ::

		>>> from binaryninja import *
		>>> bv = load("/bin/ls")
		>>> br = BinaryReader(bv)
		>>> br.offset
		4294967296
		>>> bw = BinaryWriter(bv)
		>>>

	Or using the optional endian parameter ::

		>>> from binaryninja import *
		>>> bv = load("/bin/ls")
		>>> br = BinaryReader(bv, Endianness.BigEndian)
		>>> bw = BinaryWriter(bv, Endianness.BigEndian)
		>>>
	"""
	def __init__(self, view: BinaryView, endian: Optional[Endianness] = None, address: Optional[int] = None):
		self._handle = core.BNCreateBinaryWriter(view.handle)
		assert self._handle is not None, "core.BNCreateBinaryWriter returned None"
		self._view = view
		if endian is None:
			core.BNSetBinaryWriterEndianness(self._handle, view.endianness)
		else:
			core.BNSetBinaryWriterEndianness(self._handle, endian)

		if address is not None:
			self.seek(address)

	def __del__(self):
		if core is not None:
			core.BNFreeBinaryWriter(self._handle)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		assert self._handle is not None
		assert other._handle is not None
		return ctypes.addressof(self._handle.contents) == ctypes.addressof(other._handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		assert self._handle is not None
		return hash(ctypes.addressof(self._handle.contents))

	@property
	def endianness(self) -> Endianness:
		"""
		The Endianness to written data. (read/write)

		:getter: returns the endianness of the reader
		:setter: sets the endianness of the reader (BigEndian or LittleEndian)
		:type: Endianness
		"""
		return Endianness(core.BNGetBinaryWriterEndianness(self._handle))

	@endianness.setter
	def endianness(self, value: Endianness) -> None:
		core.BNSetBinaryWriterEndianness(self._handle, value)

	@property
	def offset(self) -> int:
		"""
		The current write offset (read/write).

		:getter: returns the current internal offset
		:setter: sets the internal offset
		:type: int
		"""
		return core.BNGetWriterPosition(self._handle)

	@offset.setter
	def offset(self, value: int) -> None:
		core.BNSeekBinaryWriter(self._handle, value)

	def write(self, value: bytes, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write`` writes ``len(value)`` bytes to the internal offset, without regard to endianness.

		:param str bytes: bytes to be written at current offset
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean True on success, False on failure.
		:rtype: bool
		:Example:

			>>> bw.write("AAAA")
			True
			>>> br.read(4)
			'AAAA'
			>>>
		"""
		if address is not None:
			self.seek(address)

		if except_on_relocation and self._view.range_contains_relocation(self.offset, len(value)):
			raise RelocationWriteException("Attempting to write to a location which has a relocation")
		if isinstance(value, str):
			value = value.decode("utf-8")
		buf = ctypes.create_string_buffer(len(value))
		ctypes.memmove(buf, value, len(value))
		return core.BNWriteData(self._handle, buf, len(value))

	def write8(self, value: int, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write8`` lowest order byte from the integer ``value`` to the current offset.

		:param str value: bytes to be written at current offset
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean
		:rtype: bool
		:Example:

			>>> bw.write8(0x42)
			True
			>>> br.read(1)
			'B'
			>>>
		"""
		if address is not None:
			self.seek(address)

		if except_on_relocation and self._view.range_contains_relocation(self.offset, 1):
			raise RelocationWriteException("Attempting to write to a location which has a relocation")
		return core.BNWrite8(self._handle, value)

	def write16(self, value: int, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write16`` writes the lowest order two bytes from the integer ``value`` to the current offset, using internal endianness.

		:param int value: integer value to write.
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		if address is not None:
			self.seek(address)

		if except_on_relocation and self._view.range_contains_relocation(self.offset, 2):
			raise RelocationWriteException("Attempting to write to a location which has a relocation")
		return core.BNWrite16(self._handle, value)

	def write32(self, value: int, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write32`` writes the lowest order four bytes from the integer ``value`` to the current offset, using internal endianness.

		:param int value: integer value to write.
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		if address is not None:
			self.seek(address)

		if except_on_relocation and self._view.range_contains_relocation(self.offset, 4):
			raise RelocationWriteException("Attempting to write to a location which has a relocation")
		return core.BNWrite32(self._handle, value)

	def write64(self, value: int, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write64`` writes the lowest order eight bytes from the integer ``value`` to the current offset, using internal endianness.

		:param int value: integer value to write.
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		if address is not None:
			self.seek(address)

		if except_on_relocation and self._view.range_contains_relocation(self.offset, 8):
			raise RelocationWriteException("Attempting to write to a location which has a relocation")
		return core.BNWrite64(self._handle, value)

	def write16le(self, value: int, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write16le`` writes the lowest order two bytes from the little endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		if address is not None:
			self.seek(address)
		return self.write(struct.pack("<H", value), except_on_relocation=except_on_relocation)

	def write32le(self, value: int, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write32le`` writes the lowest order four bytes from the little endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		if address is not None:
			self.seek(address)
		return self.write(struct.pack("<I", value), except_on_relocation=except_on_relocation)

	def write64le(self, value: int, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write64le`` writes the lowest order eight bytes from the little endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		if address is not None:
			self.seek(address)
		return self.write(struct.pack("<Q", value), except_on_relocation=except_on_relocation)

	def write16be(self, value: int, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write16be`` writes the lowest order two bytes from the big endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		if address is not None:
			self.seek(address)
		return self.write(struct.pack(">H", value), except_on_relocation=except_on_relocation)

	def write32be(self, value: int, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write32be`` writes the lowest order four bytes from the big endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		if address is not None:
			self.seek(address)
		return self.write(struct.pack(">I", value), except_on_relocation=except_on_relocation)

	def write64be(self, value: int, address: Optional[int] = None, except_on_relocation=True) -> bool:
		"""
		``write64be`` writes the lowest order eight bytes from the big endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:param int address: offset to set the internal offset before writing
		:param bool except_on_relocation: (default True) raise exception when write overlaps a relocation
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		if address is not None:
			self.seek(address)
		return self.write(struct.pack(">Q", value), except_on_relocation=except_on_relocation)

	def seek(self, offset: int) -> None:
		"""
		``seek`` update internal offset to ``offset``.

		:param int offset: offset to set the internal offset to
		:rtype: None
		:Example:

			>>> hex(bw.offset)
			'0x100000008L'
			>>> bw.seek(0x100000000)
			>>> hex(bw.offset)
			'0x100000000L'
			>>>
		"""
		core.BNSeekBinaryWriter(self._handle, offset)

	def seek_relative(self, offset: int) -> None:
		"""
		``seek_relative`` updates the internal offset by ``offset``.

		:param int offset: offset to add to the internal offset
		:rtype: None
		:Example:

			>>> hex(bw.offset)
			'0x100000008L'
			>>> bw.seek_relative(-8)
			>>> hex(bw.offset)
			'0x100000000L'
			>>>
		"""
		core.BNSeekBinaryWriterRelative(self._handle, offset)


@dataclass(init=False)
class StructuredDataValue(object):
	type: '_types.Type'
	address: int
	value: bytes
	endian: Endianness

	def __str__(self):
		decode_str = "{}B".format(self.type.width)
		return ' '.join([f"{x:02x}" for x in struct.unpack(decode_str, self.value)])

	def __repr__(self):
		return f"<StructuredDataValue type:{self.type} value:{self}>"

	def __int__(self):
		if self.type.width == 1:
			code = "B"
		elif self.type.width == 2:
			code = "H"
		elif self.type.width == 4:
			code = "I"
		elif self.type.width == 8:
			code = "Q"
		else:
			raise Exception("Could not convert to integer with width {}".format(self.type.width))

		endian = "<" if self.endian == Endianness.LittleEndian else ">"
		return struct.unpack(f"{endian}{code}", self.value)[0]

	@property
	def str(self) -> str:
		return str(self)

	@property
	def width(self) -> int:
		return len(self.type)

	@property
	def int(self) -> int:
		return int(self)


@dataclass
class TypedDataAccessor:
	type: '_types.Type'
	address: int
	view: 'BinaryView'
	endian: Endianness

	def __post_init__(self):
		if not isinstance(self.type, _types.Type):
			raise TypeError("Attempting to create TypedDataAccessor with TypeBuilder")

	def __bytes__(self):
		return self.view.read(self.address, len(self))

	def __repr__(self):
		return f"<TypedDataAccessor type:{self.type} value:{self.value}>"

	def __len__(self):
		_type = self.type
		if isinstance(_type, _types.NamedTypeReferenceType):
			_type = _type.target(self.view)
			if _type is None:
				raise ValueError(f"Couldn't get target of type {_type}")
		return len(_type)

	def __int__(self):
		_type = self.type
		if isinstance(_type, _types.NamedTypeReferenceType):
			_type = _type.target(self.view)
		if isinstance(_type, _types.PointerType):
			return self.int_from_bytes(bytes(self), len(self), False, self.endian)
		elif isinstance(_type, (_types.IntegerType, _types.EnumerationType)):
			return self.int_from_bytes(bytes(self), len(self), bool(_type.signed), self.endian)
		raise ValueError(f"Attempting to coerce non integral type: {type(_type)} to an integer")

	def __bool__(self):
		return bool(self.int_from_bytes(bytes(self), len(self), False))

	def __iter__(self):
		_type = self.type
		if not isinstance(_type, _types.ArrayType):
			raise ValueError("Can't iterate over non-array")

		for i in range(_type.count):
			yield self[i]

	def __getitem__(self, key: Union[str, int]) -> 'TypedDataAccessor':
		_type = self.type
		if isinstance(_type, _types.NamedTypeReferenceType):
			_type = _type.target(self.view)
		if isinstance(_type, _types.ArrayType) and isinstance(key, int):
			if key >= _type.count:
				raise ValueError(f"Index {key} out of bounds array has {_type.count} elements")
			return TypedDataAccessor(_type.element_type, self.address + key * len(_type.element_type), self.view, self.endian)
		if not isinstance(_type, _types.StructureType):
			raise ValueError("Can't get member of non-structure")
		if not isinstance(key, str):
			raise ValueError("Must use string to get member of structure")
		m = _type[key]
		if m is None:
			raise ValueError(f"Member {key} doesn't exist in structure")
		return TypedDataAccessor(m.type.immutable_copy(), self.address + m.offset, self.view, self.endian)

	@staticmethod
	def byte_order(endian) -> str:  # as of python3.8 -> Literal["little", "big"]
		return "little" if endian == Endianness.LittleEndian else "big"

	@staticmethod
	def int_from_bytes(data: bytes, width: int, sign: bool, endian: Optional[Endianness] = None) -> int:
		return int.from_bytes(
		    data[0:width], byteorder=TypedDataAccessor.byte_order(endian), signed=sign
		)  # type: ignore

	def __float__(self):
		if not isinstance(self.type, _types.FloatType):
			raise Exception("Attempting to coerce non float type to a float")
		endian = "<" if self.endian == Endianness.LittleEndian else ">"
		if self.type.width == 2:
			code = "e"
		elif self.type.width == 4:
			code = "f"
		elif self.type.width == 8:
			code = "d"
		else:
			raise ValueError(f"Could not convert to float with width {self.type.width}")
		return struct.unpack(f"{endian}{code}", bytes(self))[0]

	@property
	def value(self) -> Any:
		return self._value_helper(self.type, self.view.read(self.address, len(self.type)))

	@value.setter
	def value(self, data: Union[bytes, int, float]) -> None:
		if isinstance(data, int):
			integral_types = (
			    _types.IntegerType, _types.IntegerBuilder, _types.BoolType, _types.BoolBuilder, _types.CharType,
			    _types.CharBuilder, _types.WideCharType, _types.WideCharBuilder, _types.PointerType,
			    _types.PointerBuilder, _types.EnumerationType, _types.EnumerationBuilder
			)
			if not isinstance(self.type, integral_types):
				raise TypeError(f"Can't set the value of type {type(self.type)} to int value")

			signed = True
			if isinstance(self.type, (_types.IntegerType, _types.IntegerBuilder)):
				signed = bool(self.type.signed)
			to_write = data.to_bytes(len(self), TypedDataAccessor.byte_order(self.endian), signed=signed)  # type: ignore
		elif isinstance(data, float) and isinstance(self.type, (_types.FloatType, _types.FloatBuilder)):
			endian = "<" if self.endian == Endianness.LittleEndian else ">"
			if self.type.width == 2:
				code = "e"
			elif self.type.width == 4:
				code = "f"
			elif self.type.width == 8:
				code = "d"
			else:
				raise ValueError(f"Could not convert to float with width {self.type.width}")
			to_write = struct.pack(f"{endian}{code}", data)
		else:
			to_write = data
		count = self.view.write(self.address, to_write)
		if count != len(to_write):
			raise ValueError("Unable to write all bytes to the location, segment might not have file backing")

	def _value_helper(self, _type: '_types.Type', data: bytes) -> Any:
		if not isinstance(_type, _types.Type):
			raise TypeError(f"Attempting to get value of TypeBuilder of type {type(_type)}")
		if isinstance(_type, _types.NamedTypeReferenceType):
			target = _type.target(self.view)
			if target is None:
				raise ValueError("Couldn't find target for type")
			_type = target

		if isinstance(_type, (_types.VoidType, _types.FunctionType)):  #, _types.VarArgsType, _types.ValueType)):
			return None
		elif isinstance(_type, _types.BoolType):
			return bool(self)
		elif isinstance(_type, _types.EnumerationType):
			value = int(self)
			for member in _type.members:
				if int(member) == value:
					return member
			return value
		elif isinstance(_type, (_types.IntegerType, _types.PointerType)):
			return int(self)
		elif isinstance(_type, _types.FloatType):
			return float(self)
		elif isinstance(_type, _types.WideCharType):
			return data.decode(f"utf-16-{'le' if self.endian == Endianness.LittleEndian else 'be'}")
		elif isinstance(_type, _types.StructureType):
			result = {}
			for member in _type.members:
				result[member.name
				       ] = TypedDataAccessor(member.type, self.address + member.offset, self.view, self.endian).value
			return result
		elif isinstance(_type, _types.ArrayType):
			result = []
			if _type.element_type is None:
				raise ValueError("Can not get value for Array type with no element type")
			if _type.element_type.width == 1 and _type.element_type.type_class == TypeClass.IntegerTypeClass:
				return bytes(self)
			if _type.element_type.width == 2 and _type.element_type.type_class == TypeClass.WideCharTypeClass:
				return bytes(self).decode(f"utf-16-{'le' if self.endian == Endianness.LittleEndian else 'be'}")
			for offset in range(0, len(_type) - 1, _type.element_type.width):
				result.append(
				    TypedDataAccessor(_type.element_type, self.address + offset, self.view, self.endian).value
				)
			return result
		else:
			raise TypeError(f"Unhandled `Type` {type(_type)}")

	def as_uuid(self, ms_format: bool = True) -> uuid.UUID:
		"""
		Converts the object to a UUID object using Microsoft byte ordering.

		:param ms_format: Flag indicating whether to use Microsoft byte ordering. Default is True.
		:type ms_format: bool
		:return: The UUID object representing the byte array.
		:rtype: uuid.UUID
		:raises ValueError: If the byte array representation of this data is not exactly 16 bytes long.
		"""
		# Ensure the byte array is 16 bytes long (128 bits)
		byte_array = bytes(self)
		if len(byte_array) != 16:
			raise ValueError("Byte array must be exactly 16 bytes long.")
		# Reorder the bytes to match the UUID format
		# First 3 components (10 bytes) are little-endian, last 2 components (6 bytes) are big-endian
		if ms_format:
			reordered = byte_array[3::-1] + byte_array[5:3:-1] + byte_array[7:5:-1] + byte_array[8:]
			# Create a UUID object and return its string representation
			return uuid.UUID(bytes=reordered)
		else:
			return uuid.UUID(bytes=byte_array)

# for backward compatibility
TypedDataReader = TypedDataAccessor


@dataclass
class CoreDataVariable:
	_address: int
	_type: '_types.Type'
	_auto_discovered: bool

	def __len__(self):
		return len(self._type)

	def __hash__(self):
		return hash((self.type, self.address, self.auto_discovered))

	@property
	def type(self) -> '_types.Type':
		return self._type

	@property
	def address(self) -> int:
		return self._address

	@property
	def auto_discovered(self) -> bool:
		return self._auto_discovered


class DataVariable(CoreDataVariable):
	def __init__(self, view: BinaryView, address: int, type: '_types.Type', auto_discovered: bool):
		super(DataVariable, self).__init__(address, type, auto_discovered)
		self.view = view
		self._accessor = TypedDataAccessor(self.type, self.address, self.view, self.view.endianness)

	@classmethod
	def from_core_struct(cls, var: core.BNDataVariable, view: 'BinaryView') -> 'DataVariable':
		var_type = _types.Type.create(
		    core.BNNewTypeReference(var.type), platform=view.platform, confidence=var.typeConfidence
		)
		return cls(view, var.address, var_type, var.autoDiscovered)

	@property
	def data_refs_from(self) -> Optional[Generator[int, None, None]]:
		"""data cross references from this data variable (read-only)"""
		return self.view.get_data_refs_from(self.address, max(1, len(self)))

	@property
	def data_refs(self) -> Optional[Generator[int, None, None]]:
		"""data cross references to this data variable (read-only)"""
		return self.view.get_data_refs(self.address, max(1, len(self)))

	@property
	def code_refs(self) -> Generator['ReferenceSource', None, None]:
		"""code references to this data variable (read-only)"""
		return self.view.get_code_refs(self.address, max(1, len(self)))

	def __len__(self):
		return len(self.type)

	def __repr__(self):
		return f"<var {self.address:#x}: {self.type}>"

	@property
	def value(self) -> Any:
		return self._accessor.value

	@value.setter
	def value(self, data: bytes) -> None:
		self._accessor.value = data

	def __getitem__(self, item: str):
		return self._accessor[item]

	def __iter__(self):
		return iter(self._accessor)

	@property
	def type(self) -> '_types.Type':
		return self._type

	@type.setter
	def type(self, value: Optional['_types.Type']) -> None:  # type: ignore
		_type = value if value is not None else _types.VoidType.create()
		assert self.view.define_user_data_var(self.address, _type) is not None, "Unable to set DataVariable's type"
		self._type = _type
		self._accessor.type = _type

	@property
	def symbol(self) -> Optional['_types.CoreSymbol']:
		return self.view.get_symbol_at(self.address)

	@symbol.setter
	def symbol(self, value: Optional[Union[str, '_types.CoreSymbol']]) -> None:  # type: ignore
		if value is None or value == "":
			if self.symbol is not None:
				self.view.undefine_user_symbol(self.symbol)
		elif isinstance(value, (str, _types.QualifiedName)):
			symbol = _types.Symbol(SymbolType.DataSymbol, self.address, str(value))
			self.view.define_user_symbol(symbol)
		elif isinstance(value, _types.CoreSymbol):
			self.view.define_user_symbol(value)
		else:
			raise ValueError("Unknown supported for symbol assignment")

	@property
	def name(self) -> Optional[str]:
		if self.symbol is None:
			return None
		return self.symbol.name

	@name.setter
	def name(self, value: str) -> None:
		self.symbol = value

	@property
	def components(self) -> List[component.Component]:
		return self.view.get_data_variable_parent_components(self)


class DataVariableAndName(CoreDataVariable):
	def __init__(self, addr: int, var_type: '_types.Type', var_name: str, auto_discovered: bool) -> None:
		super(DataVariableAndName, self).__init__(addr, var_type, auto_discovered)
		self.name = var_name

	def __repr__(self) -> str:
		return f"<var {self.address:#x}: {self.type} {self.name}>"
