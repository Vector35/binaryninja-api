# coding=utf-8
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

import struct
import traceback
import ctypes
import abc
import numbers
import json

from collections import OrderedDict

# Binary Ninja components
from binaryninja import _binaryninjacore as core
from binaryninja.enums import (AnalysisState, SymbolType, InstructionTextTokenType,
	Endianness, ModificationStatus, StringType, SegmentFlag, SectionSemantics, FindFlag, TypeClass)
import binaryninja
from binaryninja import associateddatastore # required for _BinaryViewAssociatedDataStore
from binaryninja import log
from binaryninja import types
from binaryninja import typelibrary
from binaryninja import fileaccessor
from binaryninja import databuffer
from binaryninja import basicblock
from binaryninja import lineardisassembly
from binaryninja import metadata
from binaryninja import highlight
from binaryninja import function
from binaryninja import settings
from binaryninja import pyNativeStr

# 2-3 compatibility
from binaryninja import range
from binaryninja import with_metaclass
from binaryninja import cstr

class BinaryDataNotification(object):
	def __init__(self):
		pass

	def data_written(self, view, offset, length):
		pass

	def data_inserted(self, view, offset, length):
		pass

	def data_removed(self, view, offset, length):
		pass

	def function_added(self, view, func):
		pass

	def function_removed(self, view, func):
		pass

	def function_updated(self, view, func):
		pass

	def function_update_requested(self, view, func):
		pass

	def data_var_added(self, view, var):
		pass

	def data_var_removed(self, view, var):
		pass

	def data_var_updated(self, view, var):
		pass

	def data_metadata_updated(self, view, offset):
		pass

	def tag_type_updated(self, view, tag_type):
		pass

	def tag_added(self, view, tag, ref_type, auto_defined, arch, func, addr):
		pass

	def tag_updated(self, view, tag, ref_type, auto_defined, arch, func, addr):
		pass

	def tag_removed(self, view, tag, ref_type, auto_defined, arch, func, addr):
		pass

	def symbol_added(self, view, sym):
		pass

	def symbol_updated(self, view, sym):
		pass

	def symbol_removed(self, view, sym):
		pass

	def string_found(self, view, string_type, offset, length):
		pass

	def string_removed(self, view, string_type, offset, length):
		pass

	def type_defined(self, view, name, type):
		pass

	def type_undefined(self, view, name, type):
		pass

_decodings = {
	StringType.AsciiString: "ascii",
	StringType.Utf8String: "utf-8",
	StringType.Utf16String: "utf-16",
	StringType.Utf32String: "utf-32",
}


class StringReference(object):
	def __init__(self, bv, string_type, start, length):
		self._type = string_type
		self._start = start
		self._length = length
		self._view = bv

	def __repr__(self):
		return "<%s: %#x, len %#x>" % (self._type, self._start, self._length)

	def __str__(self):
		return pyNativeStr(self.raw)

	def __len__(self):
		return self._length

	@property
	def value(self):
		return self._view.read(self._start, self._length).decode(_decodings[self._type])

	@property
	def raw(self):
		return self._view.read(self._start, self._length)

	@property
	def type(self):
		""" """
		return self._type

	@type.setter
	def type(self, value):
		self._type = value

	@property
	def start(self):
		""" """
		return self._start

	@start.setter
	def start(self, value):
		self._start = value

	@property
	def length(self):
		""" """
		return self._length

	@property
	def view(self):
		""" """
		return self._view


_pending_analysis_completion_events = {}
class AnalysisCompletionEvent(object):
	"""
	The ``AnalysisCompletionEvent`` object provides an asynchronous mechanism for receiving
	callbacks when analysis is complete. The callback runs once. A completion event must be added
	for each new analysis in order to be notified of each analysis completion.  The
	AnalysisCompletionEvent class takes responsibility for keeping track of the object's lifetime.

	:Example:
		>>> def on_complete(self):
		...     print("Analysis Complete", self._view)
		...
		>>> evt = AnalysisCompletionEvent(bv, on_complete)
		>>>
	"""
	def __init__(self, view, callback):
		self._view = view
		self.callback = callback
		self._cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._notify)
		self.handle = core.BNAddAnalysisCompletionEvent(self._view.handle, None, self._cb)
		global _pending_analysis_completion_events
		_pending_analysis_completion_events[id(self)] = self

	def __del__(self):
		global _pending_analysis_completion_events
		if id(self) in _pending_analysis_completion_events:
			del _pending_analysis_completion_events[id(self)]
		core.BNFreeAnalysisCompletionEvent(self.handle)

	def _notify(self, ctxt):
		global _pending_analysis_completion_events
		if id(self) in _pending_analysis_completion_events:
			del _pending_analysis_completion_events[id(self)]
		try:
			self.callback(self)
		except:
			log.log_error(traceback.format_exc())

	def _empty_callback(self):
		pass

	def cancel(self):
		"""
		The ``cancel`` method will cancel analysis for an :class:`AnalysisCompletionEvent`.

		.. warning: This method should only be used when the system is being shut down and no further analysis should be done afterward.

		"""
		self.callback = self._empty_callback
		core.BNCancelAnalysisCompletionEvent(self.handle)
		global _pending_analysis_completion_events
		if id(self) in _pending_analysis_completion_events:
			del _pending_analysis_completion_events[id(self)]

	@property
	def view(self):
		""" """
		return self._view

	@view.setter
	def view(self, value):
		self._view = value


class ActiveAnalysisInfo(object):
	def __init__(self, func, analysis_time, update_count, submit_count):
		self._func = func
		self._analysis_time = analysis_time
		self._update_count = update_count
		self._submit_count = submit_count

	def __repr__(self):
		return "<ActiveAnalysisInfo %s, analysis_time %d, update_count %d, submit_count %d>" % (self._func, self._analysis_time, self._update_count, self._submit_count)

	@property
	def func(self):
		""" """
		return self._func

	@func.setter
	def func(self, value):
		self._func = value

	@property
	def analysis_time(self):
		""" """
		return self._analysis_time

	@analysis_time.setter
	def analysis_time(self, value):
		self._analysis_time = value

	@property
	def update_count(self):
		""" """
		return self._update_count

	@update_count.setter
	def update_count(self, value):
		self._update_count = value

	@property
	def submit_count(self):
		""" """
		return self._submit_count

	@submit_count.setter
	def submit_count(self, value):
		self._submit_count = value


class AnalysisInfo(object):
	def __init__(self, state, analysis_time, active_info):
		self._state = AnalysisState(state)
		self._analysis_time = analysis_time
		self._active_info = active_info

	def __repr__(self):
		return "<AnalysisInfo %s, analysis_time %d, active_info %s>" % (self._state, self._analysis_time, self._active_info)

	@property
	def state(self):
		""" """
		return self._state

	@state.setter
	def state(self, value):
		self._state = value

	@property
	def analysis_time(self):
		""" """
		return self._analysis_time

	@analysis_time.setter
	def analysis_time(self, value):
		self._analysis_time = value

	@property
	def active_info(self):
		""" """
		return self._active_info

	@active_info.setter
	def active_info(self, value):
		self._active_info = value


class AnalysisProgress(object):
	def __init__(self, state, count, total):
		self._state = state
		self._count = count
		self._total = total

	def __str__(self):
		if self._state == AnalysisState.DisassembleState:
			return "Disassembling (%d/%d)" % (self._count, self._total)
		if self._state == AnalysisState.AnalyzeState:
			return "Analyzing (%d/%d)" % (self._count, self._total)
		if self._state == AnalysisState.ExtendedAnalyzeState:
			return "Extended Analysis"
		return "Idle"

	def __repr__(self):
		return "<progress: %s>" % str(self)

	@property
	def state(self):
		""" """
		return self._state

	@state.setter
	def state(self, value):
		self._state = value

	@property
	def count(self):
		""" """
		return self._count

	@count.setter
	def count(self, value):
		self._count = value

	@property
	def total(self):
		""" """
		return self._total

	@total.setter
	def total(self, value):
		self._total = value


class DataVariable(object):
	def __init__(self, addr, var_type, auto_discovered, view=None):
		self._address = addr
		self._type = var_type
		self._auto_discovered = auto_discovered
		self._view = view

	@property
	def data_refs_from(self):
		"""data cross references from this data variable (read-only)"""
		return self._view.get_data_refs_from(self._address, max(1, len(self)))

	@property
	def data_refs(self):
		"""data cross references to this data variable (read-only)"""
		return self._view.get_data_refs(self._address, max(1, len(self)))

	@property
	def code_refs(self):
		"""code references to this data variable (read-only)"""
		return self._view.get_code_refs(self._address, max(1, len(self)))

	def __len__(self):
		return len(self._type)

	def __repr__(self):
		return "<var 0x%x: %s>" % (self._address, str(self._type))

	@property
	def address(self):
		""" """
		return self._address

	@address.setter
	def address(self, value):
		self._address = value

	@property
	def type(self):
		""" """
		return self._type

	@type.setter
	def type(self, value):
		self._type = value

	@property
	def auto_discovered(self):
		""" """
		return self._auto_discovered

	@auto_discovered.setter
	def auto_discovered(self, value):
		self._auto_discovered = value

	@property
	def view(self):
		""" """
		return self._view

	@view.setter
	def view(self, value):
		self._view = value


class BinaryDataNotificationCallbacks(object):
	def __init__(self, view, notify):
		self._view = view
		self._notify = notify
		self._cb = core.BNBinaryDataNotification()
		self._cb.context = 0
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
		self._cb.tagUpdated = self._cb.tagUpdated.__class__(self._tag_updated)
		self._cb.tagRemoved = self._cb.tagRemoved.__class__(self._tag_removed)
		self._cb.symbolAdded = self._cb.symbolAdded.__class__(self._symbol_added)
		self._cb.symbolUpdated = self._cb.symbolUpdated.__class__(self._symbol_updated)
		self._cb.symbolRemoved = self._cb.symbolRemoved.__class__(self._symbol_removed)
		self._cb.stringFound = self._cb.stringFound.__class__(self._string_found)
		self._cb.stringRemoved = self._cb.stringRemoved.__class__(self._string_removed)
		self._cb.typeDefined = self._cb.typeDefined.__class__(self._type_defined)
		self._cb.typeUndefined = self._cb.typeUndefined.__class__(self._type_undefined)

	def _register(self):
		core.BNRegisterDataNotification(self._view.handle, self._cb)

	def _unregister(self):
		core.BNUnregisterDataNotification(self._view.handle, self._cb)

	def _data_written(self, ctxt, view, offset, length):
		try:
			self._notify.data_written(self._view, offset, length)
		except OSError:
			log.log_error(traceback.format_exc())

	def _data_inserted(self, ctxt, view, offset, length):
		try:
			self._notify.data_inserted(self._view, offset, length)
		except:
			log.log_error(traceback.format_exc())

	def _data_removed(self, ctxt, view, offset, length):
		try:
			self._notify.data_removed(self._view, offset, length)
		except:
			log.log_error(traceback.format_exc())

	def _function_added(self, ctxt, view, func):
		try:
			self._notify.function_added(self._view, binaryninja.function.Function(self._view, core.BNNewFunctionReference(func)))
		except:
			log.log_error(traceback.format_exc())

	def _function_removed(self, ctxt, view, func):
		try:
			self._notify.function_removed(self._view, binaryninja.function.Function(self._view, core.BNNewFunctionReference(func)))
		except:
			log.log_error(traceback.format_exc())

	def _function_updated(self, ctxt, view, func):
		try:
			self._notify.function_updated(self._view, binaryninja.function.Function(self._view, core.BNNewFunctionReference(func)))
		except:
			log.log_error(traceback.format_exc())

	def _function_update_requested(self, ctxt, view, func):
		try:
			self._notify.function_update_requested(self._view, binaryninja.function.Function(self._view, core.BNNewFunctionReference(func)))
		except:
			log.log_error(traceback.format_exc())

	def _data_var_added(self, ctxt, view, var):
		try:
			address = var[0].address
			var_type = types.Type(core.BNNewTypeReference(var[0].type), platform = self._view.platform, confidence = var[0].typeConfidence)
			auto_discovered = var[0].autoDiscovered
			self._notify.data_var_added(self._view, DataVariable(address, var_type, auto_discovered, view))
		except:
			log.log_error(traceback.format_exc())

	def _data_var_removed(self, ctxt, view, var):
		try:
			address = var[0].address
			var_type = types.Type(core.BNNewTypeReference(var[0].type), platform = self._view.platform, confidence = var[0].typeConfidence)
			auto_discovered = var[0].autoDiscovered
			self._notify.data_var_removed(self._view, DataVariable(address, var_type, auto_discovered, view))
		except:
			log.log_error(traceback.format_exc())

	def _data_var_updated(self, ctxt, view, var):
		try:
			address = var[0].address
			var_type = types.Type(core.BNNewTypeReference(var[0].type), platform = self._view.platform, confidence = var[0].typeConfidence)
			auto_discovered = var[0].autoDiscovered
			self._notify.data_var_updated(self._view, DataVariable(address, var_type, auto_discovered, view))
		except:
			log.log_error(traceback.format_exc())

	def _data_metadata_updated(self, ctxt, view, offset):
		try:
			self._notify.data_metadata_updated(self._view, offset)
		except:
			log.log_error(traceback.format_exc())

	def _tag_type_updated(self, ctxt, view, tag_type):
		try:
			self._notify.tag_type_updated(self._view, TagType(core.BNNewTagTypeReference(tag_type)))
		except:
			log.log_error(traceback.format_exc())

	def _tag_added(self, ctxt, view, tag_ref):
		try:
			ref_type = tag_ref[0].refType
			auto_defined = tag_ref[0].autoDefined
			tag = tag_ref[0].tag
			arch = tag_ref[0].arch
			func = tag_ref[0].func
			addr = tag_ref[0].addr
			self._notify.tag_added(self._view, Tag(core.BNNewTagReference(tag)), ref_type, auto_defined, arch, func, addr)
		except:
			log.log_error(traceback.format_exc())

	def _tag_updated(self, ctxt, view, tag_ref):
		try:
			ref_type = tag_ref[0].refType
			auto_defined = tag_ref[0].autoDefined
			tag = tag_ref[0].tag
			arch = tag_ref[0].arch
			func = tag_ref[0].func
			addr = tag_ref[0].addr
			self._notify.tag_updated(self._view, Tag(core.BNNewTagReference(tag)), ref_type, auto_defined, arch, func, addr)
		except:
			log.log_error(traceback.format_exc())

	def _tag_removed(self, ctxt, view, tag_ref):
		try:
			ref_type = tag_ref[0].refType
			auto_defined = tag_ref[0].autoDefined
			tag = tag_ref[0].tag
			arch = tag_ref[0].arch
			func = tag_ref[0].func
			addr = tag_ref[0].addr
			self._notify.tag_removed(self._view, Tag(core.BNNewTagReference(tag)), ref_type, auto_defined, arch, func, addr)
		except:
			log.log_error(traceback.format_exc())

	def _symbol_added(self, ctxt, view, sym):
		try:
			self._notify.symbol_added(self._view, types.Symbol(None, None, None, handle = core.BNNewSymbolReference(sym)))
		except:
			log.log_error(traceback.format_exc())

	def _symbol_updated(self, ctxt, view, sym):
		try:
			self._notify.symbol_updated(self._view, types.Symbol(None, None, None, handle = core.BNNewSymbolReference(sym)))
		except:
			log.log_error(traceback.format_exc())

	def _symbol_removed(self, ctxt, view, sym):
		try:
			self._notify.symbol_removed(self._view, types.Symbol(None, None, None, handle = core.BNNewSymbolReference(sym)))
		except:
			log.log_error(traceback.format_exc())

	def _string_found(self, ctxt, view, string_type, offset, length):
		try:
			self._notify.string_found(self._view, StringType(string_type), offset, length)
		except:
			log.log_error(traceback.format_exc())

	def _string_removed(self, ctxt, view, string_type, offset, length):
		try:
			self._notify.string_removed(self._view, StringType(string_type), offset, length)
		except:
			log.log_error(traceback.format_exc())

	def _type_defined(self, ctxt, view, name, type_obj):
		try:
			qualified_name = types.QualifiedName._from_core_struct(name[0])
			self._notify.type_defined(view, qualified_name, types.Type(core.BNNewTypeReference(type_obj), platform = self._view.platform))
		except:
			log.log_error(traceback.format_exc())

	def _type_undefined(self, ctxt, view, name, type_obj):
		try:
			qualified_name = types.QualifiedName._from_core_struct(name[0])
			self._notify.type_undefined(view, qualified_name, types.Type(core.BNNewTypeReference(type_obj), platform = self._view.platform))
		except:
			log.log_error(traceback.format_exc())

	@property
	def view(self):
		""" """
		return self._view

	@view.setter
	def view(self, value):
		self._view = value

	@property
	def notify(self):
		""" """
		return self._notify

	@notify.setter
	def notify(self, value):
		self._notify = value


class _BinaryViewTypeMetaclass(type):

	@property
	def list(self):
		"""List all BinaryView types (read-only)"""
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetBinaryViewTypes(count)
		result = []
		for i in range(0, count.value):
			result.append(BinaryViewType(types[i]))
		core.BNFreeBinaryViewTypeList(types)
		return result

	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetBinaryViewTypes(count)
		try:
			for i in range(0, count.value):
				yield BinaryViewType(types[i])
		finally:
			core.BNFreeBinaryViewTypeList(types)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		view_type = core.BNGetBinaryViewTypeByName(str(value))
		if view_type is None:
			raise KeyError("'%s' is not a valid view type" % str(value))
		return BinaryViewType(view_type)


class BinaryViewType(with_metaclass(_BinaryViewTypeMetaclass, object)):

	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNBinaryViewType)

	def __repr__(self):
		return "<view type: '%s'>" % self.name

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
	def list(self):
		"""Allow tab completion to discover metaclass list property"""
		pass

	@property
	def name(self):
		"""BinaryView name (read-only)"""
		return core.BNGetBinaryViewTypeName(self.handle)

	@property
	def long_name(self):
		"""BinaryView long name (read-only)"""
		return core.BNGetBinaryViewTypeLongName(self.handle)

	def create(self, data):
		view = core.BNCreateBinaryViewOfType(self.handle, data.handle)
		if view is None:
			return None
		return BinaryView(file_metadata=data.file, handle=view)

	def open(self, src, file_metadata=None):
		"""
		``open`` opens an instance of a particular BinaryViewType and returns it, or None if not possible.

		:param str src: path to filename or bndb to open
		:param FileMetaData file_metadata: Optional parameter for a :py:class:`FileMetaData` object
		:return: returns a :py:class:`BinaryView` object for the given filename
		:rtype: :py:class:`BinaryView` or ``None``
		"""

		data = BinaryView.open(src, file_metadata)
		if data is None:
			return None
		return self.create(data)

	@classmethod
	def get_view_of_file(cls, filename, update_analysis=True, progress_func=None):
		"""
		``get_view_of_file`` opens and returns the first available :py:class:`BinaryView`, excluding a Raw :py:class:`BinaryViewType`

		:param str filename: path to filename or bndb to open
		:param bool update_analysis: whether or not to run :func:`update_analysis_and_wait` after opening a :py:class:`BinaryView`, defaults to ``True``
		:param callback progress_func: optional function to be called with the current progress and total count
		:return: returns a :py:class:`BinaryView` object for the given filename
		:rtype: :py:class:`BinaryView` or ``None``
		"""
		sqlite = b"SQLite format 3"
		isDatabase = filename.endswith(".bndb")
		if isDatabase:
			f = open(filename, 'rb')
			if f is None or f.read(len(sqlite)) != sqlite:
				return None
			f.close()
			view = binaryninja.filemetadata.FileMetadata().open_existing_database(filename, progress_func)
		else:
			view = BinaryView.open(filename)

		if view is None:
			return None
		for available in view.available_view_types:
			if available.name != "Raw":
				if isDatabase:
					bv = view.get_view_of_type(available.name)
				else:
					bv = available.open(filename)
				break
		else:
			if isDatabase:
				bv = view.get_view_of_type("Raw")
			else:
				bv = cls["Raw"].open(filename)

		if bv is not None and update_analysis:
			bv.update_analysis_and_wait()
		return bv

	@classmethod
	def get_view_of_file_with_options(cls, filename, update_analysis=True, progress_func=None, options={}):
		"""
		``get_view_of_file_with_options`` opens, generates default load options (which are overridable), and returns the first available \
		:py:class:`BinaryView`, excluding any ``Raw`` :py:class:`BinaryViewType`

		.. note:: Calling this method without providing options is not necessarily equivalent to simply calling :func:`get_view_of_file`. This is because \
		:py:class:`BinaryViewType`s are in control of generating load options, this method allows an alternative default way to open a file. For \
		example, opening a relocatable object file with :func:`get_view_of_file` sets **'loader.imageBase'** to 0, whereas opening with \
		:func:`get_view_of_file_with_options` sets **'loader.imageBase'** to ``0x400000`` for 64-bit binaries, or ``0x10000`` for 32-bit binaries, by default.

		:param str filename: path to filename or bndb to open
		:param bool update_analysis: whether or not to run :func:`update_analysis_and_wait` after opening a :py:class:`BinaryView`, defaults to ``True``
		:param callback progress_func: optional function to be called with the current progress and total count
		:param dict options: a dictionary in the form {setting identifier string : object value}
		:return: returns a :py:class:`BinaryView` object for the given filename
		:rtype: :py:class:`BinaryView` or ``None``

		:Example:

			>>> BinaryViewType.get_view_of_file_with_options('/bin/ls', options={'loader.imageBase': 0xfffffff0000, 'loader.macho.processFunctionStarts' : False})
			<BinaryView: '/bin/ls', start 0xfffffff0000, len 0xa290>
			>>>
		"""
		sqlite = b"SQLite format 3"
		isDatabase = filename.endswith(".bndb")
		if isDatabase:
			f = open(filename, 'rb')
			if f is None or f.read(len(sqlite)) != sqlite:
				return None
			f.close()
			view = binaryninja.filemetadata.FileMetadata().open_database_for_configuration(filename)
		else:
			view = BinaryView.open(filename)

		if view is None:
			return None
		bvt = None
		for available in view.available_view_types:
			if available.name != "Raw":
				bvt = available
				break

		if bvt is None:
			bvt = cls["Mapped"]

		default_settings = settings.Settings(bvt.name + "_settings")
		default_settings.deserialize_schema(settings.Settings().serialize_schema())
		default_settings.set_resource_id(bvt.name)
		load_settings = bvt.get_load_settings_for_data(view)
		load_settings.set_resource_id(bvt.name)
		view.set_load_settings(bvt.name, load_settings)
		for key, value in options.items():
			if load_settings.contains(key):
				if not load_settings.set_json(key, json.dumps(value), view):
					raise ValueError("Setting: {} set operation failed!".format(key))
			elif default_settings.contains(key):
				if not default_settings.set_json(key, json.dumps(value), view):
					raise ValueError("Setting: {} set operation failed!".format(key))
			else:
				raise NotImplementedError("Setting: {} not available!".format(key))

		bv = bvt.create(view)

		if bv is not None and update_analysis:
			bv.update_analysis_and_wait()
		return bv

	def parse(self, data):
		view = core.BNParseBinaryViewOfType(self.handle, data.handle)
		if view is None:
			return None
		return BinaryView(file_metadata=data.file, handle=view)

	def is_valid_for_data(self, data):
		return core.BNIsBinaryViewTypeValidForData(self.handle, data.handle)

	def get_default_load_settings_for_data(self, data):
		load_settings = core.BNGetBinaryViewDefaultLoadSettingsForData(self.handle, data.handle)
		if load_settings is None:
			return None
		return settings.Settings(handle=load_settings)

	def get_load_settings_for_data(self, data):
		view_handle = None
		if data is not None:
			view_handle = data.handle
		load_settings = core.BNGetBinaryViewLoadSettingsForData(self.handle, view_handle)
		if load_settings is None:
			return None
		return settings.Settings(handle=load_settings)

	def register_arch(self, ident, endian, arch):
		core.BNRegisterArchitectureForViewType(self.handle, ident, endian, arch.handle)

	def get_arch(self, ident, endian):
		arch = core.BNGetArchitectureForViewType(self.handle, ident, endian)
		if arch is None:
			return None
		return binaryninja.architecture.CoreArchitecture._from_cache(arch)

	def register_platform(self, ident, arch, plat):
		core.BNRegisterPlatformForViewType(self.handle, ident, arch.handle, plat.handle)

	def register_default_platform(self, arch, plat):
		core.BNRegisterDefaultPlatformForViewType(self.handle, arch.handle, plat.handle)

	def get_platform(self, ident, arch):
		plat = core.BNGetPlatformForViewType(self.handle, ident, arch.handle)
		if plat is None:
			return None
		return binaryninja.platform.Platform(handle = plat)


class Segment(object):
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		core.BNFreeSegment(self.handle)

	def __repr__(self):
		return "<segment: %#x-%#x, %s%s%s>" % (self.start, self.end,
			"r" if self.readable else "-",
			"w" if self.writable else "-",
			"x" if self.executable else "-")

	def __len__(self):
		return core.BNSegmentGetLength(self.handle)

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
	def start(self):
		return core.BNSegmentGetStart(self.handle)

	@property
	def end(self):
		return core.BNSegmentGetEnd(self.handle)

	@property
	def executable(self):
		return (core.BNSegmentGetFlags(self.handle) & SegmentFlag.SegmentExecutable) != 0

	@property
	def writable(self):
		return (core.BNSegmentGetFlags(self.handle) & SegmentFlag.SegmentWritable) != 0

	@property
	def readable(self):
		return (core.BNSegmentGetFlags(self.handle) & SegmentFlag.SegmentReadable) != 0

	@property
	def data_length(self):
		return core.BNSegmentGetDataLength(self.handle)

	@property
	def data_offset(self):
		return core.BNSegmentGetDataOffset(self.handle)

	@property
	def data_end(self):
		return core.BNSegmentGetDataEnd(self.handle)

	@property
	def relocation_count(self):
		return core.BNSegmentGetRelocationsCount(self.handle)

	@property
	def auto_defined(self):
		return core.BNSegmentIsAutoDefined(self.handle)

	@property
	def relocation_ranges(self):
		"""List of relocation range tuples (read-only)"""

		count = ctypes.c_ulonglong()
		ranges = core.BNSegmentGetRelocationRanges(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append((ranges[i].start, ranges[i].end))
		core.BNFreeRelocationRanges(ranges, count)
		return result

	def relocation_ranges_at(self, addr):
		"""List of relocation range tuples (read-only)"""

		count = ctypes.c_ulonglong()
		ranges = core.BNSegmentGetRelocationRangesAtAddress(self.handle, addr, count)
		result = []
		for i in range(0, count.value):
			result.append((ranges[i].start, ranges[i].end))
		core.BNFreeRelocationRanges(ranges, count)
		return result



class Section(object):
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNSection)

	def __del__(self):
		core.BNFreeSection(self.handle)

	def __repr__(self):
		return "<section %s: %#x-%#x>" % (self.name, self.start, self.end)

	def __len__(self):
		return core.BNSectionGetLength(self.handle)

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
		return core.BNSectionGetName(self.handle)

	@property
	def type(self):
		return core.BNSectionGetType(self.handle)

	@property
	def start(self):
		return core.BNSectionGetStart(self.handle)

	@property
	def linked_section(self):
		return core.BNSectionGetLinkedSection(self.handle)

	@property
	def info_section(self):
		return core.BNSectionGetInfoSection(self.handle)

	@property
	def info_data(self):
		return core.BNSectionGetInfoData(self.handle)

	@property
	def align(self):
		return core.BNSectionGetAlign(self.handle)

	@property
	def entry_size(self):
		return core.BNSectionGetEntrySize(self.handle)

	@property
	def semantics(self):
		return SectionSemantics(core.BNSectionGetSemantics(self.handle))

	@property
	def auto_defined(self):
		return core.BNSectionIsAutoDefined(self.handle)

	@property
	def end(self):
		return self.start + len(self)


class AddressRange(object):
	def __init__(self, start, end):
		self._start = start
		self._end = end

	def __repr__(self):
		return "<%#x-%#x>" % (self._start, self._end)

	def __len__(self):
		return self._end - self.start

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._start, self._end) == (other._start, other._end)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._start, self._end))

	@property
	def length(self):
		return self._end - self._start

	@property
	def start(self):
		""" """
		return self._start

	@start.setter
	def start(self, value):
		self._start = value

	@property
	def end(self):
		""" """
		return self._end

	@end.setter
	def end(self, value):
		self._end = value


class TagType(object):
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNTagType)

	def __del__(self):
		core.BNFreeTagType(self.handle)

	def __repr__(self):
		return "<tag type %s: %s>" % (self.name, self.icon)

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
		"""Name of the TagType"""
		return core.BNTagTypeGetName(self.handle)

	@name.setter
	def name(self, value):
		core.BNTagTypeSetName(self.handle, value)

	@property
	def icon(self):
		"""Unicode str containing an emoji to be used as an icon"""
		return core.BNTagTypeGetIcon(self.handle)

	@icon.setter
	def icon(self, value):
		core.BNTagTypeSetIcon(self.handle, value)

	@property
	def visible(self):
		"""Boolean for whether the tags of this type are visible"""
		return core.BNTagTypeGetVisible(self.handle)

	@visible.setter
	def visible(self, value):
		core.BNTagTypeSetVisible(self.handle, value)

	@property
	def type(self):
		"""Type from enums.TagTypeType"""
		return core.BNTagTypeGetType(self.handle)

	@type.setter
	def type(self, value):
		core.BNTagTypeSetType(self.handle, value)



class Tag(object):
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNTag)

	def __del__(self):
		core.BNFreeTag(self.handle)

	def __repr__(self):
		return "<tag %s %s: %s>" % (self.type.icon, self.type.name, self.data)

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
	def type(self):
		return TagType(core.BNTagGetType(self.handle))

	@property
	def data(self):
		return core.BNTagGetData(self.handle)

	@data.setter
	def data(self, value):
		core.BNTagSetData(self.handle, value)


class _BinaryViewAssociatedDataStore(associateddatastore._AssociatedDataStore):
	_defaults = {}


class BinaryView(object):
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

	To open a file with a given BinaryView the following code can be used::

		>>> bv = BinaryViewType.get_view_of_file("/bin/ls")
		>>> bv
		<BinaryView: '/bin/ls', start 0x100000000, len 0xa000>

	`By convention in the rest of this document we will use bv to mean an open BinaryView of an executable file.`
	When a BinaryView is open on an executable view, analysis does not automatically run, this can be done by running
	the :func:`update_analysis_and_wait` method which disassembles the executable and returns when all disassembly is
	finished::

		>>> bv.update_analysis_and_wait()
		>>>

	Since BinaryNinja's analysis is multi-threaded (depending on version) this can also be done in the background by
	using the :func:`update_analysis` method instead.

	By standard python convention methods which start with '_' should be considered private and should not be called
	externally. Additionally, methods which begin with ``perform_`` should not be called either and are
	used explicitly for subclassing the BinaryView.

	.. note:: An important note on the ``*_user_*()`` methods. Binary Ninja makes a distinction between edits \
	performed by the user and actions performed by auto analysis.  Auto analysis actions that can quickly be recalculated \
	are not saved to the database. Auto analysis actions that take a long time and all user edits are stored in the \
	database (e.g. :func:`remove_user_function` rather than :func:`remove_function`). Thus use ``_user_`` methods if saving \
	to the database is desired.
	"""
	name = None
	long_name = None
	_registered = False
	_registered_cb = None
	registered_view_type = None
	_next_address = 0
	_associated_data = {}
	_registered_instances = []

	def __init__(self, file_metadata=None, parent_view=None, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNBinaryView)
			if file_metadata is None:
				self._file = binaryninja.filemetadata.FileMetadata(handle=core.BNGetFileForView(handle))
			else:
				self._file = file_metadata
		elif self.__class__ is BinaryView:
			binaryninja._init_plugins()
			if file_metadata is None:
				file_metadata = binaryninja.filemetadata.FileMetadata()
			self.handle = core.BNCreateBinaryDataView(file_metadata.handle)
			self._file = binaryninja.filemetadata.FileMetadata(handle=core.BNNewFileReference(file_metadata.handle))
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
			self._file = file_metadata
			if parent_view is not None:
				parent_view = parent_view.handle
			self.handle = core.BNCreateCustomBinaryView(self.__class__.name, file_metadata.handle, parent_view, self._cb)
		self._notifications = {}
		self._next_address = None  # Do NOT try to access view before init() is called, use placeholder

	def __del__(self):
		for i in self.notifications.values():
			i._unregister()
		core.BNFreeBinaryView(self.handle)

	def __repr__(self):
		start = self.start
		length = len(self)
		if start != 0:
			size = "start %#x, len %#x" % (start, length)
		else:
			size = "len %#x" % length
		filename = self._file.filename
		if len(filename) > 0:
			return "<BinaryView: '%s', %s>" % (filename, size)
		return "<BinaryView: %s>" % (size)

	def __len__(self):
		return int(core.BNGetViewLength(self.handle))

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

	def __iter__(self):
		count = ctypes.c_ulonglong(0)
		funcs = core.BNGetAnalysisFunctionList(self.handle, count)
		try:
			for i in range(0, count.value):
				yield binaryninja.function.Function(self, core.BNNewFunctionReference(funcs[i]))
		finally:
			core.BNFreeFunctionList(funcs, count.value)


	def __getitem__(self, i):
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
				return ""
			return self.read(start, stop - start)
		elif i < 0:
			if i >= -len(self):
				value = self.read(int(len(self) + i), 1)
				if len(value) == 0:
					return IndexError("index not readable")
				return value
			raise IndexError("index out of range")
		elif (i >= self.start) and (i < self.end):
			value = self.read(int(i), 1)
			if len(value) == 0:
				return IndexError("index not readable")
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
			if i >= -len(self):
				if len(value) != 1:
					raise ValueError("expected single byte for assignment")
				if self.write(int(len(self) + i), value) != 1:
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

	@classmethod
	def register(cls):
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
		cls._registered_cb.getLoadSettingsForData = cls._registered_cb.getLoadSettingsForData.__class__(cls._get_load_settings_for_data)
		cls.registered_view_type = BinaryViewType(core.BNRegisterBinaryViewType(cls.name, cls.long_name, cls._registered_cb))
		cls._registered = True

	@classmethod
	def _create(cls, ctxt, data):
		try:
			file_metadata = binaryninja.filemetadata.FileMetadata(handle=core.BNGetFileForView(data))
			view = cls(BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(data)))
			if view is None:
				return None
			# FIXME: There is probably a better way to convey this information...
			view.__dict__.update({'parse_only' : False})
			return ctypes.cast(core.BNNewViewReference(view.handle), ctypes.c_void_p).value
		except:
			log.log_error(traceback.format_exc())
			return None

	@classmethod
	def _parse(cls, ctxt, data):
		try:
			file_metadata = binaryninja.filemetadata.FileMetadata(handle=core.BNGetFileForView(data))
			view = cls(BinaryView(file_metadata=file_metadata, handle=core.BNNewViewReference(data)))
			if view is None:
				return None
			# FIXME: There is probably a better way to convey this information...
			view.__dict__.update({'parse_only' : True})
			return ctypes.cast(core.BNNewViewReference(view.handle), ctypes.c_void_p).value
		except:
			log.log_error(traceback.format_exc())
			return None

	@classmethod
	def _is_valid_for_data(cls, ctxt, data):
		try:
			return cls.is_valid_for_data(BinaryView(handle=core.BNNewViewReference(data)))
		except:
			log.log_error(traceback.format_exc())
			return False

	@classmethod
	def _get_load_settings_for_data(cls, ctxt, data):
		try:
			attr = getattr(cls, "get_load_settings_for_data", None)
			if callable(attr):
				result = cls.get_load_settings_for_data(BinaryView(handle=core.BNNewViewReference(data)))
				return ctypes.cast(core.BNNewSettingsReference(result.handle), ctypes.c_void_p).value
			else:
				return None
		except:
			log.log_error(traceback.format_exc())
			return None

	@classmethod
	def open(cls, src, file_metadata=None):
		binaryninja._init_plugins()
		if isinstance(src, fileaccessor.FileAccessor):
			if file_metadata is None:
				file_metadata = binaryninja.filemetadata.FileMetadata()
			view = core.BNCreateBinaryDataViewFromFile(file_metadata.handle, src._cb)
		else:
			if file_metadata is None:
				file_metadata = binaryninja.filemetadata.FileMetadata(str(src))
			view = core.BNCreateBinaryDataViewFromFilename(file_metadata.handle, str(src))
		if view is None:
			return None
		result = BinaryView(file_metadata=file_metadata, handle=view)
		return result

	@classmethod
	def new(cls, data=None, file_metadata=None):
		binaryninja._init_plugins()
		if file_metadata is None:
			file_metadata = binaryninja.filemetadata.FileMetadata()
		if data is None:
			view = core.BNCreateBinaryDataView(file_metadata.handle)
		else:
			buf = databuffer.DataBuffer(data)
			view = core.BNCreateBinaryDataViewFromBuffer(file_metadata.handle, buf.handle)
		if view is None:
			return None
		result = BinaryView(file_metadata=file_metadata, handle=view)
		return result

	@classmethod
	def _unregister(cls, view):
		handle = ctypes.cast(view, ctypes.c_void_p)
		if handle.value in cls._associated_data:
			del cls._associated_data[handle.value]

	@classmethod
	def set_default_session_data(cls, name, value):
		"""
		``set_default_session_data`` saves a variable to the BinaryView.
		:param str name: name of the variable to be saved
		:param str value: value of the variable to be saved

		:Example:
			>>> BinaryView.set_default_session_data("variable_name", "value")
			>>> bv.session_data.variable_name
			'value'
		"""
		_BinaryViewAssociatedDataStore.set_default(name, value)

	@property
	def basic_blocks(self):
		"""A generator of all BasicBlock objects in the BinaryView"""
		for func in self:
			for block in func.basic_blocks:
				yield block

	@property
	def llil_basic_blocks(self):
		"""A generator of all LowLevelILBasicBlock objects in the BinaryView"""
		for func in self:
			for il_block in func.low_level_il.basic_blocks:
				yield il_block

	@property
	def mlil_basic_blocks(self):
		"""A generator of all MediumLevelILBasicBlock objects in the BinaryView"""
		for func in self:
			for il_block in func.mlil.basic_blocks:
				yield il_block

	@property
	def instructions(self):
		"""A generator of instruction tokens and their start addresses"""
		for block in self.basic_blocks:
			start = block.start
			for i in block:
				yield (i[0], start)
				start += i[1]

	@property
	def llil_instructions(self):
		"""A generator of llil instructions"""
		for block in self.llil_basic_blocks:
			for i in block:
				yield i

	@property
	def mlil_instructions(self):
		"""A generator of mlil instructions"""
		for block in self.mlil_basic_blocks:
			for i in block:
				yield i

	@property
	def parent_view(self):
		"""View that contains the raw data used by this view (read-only)"""
		result = core.BNGetParentView(self.handle)
		if result is None:
			return None
		return BinaryView(handle=result)

	@property
	def modified(self):
		"""boolean modification state of the BinaryView (read/write)"""
		return self._file.modified

	@modified.setter
	def modified(self, value):
		self._file.modified = value

	@property
	def analysis_changed(self):
		"""boolean analysis state changed of the currently running analysis (read-only)"""
		return self._file.analysis_changed

	@property
	def has_database(self):
		"""boolean has a database been written to disk (read-only)"""
		return self._file.has_database

	@property
	def view(self):
		return self._file.view

	@view.setter
	def view(self, value):
		self._file.view = value

	@property
	def offset(self):
		return self._file.offset

	@offset.setter
	def offset(self, value):
		self._file.offset = value

	@property
	def file(self):
		""":py:class:`FileMetadata` backing the BinaryView """
		return self._file

	@file.setter
	def file(self, value):
		self._file = value

	@property
	def notifications(self):
		""":py:class:`FileMetadata` backing the BinaryView """
		return self._notifications

	@notifications.setter
	def notifications(self, value):
		self._notifications = value

	@property
	def next_address(self):
		""":py:class:`FileMetadata` backing the BinaryView """
		return self._next_address

	@next_address.setter
	def next_address(self, value):
		self._next_address = value

	@property
	def start(self):
		"""Start offset of the binary (read-only)"""
		return core.BNGetStartOffset(self.handle)

	@property
	def end(self):
		"""End offset of the binary (read-only)"""
		return core.BNGetEndOffset(self.handle)

	@property
	def entry_point(self):
		"""Entry point of the binary (read-only)"""
		return core.BNGetEntryPoint(self.handle)

	@property
	def arch(self):
		"""The architecture associated with the current :py:class:`BinaryView` (read/write)"""
		arch = core.BNGetDefaultArchitecture(self.handle)
		if arch is None:
			return None
		return binaryninja.architecture.CoreArchitecture._from_cache(handle=arch)

	@arch.setter
	def arch(self, value):
		if value is None:
			core.BNSetDefaultArchitecture(self.handle, None)
		else:
			core.BNSetDefaultArchitecture(self.handle, value.handle)

	@property
	def platform(self):
		"""The platform associated with the current BinaryView (read/write)"""
		plat = core.BNGetDefaultPlatform(self.handle)
		if plat is None:
			return None
		return binaryninja.platform.Platform(self.arch, handle=plat)

	@platform.setter
	def platform(self, value):
		if value is None:
			core.BNSetDefaultPlatform(self.handle, None)
		else:
			core.BNSetDefaultPlatform(self.handle, value.handle)

	@property
	def endianness(self):
		"""Endianness of the binary (read-only)"""
		return Endianness(core.BNGetDefaultEndianness(self.handle))

	@property
	def relocatable(self):
		"""Boolean - is the binary relocatable (read-only)"""
		return core.BNIsRelocatable(self.handle)

	@property
	def address_size(self):
		"""Address size of the binary (read-only)"""
		return core.BNGetViewAddressSize(self.handle)

	@property
	def executable(self):
		"""Whether the binary is an executable (read-only)"""
		return core.BNIsExecutableView(self.handle)

	@property
	def functions(self):
		"""List of functions (read-only)"""
		count = ctypes.c_ulonglong(0)
		funcs = core.BNGetAnalysisFunctionList(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(binaryninja.function.Function(self, core.BNNewFunctionReference(funcs[i])))
		core.BNFreeFunctionList(funcs, count.value)
		return result

	@property
	def has_functions(self):
		"""Boolean whether the binary has functions (read-only)"""
		return core.BNHasFunctions(self.handle)

	@property
	def has_symbols(self):
		"""Boolean whether the binary has symbols (read-only)"""
		return core.BNHasSymbols(self.handle)

	@property
	def has_data_variables(self):
		"""Boolean whether the binary has functions (read-only)"""
		return core.BNHasDataVariables(self.handle)

	@property
	def entry_function(self):
		"""Entry function (read-only)"""
		func = core.BNGetAnalysisEntryPoint(self.handle)
		if func is None:
			return None
		return binaryninja.function.Function(self, func)

	@property
	def symbols(self):
		"""Dict of symbols (read-only)"""
		count = ctypes.c_ulonglong(0)
		syms = core.BNGetSymbols(self.handle, count, None)
		result = {}
		for i in range(0, count.value):
			sym = types.Symbol(None, None, None, handle=core.BNNewSymbolReference(syms[i]))
			if sym.raw_name in result:
				result[sym.raw_name] = [result[sym.raw_name], sym]
			else:
				result[sym.raw_name] = sym
		core.BNFreeSymbolList(syms, count.value)
		return result

	@classmethod
	def internal_namespace(self):
		"""Internal namespace for the current BinaryView"""
		ns = core.BNGetInternalNameSpace()
		result = types.NameSpace._from_core_struct(ns)
		core.BNFreeNameSpace(ns)
		return result

	@classmethod
	def external_namespace(self):
		"""External namespace for the current BinaryView"""
		ns = core.BNGetExternalNameSpace()
		result = types.NameSpace._from_core_struct(ns)
		core.BNFreeNameSpace(ns)
		return result

	@property
	def namespaces(self):
		"""Returns a list of namespaces for the current BinaryView"""
		count = ctypes.c_ulonglong(0)
		nameSpaceList = core.BNGetNameSpaces(self.handle, count)
		result = []
		for i in range(count.value):
			result.append(types.NameSpace._from_core_struct(nameSpaceList[i]))
		core.BNFreeNameSpaceList(nameSpaceList, count.value)
		return result

	@property
	def view_type(self):
		"""View type (read-only)"""
		return core.BNGetViewType(self.handle)

	@property
	def available_view_types(self):
		"""Available view types (read-only)"""
		count = ctypes.c_ulonglong(0)
		types = core.BNGetBinaryViewTypesForData(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(BinaryViewType(types[i]))
		core.BNFreeBinaryViewTypeList(types)
		return result

	@property
	def strings(self):
		"""List of strings (read-only)"""
		return self.get_strings()

	@property
	def saved(self):
		"""boolean state of whether or not the file has been saved (read/write)"""
		return self._file.saved

	@saved.setter
	def saved(self, value):
		self._file.saved = value

	@property
	def analysis_info(self):
		"""Provides instantaneous analysis state information and a list of current functions under analysis (read-only).
		All times are given in units of milliseconds (ms). Per-function `analysis_time` is the aggregation of time spent
		performing incremental updates and is reset on a full function update. Per-function `update_count` tracks the
		current number of incremental updates and is reset on a full function update. Per-function `submit_count` tracks the
		current number of full updates that have completed.

		.. note:: `submit_count` is currently not reset across analysis updates.

		"""
		info_ref = core.BNGetAnalysisInfo(self.handle)
		info = info_ref[0]
		active_info_list = []
		for i in range(0, info.count):
			func = binaryninja.function.Function(self, core.BNNewFunctionReference(info.activeInfo[i].func))
			active_info = ActiveAnalysisInfo(func, info.activeInfo[i].analysisTime, info.activeInfo[i].updateCount, info.activeInfo[i].submitCount)
			active_info_list.append(active_info)
		result = AnalysisInfo(info.state, info.analysisTime, active_info_list)
		core.BNFreeAnalysisInfo(info_ref)
		return result

	@property
	def analysis_progress(self):
		"""Status of current analysis (read-only)"""
		result = core.BNGetAnalysisProgress(self.handle)
		return AnalysisProgress(result.state, result.count, result.total)

	@property
	def linear_disassembly(self):
		"""Iterator for all lines in the linear disassembly of the view"""
		return self.get_linear_disassembly(None)

	@property
	def data_vars(self):
		"""List of data variables (read-only)"""
		count = ctypes.c_ulonglong(0)
		var_list = core.BNGetDataVariables(self.handle, count)
		result = {}
		for i in range(0, count.value):
			addr = var_list[i].address
			var_type = types.Type(core.BNNewTypeReference(var_list[i].type), platform = self.platform, confidence = var_list[i].typeConfidence)
			auto_discovered = var_list[i].autoDiscovered
			result[addr] = DataVariable(addr, var_type, auto_discovered, self)
		core.BNFreeDataVariables(var_list, count.value)
		return result

	@property
	def types(self):
		"""List of defined types (read-only)"""
		count = ctypes.c_ulonglong(0)
		type_list = core.BNGetAnalysisTypeList(self.handle, count)
		result = {}
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(type_list[i].name)
			result[name] = types.Type(core.BNNewTypeReference(type_list[i].type), platform = self.platform)
		core.BNFreeTypeList(type_list, count.value)
		return result

	@property
	def type_names(self):
		"""List of defined type names (read-only)"""
		count = ctypes.c_ulonglong(0)
		name_list = core.BNGetAnalysisTypeNames(self.handle, count, "")
		result = []
		for i in range(0, count.value):
			result.append(types.QualifiedName._from_core_struct(name_list[i]))
		core.BNFreeTypeNameList(name_list, count.value)
		return result


	@property
	def type_libraries(self):
		"""List of imported type libraries (read-only)"""
		count = ctypes.c_ulonglong(0)
		libraries = core.BNGetBinaryViewTypeLibraries(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(typelibrary.TypeLibrary(core.BNNewTypeLibraryReference(libraries[i])))
		core.BNFreeTypeLibraryList(libraries, count.value)
		return result


	@property
	def segments(self):
		"""List of segments (read-only)"""
		count = ctypes.c_ulonglong(0)
		segment_list = core.BNGetSegments(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(Segment(core.BNNewSegmentReference(segment_list[i])))
		core.BNFreeSegmentList(segment_list, count.value)
		return result

	@property
	def sections(self):
		"""List of sections (read-only)"""
		count = ctypes.c_ulonglong(0)
		section_list = core.BNGetSections(self.handle, count)
		result = {}
		for i in range(0, count.value):
			result[core.BNSectionGetName(section_list[i])] = Section(core.BNNewSectionReference(section_list[i]))
		core.BNFreeSectionList(section_list, count.value)
		return result

	@property
	def allocated_ranges(self):
		"""List of valid address ranges for this view (read-only)"""
		count = ctypes.c_ulonglong(0)
		range_list = core.BNGetAllocatedRanges(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(AddressRange(range_list[i].start, range_list[i].end))
		core.BNFreeAddressRanges(range_list)
		return result

	@property
	def session_data(self):
		"""Dictionary object where plugins can store arbitrary data associated with the view"""
		handle = ctypes.cast(self.handle, ctypes.c_void_p)
		if handle.value not in BinaryView._associated_data:
			obj = _BinaryViewAssociatedDataStore()
			BinaryView._associated_data[handle.value] = obj
			return obj
		else:
			return BinaryView._associated_data[handle.value]

	@property
	def global_pointer_value(self):
		"""Discovered value of the global pointer register, if the binary uses one (read-only)"""
		result = core.BNGetGlobalPointerValue(self.handle)
		return binaryninja.function.RegisterValue(self.arch, result.value, confidence = result.confidence)

	@property
	def parameters_for_analysis(self):
		return core.BNGetParametersForAnalysis(self.handle)

	@parameters_for_analysis.setter
	def parameters_for_analysis(self, params):
		core.BNSetParametersForAnalysis(self.handle, params)

	@property
	def max_function_size_for_analysis(self):
		"""Maximum size of function (sum of basic block sizes in bytes) for auto analysis"""
		return core.BNGetMaxFunctionSizeForAnalysis(self.handle)

	@max_function_size_for_analysis.setter
	def max_function_size_for_analysis(self, size):
		core.BNSetMaxFunctionSizeForAnalysis(self.handle, size)

	@property
	def relocation_ranges(self):
		"""List of relocation range tuples (read-only)"""

		count = ctypes.c_ulonglong()
		ranges = core.BNGetRelocationRanges(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append((ranges[i].start, ranges[i].end))
		core.BNFreeRelocationRanges(ranges, count)
		return result

	def relocation_ranges_at(self, addr):
		"""List of relocation range tuples for a given address"""

		count = ctypes.c_ulonglong()
		ranges = core.BNGetRelocationRangesAtAddress(self.handle, addr, count)
		result = []
		for i in range(0, count.value):
			result.append((ranges[i].start, ranges[i].end))
		core.BNFreeRelocationRanges(ranges, count)
		return result

	@property
	def new_auto_function_analysis_suppressed(self):
		"""Whether or not automatically discovered functions will be analyzed"""
		return core.BNGetNewAutoFunctionAnalysisSuppressed(self.handle)

	@new_auto_function_analysis_suppressed.setter
	def new_auto_function_analysis_suppressed(self, suppress):
		core.BNSetNewAutoFunctionAnalysisSuppressed(self.handle, suppress)

	def _init(self, ctxt):
		try:
			return self.init()
		except:
			log.log_error(traceback.format_exc())
			return False

	def _external_ref_taken(self, ctxt):
		try:
			self.__class__._registered_instances.append(self)
		except:
			log.log_error(traceback.format_exc())

	def _external_ref_released(self, ctxt):
		try:
			self.__class__._registered_instances.remove(self)
		except:
			log.log_error(traceback.format_exc())

	def _read(self, ctxt, dest, offset, length):
		try:
			data = self.perform_read(offset, length)
			if data is None:
				return 0
			data = cstr(data)
			if len(data) > length:
				data = data[0:length]
			ctypes.memmove(dest, data, len(data))
			return len(data)
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _write(self, ctxt, offset, src, length):
		try:
			data = ctypes.create_string_buffer(length)
			ctypes.memmove(data, src, length)
			return self.perform_write(offset, data.raw)
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _insert(self, ctxt, offset, src, length):
		try:
			data = ctypes.create_string_buffer(length)
			ctypes.memmove(data, src, length)
			return self.perform_insert(offset, data.raw)
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _remove(self, ctxt, offset, length):
		try:
			return self.perform_remove(offset, length)
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _get_modification(self, ctxt, offset):
		try:
			return self.perform_get_modification(offset)
		except:
			log.log_error(traceback.format_exc())
			return ModificationStatus.Original

	def _is_valid_offset(self, ctxt, offset):
		try:
			return self.perform_is_valid_offset(offset)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_offset_readable(self, ctxt, offset):
		try:
			return self.perform_is_offset_readable(offset)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_offset_writable(self, ctxt, offset):
		try:
			return self.perform_is_offset_writable(offset)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_offset_executable(self, ctxt, offset):
		try:
			return self.perform_is_offset_executable(offset)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _get_next_valid_offset(self, ctxt, offset):
		try:
			return self.perform_get_next_valid_offset(offset)
		except:
			log.log_error(traceback.format_exc())
			return offset

	def _get_start(self, ctxt):
		try:
			return self.perform_get_start()
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _get_length(self, ctxt):
		try:
			return self.perform_get_length()
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _get_entry_point(self, ctxt):
		try:
			return self.perform_get_entry_point()
		except:
			log.log_error(traceback.format_exc())
			return 0

	def _is_executable(self, ctxt):
		try:
			return self.perform_is_executable()
		except:
			log.log_error(traceback.format_exc())
			return False

	def _get_default_endianness(self, ctxt):
		try:
			return self.perform_get_default_endianness()
		except:
			log.log_error(traceback.format_exc())
			return Endianness.LittleEndian

	def _is_relocatable(self, ctxt):
		try:
			return self.perform_is_relocatable()
		except:
			log.log_error(traceback.format_exc())
			return False

	def _get_address_size(self, ctxt):
		try:
			return self.perform_get_address_size()
		except:
			log.log_error(traceback.format_exc())
			return 8

	def _save(self, ctxt, file_accessor):
		try:
			return self.perform_save(fileaccessor.CoreFileAccessor(file_accessor))
		except:
			log.log_error(traceback.format_exc())
			return False

	def init(self):
		return True

	def get_disassembly(self, addr, arch=None):
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
		"""
		if arch is None:
			arch = self.arch
		txt, size = arch.get_instruction_text(self.read(addr, arch.max_instr_length), addr)
		self.next_address = addr + size
		if txt is None:
			return None
		return ''.join(str(a) for a in txt).strip()

	def get_next_disassembly(self, arch=None):
		"""
		``get_next_disassembly`` simple helper function for printing disassembly of the next instruction.
		The internal state of the instruction to be printed is stored in the :attr:`next_address` attribute

		:param Architecture arch: optional Architecture, ``self.arch`` is used if this parameter is None
		:return: a str representation of the instruction at virtual address :attr:`next_address`
		:rtype: str or None
		:Example:

			>>> bv.get_next_disassembly()
			'push    ebp'
			>>> bv.get_next_disassembly()
			'mov     ebp, esp'
			>>> #Now reset the starting point back to the entry point
			>>> bv.next_address = bv.entry_point
			>>> bv.get_next_disassembly()
			'push    ebp'
			>>>
		"""
		if arch is None:
			arch = self.arch
		if self.next_address is None:
			self.next_address = self.entry_point
		txt, size = arch.get_instruction_text(self.read(self.next_address, arch.max_instr_length), self.next_address)
		self.next_address += size
		if txt is None:
			return None
		return ''.join(str(a) for a in txt).strip()

	def perform_save(self, accessor):
		if self.parent_view is not None:
			return self.parent_view.save(accessor)
		return False

	@abc.abstractmethod
	def perform_get_address_size(self):
		raise NotImplementedError

	def perform_get_length(self):
		"""
		``perform_get_length`` implements a query for the size of the virtual address range used by
		the BinaryView.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:return: returns the size of the virtual address range used by the BinaryView.
		:rtype: int
		"""
		return 0

	def perform_read(self, addr, length):
		"""
		``perform_read`` implements a mapping between a virtual address and an absolute file offset, reading
		``length`` bytes from the rebased address ``addr``.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to attempt to read from
		:param int length: the number of bytes to be read
		:return: length bytes read from addr, should return empty string on error
		:rtype: str
		"""
		return ""

	def perform_write(self, addr, data):
		"""
		``perform_write`` implements a mapping between a virtual address and an absolute file offset, writing
		the bytes ``data`` to rebased address ``addr``.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address
		:param str data: the data to be written
		:return: length of data written, should return 0 on error
		:rtype: int
		"""
		return 0

	def perform_insert(self, addr, data):
		"""
		``perform_insert`` implements a mapping between a virtual address and an absolute file offset, inserting
		the bytes ``data`` to rebased address ``addr``.

		.. note:: This method **may** be overridden by custom BinaryViews. If not overridden, inserting is disallowed

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address
		:param str data: the data to be inserted
		:return: length of data inserted, should return 0 on error
		:rtype: int
		"""
		return 0

	def perform_remove(self, addr, length):
		"""
		``perform_remove`` implements a mapping between a virtual address and an absolute file offset, removing
		``length`` bytes from the rebased address ``addr``.

		.. note:: This method **may** be overridden by custom BinaryViews. If not overridden, removing data is disallowed

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address
		:param str data: the data to be removed
		:return: length of data removed, should return 0 on error
		:rtype: int
		"""
		return 0

	def perform_get_modification(self, addr):
		"""
		``perform_get_modification`` implements query to the whether the virtual address ``addr`` is modified.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: One of the following: Original = 0, Changed = 1, Inserted = 2
		:rtype: ModificationStatus
		"""
		return ModificationStatus.Original

	def perform_is_valid_offset(self, addr):
		"""
		``perform_is_valid_offset`` implements a check if an virtual address ``addr`` is valid.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid, false if the virtual address is invalid or error
		:rtype: bool
		"""
		data = self.read(addr, 1)
		return (data is not None) and (len(data) == 1)

	def perform_is_offset_readable(self, offset):
		"""
		``perform_is_offset_readable`` implements a check if an virtual address is readable.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int offset: a virtual address to be checked
		:return: true if the virtual address is readable, false if the virtual address is not readable or error
		:rtype: bool
		"""
		return self.is_valid_offset(offset)

	def perform_is_offset_writable(self, addr):
		"""
		``perform_is_offset_writable`` implements a check if a virtual address ``addr`` is writable.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is writable, false if the virtual address is not writable or error
		:rtype: bool
		"""
		return self.is_valid_offset(addr)

	def perform_is_offset_executable(self, addr):
		"""
		``perform_is_offset_executable`` implements a check if a virtual address ``addr`` is executable.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is executable, false if the virtual address is not executable or error
		:rtype: int
		"""
		return self.is_valid_offset(addr)

	def perform_get_next_valid_offset(self, addr):
		"""
		``perform_get_next_valid_offset`` implements a query for the next valid readable, writable, or executable virtual
		memory address.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to start checking from.
		:return: the next readable, writable, or executable virtual memory address
		:rtype: int
		"""
		if addr < self.perform_get_start():
			return self.perform_get_start()
		return addr

	def perform_get_start(self):
		"""
		``perform_get_start`` implements a query for the first readable, writable, or executable virtual address in
		the BinaryView.

		.. note:: This method **may** be overridden by custom BinaryViews. Use :func:`add_auto_segment` to provide \
		data without overriding this method.

		.. warning:: This method **must not** be called directly.

		:return: returns the first virtual address in the BinaryView.
		:rtype: int
		"""
		return 0

	def perform_get_entry_point(self):
		"""
		``perform_get_entry_point`` implements a query for the initial entry point for code execution.

		.. note:: This method **should** be implemented for custom BinaryViews that are executable.

		.. warning:: This method **must not** be called directly.

		:return: the virtual address of the entry point
		:rtype: int
		"""
		return 0

	def perform_is_executable(self):
		"""
		``perform_is_executable`` implements a check which returns true if the BinaryView is executable.

		.. note:: This method **must** be implemented for custom BinaryViews that are executable.

		.. warning:: This method **must not** be called directly.

		:return: true if the current BinaryView is executable, false if it is not executable or on error
		:rtype: bool
		"""
		return False

	def perform_get_default_endianness(self):
		"""
		``perform_get_default_endianness`` implements a check which returns true if the BinaryView is executable.

		.. note:: This method **may** be implemented for custom BinaryViews that are not LittleEndian.

		.. warning:: This method **must not** be called directly.

		:return: either :const:`Endianness.LittleEndian <binaryninja.enums.Endianness.LittleEndian>` or :const:`Endianness.BigEndian <binaryninja.enums.Endianness.BigEndian>`
		:rtype: Endianness
		"""
		return Endianness.LittleEndian

	def perform_is_relocatable(self):
		"""
		``perform_is_relocatable`` implements a check which returns true if the BinaryView is relocatable. Defaults to False

		.. note:: This method **may** be implemented for custom BinaryViews that are relocatable.

		.. warning:: This method **must not** be called directly.

		:return: True if the BinaryView is relocatable, False otherwise
		:rtype: boolean
		"""
		return False

	def create_database(self, filename, progress_func=None, clean=False):
		"""
		``create_database`` writes the current database (.bndb) file out to the specified file.

		:param str filename: path and filename to write the bndb to, this string `should` have ".bndb" appended to it.
		:param callback progress_func: optional function to be called with the current progress and total count.
		:param bool clean: optional argument to determine if undo data is saved in the database.
		:return: true on success, false on failure
		:rtype: bool
		"""
		return self._file.create_database(filename, progress_func, clean)

	def save_auto_snapshot(self, progress_func=None, clean=False):
		"""
		``save_auto_snapshot`` saves the current database to the already created file.

		.. note:: :py:meth:`create_database` should have been called prior to executing this method

		:param callback progress_func: optional function to be called with the current progress and total count.
		:param bool clean: optional argument to determine if undo data is saved in the database.
		:return: True if it successfully saved the snapshot, False otherwise
		:rtype: bool
		"""
		return self._file.save_auto_snapshot(progress_func, clean)

	def get_view_of_type(self, name):
		"""
		``get_view_of_type`` returns the BinaryView associated with the provided name if it exists.

		:param str name: Name of the view to be retrieved
		:return: BinaryView object associated with the provided name or None on failure
		:rtype: BinaryView or None
		"""
		return self._file.get_view_of_type(name)

	def begin_undo_actions(self):
		"""
		``begin_undo_actions`` start recording actions taken so the can be undone at some point.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		self._file.begin_undo_actions()

	def add_undo_action(self, action):
		core.BNAddUndoAction(self.handle, action.__class__.name, action._cb)

	def commit_undo_actions(self):
		"""
		``commit_undo_actions`` commit the actions taken since the last commit to the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		self._file.commit_undo_actions()

	def undo(self):
		"""
		``undo`` undo the last committed action in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions()
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

	def redo(self):
		"""
		``redo`` redo the last committed action in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(0x100012f1)
			True
			>>> bv.commit_undo_actions()
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

	def navigate(self, view, offset):
		return self._file.navigate(view, offset)

	def read(self, addr, length):
		"""
		``read`` returns the data reads at most ``length`` bytes from virtual address ``addr``.

		Note: Python2 returns a str, but Python3 returns a bytes object.  str(DataBufferObject) will \
 		still get you a str in either case.

		:param int addr: virtual address to read from.
		:param int length: number of bytes to read.
		:return: at most ``length`` bytes from the virtual address ``addr``, empty string on error or no data.
		:rtype: python2 - str; python3 - bytes
		:Example:

			>>> #Opening a x86_64 Mach-O binary
			>>> bv = BinaryViewType['Raw'].open("/bin/ls") #note that we are using open instead of get_view_of_file to get the raw view
			>>> bv.read(0,4)
			\'\\xcf\\xfa\\xed\\xfe\'
		"""
		if (addr < 0) or (length < 0):
			raise ValueError("length and address must both be positive")
		buf = databuffer.DataBuffer(handle=core.BNReadViewBuffer(self.handle, addr, length))
		return bytes(buf)

	def write(self, addr, data):
		"""
		``write`` writes the bytes in ``data`` to the virtual address ``addr``.

		:param int addr: virtual address to write to.
		:param str data: data to be written at addr.
		:return: number of bytes written to virtual address ``addr``
		:rtype: int
		:Example:

			>>> bv.read(0,4)
			'BBBB'
			>>> bv.write(0, "AAAA")
			4L
			>>> bv.read(0,4)
			'AAAA'
		"""
		if not isinstance(data, bytes):
			if isinstance(data, str):
				buf = databuffer.DataBuffer(data.encode())
			else:
				raise TypeError("Must be bytes or str")
		else:
			buf = databuffer.DataBuffer(data)
		return core.BNWriteViewBuffer(self.handle, addr, buf.handle)

	def insert(self, addr, data):
		"""
		``insert`` inserts the bytes in ``data`` to the virtual address ``addr``.

		:param int addr: virtual address to write to.
		:param str data: data to be inserted at addr.
		:return: number of bytes inserted to virtual address ``addr``
		:rtype: int
		:Example:

			>>> bv.insert(0,"BBBB")
			4L
			>>> bv.read(0,8)
			'BBBBAAAA'
		"""
		if not isinstance(data, bytes):
			raise TypeError("Must be bytes")
		buf = databuffer.DataBuffer(data)
		return core.BNInsertViewBuffer(self.handle, addr, buf.handle)

	def remove(self, addr, length):
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
			4L
			>>> bv.read(0,4)
			'AAAA'
		"""
		return core.BNRemoveViewData(self.handle, addr, length)

	def get_entropy(self, addr, length, block_size=0):
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
		data = (ctypes.c_float * ((length // block_size) + 1))()
		length = core.BNGetEntropy(self.handle, addr, length, block_size, data)

		for i in range(0, length):
			result.append(float(data[i]))
		return result

	def get_modification(self, addr, length=None):
		"""
		``get_modification`` returns the modified bytes of up to ``length`` bytes from virtual address ``addr``, or if
		``length`` is None returns the ModificationStatus.

		:param int addr: virtual address to get modification from
		:param int length: optional length of modification
		:return: Either ModificationStatus of the byte at ``addr``, or string of modified bytes at ``addr``
		:rtype: ModificationStatus or str
		"""
		if length is None:
			return ModificationStatus(core.BNGetModification(self.handle, addr))
		data = (ModificationStatus * length)()
		length = core.BNGetModificationArray(self.handle, addr, data, length)
		return data[0:length]

	def is_valid_offset(self, addr):
		"""
		``is_valid_offset`` checks if an virtual address ``addr`` is valid .

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid, false if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsValidOffset(self.handle, addr)

	def is_offset_readable(self, addr):
		"""
		``is_offset_readable`` checks if an virtual address ``addr`` is valid for reading.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid for reading, false if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetReadable(self.handle, addr)

	def is_offset_writable(self, addr):
		"""
		``is_offset_writable`` checks if an virtual address ``addr`` is valid for writing.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid for writing, false if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetWritable(self.handle, addr)

	def is_offset_executable(self, addr):
		"""
		``is_offset_executable`` checks if an virtual address ``addr`` is valid for executing.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid for executing, false if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetExecutable(self.handle, addr)

	def is_offset_code_semantics(self, addr):
		"""
		``is_offset_code_semantics`` checks if an virtual address ``addr`` is semantically valid for code.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid for writing, false if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetCodeSemantics(self.handle, addr)

	def is_offset_extern_semantics(self, addr):
		"""
		``is_offset_extern_semantics`` checks if an virtual address ``addr`` is semantically valid for external references.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid for writing, false if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetExternSemantics(self.handle, addr)

	def is_offset_writable_semantics(self, addr):
		"""
		``is_offset_writable_semantics`` checks if an virtual address ``addr`` is semantically writable. Some sections
		may have writable permissions for linking purposes but can be treated as read-only for the purposes of
		analysis.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid for writing, false if the virtual address is invalid or error
		:rtype: bool
		"""
		return core.BNIsOffsetWritableSemantics(self.handle, addr)

	def save(self, dest):
		"""
		``save`` saves the original binary file to the provided destination ``dest`` along with any modifications.

		:param str dest: destination path and filename of file to be written
		:return: boolean True on success, False on failure
		:rtype: bool
		"""
		if isinstance(dest, fileaccessor.FileAccessor):
			return core.BNSaveToFile(self.handle, dest._cb)
		return core.BNSaveToFilename(self.handle, str(dest))

	def register_notification(self, notify):
		"""
		`register_notification` provides a mechanism for receiving callbacks for various analysis events. A full
		list of callbacks can be seen in :py:Class:`BinaryDataNotification`.

		:param BinaryDataNotification notify: notify is a subclassed instance of :py:Class:`BinaryDataNotification`.
		:rtype: None
		"""
		cb = BinaryDataNotificationCallbacks(self, notify)
		cb._register()
		self.notifications[notify] = cb

	def unregister_notification(self, notify):
		"""
		`unregister_notification` unregisters the :py:Class:`BinaryDataNotification` object passed to
		`register_notification`

		:param BinaryDataNotification notify: notify is a subclassed instance of :py:Class:`BinaryDataNotification`.
		:rtype: None
		"""
		if notify in self.notifications:
			self.notifications[notify]._unregister()
			del self.notifications[notify]

	def add_function(self, addr, plat=None):
		"""
		``add_function`` add a new function of the given ``plat`` at the virtual address ``addr``

		:param int addr: virtual address of the function to be added
		:param Platform plat: Platform for the function to be added
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
		if not isinstance(plat, binaryninja.platform.Platform):
			raise AttributeError("Provided platform is not of type `binaryninja.platform.Platform`")
		core.BNAddFunctionForAnalysis(self.handle, plat.handle, addr)

	def add_entry_point(self, addr, plat=None):
		"""
		``add_entry_point`` adds an virtual address to start analysis from for a given plat.

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
		if not isinstance(plat, binaryninja.platform.Platform):
			raise AttributeError("Provided platform is not of type `binaryninja.platform.Platform`")
		core.BNAddEntryPointForAnalysis(self.handle, plat.handle, addr)

	def remove_function(self, func):
		"""
		``remove_function`` removes the function ``func`` from the list of functions

		:param Function func: a Function object.
		:rtype: None
		:Example:

			>>> bv.functions
			[<func: x86_64@0x1>]
			>>> bv.remove_function(bv.functions[0])
			>>> bv.functions
			[]
		"""
		core.BNRemoveAnalysisFunction(self.handle, func.handle)

	def create_user_function(self, addr, plat=None):
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
			plat = self.platform
		core.BNCreateUserFunction(self.handle, plat.handle, addr)

	def remove_user_function(self, func):
		"""
		``remove_user_function`` removes the *user* function ``func`` from the list of functions

		:param Function func: a Function object.
		:rtype: None
		:Example:

			>>> bv.functions
			[<func: x86_64@0x1>]
			>>> bv.remove_user_function(bv.functions[0])
			>>> bv.functions
			[]
		"""
		core.BNRemoveUserFunction(self.handle, func.handle)

	def add_analysis_option(self, name):
		"""
		``add_analysis_option`` adds an analysis option. Analysis options elaborate the analysis phase. The user must
		start analysis by calling either :func:`update_analysis` or :func:`update_analysis_and_wait`.

		:param str name: name of the analysis option. Available options are: "linearsweep", and "signaturematcher".

		:rtype: None
		:Example:

			>>> bv.add_analysis_option("linearsweep")
			>>> bv.update_analysis_and_wait()
		"""
		core.BNAddAnalysisOption(self.handle, name)

	def update_analysis(self):
		"""
		``update_analysis`` asynchronously starts the analysis running and returns immediately. Analysis of BinaryViews
		does not occur automatically, the user must start analysis by calling either :func:`update_analysis` or
		:func:`update_analysis_and_wait`. An analysis update **must** be run after changes are made which could change
		analysis results such as adding functions.

		:rtype: None
		"""
		core.BNUpdateAnalysis(self.handle)

	def update_analysis_and_wait(self):
		"""
		``update_analysis_and_wait`` blocking call to update the analysis, this call returns when the analysis is
		complete.  Analysis of BinaryViews does not occur automatically, the user must start analysis by calling either
		:func:`update_analysis` or :func:`update_analysis_and_wait`. An analysis update **must** be run after changes are
		made which could change analysis results such as adding functions.

		:rtype: None
		"""
		core.BNUpdateAnalysisAndWait(self.handle)

	def abort_analysis(self):
		"""
		``abort_analysis`` will abort the currently running analysis.

		:rtype: None
		"""
		core.BNAbortAnalysis(self.handle)

	def define_data_var(self, addr, var_type):
		"""
		``define_data_var`` defines a non-user data variable ``var_type`` at the virtual address ``addr``.

		:param int addr: virtual address to define the given data variable
		:param Type var_type: type to be defined at the given virtual address
		:rtype: None
		:Example:

			>>> t = bv.parse_type_string("int foo")
			>>> t
			(<type: int32_t>, 'foo')
			>>> bv.define_data_var(bv.entry_point, t[0])
			>>>
		"""
		tc = core.BNTypeWithConfidence()
		tc.type = var_type.handle
		tc.confidence = var_type.confidence
		core.BNDefineDataVariable(self.handle, addr, tc)

	def define_user_data_var(self, addr, var_type):
		"""
		``define_user_data_var`` defines a user data variable ``var_type`` at the virtual address ``addr``.

		:param int addr: virtual address to define the given data variable
		:param binaryninja.Type var_type: type to be defined at the given virtual address
		:rtype: None
		:Example:

			>>> t = bv.parse_type_string("int foo")
			>>> t
			(<type: int32_t>, 'foo')
			>>> bv.define_user_data_var(bv.entry_point, t[0])
			>>>
		"""
		tc = core.BNTypeWithConfidence()
		tc.type = var_type.handle
		tc.confidence = var_type.confidence
		core.BNDefineUserDataVariable(self.handle, addr, tc)

	def undefine_data_var(self, addr):
		"""
		``undefine_data_var`` removes the non-user data variable at the virtual address ``addr``.

		:param int addr: virtual address to define the data variable to be removed
		:rtype: None
		:Example:

			>>> bv.undefine_data_var(bv.entry_point)
			>>>
		"""
		core.BNUndefineDataVariable(self.handle, addr)

	def undefine_user_data_var(self, addr):
		"""
		``undefine_user_data_var`` removes the user data variable at the virtual address ``addr``.

		:param int addr: virtual address to define the data variable to be removed
		:rtype: None
		:Example:

			>>> bv.undefine_user_data_var(bv.entry_point)
			>>>
		"""
		core.BNUndefineUserDataVariable(self.handle, addr)

	def get_data_var_at(self, addr):
		"""
		``get_data_var_at`` returns the data type at a given virtual address.

		:param int addr: virtual address to get the data type from
		:return: returns the DataVariable at the given virtual address, None on error.
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
		return DataVariable(var.address, types.Type(var.type, platform = self.platform, confidence = var.typeConfidence), var.autoDiscovered, self)

	def get_functions_containing(self, addr):
		"""
		``get_functions_containing`` returns a list of functions which contain the given address.

		:param int addr: virtual address to query.
		:rtype: list of Function objects
		"""
		basic_blocks = self.get_basic_blocks_at(addr)

		result = []
		for block in basic_blocks:
			result.append(block.function)
		return result

	def get_function_at(self, addr, plat=None):
		"""
		``get_function_at`` gets a Function object for the function that starts at virtual address ``addr``:

		:param int addr: starting virtual address of the desired function
		:param Platform plat: plat of the desired function
		:return: returns a Function object or None for the function at the virtual address provided
		:rtype: Function
		:Example:

			>>> bv.get_function_at(bv.entry_point)
			<func: x86_64@0x100001174>
			>>>
		"""
		if plat is None:
			plat = self.platform
		if plat is None:
			return None
		func = core.BNGetAnalysisFunction(self.handle, plat.handle, addr)
		if func is None:
			return None
		return binaryninja.function.Function(self, func)

	def get_functions_at(self, addr):
		"""

		``get_functions_at`` get a list of binaryninja.Function objects (one for each valid platform) that start at the
		given virtual address. Binary Ninja does not limit the number of platforms in a given file thus there may be
		multiple functions defined from different architectures at the same location. This API allows you to query all
		of valid platforms.

		You may also be interested in :func:`get_functions_containing` which is useful for requesting all function
		that contain a given address

		:param int addr: virtual address of the desired Function object list.
		:return: a list of binaryninja.Function objects defined at the provided virtual address
		:rtype: list(Function)
		"""
		count = ctypes.c_ulonglong(0)
		funcs = core.BNGetAnalysisFunctionsForAddress(self.handle, addr, count)
		result = []
		for i in range(0, count.value):
			result.append(binaryninja.function.Function(self, core.BNNewFunctionReference(funcs[i])))
		core.BNFreeFunctionList(funcs, count.value)
		return result

	def get_recent_function_at(self, addr):
		func = core.BNGetRecentAnalysisFunctionForAddress(self.handle, addr)
		if func is None:
			return None
		return binaryninja.function.Function(self, func)

	def get_basic_blocks_at(self, addr):
		"""
		``get_basic_blocks_at`` get a list of :py:Class:`BasicBlock` objects which exist at the provided virtual address.

		:param int addr: virtual address of BasicBlock desired
		:return: a list of :py:Class:`BasicBlock` objects
		:rtype: list(BasicBlock)
		"""
		count = ctypes.c_ulonglong(0)
		blocks = core.BNGetBasicBlocksForAddress(self.handle, addr, count)
		result = []
		for i in range(0, count.value):
			result.append(basicblock.BasicBlock(core.BNNewBasicBlockReference(blocks[i]), self))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	def get_basic_blocks_starting_at(self, addr):
		"""
		``get_basic_blocks_starting_at`` get a list of :py:Class:`BasicBlock` objects which start at the provided virtual address.

		:param int addr: virtual address of BasicBlock desired
		:return: a list of :py:Class:`BasicBlock` objects
		:rtype: list(BasicBlock)
		"""
		count = ctypes.c_ulonglong(0)
		blocks = core.BNGetBasicBlocksStartingAtAddress(self.handle, addr, count)
		result = []
		for i in range(0, count.value):
			result.append(basicblock.BasicBlock(core.BNNewBasicBlockReference(blocks[i]), self))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	def get_recent_basic_block_at(self, addr):
		block = core.BNGetRecentBasicBlockForAddress(self.handle, addr)
		if block is None:
			return None
		return basicblock.BasicBlock(block, self)

	def get_code_refs(self, addr, length=None):
		"""
		``get_code_refs`` returns a list of ReferenceSource objects (xrefs or cross-references) that point to the provided virtual address.
		This function returns both autoanalysis ("auto") and user-specified ("user") xrefs.
		To add a user-specified reference, see :func:`~binaryninja.function.Function.add_user_code_ref`.

		:param int addr: virtual address to query for references
		:param int length: optional length of query
		:return: List of References for the given virtual address
		:rtype: list(ReferenceSource)
		:Example:

			>>> bv.get_code_refs(here)
			[<ref: x86@0x4165ff>]
			>>>

		"""
		count = ctypes.c_ulonglong(0)
		if length is None:
			refs = core.BNGetCodeReferences(self.handle, addr, count)
		else:
			refs = core.BNGetCodeReferencesInRange(self.handle, addr, length, count)
		result = []
		for i in range(0, count.value):
			if refs[i].func:
				func = binaryninja.function.Function(self, core.BNNewFunctionReference(refs[i].func))
			else:
				func = None
			if refs[i].arch:
				arch = binaryninja.architecture.CoreArchitecture._from_cache(refs[i].arch)
			else:
				arch = None
			addr = refs[i].addr
			result.append(binaryninja.architecture.ReferenceSource(func, arch, addr))
		core.BNFreeCodeReferences(refs, count.value)
		return result

	def get_code_refs_from(self, addr, func=None, arch=None, length=None):
		"""
		``get_code_refs_from`` returns a list of virtual addresses referenced by code in the function ``func``,
		of the architecture ``arch``, and at the address ``addr``. If no function is specified, references from
		all functions and containing the address will be returned. If no architecture is specified, the
		architecture of the function will be used.
		This function returns both autoanalysis ("auto") and user-specified ("user") xrefs.
		To add a user-specified reference, see :func:`~binaryninja.function.Function.add_user_code_ref`.

		:param int addr: virtual address to query for references
		:param int length: optional length of query
		:return: list of integers
		:rtype: list(integer)
		"""

		result = []
		funcs = self.get_functions_containing(addr) if func is None else [func]
		if not funcs:
			return []
		for src_func in funcs:
			src_arch = src_func.arch if arch is None else arch
			ref_src = core.BNReferenceSource(src_func.handle, src_arch.handle, addr)
			count = ctypes.c_ulonglong(0)
			if length is None:
				refs = core.BNGetCodeReferencesFrom(self.handle, ref_src, count)
			else:
				refs = core.BNGetCodeReferencesFromInRange(self.handle, ref_src, length, count)
			for i in range(0, count.value):
				result.append(refs[i])
			core.BNFreeAddressList(refs)
		return result

	def get_data_refs(self, addr, length=None):
		"""
		``get_data_refs`` returns a list of virtual addresses of data which references ``addr``. Optionally specifying
		a length. When ``length`` is set ``get_data_refs`` returns the data which references in the range ``addr``-``addr``+``length``.
		This function returns both autoanalysis ("auto") and user-specified ("user") xrefs. To add a user-specified
		reference, see :func:`add_user_data_ref`.

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
		else:
			refs = core.BNGetDataReferencesInRange(self.handle, addr, length, count)

		result = []
		for i in range(0, count.value):
			result.append(refs[i])
		core.BNFreeDataReferences(refs, count.value)
		return result

	def get_data_refs_from(self, addr, length=None):
		"""
		``get_data_refs_from`` returns a list of virtual addresses referenced by the address ``addr``. Optionally specifying
		a length. When ``length`` is set ``get_data_refs_from`` returns the data referenced in the range ``addr``-``addr``+``length``.
		This function returns both autoanalysis ("auto") and user-specified ("user") xrefs. To add a user-specified
		reference, see :func:`add_user_data_ref`.

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
		else:
			refs = core.BNGetDataReferencesFromInRange(self.handle, addr, length, count)

		result = []
		for i in range(0, count.value):
			result.append(refs[i])
		core.BNFreeDataReferences(refs, count.value)
		return result


	def add_user_data_ref(self, from_addr, to_addr):
		"""
		``add_user_data_ref`` adds a user-specified data cross-reference (xref) from the address ``from_addr`` to the address ``to_addr``.
		If the reference already exists, no action is performed. To remove the reference, use :func:`remove_user_data_ref`.

		:param int from_addr: the reference's source virtual address.
		:param int to_addr: the reference's destination virtual address.
		:rtype: None
		"""
		core.BNAddUserDataReference(self.handle, from_addr, to_addr)


	def remove_user_data_ref(self, from_addr, to_addr):
		"""
		``remove_user_data_ref`` removes a user-specified data cross-reference (xref) from the address ``from_addr`` to the address ``to_addr``.
		This function will only remove user-specified references, not ones generated during autoanalysis.
		If the reference does not exist, no action is performed.

		:param int from_addr: the reference's source virtual address.
		:param int to_addr: the reference's destination virtual address.
		:rtype: None
		"""
		core.BNRemoveUserDataReference(self.handle, from_addr, to_addr)


	def get_callers(self, addr):
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
		result = []
		for i in range(0, count.value):
			if refs[i].func:
				func = binaryninja.function.Function(self, core.BNNewFunctionReference(refs[i].func))
			else:
				func = None
			if refs[i].arch:
				arch = binaryninja.architecture.CoreArchitecture._from_cache(refs[i].arch)
			else:
				arch = None
			addr = refs[i].addr
			result.append(binaryninja.architecture.ReferenceSource(func, arch, addr))
		core.BNFreeCodeReferences(refs, count.value)
		return result

	def get_callees(self, addr, func=None, arch=None):
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
			ref_src = core.BNReferenceSource(src_func.handle, src_arch.handle, addr)
			count = ctypes.c_ulonglong(0)
			refs = core.BNGetCallees(self.handle, ref_src, count)
			for i in range(0, count.value):
				result.append(refs[i])
			core.BNFreeAddressList(refs)
		return result


	def get_symbol_at(self, addr, namespace=None):
		"""
		``get_symbol_at`` returns the Symbol at the provided virtual address.

		:param int addr: virtual address to query for symbol
		:return: Symbol for the given virtual address
		:param NameSpace namespace: the namespace of the symbols to retrieve
		:rtype: Symbol
		:Example:

			>>> bv.get_symbol_at(bv.entry_point)
			<FunctionSymbol: "_start" @ 0x100001174>
			>>>
		"""
		if isinstance(namespace, str):
			namespace = types.NameSpace(namespace)
		if isinstance(namespace, types.NameSpace):
			namespace = namespace._get_core_struct()

		sym = core.BNGetSymbolByAddress(self.handle, addr, namespace)
		if sym is None:
			return None
		return types.Symbol(None, None, None, handle = sym)

	def get_symbol_by_raw_name(self, name, namespace=None):
		"""
		``get_symbol_by_raw_name`` retrieves a Symbol object for the given a raw (mangled) name.

		:param str name: raw (mangled) name of Symbol to be retrieved
		:return: Symbol object corresponding to the provided raw name
		:param NameSpace namespace: the namespace to search for the given symbol
		:rtype: Symbol
		:Example:

			>>> bv.get_symbol_by_raw_name('?testf@Foobar@@SA?AW4foo@1@W421@@Z')
			<FunctionSymbol: "public: static enum Foobar::foo __cdecl Foobar::testf(enum Foobar::foo)" @ 0x10001100>
			>>>
		"""
		if isinstance(namespace, str):
			namespace = types.NameSpace(namespace)
		if isinstance(namespace, types.NameSpace):
			namespace = namespace._get_core_struct()
		sym = core.BNGetSymbolByRawName(self.handle, name, namespace)
		if sym is None:
			return None
		return types.Symbol(None, None, None, handle = sym)

	def get_symbols_by_name(self, name, namespace=None):
		"""
		``get_symbols_by_name`` retrieves a list of Symbol objects for the given symbol name.

		:param str name: name of Symbol object to be retrieved
		:return: Symbol object corresponding to the provided name
		:param NameSpace namespace: the namespace of the symbol
		:rtype: Symbol
		:Example:

			>>> bv.get_symbols_by_name('?testf@Foobar@@SA?AW4foo@1@W421@@Z')
			[<FunctionSymbol: "public: static enum Foobar::foo __cdecl Foobar::testf(enum Foobar::foo)" @ 0x10001100>]
			>>>
		"""
		if isinstance(namespace, str):
			namespace = types.NameSpace(namespace)
		if isinstance(namespace, types.NameSpace):
			namespace = namespace._get_core_struct()
		count = ctypes.c_ulonglong(0)
		syms = core.BNGetSymbolsByName(self.handle, name, count, namespace)
		result = []
		for i in range(0, count.value):
			result.append(types.Symbol(None, None, None, handle = core.BNNewSymbolReference(syms[i])))
		core.BNFreeSymbolList(syms, count.value)
		return result

	def get_symbols(self, start=None, length=None, namespace=None):
		"""
		``get_symbols`` retrieves the list of all Symbol objects in the optionally provided range.

		:param int start: optional start virtual address
		:param int length: optional length
		:return: list of all Symbol objects, or those Symbol objects in the range of ``start``-``start+length``
		:rtype: list(Symbol)
		:Example:

			>>> bv.get_symbols(0x1000200c, 1)
			[<ImportAddressSymbol: "KERNEL32!IsProcessorFeaturePresent@IAT" @ 0x1000200c>]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		if isinstance(namespace, str):
			namespace = types.NameSpace(namespace)
		if isinstance(namespace, types.NameSpace):
			namespace = namespace._get_core_struct()
		if start is None:
			syms = core.BNGetSymbols(self.handle, count, namespace)
		else:
			syms = core.BNGetSymbolsInRange(self.handle, start, length, count, namespace)
		result = []
		for i in range(0, count.value):
			result.append(types.Symbol(None, None, None, handle = core.BNNewSymbolReference(syms[i])))
		core.BNFreeSymbolList(syms, count.value)
		return result

	def get_symbols_of_type(self, sym_type, start=None, length=None, namespace=None):
		"""
		``get_symbols_of_type`` retrieves a list of all Symbol objects of the provided symbol type in the optionally
		 provided range.

		:param SymbolType sym_type: A Symbol type: :py:Class:`Symbol`.
		:param int start: optional start virtual address
		:param int length: optional length
		:return: list of all Symbol objects of type sym_type, or those Symbol objects in the range of ``start``-``start+length``
		:rtype: list(Symbol)
		:Example:

			>>> bv.get_symbols_of_type(SymbolType.ImportAddressSymbol, 0x10002028, 1)
			[<ImportAddressSymbol: "KERNEL32!GetCurrentThreadId@IAT" @ 0x10002028>]
			>>>
		"""
		if isinstance(sym_type, str):
			sym_type = SymbolType[sym_type]
		if isinstance(namespace, str):
			namespace = types.NameSpace(namespace)
		if isinstance(namespace, types.NameSpace):
			namespace = namespace._get_core_struct()
		count = ctypes.c_ulonglong(0)
		if start is None:
			syms = core.BNGetSymbolsOfType(self.handle, sym_type, count, namespace)
		else:
			syms = core.BNGetSymbolsOfTypeInRange(self.handle, sym_type, start, length, count)
		result = []
		for i in range(0, count.value):
			result.append(types.Symbol(None, None, None, handle = core.BNNewSymbolReference(syms[i])))
		core.BNFreeSymbolList(syms, count.value)
		return result

	def define_auto_symbol(self, sym):
		"""
		``define_auto_symbol`` adds a symbol to the internal list of automatically discovered Symbol objects in a given
		namespace.

		.. warning:: If multiple symbols for the same address are defined, only the most recent symbol will ever be used.

		:param Symbol sym: the symbol to define
		:rtype: None
		"""
		core.BNDefineAutoSymbol(self.handle, sym.handle)

	def define_auto_symbol_and_var_or_function(self, sym, sym_type, plat=None):
		"""
		``define_auto_symbol_and_var_or_function``

		.. warning:: If multiple symbols for the same address are defined, only the most recent symbol will ever be used.

		:param Symbol sym: the symbol to define
		:param SymbolType sym_type: Type of symbol being defined (can be None)
		:param Platform plat: (optional) platform
		:rtype: None
		"""
		if plat is None:
			plat = self.platform
		elif not isinstance(plat, binaryninja.platform.Platform):
			raise AttributeError("Provided platform is not of type `binaryninja.platform.Platform`")

		if isinstance(sym_type, binaryninja.Type):
			sym_type = sym_type.handle
		elif sym_type is not None:
			raise AttributeError("Provided sym_type is not of type `binaryninja.SymbolType`")

		core.BNDefineAutoSymbolAndVariableOrFunction(self.handle, plat.handle, sym.handle, sym_type)

	def undefine_auto_symbol(self, sym):
		"""
		``undefine_auto_symbol`` removes a symbol from the internal list of automatically discovered Symbol objects.

		:param Symbol sym: the symbol to undefine
		:rtype: None
		"""
		core.BNUndefineAutoSymbol(self.handle, sym.handle)

	def define_user_symbol(self, sym):
		"""
		``define_user_symbol`` adds a symbol to the internal list of user added Symbol objects.

		.. warning:: If multiple symbols for the same address are defined, only the most recent symbol will ever be used.

		:param Symbol sym: the symbol to define
		:rtype: None
		"""
		core.BNDefineUserSymbol(self.handle, sym.handle)

	def undefine_user_symbol(self, sym):
		"""
		``undefine_user_symbol`` removes a symbol from the internal list of user added Symbol objects.

		:param Symbol sym: the symbol to undefine
		:rtype: None
		"""
		core.BNUndefineUserSymbol(self.handle, sym.handle)

	def define_imported_function(self, import_addr_sym, func):
		"""
		``define_imported_function`` defines an imported Function ``func`` with a ImportedFunctionSymbol type.

		:param Symbol import_addr_sym: A Symbol object with type ImportedFunctionSymbol
		:param Function func: A Function object to define as an imported function
		:rtype: None
		"""
		core.BNDefineImportedFunction(self.handle, import_addr_sym.handle, func.handle)

	def create_tag_type(self, name, icon):
		"""
		``create_tag_type`` creates a new Tag Type and adds it to the view

		:param str name: The name for the tag
		:param str icon: The icon (recommended 1 emoji or 2 chars) for the tag
		:return: The created tag type
		:rtype: TagType
		:Example:

			>>> tt = bv.create_tag_type("Crabby Functions", "🦀")
			>>> bv.create_user_data_tag(here, tt, "Get Crabbed")
			>>>
		"""
		tag_type = TagType(core.BNCreateTagType(self.handle, name, icon))
		tag_type.name = name
		tag_type.icon = icon
		core.BNAddTagType(self.handle, tag_type.handle)
		return tag_type

	def remove_tag_type(self, tag_type):
		"""
		``remove_tag_type`` removes a new Tag Type and all tags that use it

		:param TagType tag_type: The Tag Type to remove
		:rtype: None
		"""
		core.BNRemoveTagType(self.handle, tag_type.handle)

	@property
	def tag_types(self):
		"""
		``tag_types`` gets a dictionary of all Tag Types present for the view,
		structured as {Tag Type Name => Tag Type}.

		:rtype: dict of (str, TagType)
		"""
		count = ctypes.c_ulonglong(0)
		types = core.BNGetTagTypes(self.handle, count)
		result = {}
		for i in range(0, count.value):
			tag = TagType(core.BNNewTagTypeReference(types[i]))
			if tag.name in result:
				if type(result[tag.name]) == list:
					result[tag.name].append(tag)
				else:
					result[tag.name] = [result[tag.name], tag]
			else:
				result[tag.name] = tag
		core.BNFreeTagTypeList(types, count.value)
		return result

	def create_user_tag(self, type, data):
		return self.create_tag(type, data, True)

	def create_auto_tag(self, type, data):
		return self.create_tag(type, data, False)

	def create_tag(self, type, data, user=True):
		"""
		``create_tag`` creates a new Tag object but does not add it anywhere.
		Use :py:meth:`create_user_data_tag` to create and add in one step.

		:param TagType type: The Tag Type for this Tag
		:param str data: Additional data for the Tag
		:return: The created Tag
		:rtype: Tag
		:Example:

			>>> tt = bv.tag_types["Crashes"]
			>>> tag = bv.create_tag(tt, "Null pointer dereference", True)
			>>> bv.add_user_data_tag(here, tag)
			>>>
		"""
		tag = Tag(core.BNCreateTag(type.handle, data))
		core.BNAddTag(self.handle, tag.handle, user)
		return tag

	@property
	def data_tags(self):
		"""
		``data_tags`` gets a list of all data Tags in the view.
		Tags are returned as a list of (address, Tag) pairs.

		:type: list(int, Tag)
		"""
		count = ctypes.c_ulonglong()
		tags = core.BNGetDataTagReferences(self.handle, count)
		result = []
		for i in range(0, count.value):
			tag = Tag(core.BNNewTagReference(tags[i].tag))
			result.append((tags[i].addr, tag))
		core.BNFreeTagReferences(tags, count.value)
		return result

	def get_data_tags_at(self, addr):
		"""
		``get_data_tags_at`` gets a list of all Tags for a data address.

		:param int addr: Address to get tags at
		:return: A list of data Tags
		:rtype: list(Tag)
		"""
		count = ctypes.c_ulonglong()
		tags = core.BNGetDataTags(self.handle, addr, count)
		result = []
		for i in range(0, count.value):
			result.append(Tag(core.BNNewTagReference(tags[i])))
		core.BNFreeTagList(tags, count.value)
		return result

	def get_data_tags_in_range(self, range):
		"""
		``get_data_tags_in_range`` gets a list of all data Tags in a given range.
		Range is inclusive at the start, exclusive at the end.

		:param AddressRange range: Address range from which to get tags
		:return: A list of data Tags
		:rtype: list(Tag)
		"""
		count = ctypes.c_ulonglong()
		tags = core.BNGetDataTagsInRange(self.handle, range.start, range.end, count)
		result = []
		for i in range(0, count.value):
			result.append(Tag(core.BNNewTagReference(tags[i])))
		core.BNFreeTagList(tags, count.value)
		return result

	def add_user_data_tag(self, addr, tag):
		"""
		``add_user_data_tag`` adds an already-created Tag object at a data address.
		Since this adds a user tag, it will be added to the current undo buffer.

		:param int addr: Address at which to add the tag
		:param Tag tag: Tag object to be added
		:rtype: None
		"""
		core.BNAddUserDataTag(self.handle, addr, tag.handle)

	def create_user_data_tag(self, addr, type, data, unique=False):
		"""
		``create_user_data_tag`` creates and adds a Tag object at a data
		address. Since this adds a user tag, it will be added to the current
		undo buffer.

		This API is appropriate for generic data tags, for functions,
		consider using :meth:`create_user_function_tag <binaryninja.function.Function.create_user_function_tag>` or for
		specific addresses inside of functions: :meth:`create_user_address_tag <binaryninja.function.Function.create_user_address_tag>`.

		:param int addr: Address at which to add the tag
		:param TagType type: Tag Type for the Tag that is created
		:param str data: Additional data for the Tag
		:param bool unique: If a tag already exists at this location with this data, don't add another
		:return: The created Tag
		:rtype: Tag
		:Example:

			>>> tt = bv.tag_types["Crashes"]
			>>> bv.create_user_data_tag(here, tt, "String data to associate with this tag")
			>>>
		"""
		if unique:
			tags = self.get_data_tags_at(addr)
			for tag in tags:
				if tag.type == type and tag.data == data:
					return

		tag = self.create_tag(type, data, True)
		core.BNAddUserDataTag(self.handle, addr, tag.handle)
		return tag

	def remove_user_data_tag(self, addr, tag):
		"""
		``remove_user_data_tag`` removes a Tag object at a data address.
		Since this removes a user tag, it will be added to the current undo buffer.

		:param int addr: Address at which to add the tag
		:param Tag tag: Tag object to be added
		:rtype: None
		"""
		core.BNRemoveUserDataTag(self.handle, addr, tag.handle)

	def add_auto_data_tag(self, addr, tag):
		"""
		``add_auto_data_tag`` adds an already-created Tag object at a data address.

		:param int addr: Address at which to add the tag
		:param Tag tag: Tag object to be added
		:rtype: None
		"""
		core.BNAddAutoDataTag(self.handle, addr, tag.handle)

	def create_auto_data_tag(self, addr, type, data, unique=False):
		"""
		``create_auto_data_tag`` creates and adds a Tag object at a data address.

		:param int addr: Address at which to add the tag
		:param TagType type: Tag Type for the Tag that is created
		:param str data: Additional data for the Tag
		:param bool unique: If a tag already exists at this location with this data, don't add another
		:return: The created Tag
		:rtype: Tag
		"""
		if unique:
			tags = self.get_data_tags_at(addr)
			for tag in tags:
				if tag.type == type and tag.data == data:
					return

		tag = self.create_tag(type, data, False)
		core.BNAddAutoDataTag(self.handle, addr, tag.handle)
		return tag

	def remove_auto_data_tag(self, addr, tag):
		"""
		``remove_auto_data_tag`` removes a Tag object at a data address.
		Since this removes a user tag, it will be added to the current undo buffer.

		:param int addr: Address at which to add the tag
		:param Tag tag: Tag object to be added
		:rtype: None
		"""
		core.BNRemoveAutoDataTag(self.handle, addr, tag.handle)

	def is_never_branch_patch_available(self, addr, arch=None):
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
			arch = self.arch
		return core.BNIsNeverBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_always_branch_patch_available(self, addr, arch=None):
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
			arch = self.arch
		return core.BNIsAlwaysBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_invert_branch_patch_available(self, addr, arch=None):
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
			arch = self.arch
		return core.BNIsInvertBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_skip_and_return_zero_patch_available(self, addr, arch=None):
		"""
		``is_skip_and_return_zero_patch_available`` queries the architecture plugin to determine if the
		instruction at ``addr`` is similar to an x86 "call"  instruction which can be made to return zero.  The actual
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
			arch = self.arch
		return core.BNIsSkipAndReturnZeroPatchAvailable(self.handle, arch.handle, addr)

	def is_skip_and_return_value_patch_available(self, addr, arch=None):
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
			arch = self.arch
		return core.BNIsSkipAndReturnValuePatchAvailable(self.handle, arch.handle, addr)

	def convert_to_nop(self, addr, arch=None):
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
			>>> bv.get_next_disassembly()
			'nop'
			>>> bv.get_next_disassembly()
			'nop'
			>>> bv.get_next_disassembly()
			'nop'
			>>> bv.get_next_disassembly()
			'nop'
			>>> bv.get_next_disassembly()
			'mov     byte [ebp-0x1c], al'
		"""
		if arch is None:
			arch = self.arch
		return core.BNConvertToNop(self.handle, arch.handle, addr)

	def always_branch(self, addr, arch=None):
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
			arch = self.arch
		return core.BNAlwaysBranch(self.handle, arch.handle, addr)

	def never_branch(self, addr, arch=None):
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
			arch = self.arch
		return core.BNConvertToNop(self.handle, arch.handle, addr)

	def invert_branch(self, addr, arch=None):
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
			arch = self.arch
		return core.BNInvertBranch(self.handle, arch.handle, addr)

	def skip_and_return_value(self, addr, value, arch=None):
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
			arch = self.arch
		return core.BNSkipAndReturnValue(self.handle, arch.handle, addr, value)

	def get_instruction_length(self, addr, arch=None):
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
			arch = self.arch
		return core.BNGetInstructionLength(self.handle, arch.handle, addr)

	def notify_data_written(self, offset, length):
		core.BNNotifyDataWritten(self.handle, offset, length)

	def notify_data_inserted(self, offset, length):
		core.BNNotifyDataInserted(self.handle, offset, length)

	def notify_data_removed(self, offset, length):
		core.BNNotifyDataRemoved(self.handle, offset, length)

	def get_strings(self, start = None, length = None):
		"""
		``get_strings`` returns a list of strings defined in the binary in the optional virtual address range:
		``start-(start+length)``

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
		else:
			if length is None:
				length = self.end - start
			strings = core.BNGetStringsInRange(self.handle, start, length, count)
		result = []
		for i in range(0, count.value):
			result.append(StringReference(self, StringType(strings[i].type), strings[i].start, strings[i].length))
		core.BNFreeStringReferenceList(strings)
		return result

	def get_string_at(self, addr, partial=False):
		"""
		``get_string_at`` returns the string that falls on given virtual address.

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
		if str_ref.type != StringType.AsciiString:
			partial = False
			log.log_warn("Partial string not supported at {}".format(hex(addr)))
		start = addr if partial else str_ref.start
		length = str_ref.length - (addr - str_ref.start) if partial else str_ref.length
		return StringReference(self, StringType(str_ref.type), start, length)

	def get_ascii_string_at(self, addr, min_length=4, max_length=None, require_cstring=True):
		"""
		``get_ascii_string_at`` returns the string found at ``addr``

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
		if not isinstance(addr, numbers.Integral):
			raise AttributeError("Input address (" + str(addr) + ") is not a number.")
		if addr < self.start or addr >= self.end:
			return None

		br = BinaryReader(self)
		br.seek(addr)
		length = 0
		c = br.read8()
		while c > 0 and c <= 0x7f:
			if length == max_length:
				break
			length += 1
			c = br.read8()
		if length < min_length:
			return None
		if require_cstring and c != 0:
			return None
		return StringReference(self, StringType.AsciiString, addr, length)

	def add_analysis_completion_event(self, callback):
		"""
		``add_analysis_completion_event`` sets up a call back function to be called when analysis has been completed.
		This is helpful when using :func:`update_analysis` which does not wait for analysis completion before returning.

		The callee of this function is not responsible for maintaining the lifetime of the returned AnalysisCompletionEvent object.

		:param callback callback: A function to be called with no parameters when analysis has completed.
		:return: An initialized AnalysisCompletionEvent object.
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

	def get_next_function_start_after(self, addr):
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

	def get_next_basic_block_start_after(self, addr):
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

	def get_next_data_after(self, addr):
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

	def get_next_data_var_after(self, addr):
		"""
		``get_next_data_var_after`` retrieves the next :py:Class:`DataVariable`, or None.

		:param int addr: the virtual address to start looking from.
		:return: the next :py:Class:`DataVariable`
		:rtype: DataVariable
		:Example:

			>>> bv.get_next_data_var_after(0x10000000)
			<var 0x1000003c: int32_t>
			>>>
		"""
		next_data_var_start = core.BNGetNextDataVariableStartAfterAddress(self.handle, addr)
		if next_data_var_start == self.end:
			return None
		var = core.BNDataVariable()
		if not core.BNGetDataVariableAtAddress(self.handle, next_data_var_start, var):
			return None
		return DataVariable(var.address, types.Type(var.type, platform = self.platform, confidence = var.typeConfidence), var.autoDiscovered, self)

	def get_next_data_var_start_after(self, addr):
		"""
		``get_next_data_var_start_after`` retrieves the next virtual address of the next :py:Class:`DataVariable`

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the next :py:Class:`DataVariable`
		:rtype: int
		:Example:

			>>> hex(bv.get_next_data_var_start_after(0x10000000))
			'0x1000003cL'
			>>> bv.get_data_var_at(0x1000003c)
			<var 0x1000003c: int32_t>
			>>>
		"""
		return core.BNGetNextDataVariableStartAfterAddress(self.handle, addr)

	def get_previous_function_start_before(self, addr):
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

	def get_previous_basic_block_start_before(self, addr):
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

	def get_previous_basic_block_end_before(self, addr):
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

	def get_previous_data_before(self, addr):
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

	def get_previous_data_var_before(self, addr):
		"""
		``get_previous_data_var_before`` retrieves the previous :py:Class:`DataVariable`, or None.

		:param int addr: the virtual address to start looking from.
		:return: the previous :py:Class:`DataVariable`
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
		return DataVariable(var.address, types.Type(var.type, platform = self.platform, confidence = var.typeConfidence), var.autoDiscovered, self)

	def get_previous_data_var_start_before(self, addr):
		"""
		``get_previous_data_var_start_before``

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the previous :py:Class:`DataVariable`
		:rtype: int
		:Example:

			>>> hex(bv.get_previous_data_var_start_before(0x1000003c))
			'0x10000000L'
			>>> bv.get_data_var_at(0x10000000)
			<var 0x10000000: int16_t>
			>>>
		"""
		return core.BNGetPreviousDataVariableStartBeforeAddress(self.handle, addr)

	def get_linear_disassembly_position_at(self, addr, settings=None):
		"""
		``get_linear_disassembly_position_at`` instantiates a :py:class:`LinearViewCursor <binaryninja.lineardisassembly.LinearViewCursor>` object for use in
		:py:meth:`get_previous_linear_disassembly_lines` or :py:meth:`get_next_linear_disassembly_lines`.

		:param int addr: virtual address of linear disassembly position
		:param DisassemblySettings settings: an instantiated :py:class:`DisassemblySettings` object, defaults to None which will use default settings
		:return: An instantiated :py:class:`LinearViewCursor` object for the provided virtual address
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

	def get_previous_linear_disassembly_lines(self, pos):
		"""
		``get_previous_linear_disassembly_lines`` retrieves a list of :py:class:`LinearDisassemblyLine` objects for the
		previous disassembly lines, and updates the LinearViewCursor passed in. This function can be called
		repeatedly to get more lines of linear disassembly.

		:param LinearViewCursor pos: Position to start retrieving linear disassembly lines from
		:return: a list of :py:class:`LinearDisassemblyLine` objects for the previous lines.
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

	def get_next_linear_disassembly_lines(self, pos):
		"""
		``get_next_linear_disassembly_lines`` retrieves a list of :py:class:`LinearDisassemblyLine` objects for the
		next disassembly lines, and updates the LinearViewCursor passed in. This function can be called
		repeatedly to get more lines of linear disassembly.

		:param LinearViewCursor pos: Position to start retrieving linear disassembly lines from
		:return: a list of :py:class:`LinearDisassemblyLine` objects for the next lines.
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

	def get_linear_disassembly(self, settings=None):
		"""
		``get_linear_disassembly`` gets an iterator for all lines in the linear disassembly of the view for the given
		disassembly settings.

		.. note:: linear_disassembly doesn't just return disassembly it will return a single line from the linear view,\
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
		class LinearDisassemblyIterator(object):
			def __init__(self, view, settings):
				self._view = view
				self._settings = settings

			def __iter__(self):
				pos = lineardisassembly.LinearViewCursor(lineardisassembly.LinearViewObject.disassembly(
					self.view, self.settings))
				while True:
					lines = self._view.get_next_linear_disassembly_lines(pos)
					if len(lines) == 0:
						break
					for line in lines:
						yield line

			@property
			def view(self):
				""" """
				return self._view

			@view.setter
			def view(self, value):
				self._view = value

			@property
			def settings(self):
				""" """
				return self._settings

			@settings.setter
			def settings(self, value):
				self._settings = value


		return iter(LinearDisassemblyIterator(self, settings))

	def parse_type_string(self, text):
		"""
		``parse_type_string`` converts `C-style` string into a :py:Class:`Type`.

		:param str text: `C-style` string of type to create
		:return: A tuple of a :py:Class:`Type` and type name
		:rtype: tuple(Type, QualifiedName)
		:Example:

			>>> bv.parse_type_string("int foo")
			(<type: int32_t>, 'foo')
			>>>
		"""
		result = core.BNQualifiedNameAndType()
		errors = ctypes.c_char_p()
		if not core.BNParseTypeString(self.handle, text, result, errors):
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise SyntaxError(error_str)
		type_obj = types.Type(core.BNNewTypeReference(result.type), platform = self.platform)
		name = types.QualifiedName._from_core_struct(result.name)
		core.BNFreeQualifiedNameAndType(result)
		return type_obj, name

	def get_type_by_name(self, name):
		"""
		``get_type_by_name`` returns the defined type whose name corresponds with the provided ``name``

		:param QualifiedName name: Type name to lookup
		:return: A :py:Class:`Type` or None if the type does not exist
		:rtype: Type or None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_user_type(name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
			>>>
		"""
		name = types.QualifiedName(name)._get_core_struct()
		obj = core.BNGetAnalysisTypeByName(self.handle, name)
		if not obj:
			return None
		return types.Type(obj, platform = self.platform)

	def get_type_by_id(self, id):
		"""
		``get_type_by_id`` returns the defined type whose unique identifier corresponds with the provided ``id``

		:param str id: Unique identifier to lookup
		:return: A :py:Class:`Type` or None if the type does not exist
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
		return types.Type(obj, platform = self.platform)

	def get_type_name_by_id(self, id):
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
		result = types.QualifiedName._from_core_struct(name)
		core.BNFreeQualifiedName(name)
		if len(result) == 0:
			return None
		return result

	def get_type_id(self, name):
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
		name = types.QualifiedName(name)._get_core_struct()
		return core.BNGetAnalysisTypeId(self.handle, name)

	def add_type_library(self, lib):
		"""
		``add_type_library`` make the contents of a type library available for type/import resolution

		:param TypeLibrary lib: library to register with the view
		:rtype: None
		"""
		if not isinstance(lib, typelibrary.TypeLibrary):
			raise ValueError("must pass in a TypeLibrary object")
		core.BNAddBinaryViewTypeLibrary(self.handle, lib.handle)

	def get_type_library(self, name):
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

	def is_type_auto_defined(self, name):
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
		name = types.QualifiedName(name)._get_core_struct()
		return core.BNIsAnalysisTypeAutoDefined(self.handle, name)

	def define_type(self, type_id, default_name, type_obj):
		"""
		``define_type`` registers a :py:Class:`Type` ``type_obj`` of the given ``name`` in the global list of types for
		the current :py:Class:`BinaryView`. This method should only be used for automatically generated types.

		:param str type_id: Unique identifier for the automatically generated type
		:param QualifiedName default_name: Name of the type to be registered
		:param Type type_obj: Type object to be registered
		:return: Registered name of the type. May not be the same as the requested name if the user has renamed types.
		:rtype: QualifiedName
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> registered_name = bv.define_type(Type.generate_auto_type_id("source", name), name, type)
			>>> bv.get_type_by_name(registered_name)
			<type: int32_t>
		"""
		name = types.QualifiedName(default_name)._get_core_struct()
		reg_name = core.BNDefineAnalysisType(self.handle, type_id, name, type_obj.handle)
		result = types.QualifiedName._from_core_struct(reg_name)
		core.BNFreeQualifiedName(reg_name)
		return result

	def define_user_type(self, name, type_obj):
		"""
		``define_user_type`` registers a :py:Class:`Type` ``type_obj`` of the given ``name`` in the global list of user
		types for the current :py:Class:`BinaryView`.

		:param QualifiedName name: Name of the user type to be registered
		:param Type type_obj: Type object to be registered
		:rtype: None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_user_type(name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
		"""
		name = types.QualifiedName(name)._get_core_struct()
		core.BNDefineUserAnalysisType(self.handle, name, type_obj.handle)

	def undefine_type(self, type_id):
		"""
		``undefine_type`` removes a :py:Class:`Type` from the global list of types for the current :py:Class:`BinaryView`

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

	def undefine_user_type(self, name):
		"""
		``undefine_user_type`` removes a :py:Class:`Type` from the global list of user types for the current
		:py:Class:`BinaryView`

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
		name = types.QualifiedName(name)._get_core_struct()
		core.BNUndefineUserAnalysisType(self.handle, name)

	def rename_type(self, old_name, new_name):
		"""
		``rename_type`` renames a type in the global list of types for the current :py:Class:`BinaryView`

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
		old_name = types.QualifiedName(old_name)._get_core_struct()
		new_name = types.QualifiedName(new_name)._get_core_struct()
		core.BNRenameAnalysisType(self.handle, old_name, new_name)

	def import_library_type(self, name, lib = None):
		"""
		``import_library_type`` recursively imports a type from the specified type library, or, if
		no library was explicitly provided, the first type library associated with the current :py:Class:`BinaryView`
		that provides the name requested.

		This may have the impact of loading other type libraries as dependencies on other type libraries are lazily resolved
		when references to types provided by them are first encountered.

		Note that the name actually inserted into the view may not match the name as it exists in the type library in
		the event of a name conflict. To aid in this, the :py:Class:`Type` object returned is a `NamedTypeReference` to
		the deconflicted name used.

		:param QualifiedName name:
		:param TypeLibrary lib:
		:return: a `NamedTypeReference` to the type, taking into account any renaming performed
		:rtype: Type
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		handle = core.BNBinaryViewImportTypeLibraryType(self.handle, None if lib is None else lib.handle, name._get_core_struct())
		if handle is None:
			return None
		return types.Type(handle, platform = self.platform)

	def import_library_object(self, name, lib = None):
		"""
		``import_library_object`` recursively imports an object from the specified type library, or, if
		no library was explicitly provided, the first type library associated with the current :py:Class:`BinaryView`
		that provides the name requested.

		This may have the impact of loading other type libraries as dependencies on other type libraries are lazily resolved
		when references to types provided by them are first encountered.

		:param QualifiedName name:
		:param TypeLibrary lib:
		:return: the object type, with any interior `NamedTypeReferences` renamed as necessary to be appropriate for the current view
		:rtype: Type
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		handle = core.BNBinaryViewImportTypeLibraryObject(self.handle, None if lib is None else lib.handle, name._get_core_struct())
		if handle is None:
			return None
		return types.Type(handle, platform = self.platform)

	def export_type_to_library(self, lib, name, type_obj):
		"""
		``export_type_to_library`` recursively exports ``type_obj`` into ``lib`` as a type with name ``name``

		As other referenced types are encountered, they are either copied into the destination type library or
		else the type library that provided the referenced type is added as a dependency for the destination library.

		:param TypeLibrary lib:
		:param QualifiedName name:
		:param Type type_obj:
		:rtype: None
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		if not isinstance(lib, typelibrary.TypeLibrary):
			raise ValueError("lib must be a TypeLibrary object")
		if not isinstance(type_obj, types.Type):
			raise ValueError("type_obj must be a Type object")
		core.BNBinaryViewExportTypeToTypeLibrary(self.handle, lib.handle, name._get_core_struct(), type_obj.handle)

	def export_object_to_library(self, lib, name, type_obj):
		"""
		``export_object_to_library`` recursively exports ``type_obj`` into ``lib`` as an object with name ``name``

		As other referenced types are encountered, they are either copied into the destination type library or
		else the type library that provided the referenced type is added as a dependency for the destination library.

		:param TypeLibrary lib:
		:param QualifiedName name:
		:param Type type_obj:
		:rtype: None
		"""
		if not isinstance(name, types.QualifiedName):
			name = types.QualifiedName(name)
		if not isinstance(lib, typelibrary.TypeLibrary):
			raise ValueError("lib must be a TypeLibrary object")
		if not isinstance(type_obj, types.Type):
			raise ValueError("type_obj must be a Type object")
		core.BNBinaryViewExportObjectToTypeLibrary(self.handle, lib.handle, name._get_core_struct(), type_obj.handle)

	def register_platform_types(self, platform):
		"""
		``register_platform_types`` ensures that the platform-specific types for a :py:Class:`Platform` are available
		for the current :py:Class:`BinaryView`. This is automatically performed when adding a new function or setting
		the default platform.

		:param Platform platform: Platform containing types to be registered
		:rtype: None
		:Example:

			>>> platform = Platform["linux-x86"]
			>>> bv.register_platform_types(platform)
			>>>
		"""
		core.BNRegisterPlatformTypes(self.handle, platform.handle)

	def find_next_data(self, start, data, flags=FindFlag.FindCaseSensitive):
		"""
		``find_next_data`` searches for the bytes ``data`` starting at the virtual address ``start`` until the end of the BinaryView.

		:param int start: virtual address to start searching from.
		:param str data: data to search for
		:param FindFlag flags: (optional) defaults to case-insensitive data search

			====================  ============================
			FindFlag              Description
			====================  ============================
			FindCaseSensitive     Case-sensitive search
			FindCaseInsensitive   Case-insensitive search
			===================== ============================
		"""
		buf = databuffer.DataBuffer(str(data))
		result = ctypes.c_ulonglong()
		if not core.BNFindNextData(self.handle, start, buf.handle, result, flags):
			return None
		return result.value


	def find_next_text(self, start, text, settings=None, flags=FindFlag.FindCaseSensitive):
		"""
		``find_next_text`` searches for string ``text`` occurring in the linear view output starting at the virtual
		address ``start`` until the end of the BinaryView.

		:param int start: virtual address to start searching from.
		:param str text: text to search for
		:param FindFlag flags: (optional) defaults to case-insensitive data search

			====================  ============================
			FindFlag              Description
			====================  ============================
			FindCaseSensitive     Case-sensitive search
			FindCaseInsensitive   Case-insensitive search
			===================== ============================
		"""
		if not isinstance(text, str):
			raise TypeError("text parameter is not str type")
		if settings is None:
			settings = function.DisassemblySettings()
		if not isinstance(settings, function.DisassemblySettings):
			raise TypeError("settings parameter is not DisassemblySettings type")

		result = ctypes.c_ulonglong()
		if not core.BNFindNextText(self.handle, start, text, result, settings.handle, flags):
			return None
		return result.value

	def find_next_constant(self, start, constant, settings=None):
		"""
		``find_next_constant`` searches for integer constant ``constant`` occurring in the linear view output starting at the virtual
		address ``start`` until the end of the BinaryView.

		:param int start: virtual address to start searching from.
		:param int constant: constant to search for
		"""
		if not isinstance(constant, numbers.Integral):
			raise TypeError("constant parameter is not integral type")
		if settings is None:
			settings = function.DisassemblySettings()
		if not isinstance(settings, function.DisassemblySettings):
			raise TypeError("settings parameter is not DisassemblySettings type")

		result = ctypes.c_ulonglong()
		if not core.BNFindNextConstant(self.handle, start, constant, result, settings.handle):
			return None
		return result.value

	def reanalyze(self):
		"""
		``reanalyze`` causes all functions to be reanalyzed. This function does not wait for the analysis to finish.

		:rtype: None
		"""
		core.BNReanalyzeAllFunctions(self.handle)

	def rebase(self, address, progress_func = None):
		"""
		``rebase`` rebase the existing BinaryView into a new BinaryView at the specified virtual address

		.. note:: This method should not be called from the UI and is intended for headless operation only.

		:param int address: virtual address of the start of the binary view
		:return: the new BinaryView object or None on failure
		:rtype: BinaryView or None
		"""
		result = False
		if core.BNIsUIEnabled():
			log.log_warn("The BinaryView.rebase API is for headless operation only.")
			return False
		if progress_func is None:
			result = core.BNRebase(self.handle, address)
		else:
			result = core.BNRebaseWithProgress(self.handle, address, None, ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
				lambda ctxt, cur, total: progress_func(cur, total)))
		if result:
			return self.get_view_of_type(self.view_type)
		else:
			return None

	def show_plain_text_report(self, title, contents):
		core.BNShowPlainTextReport(self.handle, title, contents)

	def show_markdown_report(self, title, contents, plaintext = ""):
		"""
		``show_markdown_report`` displays the markdown contents in UI applications and plaintext in command-line
		applications. Markdown reports support hyperlinking into the BinaryView. Hyperlinks can be specified as follows:
		``binaryninja://?expr=_start`` Where ``expr=`` specifies an expression parsable by the :py:meth:`parse_expression` API.

		Note: This API functions differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line \
			a simple text prompt is used.

		:param str contents: markdown contents to display
		:param str plaintext: Plain text version to display (used on the command-line)
		:rtype: None
		:Example:
			>>> bv.show_markdown_report("title", "##Contents", "Plain text contents")
			Plain text contents
		"""
		core.BNShowMarkdownReport(self.handle, title, contents, plaintext)

	def show_html_report(self, title, contents, plaintext = ""):
		"""
		``show_html_report`` displays the HTML contents in UI applications and plaintext in command-line
		applications. HTML reports support hyperlinking into the BinaryView. Hyperlinks can be specified as follows:
		``binaryninja://?expr=_start`` Where ``expr=`` specifies an expression parsable by the :py:meth:`parse_expression` API.

		Note: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line \
			a simple text prompt is used.

		:param str contents: HTML contents to display
		:param str plaintext: Plain text version to display (used on the command-line)
		:rtype: None
		:Example:
			>>> bv.show_html_report("title", "<h1>Contents</h1>", "Plain text contents")
			Plain text contents
		"""
		core.BNShowHTMLReport(self.handle, title, contents, plaintext)

	def show_graph_report(self, title, graph):
		"""
		``show_graph_report`` displays a :py:Class:`FlowGraph` object `graph` in a new tab with ``title``.

		:param title: Title of the graph
		:type title: Plain text string title
		:param graph: The graph you wish to display
		:type graph: :py:Class:`FlowGraph` object
		"""
		core.BNShowGraphReport(self.handle, title, graph.handle)

	def get_address_input(self, prompt, title, current_address = None):
		if current_address is None:
			current_address = self._file.offset
		value = ctypes.c_ulonglong()
		if not core.BNGetAddressInput(value, prompt, title, self.handle, current_address):
			return None
		return value.value

	def add_auto_segment(self, start, length, data_offset, data_length, flags):
		core.BNAddAutoSegment(self.handle, start, length, data_offset, data_length, flags)

	def remove_auto_segment(self, start, length):
		core.BNRemoveAutoSegment(self.handle, start, length)

	def add_user_segment(self, start, length, data_offset, data_length, flags):
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

	def remove_user_segment(self, start, length):
		core.BNRemoveUserSegment(self.handle, start, length)

	def get_segment_at(self, addr):
		seg = core.BNGetSegmentAt(self.handle, addr)
		if not seg:
			return None
		return Segment(core.BNNewSegmentReference(seg))

	def get_address_for_data_offset(self, offset):
		address = ctypes.c_ulonglong()
		if not core.BNGetAddressForDataOffset(self.handle, offset, address):
			return None
		return address.value

	def add_auto_section(self, name, start, length, semantics = SectionSemantics.DefaultSectionSemantics,
		type = "", align = 1, entry_size = 1, linked_section = "", info_section = "", info_data = 0):
		core.BNAddAutoSection(self.handle, name, start, length, semantics, type, align, entry_size, linked_section,
			info_section, info_data)

	def remove_auto_section(self, name):
		core.BNRemoveAutoSection(self.handle, name)

	def add_user_section(self, name, start, length, semantics = SectionSemantics.DefaultSectionSemantics,
		type = "", align = 1, entry_size = 1, linked_section = "", info_section = "", info_data = 0):
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
		core.BNAddUserSection(self.handle, name, start, length, semantics, type, align, entry_size, linked_section,
			info_section, info_data)

	def remove_user_section(self, name):
		core.BNRemoveUserSection(self.handle, name)

	def get_sections_at(self, addr):
		count = ctypes.c_ulonglong(0)
		section_list = core.BNGetSectionsAt(self.handle, addr, count)
		result = []
		for i in range(0, count.value):
			result.append(Section(core.BNNewSectionReference(section_list[i])))
		core.BNFreeSectionList(section_list, count.value)
		return result

	def get_section_by_name(self, name):
		section = core.BNGetSectionByName(self.handle, name)
		if not section:
			return None
		result = Section(core.BNNewSectionReference(section))
		return result

	def get_unique_section_names(self, name_list):
		incoming_names = (ctypes.c_char_p * len(name_list))()
		for i in range(0, len(name_list)):
			incoming_names[i] = binaryninja.cstr(name_list[i])
		outgoing_names = core.BNGetUniqueSectionNames(self.handle, incoming_names, len(name_list))
		result = []
		for i in range(0, len(name_list)):
			result.append(str(outgoing_names[i]))
		core.BNFreeStringList(outgoing_names, len(name_list))
		return result

	@property
	def address_comments(self):
		"""
		Returns a read-only dict of the address comments attached to this BinaryView

		Note that these are different from function-level comments which are specific to each function.
		For annotating code, it is recommended to use comments attached to functions rather than address
		comments attached to the BinaryView. On the other hand, BinaryView comments can be attached to data
		whereas function comments cannot.
		To create a function-level comment, use :func:`~binaryninja.function.Function.add_user_code_ref`.
		"""
		count = ctypes.c_ulonglong()
		addrs = core.BNGetGlobalCommentedAddresses(self.handle, count)
		result = {}
		for i in range(0, count.value):
			result[addrs[i]] = self.get_comment_at(addrs[i])
		core.BNFreeAddressList(addrs)
		return result

	def get_comment_at(self, addr):
		"""
		``get_comment_at`` returns the address-based comment attached to the given address in this BinaryView
		Note that address-based comments are different from function-level comments which are specific to each function.
		For more information, see :func:`address_comments`.
		:param int addr: virtual address within the current BinaryView to apply the comment to
		:rtype: str

		"""
		return core.BNGetGlobalCommentForAddress(self.handle, addr)

	def set_comment_at(self, addr, comment):
		"""
		``set_comment_at`` sets a comment for the BinaryView at the address specified

		Note that these are different from function-level comments which are specific to each function. \
		For more information, see :func:`address_comments`.

		:param int addr: virtual address within the current BinaryView to apply the comment to
		:param str comment: string comment to apply
		:rtype: None
		:Example:

			>>> bv.set_comment_at(here, "hi")

		"""
		core.BNSetGlobalCommentForAddress(self.handle, addr, comment)

	def query_metadata(self, key):
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

	def store_metadata(self, key, md):
		"""
		`store_metadata` stores an object for the given key in the current BinaryView. Objects stored using
		`store_metadata` can be retrieved when the database is reopened. Objects stored are not arbitrary python
		objects! The values stored must be able to be held in a Metadata object. See :py:class:`Metadata`
		for more information. Python objects could obviously be serialized using pickle but this intentionally
		a task left to the user since there is the potential security issues.

		:param str key: key value to associate the Metadata object with
		:param Varies md: object to store.
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
		if not isinstance(md, metadata.Metadata):
			md = metadata.Metadata(md)
		core.BNBinaryViewStoreMetadata(self.handle, key, md.handle)

	def remove_metadata(self, key):
		"""
		`remove_metadata` removes the metadata associated with key from the current BinaryView.

		:param str key: key associated with metadata to remove from the BinaryView
		:rtype: None
		:Example:

			>>> bv.store_metadata("integer", 1337)
			>>> bv.remove_metadata("integer")
		"""
		core.BNBinaryViewRemoveMetadata(self.handle, key)

	def get_load_settings_type_names(self):
		"""
		``get_load_settings_type_names`` retrieve a list :py:class:`BinaryViewType` names for which load settings exist in \
		this :py:class:`BinaryView` context

		:return: list of :py:class:`BinaryViewType` names
		:rtype: list(str)
		"""
		result = []
		count = ctypes.c_ulonglong(0)
		names = core.BNBinaryViewGetLoadSettingsTypeNames(self.handle, count)
		for i in range(count.value):
			result.append(names[i])
		core.BNFreeStringList(names, count)
		return result

	def get_load_settings(self, type_name):
		"""
		``get_load_settings`` retrieve a :py:class:`Settings` object which defines the load settings for the given :py:class:`BinaryViewType` ``type_name``

		:param str type_name: the :py:class:`BinaryViewType` name
		:return: the load settings
		:rtype: :py:class:`Settings`, or ``None``
		"""
		settings_handle = core.BNBinaryViewGetLoadSettings(self.handle, type_name)
		if settings_handle is None:
			return None
		return settings.Settings(handle=settings_handle)

	def set_load_settings(self, type_name, settings):
		"""
		``set_load_settings`` set a :py:class:`Settings` object which defines the load settings for the given :py:class:`BinaryViewType` ``type_name``

		:param str type_name: the :py:class:`BinaryViewType` name
		:param Settings settings: the load settings
		:rtype: None
		"""
		core.BNBinaryViewSetLoadSettings(self.handle, type_name, settings.handle)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def parse_expression(self, expression, here=0):
		"""
		Evaluates a string expression to an integer value.

		The parser uses the following rules:

			- Symbols are defined by the lexer as ``[A-Za-z0-9_:<>][A-Za-z0-9_:$\\-<>]+`` or anything enclosed in either single or double quotes
			- Symbols are everything in ``bv.symbols``, unnamed DataVariables (i.e. ``data_00005000``), unnamed functions (i.e. ``sub_00005000``), or section names (i.e. ``.text``)
			- Numbers are defaulted to hexadecimal thus `_printf + 10` is equivalent to `printf + 0x10` If decimal numbers required use the decimal prefix.
			- Since numbers and symbols can be ambiguous its recommended that you prefix your numbers with the following:

				- ``0x`` - Hexadecimal
				- ``0n`` - Decimal
				- ``0`` - Octal

			- In the case of an ambiguous number/symbol (one with no prefix) for instance ``12345`` we will first attempt
			  to look up the string as a symbol, if a symbol is found its address is used, otherwise we attempt to convert
			  it to a hexadecimal number.
			- The following operations are valid: ``+, -, \*, /, %, (), &, \|, ^, ~``
			- In addition to the above operators there are dereference operators similar to BNIL style IL:

				- ``[<expression>]`` - read the `current address size` at ``<expression>``
				- ``[<expression>].b`` - read the byte at ``<expression>``
				- ``[<expression>].w`` - read the word (2 bytes) at ``<expression>``
				- ``[<expression>].d`` - read the dword (4 bytes) at ``<expression>``
				- ``[<expression>].q`` - read the quadword (8 bytes) at ``<expression>``

			- The ``$here`` keyword can be used in calculations and is defined as the ``here`` parameter
			- The ``$start``/``$end`` keyword represents the address of the first/last bytes in the file respectively

		:param str expression: Arithmetic expression to be evaluated
		:param int here: (optional) Base address for relative expressions, defaults to zero
		:rtype: int
		"""
		offset = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		if not core.BNParseExpression(self.handle, expression, offset, here, errors):
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise ValueError(error_str)
		return offset.value

	def eval(self, expression, here=0):
		"""
		Evaluates an string expression to an integer value. This is a more concise alias for the :py:meth:`parse_expression` API
		"""
		return self.parse_expression(expression, here)


class BinaryReader(object):
	"""
	``class BinaryReader`` is a convenience class for reading binary data.

	BinaryReader can be instantiated as follows and the rest of the document will start from this context ::

		>>> from binaryninja import *
		>>> bv = BinaryViewType.get_view_of_file("/bin/ls")
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
	def __init__(self, view, endian = None):
		self.handle = core.BNCreateBinaryReader(view.handle)
		if endian is None:
			core.BNSetBinaryReaderEndianness(self.handle, view.endianness)
		else:
			core.BNSetBinaryReaderEndianness(self.handle, endian)

	def __del__(self):
		core.BNFreeBinaryReader(self.handle)

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
	def endianness(self):
		"""
		The Endianness to read data. (read/write)

		:getter: returns the endianness of the reader
		:setter: sets the endianness of the reader (BigEndian or LittleEndian)
		:type: Endianness
		"""
		return core.BNGetBinaryReaderEndianness(self.handle)

	@endianness.setter
	def endianness(self, value):
		core.BNSetBinaryReaderEndianness(self.handle, value)

	@property
	def offset(self):
		"""
		The current read offset (read/write).

		:getter: returns the current internal offset
		:setter: sets the internal offset
		:type: int
		"""
		return core.BNGetReaderPosition(self.handle)

	@offset.setter
	def offset(self, value):
		core.BNSeekBinaryReader(self.handle, value)

	@property
	def eof(self):
		"""
		Is end of file (read-only)

		:getter: returns boolean, true if end of file, false otherwise
		:type: bool
		"""
		return core.BNIsEndOfFile(self.handle)

	def read(self, length):
		"""
		``read`` returns ``length`` bytes read from the current offset, adding ``length`` to offset.

		:param int length: number of bytes to read.
		:return: ``length`` bytes from current offset
		:rtype: str, or None on failure
		:Example:

			>>> br.read(8)
			'\\xcf\\xfa\\xed\\xfe\\x07\\x00\\x00\\x01'
			>>>
		"""
		dest = ctypes.create_string_buffer(length)
		if not core.BNReadData(self.handle, dest, length):
			return None
		return dest.raw

	def read8(self):
		"""
		``read8`` returns a one byte integer from offset incrementing the offset.

		:return: byte at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> br.read8()
			207
			>>>
		"""
		result = ctypes.c_ubyte()
		if not core.BNRead8(self.handle, result):
			return None
		return result.value

	def read16(self):
		"""
		``read16`` returns a two byte integer from offset incrementing the offset by two, using specified endianness.

		:return: a two byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read16())
			'0xfacf'
			>>>
		"""
		result = ctypes.c_ushort()
		if not core.BNRead16(self.handle, result):
			return None
		return result.value

	def read32(self):
		"""
		``read32`` returns a four byte integer from offset incrementing the offset by four, using specified endianness.

		:return: a four byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read32())
			'0xfeedfacfL'
			>>>
		"""
		result = ctypes.c_uint()
		if not core.BNRead32(self.handle, result):
			return None
		return result.value

	def read64(self):
		"""
		``read64`` returns an eight byte integer from offset incrementing the offset by eight, using specified endianness.

		:return: an eight byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read64())
			'0x1000007feedfacfL'
			>>>
		"""
		result = ctypes.c_ulonglong()
		if not core.BNRead64(self.handle, result):
			return None
		return result.value

	def read16le(self):
		"""
		``read16le`` returns a two byte little endian integer from offset incrementing the offset by two.

		:return: a two byte integer at offset.
		:rtype: int, or None on failure
		:Exmaple:

			>>> br.seek(0x100000000)
			>>> hex(br.read16le())
			'0xfacf'
			>>>
		"""
		result = self.read(2)
		if (result is None) or (len(result) != 2):
			return None
		return struct.unpack("<H", result)[0]

	def read32le(self):
		"""
		``read32le`` returns a four byte little endian integer from offset incrementing the offset by four.

		:return: a four byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read32le())
			'0xfeedfacf'
			>>>
		"""
		result = self.read(4)
		if (result is None) or (len(result) != 4):
			return None
		return struct.unpack("<I", result)[0]

	def read64le(self):
		"""
		``read64le`` returns an eight byte little endian integer from offset incrementing the offset by eight.

		:return: a eight byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read64le())
			'0x1000007feedfacf'
			>>>
		"""
		result = self.read(8)
		if (result is None) or (len(result) != 8):
			return None
		return struct.unpack("<Q", result)[0]

	def read16be(self):
		"""
		``read16be`` returns a two byte big endian integer from offset incrementing the offset by two.

		:return: a two byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read16be())
			'0xcffa'
			>>>
		"""
		result = self.read(2)
		if (result is None) or (len(result) != 2):
			return None
		return struct.unpack(">H", result)[0]

	def read32be(self):
		"""
		``read32be`` returns a four byte big endian integer from offset incrementing the offset by four.

		:return: a four byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read32be())
			'0xcffaedfe'
			>>>
		"""
		result = self.read(4)
		if (result is None) or (len(result) != 4):
			return None
		return struct.unpack(">I", result)[0]

	def read64be(self):
		"""
		``read64be`` returns an eight byte big endian integer from offset incrementing the offset by eight.

		:return: a eight byte integer at offset.
		:rtype: int, or None on failure
		:Example:

			>>> br.seek(0x100000000)
			>>> hex(br.read64be())
			'0xcffaedfe07000001L'
		"""
		result = self.read(8)
		if (result is None) or (len(result) != 8):
			return None
		return struct.unpack(">Q", result)[0]

	def seek(self, offset):
		"""
		``seek`` update internal offset to ``offset``.

		:param int offset: offset to set the internal offset to
		:rtype: None
		:Example:

			>>> hex(br.offset)
			'0x100000008L'
			>>> br.seek(0x100000000)
			>>> hex(br.offset)
			'0x100000000L'
			>>>
		"""
		core.BNSeekBinaryReader(self.handle, offset)

	def seek_relative(self, offset):
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
		core.BNSeekBinaryReaderRelative(self.handle, offset)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class BinaryWriter(object):
	"""
	``class BinaryWriter`` is a convenience class for writing binary data.

	BinaryWriter can be instantiated as follows and the rest of the document will start from this context ::

		>>> from binaryninja import *
		>>> bv = BinaryViewType.get_view_of_file("/bin/ls")
		>>> br = BinaryReader(bv)
		>>> br.offset
		4294967296
		>>> bw = BinaryWriter(bv)
		>>>

	Or using the optional endian parameter ::

		>>> from binaryninja import *
		>>> bv = BinaryViewType.get_view_of_file("/bin/ls")
		>>> br = BinaryReader(bv, Endianness.BigEndian)
		>>> bw = BinaryWriter(bv, Endianness.BigEndian)
		>>>
	"""
	def __init__(self, view, endian = None):
		self.handle = core.BNCreateBinaryWriter(view.handle)
		if endian is None:
			core.BNSetBinaryWriterEndianness(self.handle, view.endianness)
		else:
			core.BNSetBinaryWriterEndianness(self.handle, endian)

	def __del__(self):
		core.BNFreeBinaryWriter(self.handle)

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
	def endianness(self):
		"""
		The Endianness to written data. (read/write)

		:getter: returns the endianness of the reader
		:setter: sets the endianness of the reader (BigEndian or LittleEndian)
		:type: Endianness
		"""
		return core.BNGetBinaryWriterEndianness(self.handle)

	@endianness.setter
	def endianness(self, value):
		core.BNSetBinaryWriterEndianness(self.handle, value)

	@property
	def offset(self):
		"""
		The current write offset (read/write).

		:getter: returns the current internal offset
		:setter: sets the internal offset
		:type: int
		"""
		return core.BNGetWriterPosition(self.handle)

	@offset.setter
	def offset(self, value):
		core.BNSeekBinaryWriter(self.handle, value)

	def write(self, value):
		"""
		``write`` writes ``len(value)`` bytes to the internal offset, without regard to endianness.

		:param str value: bytes to be written at current offset
		:return: boolean True on success, False on failure.
		:rtype: bool
		:Example:

			>>> bw.write("AAAA")
			True
			>>> br.read(4)
			'AAAA'
			>>>
		"""

		value = cstr(value)
		buf = ctypes.create_string_buffer(len(value))
		ctypes.memmove(buf, value, len(value))
		return core.BNWriteData(self.handle, buf, len(value))

	def write8(self, value):
		"""
		``write8`` lowest order byte from the integer ``value`` to the current offset.

		:param str value: bytes to be written at current offset
		:return: boolean
		:rtype: bool
		:Example:

			>>> bw.write8(0x42)
			True
			>>> br.read(1)
			'B'
			>>>
		"""
		return core.BNWrite8(self.handle, value)

	def write16(self, value):
		"""
		``write16`` writes the lowest order two bytes from the integer ``value`` to the current offset, using internal endianness.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		return core.BNWrite16(self.handle, value)

	def write32(self, value):
		"""
		``write32`` writes the lowest order four bytes from the integer ``value`` to the current offset, using internal endianness.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		return core.BNWrite32(self.handle, value)

	def write64(self, value):
		"""
		``write64`` writes the lowest order eight bytes from the integer ``value`` to the current offset, using internal endianness.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		return core.BNWrite64(self.handle, value)

	def write16le(self, value):
		"""
		``write16le`` writes the lowest order two bytes from the little endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		value = struct.pack("<H", value)
		return self.write(value)

	def write32le(self, value):
		"""
		``write32le`` writes the lowest order four bytes from the little endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		value = struct.pack("<I", value)
		return self.write(value)

	def write64le(self, value):
		"""
		``write64le`` writes the lowest order eight bytes from the little endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		value = struct.pack("<Q", value)
		return self.write(value)

	def write16be(self, value):
		"""
		``write16be`` writes the lowest order two bytes from the big endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		value = struct.pack(">H", value)
		return self.write(value)

	def write32be(self, value):
		"""
		``write32be`` writes the lowest order four bytes from the big endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		value = struct.pack(">I", value)
		return self.write(value)

	def write64be(self, value):
		"""
		``write64be`` writes the lowest order eight bytes from the big endian integer ``value`` to the current offset.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		value = struct.pack(">Q", value)
		return self.write(value)

	def seek(self, offset):
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
		core.BNSeekBinaryWriter(self.handle, offset)

	def seek_relative(self, offset):
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
		core.BNSeekBinaryWriterRelative(self.handle, offset)

class StructuredDataValue(object):
	def __init__(self, type, address, value):
		self._type = type
		self._address = address
		self._value = value

	def __str__(self):
		decode_str = "{}B".format(self._type.width)
		return ' '.join(["{:02x}".format(x) for x in struct.unpack(decode_str, self._value)])

	def __repr__(self):
		return "<StructuredDataValue type:{} value:{}>".format(str(self._type), str(self))

	def __int__(self):
		if self._type.width == 1:
			code = "B"
		elif self._type.width == 2:
			code = "H"
		elif self._type.width == 4:
			code = "I"
		elif self._type.width == 8:
			code = "Q"
		else:
			raise Exception("Could not convert to integer with width {}".format(self._type.width))

		return struct.unpack(code, self._value)[0]

	@property
	def type(self):
		return self._type

	@property
	def width(self):
		return self._type.width

	@property
	def address(self):
		return self._address

	@property
	def value(self):
		return self._value

	@property
	def int(self):
		return int(self)

	@property
	def str(self):
		return str(self)


class StructuredDataView(object):
	"""
		``class StructuredDataView`` is a convenience class for reading structured binary data.

		StructuredDataView can be instantiated as follows:

			>>> from binaryninja import *
			>>> bv = BinaryViewType.get_view_of_file("/bin/ls")
			>>> structure = "Elf64_Header"
			>>> address = bv.start
			>>> elf = StructuredDataView(bv, structure, address)
			>>>

		Once instantiated, members can be accessed:

			>>> print("{:x}".format(elf.machine))
			003e
			>>>

		"""
	_structure = None
	_structure_name = None
	_address = 0
	_bv = None

	def __init__(self, bv, structure_name, address):
		self._bv = bv
		self._structure_name = structure_name
		self._address = address
		self._members = OrderedDict()

		self._lookup_structure()
		self._define_members()

	def __repr__(self):
		return "<StructuredDataView type:{} size:{:#x} address:{:#x}>".format(self._structure_name,
																			  self._structure.width, self._address)

	def __len__(self):
		return self._structure.width

	def __getattr__(self, key):
		m = self._members.get(key, None)
		if m is None:
			return self.__getattribute__(key)

		return self[key]

	def __getitem__(self, key):
		m = self._members.get(key, None)
		if m is None:
			return m

		ty = m.type
		offset = m.offset
		width = ty.width

		value = self._bv.read(self._address + offset, width)
		return StructuredDataValue(ty, self._address + offset, value)

	def __str__(self):
		rv = "struct {name} 0x{addr:x} {{\n".format(name=self._structure_name, addr=self._address)
		for k in self._members:
			m = self._members[k]

			ty = m.type
			offset = m.offset

			formatted_offset = "{:=+x}".format(offset)
			formatted_type = "{:s} {:s}".format(str(ty), k)

			value = self[k]
			if value.width in (1, 2, 4, 8):
				formatted_value = str.zfill("{:x}".format(value.int), value.width * 2)
			else:
				formatted_value = str(value)

			rv += "\t{:>6s} {:40s} = {:30s}\n".format(formatted_offset, formatted_type, formatted_value)

		rv += "}\n"

		return rv

	def _lookup_structure(self):
		s = self._bv.get_type_by_name(self._structure_name)
		if s is None:
			raise Exception("Could not find structure with name: {}".format(self._structure_name))

		if s.type_class != TypeClass.StructureTypeClass:
			raise Exception("{} is not a StructureTypeClass, got: {}".format(self._structure_name, s._type_class))

		self._structure = s.structure

	def _define_members(self):
		for m in self._structure.members:
			self._members[m.name] = m
