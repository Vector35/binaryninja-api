# Copyright (c) 2015-2016 Vector 35 LLC
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

import _binaryninjacore as core
import abc
import ctypes
import traceback
import json
import struct
import threading
import code
import sys

_plugin_init = False
def _init_plugins():
	global _plugin_init
	if not _plugin_init:
		_plugin_init = True
		core.BNInitCorePlugins()
		core.BNInitUserPlugins()
	if not core.BNIsLicenseValidated():
		raise RuntimeError, "License is not valid. Please supply a valid license."

class DataBuffer(object):
	def __init__(self, contents="", handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNDataBuffer)
		elif isinstance(contents, int) or isinstance(contents, long):
			self.handle = core.BNCreateDataBuffer(None, contents)
		elif isinstance(contents, DataBuffer):
			self.handle = core.BNDuplicateDataBuffer(contents.handle)
		else:
			self.handle = core.BNCreateDataBuffer(contents, len(contents))

	def __del__(self):
		core.BNFreeDataBuffer(self.handle)

	def __len__(self):
		return int(core.BNGetDataBufferLength(self.handle))

	def __getitem__(self, i):
		if isinstance(i, tuple):
			result = ""
			source = str(self)
			for s in i:
				result += source[s]
			return result
		elif isinstance(i, slice):
			if i.step is not None:
				i = i.indices(len(self))
				start = i[0]
				stop = i[1]
				if stop <= start:
					return ""
				buf = ctypes.create_string_buffer(stop - start)
				ctypes.memmove(buf, core.BNGetDataBufferContentsAt(self.handle, start), stop - start)
				return buf.raw
			else:
				return str(self)[i]
		elif i < 0:
			if i >= -len(self):
				return chr(core.BNGetDataBufferByte(self.handle, int(len(self) + i)))
			raise IndexError, "index out of range"
		elif i < len(self):
			return chr(core.BNGetDataBufferByte(self.handle, int(i)))
		else:
			raise IndexError, "index out of range"

	def __setitem__(self, i, value):
		if isinstance(i, slice):
			if i.step is not None:
				raise IndexError, "step not supported on assignment"
			i = i.indices(len(self))
			start = i[0]
			stop = i[1]
			if stop < start:
				stop = start
			if len(value) != (stop - start):
				data = str(self)
				data = data[0:start] + value + data[stop:]
				core.BNSetDataBufferContents(self.handle, data, len(data))
			else:
				value = str(value)
				buf = ctypes.create_string_buffer(value)
				ctypes.memmove(core.BNGetDataBufferContentsAt(self.handle, start), buf, len(value))
		elif i < 0:
			if i >= -len(self):
				if len(value) != 1:
					raise ValueError, "expected single byte for assignment"
				value = str(value)
				buf = ctypes.create_string_buffer(value)
				ctypes.memmove(core.BNGetDataBufferContentsAt(self.handle, int(len(self) + i)), buf, 1)
			else:
				raise IndexError, "index out of range"
		elif i < len(self):
			if len(value) != 1:
				raise ValueError, "expected single byte for assignment"
			value = str(value)
			buf = ctypes.create_string_buffer(value)
			ctypes.memmove(core.BNGetDataBufferContentsAt(self.handle, int(i)), buf, 1)
		else:
			raise IndexError, "index out of range"

	def __str__(self):
		buf = ctypes.create_string_buffer(len(self))
		ctypes.memmove(buf, core.BNGetDataBufferContents(self.handle), len(self))
		return buf.raw

	def __repr__(self):
		return repr(str(self))

	def escape(self):
		return core.BNDataBufferToEscapedString(self.handle)

	def unescape(self):
		return DataBuffer(handle=core.BNDecodeEscapedString(str(self)))

	def base64_encode(self):
		return core.BNDataBufferToBase64(self.handle)

	def base64_decode(self):
		return DataBuffer(handle = core.BNDecodeBase64(str(self)))

	def zlib_compress(self):
		buf = core.BNZlibCompress(self.handle)
		if buf is None:
			return None
		return DataBuffer(handle = buf)

	def zlib_decompress(self):
		buf = core.BNZlibDecompress(self.handle)
		if buf is None:
			return None
		return DataBuffer(handle = buf)

class NavigationHandler(object):
	def _register(self, handle):
		self._cb = core.BNNavigationHandler()
		self._cb.context = 0
		self._cb.getCurrentView = self._cb.getCurrentView.__class__(self._get_current_view)
		self._cb.getCurrentOffset = self._cb.getCurrentOffset.__class__(self._get_current_offset)
		self._cb.navigate = self._cb.navigate.__class__(self._navigate)
		core.BNSetFileMetadataNavigationHandler(handle, self._cb)

	def _get_current_view(self, ctxt):
		try:
			view = self.get_current_view()
		except:
			log_error(traceback.format_exc())
			view = ""
		return core.BNAllocString(view)

	def _get_current_offset(self, ctxt):
		try:
			return self.get_current_offset()
		except:
			log_error(traceback.format_exc())
			return 0

	def _navigate(self, ctxt, view, offset):
		try:
			return self.navigate(view, offset)
		except:
			log_error(traceback.format_exc())
			return False

class FileMetadata(object):
	"""
	``class FileMetadata`` represents the file being analyzed by Binary Ninja. It is responsible for opening,
	closing, creating the database (.bndb) files, and is used to keep track of undoable actions.
	"""
	def __init__(self, filename = None, handle = None):
		"""
		Instantiates a new FileMetadata class.

		:param filename: The string path to the file to be opened. Defaults to None.
		:param handle: A handle to the underlying C FileMetadata object. Defaults to None.
		"""
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNFileMetadata)
		else:
			_init_plugins()
			self.handle = core.BNCreateFileMetadata()
			if filename is not None:
				core.BNSetFilename(self.handle, str(filename))
		self.nav = None

	def __del__(self):
		if self.navigation is not None:
			core.BNSetFileMetadataNavigationHandler(self.handle, None)
		core.BNFreeFileMetadata(self.handle)

	@property
	def filename(self):
		"""The name of the file (read/write)"""
		return core.BNGetFilename(self.handle)

	@filename.setter
	def filename(self, value):
		core.BNSetFilename(self.handle, str(value))

	@property
	def modified(self):
		"""Boolean result of whether the file is modified (Inverse of 'saved' property) (read/write)"""
		return core.BNIsFileModified(self.handle)

	@modified.setter
	def modified(self, value):
		if value:
			core.BNMarkFileModified(self.handle)
		else:
			core.BNMarkFileSaved(self.handle)

	@property
	def analysis_changed(self):
		"""Boolean result of whether the auto-analysis results have changed (read-only)"""
		return core.BNIsAnalysisChanged(self.handle)

	@property
	def has_database(self):
		"""Whether the FileMetadata is backed by a database (read-only)"""
		return core.BNIsBackedByDatabase(self.handle)

	@property
	def view(self):
		return core.BNGetCurrentView(self.handle)

	@view.setter
	def view(self, value):
		core.BNNavigate(self.handle, str(value), core.BNGetCurrentOffset(self.handle))

	@property
	def offset(self):
		"""The current offset into the file (read/write)"""
		return core.BNGetCurrentOffset(self.handle)

	@offset.setter
	def offset(self, value):
		core.BNNavigate(self.handle, core.BNGetCurrentView(self.handle), value)

	@property
	def raw(self):
		"""Gets the "Raw" BinaryView of the file"""
		view = core.BNGetFileViewOfType(self.handle, "Raw")
		if view is None:
			return None
		return BinaryView(self, handle = view)

	@property
	def saved(self):
		"""Boolean result of whether the file has been saved (Inverse of 'modified' property) (read/write)"""
		return not core.BNIsFileModified(self.handle)

	@saved.setter
	def saved(self, value):
		if value:
			core.BNMarkFileSaved(self.handle)
		else:
			core.BNMarkFileModified(self.handle)

	@property
	def navigation(self):
		return self.nav

	@navigation.setter
	def navigation(self, value):
		value._register(self.handle)
		self.nav = value

	def close(self):
		"""
		Closes the underlying file handle. It is recommended that this is done in a
		`finally` clause to avoid handle leaks.
		"""
		core.BNCloseFile(self.handle)

	def begin_undo_actions(self):
		"""
		``begin_undo_actions`` start recording actions taken so the can be undone at some point.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(bv.arch, 0x100012f1)
			True
			>>> bv.commit_undo_actions()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		core.BNBeginUndoActions(self.handle)

	def commit_undo_actions(self):
		"""
		``commit_undo_actions`` commit the actions taken since the last commit to the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(bv.arch, 0x100012f1)
			True
			>>> bv.commit_undo_actions()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		core.BNCommitUndoActions(self.handle)

	def undo(self):
		"""
		``undo`` undo the last commited action in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(bv.arch, 0x100012f1)
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
		core.BNUndo(self.handle)

	def redo(self):
		"""
		``redo`` redo the last commited action in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(bv.arch, 0x100012f1)
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
		core.BNRedo(self.handle)

	def navigate(self, view, offset):
		return core.BNNavigate(self.handle, str(view), offset)

	def create_database(self, filename, progress_func = None):
		if progress_func is None:
			return core.BNCreateDatabase(self.raw.handle, str(filename))
		else:
			return core.BNCreateDatabaseWithProgress(self.raw.handle, str(filename), None,
				ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
					lambda ctxt, cur, total: progress_func(cur, total)))

	def open_existing_database(self, filename, progress_func = None):
		if progress_func is None:
			view = core.BNOpenExistingDatabase(self.handle, str(filename))
		else:
			view = core.BNOpenExistingDatabaseWithProgress(self.handle, str(filename), None,
				ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
				lambda ctxt, cur, total: progress_func(cur, total)))
		if view is None:
			return None
		return BinaryView(self, handle = view)

	def save_auto_snapshot(self, progress_func = None):
		if progress_func is None:
			return core.BNSaveAutoSnapshot(self.raw.handle)
		else:
			return core.BNSaveAutoSnapshotWithProgress(self.raw.handle, None,
				ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(
				lambda ctxt, cur, total: progress_func(cur, total)))

	def get_view_of_type(self, name):
		view = core.BNGetFileViewOfType(self.handle, str(name))
		if view is None:
			view_type = core.BNGetBinaryViewTypeByName(str(name))
			if view_type is None:
				return None
			view = core.BNCreateBinaryViewOfType(view_type, self.raw.handle)
			if view is None:
				return None
		return BinaryView(self, handle = view)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

class FileAccessor:
	def __init__(self):
		self._cb = core.BNFileAccessor()
		self._cb.context = 0
		self._cb.getLength = self._cb.getLength.__class__(self._get_length)
		self._cb.read = self._cb.read.__class__(self._read)
		self._cb.write = self._cb.write.__class__(self._write)

	def __len__(self):
		return self.get_length()

	def _get_length(self, ctxt):
		try:
			return self.get_length()
		except:
			log_error(traceback.format_exc())
			return 0

	def _read(self, ctxt, dest, offset, length):
		try:
			data = self.read(offset, length)
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
			return self.write(offset, data.raw)
		except:
			log_error(traceback.format_exc())
			return 0

class CoreFileAccessor(FileAccessor):
	def __init__(self, accessor):
		self._cb.context = accessor.context
		self._cb.getLength = accessor.getLength
		self._cb.read = accessor.read
		self._cb.write = accessor.write

	def get_length(self):
		return self._cb.getLength(self._cb.context)

	def read(self, offset, length):
		data = ctypes.create_string_buffer(length)
		length = self._cb.read(self._cb.context, data, offset, length)
		return data.raw[0:length]

	def write(self, offset, value):
		value = str(value)
		data = ctypes.create_string_buffer(value)
		return self._cb.write(self._cb.context, offset, data, len(value))

class BinaryDataNotification:
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

	def data_var_added(self, view, var):
		pass

	def data_var_removed(self, view, var):
		pass

	def data_var_updated(self, view, var):
		pass

	def string_found(self, view, string_type, offset, length):
		pass

	def string_removed(self, view, string_type, offset, length):
		pass

class UndoAction:
	name = None
	action_type = None
	_registered = False
	_registered_cb = None

	def __init__(self, view):
		self._cb = core.BNUndoAction()
		if not self.__class__._registered:
			raise TypeError, "undo action type not registered"
		action_type = self.__class__.action_type
		if isinstance(action_type, str):
			self._cb.type = core.BNActionType_by_name[action_type]
		else:
			self._cb.type = action_type
		self._cb.context = 0
		self._cb.undo = self._cb.undo.__class__(self._undo)
		self._cb.redo = self._cb.redo.__class__(self._redo)
		self._cb.serialize = self._cb.serialize.__class__(self._serialize)
		self.view = view

	@classmethod
	def register(cls):
		_init_plugins()
		if cls.name is None:
			raise ValueError, "undo action 'name' not defined"
		if cls.action_type is None:
			raise ValueError, "undo action 'action_type' not defined"
		cb_type = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(core.BNUndoAction))
		cls._registered_cb = cb_type(cls._deserialize)
		core.BNRegisterUndoActionType(cls.name, 0, cls._registered_cb)
		cls._registered = True

	@classmethod
	def _deserialize(cls, ctxt, data, result):
		try:
			action = cls.deserialize(json.loads(data))
			if action is None:
				return False
			result.context = action._cb.context
			result.undo = action._cb.undo
			result.redo = action._cb.redo
			result.serialize = action._cb.serialize
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _undo(self, ctxt, view):
		try:
			self.undo()
		except:
			log_error(traceback.format_exc())
			return False

	def _redo(self, ctxt, view):
		try:
			self.redo()
		except:
			log_error(traceback.format_exc())
			return False

	def _serialize(self, ctxt):
		try:
			return json.dumps(self.serialize())
		except:
			log_error(traceback.format_exc())
			return "null"

class StringReference(object):
	def __init__(self, string_type, start, length):
		self.type = string_type
		self.start = start
		self.length = length

	def __repr__(self):
		return "<%s: %#x, len %#x>" % (self.type, self.start, self.length)

class BinaryDataNotificationCallbacks(object):
	def __init__(self, view, notify):
		self.view = view
		self.notify = notify
		self._cb = core.BNBinaryDataNotification()
		self._cb.context = 0
		self._cb.dataWritten = self._cb.dataWritten.__class__(self._data_written)
		self._cb.dataInserted = self._cb.dataInserted.__class__(self._data_inserted)
		self._cb.dataRemoved = self._cb.dataRemoved.__class__(self._data_removed)
		self._cb.functionAdded = self._cb.functionAdded.__class__(self._function_added)
		self._cb.functionRemoved = self._cb.functionRemoved.__class__(self._function_removed)
		self._cb.functionUpdated = self._cb.functionUpdated.__class__(self._function_updated)
		self._cb.dataVariableAdded = self._cb.dataVariableAdded.__class__(self._data_var_added)
		self._cb.dataVariableRemoved = self._cb.dataVariableRemoved.__class__(self._data_var_removed)
		self._cb.dataVariableUpdated = self._cb.dataVariableUpdated.__class__(self._data_var_updated)
		self._cb.stringFound = self._cb.stringFound.__class__(self._string_found)
		self._cb.stringRemoved = self._cb.stringRemoved.__class__(self._string_removed)

	def _register(self):
		core.BNRegisterDataNotification(self.view.handle, self._cb)

	def _unregister(self):
		core.BNUnregisterDataNotification(self.view.handle, self._cb)

	def _data_written(self, ctxt, view, offset, length):
		try:
			self.notify.data_written(self.view, offset, length)
		except OSError:
			log_error(traceback.format_exc())

	def _data_inserted(self, ctxt, view, offset, length):
		try:
			self.notify.data_inserted(self.view, offset, length)
		except:
			log_error(traceback.format_exc())

	def _data_removed(self, ctxt, view, offset, length):
		try:
			self.notify.data_removed(self.view, offset, length)
		except:
			log_error(traceback.format_exc())

	def _function_added(self, ctxt, view, func):
		try:
			self.notify.function_added(self.view, Function(self.view, core.BNNewFunctionReference(func)))
		except:
			log_error(traceback.format_exc())

	def _function_removed(self, ctxt, view, func):
		try:
			self.notify.function_removed(self.view, Function(self.view, core.BNNewFunctionReference(func)))
		except:
			log_error(traceback.format_exc())

	def _function_updated(self, ctxt, view, func):
		try:
			self.notify.function_updated(self.view, Function(self.view, core.BNNewFunctionReference(func)))
		except:
			log_error(traceback.format_exc())

	def _data_var_added(self, ctxt, view, var):
		try:
			address = var.address
			var_type = Type(core.BNNewTypeReference(var.type))
			auto_discovered = var.autoDiscovered
			self.notify.data_var_added(self.view, DataVariable(address, var_type, auto_discovered))
		except:
			log_error(traceback.format_exc())

	def _data_var_removed(self, ctxt, view, var):
		try:
			address = var.address
			var_type = Type(core.BNNewTypeReference(var.type))
			auto_discovered = var.autoDiscovered
			self.notify.data_var_removed(self.view, DataVariable(address, var_type, auto_discovered))
		except:
			log_error(traceback.format_exc())

	def _data_var_updated(self, ctxt, view, var):
		try:
			address = var.address
			var_type = Type(core.BNNewTypeReference(var.type))
			auto_discovered = var.autoDiscovered
			self.notify.data_var_updated(self.view, DataVariable(address, var_type, auto_discovered))
		except:
			log_error(traceback.format_exc())

	def _string_found(self, ctxt, view, string_type, offset, length):
		try:
			self.notify.string_found(self.view, core.BNStringType_names[string_type], offset, length)
		except:
			log_error(traceback.format_exc())

	def _string_removed(self, ctxt, view, string_type, offset, length):
		try:
			self.notify.string_removed(self.view, core.BNStringType_names[string_type], offset, length)
		except:
			log_error(traceback.format_exc())

class _BinaryViewTypeMetaclass(type):
	@property
	def list(self):
		"""List all BinaryView types (read-only)"""
		_init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetBinaryViewTypes(count)
		result = []
		for i in xrange(0, count.value):
			result.append(BinaryViewType(types[i]))
		core.BNFreeBinaryViewTypeList(types)
		return result

	def __iter__(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetBinaryViewTypes(count)
		try:
			for i in xrange(0, count.value):
				yield BinaryViewType(types[i])
		finally:
			core.BNFreeBinaryViewTypeList(types)

	def __getitem__(self, value):
		_init_plugins()
		view_type = core.BNGetBinaryViewTypeByName(str(value))
		if view_type is None:
			raise KeyError, "'%s' is not a valid view type" % str(value)
		return BinaryViewType(view_type)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

class BinaryViewType(object):
	__metaclass__ = _BinaryViewTypeMetaclass

	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNBinaryViewType)

	@property
	def name(self):
		"""Binary View name (read-only)"""
		return core.BNGetBinaryViewTypeName(self.handle)

	@property
	def long_name(self):
		"""BinaryView long name (read-only)"""
		return core.BNGetBinaryViewTypeLongName(self.handle)

	def __repr__(self):
		return "<view type: '%s'>" % self.name

	def create(self, data):
		view = core.BNCreateBinaryViewOfType(self.handle, data.handle)
		if view is None:
			return None
		return BinaryView(data.file, handle = view)

	def open(self, src, file_metadata = None):
		data = BinaryView.open(src, file_metadata)
		if data is None:
			return None
		return self.create(data)

	def is_valid_for_data(self, data):
		return core.BNIsBinaryViewTypeValidForData(self.handle, data.handle)

	def register_arch(self, ident, endian, arch):
		core.BNRegisterArchitectureForViewType(self.handle, ident, endian, arch.handle)

	def get_arch(self, ident, endian):
		arch = core.BNGetArchitectureForViewType(self.handle, ident, endian)
		if arch is None:
			return None
		return Architecture(arch)

	def register_platform(self, ident, arch, platform):
		core.BNRegisterPlatformForViewType(self.handle, ident, arch.handle, platform.handle)

	def register_default_platform(self, arch, platform):
		core.BNRegisterDefaultPlatformForViewType(self.handle, arch.handle, platform.handle)

	def get_platform(self, ident, arch):
		platform = core.BNGetPlatformForViewType(self.handle, ident, arch.handle)
		if platform is None:
			return None
		return Platform(None, platform)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

class AnalysisCompletionEvent(object):
	def __init__(self, view, callback):
		self.view = view
		self.callback = callback
		self._cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._notify)
		self.handle = core.BNAddAnalysisCompletionEvent(self.view.handle, None, self._cb)

	def __del__(self):
		core.BNFreeAnalysisCompletionEvent(self.handle)

	def _notify(self, ctxt):
		try:
			self.callback()
		except:
			log_error(traceback.format_exc())

	def _empty_callback(self):
		pass

	def cancel(self):
		self.callback = self._empty_callback
		core.BNCancelAnalysisCompletionEvent(self.handle)

class AnalysisProgress(object):
	def __init__(self, state, count, total):
		self.state = state
		self.count = count
		self.total = total

	def __str__(self):
		if self.state == core.DisassembleState:
			return "Disassembling (%d/%d)" % (self.count, self.total)
		if self.state == core.AnalyzeState:
			return "Analyzing (%d/%d)" % (self.count, self.total)
		return "Idle"

	def __repr__(self):
		return "<progress: %s>" % str(self)

class LinearDisassemblyPosition(object):
	"""
	``class LinearDisassemblyPosition`` is a helper object containing the position of the current Linear Disassembly.

	.. note:: This object should not be instantiated directly. Rather call \
	:py:method:`get_linear_disassembly_position_at` which instantiates this object.
	"""
	def __init__(self, func, block, addr):
		self.function = func
		self.block = block
		self.address = addr

class LinearDisassemblyLine(object):
	def __init__(self, line_type, func, block, line_offset, contents):
		self.type = line_type
		self.function = func
		self.block = block
		self.line_offset = line_offset
		self.contents = contents

	def __str__(self):
		return str(self.contents)

	def __repr__(self):
		return repr(self.contents)

class DataVariable(object):
	def __init__(self, addr, var_type, auto_discovered):
		self.address = addr
		self.type = var_type
		self.auto_discovered = auto_discovered

	def __repr__(self):
		return "<var 0x%x: %s>" % (self.address, str(self.type))

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

		>>> bv = BinaryViewType['Mach-O'].open("/bin/ls")
		>>> bv
		<BinaryView: '/bin/ls', start 0x100000000, len 0xa000>

	`By convention in the rest of this document we will use bv to mean an open BinaryView of an executable file.`
	When a BinaryView is open on an executable view, analysis does not automatically run, this can be done by running
	the ``update_analysis_and_wait()`` method which disassembles the executable and returns when all disassembly is
	finished::

		>>> bv.update_analysis_and_wait()
		>>>

	Since BinaryNinja's analysis is multi-threaded (depending on version) this can also be done in the background by
	using the ``update_analysis()`` method instead.

	By standard python convention methods which start with '_' should be considered private and should not be called
	externally. Additionanlly, methods which begin with ``perform_`` should not be called either and are
	used explicitly for subclassing the BinaryView.

	.. note:: An important note on the ``*_user_*()`` methods. Binary Ninja makes a distinction between edits \
	performed by the user and actions performed by auto analysis.  Auto analysis actions that can quickly be recalculated \
	are not saved to the database. Auto analysis actions that take a long time and all user edits are stored in the \
	database (e.g. ``remove_user_function()`` rather than ``remove_function()``). Thus use ``_user_`` methods if saving \
	to the database is desired.
	"""
	name = None
	long_name = None
	_registered = False
	_registered_cb = None
	registered_view_type = None
	next_address = 0

	def __init__(self, file_metadata = None, handle = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNBinaryView)
			if file_metadata is None:
				self.file = FileMetadata(handle = core.BNGetFileForView(handle))
			else:
				self.file = file_metadata
		elif self.__class__ is BinaryView:
			_init_plugins()
			if file_metadata is None:
				file_metadata = FileMetadata()
			self.handle = core.BNCreateBinaryDataView(file_metadata.handle)
			self.file = FileMetadata(handle = core.BNNewFileReference(file_metadata))
		else:
			_init_plugins()
			if not self.__class__._registered:
				raise TypeError, "view type not registered"
			self._cb = core.BNCustomBinaryView()
			self._cb.context = 0
			self._cb.init = self._cb.init.__class__(self._init)
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
			self._cb.getAddressSize = self._cb.getAddressSize.__class__(self._get_address_size)
			self._cb.save = self._cb.save.__class__(self._save)
			self.file = file_metadata
			self.handle = core.BNCreateCustomBinaryView(self.__class__.name, file_metadata.handle, self._cb)
		self.notifications = {}
		self.next_address = self.entry_point

	@classmethod
	def register(cls):
		_init_plugins()
		if cls.name is None:
			raise ValueError, "view 'name' not defined"
		if cls.long_name is None:
			cls.long_name = cls.name
		cls._registered_cb = core.BNCustomBinaryViewType()
		cls._registered_cb.context = 0
		cls._registered_cb.create = cls._registered_cb.create.__class__(cls._create)
		cls._registered_cb.isValidForData = cls._registered_cb.isValidForData.__class__(cls._is_valid_for_data)
		cls.registered_view_type = BinaryViewType(core.BNRegisterBinaryViewType(cls.name, cls.long_name, cls._registered_cb))
		cls._registered = True

	@classmethod
	def _create(cls, ctxt, data):
		try:
			file_metadata = FileMetadata(handle = core.BNGetFileForView(data))
			view = cls(BinaryView(file_metadata, handle = core.BNNewViewReference(data)))
			if view is None:
				return None
			return ctypes.cast(core.BNNewViewReference(view.handle), ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	@classmethod
	def _is_valid_for_data(cls, ctxt, data):
		try:
			return cls.is_valid_for_data(BinaryView(None, handle = core.BNNewViewReference(data)))
		except:
			log_error(traceback.format_exc())
			return False

	@classmethod
	def open(cls, src, file_metadata = None):
		_init_plugins()
		if isinstance(src, FileAccessor):
			if file_metadata is None:
				file_metadata = FileMetadata()
			view = core.BNCreateBinaryDataViewFromFile(file_metadata.handle, src._cb)
		else:
			if file_metadata is None:
				file_metadata = FileMetadata(str(src))
			view = core.BNCreateBinaryDataViewFromFilename(file_metadata.handle, str(src))
		if view is None:
			return None
		result = BinaryView(file_metadata, handle = view)
		return result

	@classmethod
	def new(cls, data = None, file_metadata = None):
		_init_plugins()
		if file_metadata is None:
			file_metadata = FileMetadata()
		if data is None:
			view = core.BNCreateBinaryDataView(file_metadata.handle)
		else:
			buf = DataBuffer(data)
			view = core.BNCreateBinaryDataViewFromBuffer(file_metadata.handle, buf.handle)
		if view is None:
			return None
		result = BinaryView(file_metadata, handle = view)
		return result

	def __del__(self):
		for i in self.notifications.values():
			i._unregister()
		core.BNFreeBinaryView(self.handle)

	def __iter__(self):
		count = ctypes.c_ulonglong(0)
		funcs = core.BNGetAnalysisFunctionList(self.handle, count)
		try:
			for i in xrange(0, count.value):
				yield Function(self, core.BNNewFunctionReference(funcs[i]))
		finally:
			core.BNFreeFunctionList(funcs, count.value)

	@property
	def modified(self):
		"""boolean modification state of the BinaryView (read/write)"""
		return self.file.modified

	@modified.setter
	def modified(self, value):
		self.file.modified = value

	@property
	def analysis_changed(self):
		"""boolean analysis state changed of the currently running analysis (read-only)"""
		return self.file.analysis_changed

	@property
	def has_database(self):
		"""boolean has a database been written to disk (read-only)"""
		return self.file.has_database

	@property
	def view(self):
		return self.file.view

	@view.setter
	def view(self, value):
		self.file.view = value

	@property
	def offset(self):
		return self.file.offset

	@offset.setter
	def offset(self, value):
		self.file.offset = value

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
		"""The architecture associated with the current BinaryView (read/write)"""
		arch = core.BNGetDefaultArchitecture(self.handle)
		if arch is None:
			return None
		return Architecture(handle = arch)

	@arch.setter
	def arch(self, value):
		if value is None:
			core.BNSetDefaultArchitecture(self.handle, None)
		else:
			core.BNSetDefaultArchitecture(self.handle, value.handle)

	@property
	def platform(self):
		"""The platform associated with the current BinaryView (read/write)"""
		platform = core.BNGetDefaultPlatform(self.handle)
		if platform is None:
			return None
		return Platform(self.arch, handle = platform)

	@platform.setter
	def platform(self, value):
		if value is None:
			core.BNSetDefaultPlatform(self.handle, None)
		else:
			core.BNSetDefaultPlatform(self.handle, value.handle)

	@property
	def endianness(self):
		"""Endianness of the binary (read-only)"""
		return core.BNGetDefaultEndianness(self.handle)

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
		for i in xrange(0, count.value):
			result.append(Function(self, core.BNNewFunctionReference(funcs[i])))
		core.BNFreeFunctionList(funcs, count.value)
		return result

	@property
	def has_functions(self):
		"""Boolean whether the binary has functions (read-only)"""
		return core.BNHasFunctions(self.handle)

	@property
	def entry_function(self):
		"""Entry function (read-only)"""
		func = core.BNGetAnalysisEntryPoint(self.handle)
		if func is None:
			return None
		return Function(self, func)

	@property
	def symbols(self):
		"""Dict of symbols (read-only)"""
		count = ctypes.c_ulonglong(0)
		syms = core.BNGetSymbols(self.handle, count)
		result = {}
		for i in xrange(0, count.value):
			sym = Symbol(None, None, None, handle = core.BNNewSymbolReference(syms[i]))
			result[sym.raw_name] = sym
		core.BNFreeSymbolList(syms, count.value)
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
		for i in xrange(0, count.value):
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
		return self.file.saved

	@saved.setter
	def saved(self, value):
		self.file.saved = value

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
		for i in xrange(0, count.value):
			addr = var_list[i].address
			var_type = Type(core.BNNewTypeReference(var_list[i].type))
			auto_discovered = var_list[i].autoDiscovered
			result[addr] = DataVariable(addr, var_type, auto_discovered)
		core.BNFreeDataVariables(var_list, count.value)
		return result

	@property
	def types(self):
		"""List of defined types (read-only)"""
		count = ctypes.c_ulonglong(0)
		type_list = core.BNGetAnalysisTypeList(self.handle, count)
		result = {}
		for i in xrange(0, count.value):
			result[type_list[i].name] = Type(core.BNNewTypeReference(type_list[i].type))
		core.BNFreeTypeList(type_list, count.value)
		return result

	def __len__(self):
		return int(core.BNGetViewLength(self.handle))

	def __getitem__(self, i):
		if isinstance(i, tuple):
			result = ""
			for s in i:
				result += self.__getitem__(s)
			return result
		elif isinstance(i, slice):
			if i.step is not None:
				raise IndexError, "step not implemented"
			i = i.indices(self.end)
			start = i[0]
			stop = i[1]
			if stop <= start:
				return ""
			return str(self.read(start, stop - start))
		elif i < 0:
			if i >= -len(self):
				value = str(self.read(int(len(self) + i), 1))
				if len(value) == 0:
					return IndexError, "index not readable"
				return value
			raise IndexError, "index out of range"
		elif (i >= self.start) and (i < self.end):
			value = str(self.read(int(i), 1))
			if len(value) == 0:
				return IndexError, "index not readable"
			return value
		else:
			raise IndexError, "index out of range"

	def __setitem__(self, i, value):
		if isinstance(i, slice):
			if i.step is not None:
				raise IndexError, "step not supported on assignment"
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
					raise ValueError, "expected single byte for assignment"
				if self.write(int(len(self) + i), value) != 1:
					raise IndexError, "index not writable"
			else:
				raise IndexError, "index out of range"
		elif (i >= self.start) and (i < self.end):
			if len(value) != 1:
				raise ValueError, "expected single byte for assignment"
			if self.write(int(i), value) != 1:
				raise IndexError, "index not writable"
		else:
			raise IndexError, "index out of range"

	def __repr__(self):
		start = self.start
		length = len(self)
		if start != 0:
			size = "start %#x, len %#x" % (start, length)
		else:
			size = "len %#x" % length
		filename = self.file.filename
		if len(filename) > 0:
			return "<BinaryView: '%s', %s>" % (filename, size)
		return "<BinaryView: %s>" % (size)

	def _init(self, ctxt):
		try:
			return self.init()
		except:
			log_error(traceback.format_exc())
			return False

	def _read(self, ctxt, dest, offset, length):
		try:
			data = self.perform_read(offset, length)
			if data is None:
				return 0
			if len(data) > length:
				data = data[0:length]
			ctypes.memmove(dest, str(data), len(data))
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
			return core.Original

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
			return core.LittleEndian

	def _get_address_size(self, ctxt):
		try:
			return self.perform_get_address_size()
		except:
			log_error(traceback.format_exc())
			return 8

	def _save(self, ctxt, file_accessor):
		try:
			return self.perform_save(CoreFileAccessor(file_accessor))
		except:
			log_error(traceback.format_exc())
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
		txt, size = arch.get_instruction_text(self.read(addr, self.arch.max_instr_length), addr)
		self.next_address = addr + size
		if txt is None:
			return None
		return ''.join(str(a) for a in txt).strip()

	def get_next_disassembly(self, arch=None):
		"""
		``get_next_disassembly`` simple helper function for printing disassembly of the next instruction.
		The internal state of the instruction to be printed is stored in the ``next_address`` attribute

		:param Architecture arch: optional Architecture, ``self.arch`` is used if this parameter is None
		:return: a str representation of the instruction at virtual address ``self.next_address``
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
		txt, size = arch.get_instruction_text(self.read(self.next_address, self.arch.max_instr_length), self.next_address)
		self.next_address += size
		if txt is None:
			return None
		return ''.join(str(a) for a in txt).strip()

	@abc.abstractmethod
	def perform_save(self, accessor):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_address_size(self):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_length(self):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_read(self, addr, length):
		"""
		``perform_read`` implements a mapping between a virtual address and an absolute file offset, reading
		``length`` bytes from the rebased address ``addr``.

		.. note:: This method must be overridden by custom BinaryViews if they have segments or the virtual address is\
		 different from the physical address.
		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to attempt to read from
		:param int length: the number of bytes to be read
		:return: length bytes read from addr, should return empty string on error
		:rtype: int
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_write(self, addr, data):
		"""
		``perform_write`` implements a mapping between a virtual address and an absolute file offset, writing
		the bytes ``data`` to rebased address ``addr``.

		.. note:: This method must be overridden by custom BinaryViews if they have segments or the virtual address is \
		different from the physical address.
		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address
		:param str data: the data to be written
		:return: length of data written, should return 0 on error
		:rtype: int
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_insert(self, addr, data):
		"""
		``perform_insert`` implements a mapping between a virtual address and an absolute file offset, inserting
		the bytes ``data`` to rebased address ``addr``.

		.. note:: This method must be overridden by custom BinaryViews if they have segments or the virtual address is \
		different from the physical address.
		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address
		:param str data: the data to be inserted
		:return: length of data inserted, should return 0 on error
		:rtype: int
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_remove(self, addr, length):
		"""
		``perform_remove`` implements a mapping between a virtual address and an absolute file offset, removing
		``length`` bytes from the rebased address ``addr``.

		.. note:: This method must be overridden by custom BinaryViews if they have segments or the virtual address is \
		different from the physical address.
		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address
		:param str data: the data to be removed
		:return: length of data removed, should return 0 on error
		:rtype: int
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_modification(self, addr):
		"""
		``perform_get_modification`` implements query to the whether the virtual address ``addr`` is modified.

		.. note:: This method **may** be overridden by custom BinaryViews.
		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: One of the following: Original = 0, Changed = 1, Inserted = 2
		:rtype: BNModificationStatus
		"""
		return core.Original

	@abc.abstractmethod
	def perform_is_valid_offset(self, addr):
		"""
		``perform_is_valid_offset`` implements a check if an virtual address ``addr`` is valid.

		.. note:: This method **must** be implemented for custom BinaryViews whose virtual addresses differ from \
		physical file offsets.
		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is valid, false if the virtual address is invalid or error
		:rtype: bool
		"""
		data = self.read(addr, 1)
		return (data is not None) and (len(data) == 1)

	@abc.abstractmethod
	def perform_is_offset_readable(self, offset):
		"""
		``perform_is_offset_readable`` implements a check if an virtual address is readable.

		.. note:: This method **must** be implemented for custom BinaryViews whose virtual addresses differ from \
		physical file offsets, or if memory protections exist.
		.. warning:: This method **must not** be called directly.

		:param int offset: a virtual address to be checked
		:return: true if the virtual address is readable, false if the virtual address is not readable or error
		:rtype: bool
		"""
		return self.is_valid_offset(offset)

	@abc.abstractmethod
	def perform_is_offset_writable(self, addr):
		"""
		``perform_is_offset_writable`` implements a check if a virtual address ``addr`` is writable.

		.. note:: This method **must** be implemented for custom BinaryViews whose virtual addresses differ from \
		physical file offsets, or if memory protections exist.
		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is writable, false if the virtual address is not writable or error
		:rtype: bool
		"""
		return self.is_valid_offset(addr)

	@abc.abstractmethod
	def perform_is_offset_executable(self, addr):
		"""
		``perform_is_offset_writable`` implements a check if a virtual address ``addr`` is executable.

		.. note:: This method **must** be implemented for custom BinaryViews whose virtual addresses differ from \
		physical file offsets, or if memory protections exist.
		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to be checked
		:return: true if the virtual address is executable, false if the virtual address is not executable or error
		:rtype: int
		"""
		return self.is_valid_offset(addr)

	@abc.abstractmethod
	def perform_get_next_valid_offset(self, addr):
		"""
		``perform_get_next_valid_offset`` implements a query for the next valid readable, writable, or executable virtual
		memory address.

		.. note:: This method **may** be implemented by custom BinaryViews
		.. warning:: This method **must not** be called directly.

		:param int addr: a virtual address to start checking from.
		:return: the next readable, writable, or executable virtual memory address
		:rtype: int
		"""
		if addr < self.perform_get_start():
			return self.perform_get_start()
		return addr

	@abc.abstractmethod
	def perform_get_start(self):
		"""
		``perform_get_start`` implements a query for the first readable, writable, or executable virtual address in
		the BinaryView.

		.. note:: This method **may** be implemented by custom BinaryViews
		.. warning:: This method **must not** be called directly.

		:return: returns the first virtual address in the BinaryView.
		:rtype: int
		"""
		return 0

	@abc.abstractmethod
	def perform_get_entry_point(self):
		"""
		``perform_get_entry_point`` implements a query for the initial entry point for code execution.

		.. note:: This method **should** be implmented for custom BinaryViews that are executable.
		.. warning:: This method **must not** be called directly.

		:return: the virtual address of the entry point
		:rtype: int
		"""
		return 0

	@abc.abstractmethod
	def perform_is_executable(self):
		"""
		``perform_is_executable`` implements a check which returns true if the BinaryView is executable.

		.. note:: This method **must** be implemented for custom BinaryViews that are executable.
		.. warning:: This method **must not** be called directly.

		:return: true if the current BinaryView is executable, false if it is not executable or on error
		:rtype: bool
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_default_endianness(self):
		"""
		``perform_get_default_endianness`` implements a check which returns true if the BinaryView is executable.

		.. note:: This method **may** be implemented for custom BinaryViews that are not LittleEndian.
		.. warning:: This method **must not** be called directly.

		:return: either ``core.LittleEndian`` or ``core.BigEndian``
		:rtype: BNEndianness
		"""
		return core.LittleEndian

	def create_database(self, filename, progress_func = None):
		"""
		``perform_get_database`` writes the current database (.bndb) file out to the specified file.

		:param str filename: path and filename to write the bndb to, this string `should` have ".bndb" appended to it.
		:param callable() progress_func: optional function to be called with the current progress and total count.
		:return: true on success, false on failure
		:rtype: bool
		"""
		return self.file.create_database(filename, progress_func)

	def save_auto_snapshot(self, progress_func = None):
		"""
		``save_auto_snapshot`` saves the current database to the already created file.

		.. note:: :py:method:`create_database` should have been called prior to executing this method

		:param callable() progress_func: optional function to be called with the current progress and total count.
		:return: True if it successfully saved the snapshot, False otherwise
		:rtype: bool
		"""
		return self.file.save_auto_snapshot(progress_func)

	def get_view_of_type(self, name):
		"""
		``get_view_of_type`` returns the BinaryView associated with the provided name if it exists.

		:param str name: Name of the view to be retrieved
		:return: BinaryView object assocated with the provided name or None on failure
		:rtype: BinaryView or None
		"""
		return self.file.get_view_of_type(name)

	def begin_undo_actions(self):
		"""
		``begin_undo_actions`` start recording actions taken so the can be undone at some point.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(bv.arch, 0x100012f1)
			True
			>>> bv.commit_undo_actions()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		self.file.begin_undo_actions()

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
			>>> bv.convert_to_nop(bv.arch, 0x100012f1)
			True
			>>> bv.commit_undo_actions()
			>>> bv.get_disassembly(0x100012f1)
			'nop'
			>>> bv.undo()
			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>>
		"""
		self.file.commit_undo_actions()

	def undo(self):
		"""
		``undo`` undo the last commited action in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(bv.arch, 0x100012f1)
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
		self.file.undo()

	def redo(self):
		"""
		``redo`` redo the last commited action in the undo database.

		:rtype: None
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.begin_undo_actions()
			>>> bv.convert_to_nop(bv.arch, 0x100012f1)
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
		self.file.redo()

	def navigate(self, view, offset):
		self.file.navigate(view, offset)

	def read(self, addr, length):
		"""
		``read`` returns the data reads at most ``length`` bytes from virtual address ``addr``.

		:param int addr: virtual address to read from.
		:param int length: number of bytes to read.
		:return: at most ``length`` bytes from the virtual address ``addr``, empty string on error or no data.
		:rtype: str
		:Example:

			>>> #Opening a x86_64 Mach-O binary
			>>> bv = BinaryViewType['Raw'].open("/bin/ls")
			>>> bv.read(0,4)
			\'\\xcf\\xfa\\xed\\xfe\'
		"""
		buf = DataBuffer(handle = core.BNReadViewBuffer(self.handle, addr, length))
		return str(buf)

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
		buf = DataBuffer(data)
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
		buf = DataBuffer(data)
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

	def get_modification(self, addr, length = None):
		"""
		``get_modification`` returns the modified bytes of up to ``length`` bytes from virtual address ``addr``, or if
		``length`` is None returns the core.BNModificationStatus.

		:param int addr: virtual address to get modification from
		:param int length: optional length of modification
		:return: Either core.BNModificationStatus of the byte at ``addr``, or string of modified bytes at ``addr``
		:rtype: core.BNModificationStatus or str
		"""
		if length is None:
			return core.BNGetModification(self.handle, addr)
		data = (core.BNModificationStatus * length)()
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

	def save(self, dest):
		"""
		``save`` saves the original binary file to the provided destination ``dest`` along with any modifications.

		:param str dest: destination path and filename of file to be written
		:return: boolean True on success, False on failure
		:rtype: bool
		"""
		if isinstance(dest, FileAccessor):
			return core.BNSaveToFile(self.handle, dest._cb)
		return core.BNSaveToFilename(self.handle, str(dest))

	def register_notification(self, notify):
		cb = BinaryDataNotificationCallbacks(self, notify)
		cb._register()
		self.notifications[notify] = cb

	def unregister_notification(self, notify):
		if notify in self.notifications:
			self.notifications[notify]._unregister()
			del self.notifications[notify]

	def add_function(self, platform, addr):
		"""
		``add_function`` add a new function of the given ``platform`` at the virtual address ``addr``

		:param Platform platform: Platform for the function to be added
		:param int addr: virtual address of the function to be added
		:rtype: None
		:Example:

			>>> bv.add_function(bv.platform, 1)
			>>> bv.functions
			[<func: x86_64@0x1>]

		"""
		core.BNAddFunctionForAnalysis(self.handle, platform.handle, addr)

	def add_entry_point(self, platform, addr):
		"""
		``add_entry_point`` adds an virtual address to start analysis from for a given platform.

		:param Platform platform: Platform for the entry point analysis
		:param int addr: virtual address to start analysis from
		:rtype: None
		:Example:
			>>> bv.add_entry_point(bv.platform, 0xdeadbeef)
			>>>
		"""
		core.BNAddEntryPointForAnalysis(self.handle, platform.handle, addr)

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

	def create_user_function(self, platform, addr):
		"""
		``create_user_function`` add a new *user* function of the given ``platform`` at the virtual address ``addr``

		:param Platform platform: Platform for the function to be added
		:param int addr: virtual address of the *user* function to be added
		:rtype: None
		:Example:

			>>> bv.create_user_function(bv.platform, 1)
			>>> bv.functions
			[<func: x86_64@0x1>]

		"""
		core.BNCreateUserFunction(self.handle, platform.handle, addr)

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

	def update_analysis(self):
		"""
		``update_analysis`` asynchronously starts the analysis running and returns immediately. Analysis of BinaryViews
		does not occur automatically, the user must start analysis by calling either ``update_analysis()`` or
		``update_analysis_and_wait()``. An analysis update **must** be run after changes are made which could change
		analysis results such as adding functions.

		:rtype: None
		"""
		core.BNUpdateAnalysis(self.handle)

	def update_analysis_and_wait(self):
		"""
		``update_analysis_and_wait`` blocking call to update the analysis, this call returns when the analysis is
		complete.  Analysis of BinaryViews does not occur automatically, the user must start analysis by calling either
		``update_analysis()`` or ``update_analysis_and_wait()``. An analysis update **must** be run after changes are
		made which could change analysis results such as adding functions.

		:rtype: None
		"""
		class WaitEvent:
			def __init__(self):
				self.cond = threading.Condition()
				self.done = False

			def complete(self):
				self.cond.acquire()
				self.done = True
				self.cond.notify()
				self.cond.release()

			def wait(self):
				self.cond.acquire()
				while not self.done:
					self.cond.wait()
				self.cond.release()

		wait = WaitEvent()
		event = AnalysisCompletionEvent(self, lambda: wait.complete())
		core.BNUpdateAnalysis(self.handle)
		wait.wait()

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
		core.BNDefineDataVariable(self.handle, addr, var_type.handle)

	def define_user_data_var(self, addr, var_type):
		"""
		``define_data_var`` defines a user data variable ``var_type`` at the virtual address ``addr``.

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
		core.BNDefineUserDataVariable(self.handle, addr, var_type.handle)

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
		``undefine_data_var`` removes the user data variable at the virtual address ``addr``.

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
		return DataVariable(var.address, Type(var.type), var.autoDiscovered)

	def get_function_at(self, platform, addr):
		"""
		``get_function_at`` gets a binaryninja.Function object for the function at the virtual address ``addr``:

		:param binaryninja.Platform platform: platform of the desired function
		:param int addr: virtual address of the desired function
		:return: returns a Function object or None for the function at the virtual address provided
		:rtype: Function
		:Example:

			>>> bv.get_function_at(bv.platform, bv.entry_point)
			<func: x86_64@0x100001174>
			>>>
		"""
		func = core.BNGetAnalysisFunction(self.handle, platform.handle, addr)
		if func is None:
			return None
		return Function(self, func)

	def get_functions_at(self, addr):
		"""
		``get_functions_at`` get a list of binaryninja.Function objects (one for each valid platform) at the given
		virtual address. Binary Ninja does not limit the number of platforms in a given file thus there may be multiple
		functions defined from different architectures at the same location. This API allows you to query all of valid
		platforms.

		:param int addr: virtual address of the desired Function object list.
		:return: a list of binaryninja.Function objects defined at the provided virtual address
		:rtype: list(Function)
		"""
		count = ctypes.c_ulonglong(0)
		funcs = core.BNGetAnalysisFunctionsForAddress(self.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(Function(self, core.BNNewFunctionReference(funcs[i])))
		core.BNFreeFunctionList(funcs, count.value)
		return result

	def get_recent_function_at(self, addr):
		func = core.BNGetRecentAnalysisFunctionForAddress(self.handle, addr)
		if func is None:
			return None
		return Function(self, func)

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
		for i in xrange(0, count.value):
			result.append(BasicBlock(self, core.BNNewBasicBlockReference(blocks[i])))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	def get_basic_blocks_starting_at(self, addr):
		"""
		``get_basic_blocks_at`` get a list of :py:Class:`BasicBlock` objects which start at the provided virtual address.

		:param int addr: virtual address of BasicBlock desired
		:return: a list of :py:Class:`BasicBlock` objects
		:rtype: list(BasicBlock)
		"""
		count = ctypes.c_ulonglong(0)
		blocks = core.BNGetBasicBlocksStartingAtAddress(self.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(BasicBlock(self, core.BNNewBasicBlockReference(blocks[i])))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	def get_recent_basic_block_at(self, addr):
		block = core.BNGetRecentBasicBlockForAddress(self.handle, addr)
		if block is None:
			return None
		return BasicBlock(self, block)

	def get_code_refs(self, addr, length = None):
		count = ctypes.c_ulonglong(0)
		if length is None:
			refs = core.BNGetCodeReferences(self.handle, addr, count)
		else:
			refs = core.BNGetCodeReferencesInRange(self.handle, addr, length, count)
		result = []
		for i in xrange(0, count.value):
			if refs[i].func:
				func = Function(self, core.BNNewFunctionReference(refs[i].func))
			else:
				func = None
			if refs[i].arch:
				arch = Architecture(refs[i].arch)
			else:
				arch = None
			addr = refs[i].addr
			result.append(ReferenceSource(func, arch, addr))
		core.BNFreeCodeReferences(refs, count.value)
		return result

	def get_symbol_at(self, addr):
		"""
		``get_symbol_at`` returns the Symbol at the provided virtual address.

		:param int addr: virtual address to query for symbol
		:return: Symbol for the given virtual address
		:rtype: Symbol
		:Example:

			>>> bv.get_symbol_at(bv.entry_point)
			<FunctionSymbol: "_start" @ 0x100001174>
			>>>
		"""
		sym = core.BNGetSymbolByAddress(self.handle, addr)
		if sym is None:
			return None
		return Symbol(None, None, None, handle = sym)

	def get_symbol_by_raw_name(self, name):
		"""
		``get_symbol_by_raw_name`` retrieves a Symbol object for the given a raw (mangled) name.

		:param str name: raw (mangled) name of Symbol to be retrieved
		:return: Symbol object corresponding to the provided raw name
		:rtype: Symbol
		:Example:

			>>> bv.get_symbol_by_raw_name('?testf@Foobar@@SA?AW4foo@1@W421@@Z')
			<FunctionSymbol: "public: static enum Foobar::foo __cdecl Foobar::testf(enum Foobar::foo)" @ 0x10001100>
			>>>
		"""
		sym = core.BNGetSymbolByRawName(self.handle, name)
		if sym is None:
			return None
		return Symbol(None, None, None, handle = sym)

	def get_symbols_by_name(self, name):
		"""
		``get_symbols_by_name`` retrieves a list of Symbol objects for the given symbol name.

		:param str name: name of Symbol object to be retrieved
		:return: Symbol object corresponding to the provided name
		:rtype: Symbol
		:Example:

			>>> bv.get_symbols_by_name('?testf@Foobar@@SA?AW4foo@1@W421@@Z')
			[<FunctionSymbol: "public: static enum Foobar::foo __cdecl Foobar::testf(enum Foobar::foo)" @ 0x10001100>]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		syms = core.BNGetSymbolsByName(self.handle, name, count)
		result = []
		for i in xrange(0, count.value):
			result.append(Symbol(None, None, None, handle = core.BNNewSymbolReference(syms[i])))
		core.BNFreeSymbolList(syms, count.value)
		return result

	def get_symbols(self, start = None, length = None):
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
		if start is None:
			syms = core.BNGetSymbols(self.handle, count)
		else:
			syms = core.BNGetSymbolsInRange(self.handle, start, length, count)
		result = []
		for i in xrange(0, count.value):
			result.append(Symbol(None, None, None, handle = core.BNNewSymbolReference(syms[i])))
		core.BNFreeSymbolList(syms, count.value)
		return result

	def get_symbols_of_type(self, sym_type, start = None, length = None):
		"""
		``get_symbols_of_type`` retrieves a list of all Symbol objects of the provided symbol type in the optionally
		 provided range.

		:param SymbolType sym_type: A Symbol type: :py:Class:`Symbol`.
		:param int start: optional start virtual address
		:param int length: optional length
		:return: list of all Symbol objects of type sym_type, or those Symbol objects in the range of ``start``-``start+length``
		:rtype: list(Symbol)
		:Example:

			>>> bv.get_symbols_of_type(core.ImportAddressSymbol, 0x10002028, 1)
			[<ImportAddressSymbol: "KERNEL32!GetCurrentThreadId@IAT" @ 0x10002028>]
			>>>
		"""
		if isinstance(sym_type, str):
			sym_type = core.BNSymbolType_by_name[sym_type]
		count = ctypes.c_ulonglong(0)
		if start is None:
			syms = core.BNGetSymbolsOfType(self.handle, sym_type, count)
		else:
			syms = core.BNGetSymbolsOfTypeInRange(self.handle, sym_type, start, length, count)
		result = []
		for i in xrange(0, count.value):
			result.append(Symbol(None, None, None, handle = core.BNNewSymbolReference(syms[i])))
		core.BNFreeSymbolList(syms, count.value)
		return result

	def define_auto_symbol(self, sym):
		"""
		``define_auto_symbol`` adds a symbol to the internal list of automatically discovered Symbol objects.

		:param Symbol sym: the symbol to define
		:rtype: None
		"""
		core.BNDefineAutoSymbol(self.handle, sym.handle)

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

	def is_never_branch_patch_available(self, arch, addr):
		"""
		``is_never_branch_patch_available`` queries the architecture plugin to determine if the instruction at the
		instruction at ``addr`` can be made to **never branch**. The actual logic of which is implemented in the
		``perform_is_never_branch_patch_available`` in the corresponding architecture.

		:param Architecture arch: the architecture for the current view
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012ed)
			'test    eax, eax'
			>>> bv.is_never_branch_patch_available(bv.arch, 0x100012ed)
			False
			>>> bv.get_disassembly(0x100012ef)
			'jg      0x100012f5'
			>>> bv.is_never_branch_patch_available(bv.arch, 0x100012ef)
			True
			>>>
		"""
		return core.BNIsNeverBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_always_branch_patch_available(self, arch, addr):
		"""
		``is_always_branch_patch_available`` queries the architecture plugin to determine if the
		instruction at ``addr`` can be made to **always branch**. The actual logic of which is implemented in the
		``perform_is_always_branch_patch_available`` in the corresponding architecture.

		:param Architecture arch: the architecture for the current view
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012ed)
			'test    eax, eax'
			>>> bv.is_always_branch_patch_available(bv.arch, 0x100012ed)
			False
			>>> bv.get_disassembly(0x100012ef)
			'jg      0x100012f5'
			>>> bv.is_always_branch_patch_available(bv.arch, 0x100012ef)
			True
			>>>
		"""
		return core.BNIsAlwaysBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_invert_branch_patch_available(self, arch, addr):
		"""
		``is_invert_branch_patch_available`` queries the architecture plugin to determine if the instruction at ``addr``
		is a branch that can be inverted. The actual logic of which is implemented in the
		``perform_is_invert_branch_patch_available`` in the corresponding architecture.

		:param Architecture arch: the architecture for the current view
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012ed)
			'test    eax, eax'
			>>> bv.is_invert_branch_patch_available(bv.arch, 0x100012ed)
			False
			>>> bv.get_disassembly(0x100012ef)
			'jg      0x100012f5'
			>>> bv.is_invert_branch_patch_available(bv.arch, 0x100012ef)
			True
			>>>
		"""
		return core.BNIsInvertBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_skip_and_return_zero_patch_available(self, arch, addr):
		"""
		``is_skip_and_return_zero_patch_available`` queries the architecture plugin to determine if the
		instruction at ``addr`` is similar to an x86 "call"  instruction which can be made to return zero.  The actual
		logic of which is implemented in the ``perform_is_skip_and_return_zero_patch_available`` in the corresponding
		architecture.

		:param Architecture arch: the architecture for the current view
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012f6)
			'mov     dword [0x10003020], eax'
			>>> bv.is_skip_and_return_zero_patch_available(bv.arch, 0x100012f6)
			False
			>>> bv.get_disassembly(0x100012fb)
			'call    0x10001629'
			>>> bv.is_skip_and_return_zero_patch_available(bv.arch, 0x100012fb)
			True
			>>>
		"""
		return core.BNIsSkipAndReturnZeroPatchAvailable(self.handle, arch.handle, addr)

	def is_skip_and_return_value_patch_available(self, arch, addr):
		"""
		``is_skip_and_return_value_patch_available`` queries the architecture plugin to determine if the
		instruction at ``addr`` is similar to an x86 "call" instruction which can be made to return a value. The actual
		logic of which is implemented in the ``perform_is_skip_and_return_value_patch_available`` in the corresponding
		architecture.

		:param Architecture arch: the architecture for the current view
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012f6)
			'mov     dword [0x10003020], eax'
			>>> bv.is_skip_and_return_value_patch_available(bv.arch, 0x100012f6)
			False
			>>> bv.get_disassembly(0x100012fb)
			'call    0x10001629'
			>>> bv.is_skip_and_return_value_patch_available(bv.arch, 0x100012fb)
			True
			>>>
		"""
		return core.BNIsSkipAndReturnValuePatchAvailable(self.handle, arch.handle, addr)

	def convert_to_nop(self, arch, addr):
		"""
		``convert_to_nop`` converts the instruction at virtual address ``addr`` to a nop of the provided architecture.

		.. note:: This API performs a binary patch, analysis may need to be updated afterward. Additionally the binary\
		file must be saved in order to preserve the changes made.

		:param Architecture arch: architecture of the current BinaryView
		:param int addr: virtual address of the instruction to conver to nops
		:return: True on success, False on falure.
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012fb)
			'call    0x10001629'
			>>> bv.convert_to_nop(bv.arch, 0x100012fb)
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
		return core.BNConvertToNop(self.handle, arch.handle, addr)

	def always_branch(self, arch, addr):
		"""
		``always_branch`` convert the instruction of architecture ``arch`` at the virtual address ``addr`` to an
		unconditional branch.

		.. note:: This API performs a binary patch, analysis may need to be updated afterward. Additionally the binary\
		file must be saved in order to preserve the changes made.

		:param Architecture arch: architecture of the current binary view
		:param int addr: virtual address of the instruction to be modified
		:return: True on success, False on falure.
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x100012ef)
			'jg      0x100012f5'
			>>> bv.always_branch(bv.arch, 0x100012ef)
			True
			>>> bv.get_disassembly(0x100012ef)
			'jmp     0x100012f5'
			>>>
		"""
		return core.BNAlwaysBranch(self.handle, arch.handle, addr)

	def never_branch(self, arch, addr):
		"""
		``never_branch`` convert the branch instruction of architecture ``arch`` at the virtual address ``addr`` to
		a fall through.

		.. note:: This API performs a binary patch, analysis may need to be updated afterward. Additionally the binary\
		file must be saved in order to preserve the changes made.

		:param Architecture arch: architecture of the current binary view
		:param int addr: virtual address of the instruction to be modified
		:return: True on success, False on falure.
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x1000130e)
			'jne     0x10001317'
			>>> bv.never_branch(bv.arch, 0x1000130e)
			True
			>>> bv.get_disassembly(0x1000130e)
			'nop'
			>>>
		"""
		return core.BNConvertToNop(self.handle, arch.handle, addr)

	def invert_branch(self, arch, addr):
		"""
		``invert_branch`` convert the branch instruction of architecture ``arch`` at the virtual address ``addr`` to the
		inverse branch.

		.. note:: This API performs a binary patch, analysis may need to be updated afterward. Additionally the binary
		file must be saved in order to preserve the changes made.

		:param Architecture arch: architecture of the current binary view
		:param int addr: virtual address of the instruction to be modified
		:return: True on success, False on falure.
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x1000130e)
			'je      0x10001317'
			>>> bv.invert_branch(bv.arch, 0x1000130e)
			True
			>>>
			>>> bv.get_disassembly(0x1000130e)
			'jne     0x10001317'
			>>>
		"""
		return core.BNInvertBranch(self.handle, arch.handle, addr)

	def skip_and_return_value(self, arch, addr, value):
		"""
		``skip_and_return_value`` convert the ``call`` instruction of architecture ``arch`` at the virtual address
		``addr`` to the equivilent of returning a value.

		:param Architecture arch: architecture of the current binary view
		:param int addr: virtual address of the instruction to be modified
		:param int value: value to make the instruction *return*
		:return: True on success, False on falure.
		:rtype: bool
		:Example:

			>>> bv.get_disassembly(0x1000132a)
			'call    0x1000134a'
			>>> bv.skip_and_return_value(bv.arch, 0x1000132a, 42)
			True
			>>> #The return value from x86 functions is stored in eax thus:
			>>> bv.get_disassembly(0x1000132a)
			'mov     eax, 0x2a'
			>>>
		"""
		return core.BNSkipAndReturnValue(self.handle, arch.handle, addr, value)

	def get_instruction_length(self, arch, addr):
		"""
		``get_instruction_length`` returns the number of bytes in the instruction of Architecture ``arch`` at the virtual
		address ``addr``

		:param Architecture arch: architecture of the current binary view
		:param int addr: virtual address of the instruction query
		:return: Number of bytes in instruction
		:rtype: int
		:Example:

			>>> bv.get_disassembly(0x100012f1)
			'xor     eax, eax'
			>>> bv.get_instruction_length(bv.arch, 0x100012f1)
			2L
			>>>
		"""
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
		:rtype: list(str())
		:Example:

			>>> bv.get_strings(0x1000004d, 1)
			[<AsciiString: 0x1000004d, len 0x2c>]
			>>>
		"""
		count = ctypes.c_ulonglong(0)
		if start is None:
			strings = core.BNGetStrings(self.handle, count)
		else:
			strings = core.BNGetStringsInRange(self.handle, start, length, count)
		result = []
		for i in xrange(0, count.value):
			result.append(StringReference(core.BNStringType_names[strings[i].type], strings[i].start, strings[i].length))
		core.BNFreeStringList(strings)
		return result

	def add_analysis_completion_event(self, callback):
		"""
		``add_analysis_completion_event`` sets up a call back function to be called when analysis has been completed.
		This is helpful when using asynchronously analysis.

		:param callable() callback: A function to be called with no parameters when analysis has completed.
		:return: An initialized AnalysisCompletionEvent object.
		:rtype: AnalysisCompletionEvent
		:Example:

			>>> def completionEvent():
			...   print "done"
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
		``get_next_data_var_after`` retrieves the next virtual address of the next :py:Class:`DataVariable`

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the next :py:Class:`DataVariable`
		:rtype: int
		:Example:

			>>> hex(bv.get_next_data_var_after(0x10000000))
			'0x1000003cL'
			>>> bv.get_data_var_at(0x1000003c)
			<var 0x1000003c: int32_t>
			>>>
		"""
		return core.BNGetNextDataVariableAfterAddress(self.handle, addr)

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
		``get_previous_data_var_before``

		:param int addr: the virtual address to start looking from.
		:return: the virtual address of the previous :py:Class:`DataVariable`
		:rtype: int
		:Example:

			>>> hex(bv.get_previous_data_var_before(0x1000003c))
			'0x10000000L'
			>>> bv.get_data_var_at(0x10000000)
			<var 0x10000000: int16_t>
			>>>
		"""
		return core.BNGetPreviousDataVariableBeforeAddress(self.handle, addr)

	def get_linear_disassembly_position_at(self, addr, settings):
		"""
		``get_linear_disassembly_position_at`` instantiates a :py:class:`LinearDisassemblyPosition` object for use in
		:py:method:`get_previous_linear_disassembly_lines` or :py:method:`get_next_linear_disassembly_lines`.

		:param int addr: virtual address of linear disassembly position
		:param DisassemblySettings settings: an instantiated :py:class:`DisassemblySettings` object
		:return: An instantied :py:class:`LinearDisassemblyPosition` object for the provided virtual address
		:rtype: LinearDisassemblyPosition
		:Example:

			>>> settings = DisassemblySettings()
			>>> pos = bv.get_linear_disassembly_position_at(0x1000149f, settings)
			>>> lines = bv.get_previous_linear_disassembly_lines(pos, settings)
			>>> lines
			[<0x1000149a: pop     esi>, <0x1000149b: pop     ebp>,
			<0x1000149c: retn    0xc>, <0x1000149f: >]
		"""
		if settings is not None:
			settings = settings.handle
		pos = core.BNGetLinearDisassemblyPositionForAddress(self.handle, addr, settings)
		func = None
		block = None
		if pos.function:
			func = Function(self, pos.function)
		if pos.block:
			block = BasicBlock(self, pos.block)
		return LinearDisassemblyPosition(func, block, pos.address)

	def _get_linear_disassembly_lines(self, api, pos, settings):
		pos_obj = core.BNLinearDisassemblyPosition()
		pos_obj.function = None
		pos_obj.block = None
		pos_obj.address = pos.address
		if pos.function is not None:
			pos_obj.function = core.BNNewFunctionReference(pos.function.handle)
		if pos.block is not None:
			pos_obj.block = core.BNNewBasicBlockReference(pos.block.handle)

		if settings is not None:
			settings = settings.handle

		count = ctypes.c_ulonglong(0)
		lines = api(self.handle, pos_obj, settings, count)

		result = []
		for i in xrange(0, count.value):
			func = None
			block = None
			if lines[i].function:
				func = Function(self, core.BNNewFunctionReference(lines[i].function))
			if lines[i].block:
				block = BasicBlock(self, core.BNNewBasicBlockReference(lines[i].block))
			addr = lines[i].contents.addr
			tokens = []
			for j in xrange(0, lines[i].contents.count):
				token_type = core.BNInstructionTextTokenType_names[lines[i].contents.tokens[j].type]
				text = lines[i].contents.tokens[j].text
				value = lines[i].contents.tokens[j].value
				size = lines[i].contents.tokens[j].size
				operand = lines[i].contents.tokens[j].operand
				tokens.append(InstructionTextToken(token_type, text, value, size, operand))
			contents = DisassemblyTextLine(addr, tokens)
			result.append(LinearDisassemblyLine(lines[i].type, func, block, lines[i].lineOffset, contents))

		func = None
		block = None
		if pos_obj.function:
			func = Function(self, pos_obj.function)
		if pos_obj.block:
			block = BasicBlock(self, pos_obj.block)
		pos.function = func
		pos.block = block
		pos.address = pos_obj.address

		core.BNFreeLinearDisassemblyLines(lines, count.value)
		return result

	def get_previous_linear_disassembly_lines(self, pos, settings):
		"""
		``get_previous_linear_disassembly_lines`` retrieves a list of :py:class:`LinearDisassemblyLine` objects for the
		previous disassembly lines, and updates the LinearDisassemblyPosition passed in. This function can be called
		repeatedly to get more lines of linear disassembly.

		:param LinearDisassemblyPosition pos: Position to start retrieving linear disassembly lines from
		:param DisassemblySettings settings: DisassemblySettings display settings for the linear disassembly
		:return: a list of :py:class:`LinearDisassemblyLine` objects for the previous lines.
		:Example:

			>>> settings = DisassemblySettings()
			>>> pos = bv.get_linear_disassembly_position_at(0x1000149a, settings)
			>>> bv.get_previous_linear_disassembly_lines(pos, settings)
			[<0x10001488: push    dword [ebp+0x10 {arg_c}]>, ... , <0x1000149a: >]
			>>> bv.get_previous_linear_disassembly_lines(pos, settings)
			[<0x10001483: xor     eax, eax  {0x0}>, ... , <0x10001488: >]
		"""
		return self._get_linear_disassembly_lines(core.BNGetPreviousLinearDisassemblyLines, pos, settings)

	def get_next_linear_disassembly_lines(self, pos, settings):
		"""
		``get_next_linear_disassembly_lines`` retrieves a list of :py:class:`LinearDisassemblyLine` objects for the
		next disassembly lines, and updates the LinearDisassemblyPosition passed in. This function can be called
		repeatedly to get more lines of linear disassembly.

		:param LinearDisassemblyPosition pos: Position to start retrieving linear disassembly lines from
		:param DisassemblySettings settings: DisassemblySettings display settings for the linear disassembly
		:return: a list of :py:class:`LinearDisassemblyLine` objects for the next lines.
		:Example:

			>>> settings = DisassemblySettings()
			>>> pos = bv.get_linear_disassembly_position_at(0x10001483, settings)
			>>> bv.get_next_linear_disassembly_lines(pos, settings)
			[<0x10001483: xor     eax, eax  {0x0}>, <0x10001485: inc     eax  {0x1}>, ... , <0x10001488: >]
			>>> bv.get_next_linear_disassembly_lines(pos, settings)
			[<0x10001488: push    dword [ebp+0x10 {arg_c}]>, ... , <0x1000149a: >]
			>>>
		"""
		return self._get_linear_disassembly_lines(core.BNGetNextLinearDisassemblyLines, pos, settings)

	def get_linear_disassembly(self, settings):
		"""
		``get_linear_disassembly`` gets an iterator for all lines in the linear disassembly of the view for the given
		disassembly settings.

		.. note:: linear_disassembly doesn't just return disassembly it will return a single line from the linear view,\
		 and thus will contain both data views, and disassembly.

		:param DisassemblySettings settings: instance specifying the desired output formatting.
		:return: An iterator containing formatted dissassembly lines.
		:rtype: LinearDisassemblyIterator
		:Example:

			>>> settings = DisassemblySettings()
			>>> lines = bv.get_linear_disassembly(settings)
			>>> for line in lines:
			...  print line
			...  break
			...
			cf fa ed fe 07 00 00 01  ........
		"""
		class LinearDisassemblyIterator(object):
			def __init__(self, view, settings):
				self.view = view
				self.settings = settings

			def __iter__(self):
				pos = self.view.get_linear_disassembly_position_at(self.view.start, self.settings)
				while True:
					lines = self.view.get_next_linear_disassembly_lines(pos, self.settings)
					if len(lines) == 0:
						break
					for line in lines:
						yield line

		return iter(LinearDisassemblyIterator(self, settings))

	def parse_type_string(self, text):
		"""
		``parse_type_string`` converts `C-style` string into a :py:Class:`Type`.

		:param str text: `C-style` string of type to create
		:return: A tuple of a :py:Class:`Type` and string type name
		:rtype: tuple(Type, str)
		:Example:

			>>> bv.parse_type_string("int foo")
			(<type: int32_t>, 'foo')
			>>>
		"""
		result = core.BNNameAndType()
		errors = ctypes.c_char_p()
		if not core.BNParseTypeString(self.handle, text, result, errors):
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise SyntaxError, error_str
		type_obj = Type(core.BNNewTypeReference(result.type))
		name = result.name
		core.BNFreeNameAndType(result)
		return type_obj, name

	def get_type_by_name(self, name):
		"""
		``get_type_by_name`` returns the defined type whose name corresponds with the provided ``name``

		:param str name: Type name to lookup
		:return: A :py:Class:`Type` or None if the type does not exist
		:rtype: Type or None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_type(name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
			>>>
		"""
		obj = core.BNGetAnalysisTypeByName(self.handle, name)
		if not obj:
			return None
		return Type(obj)

	def is_type_auto_defined(self, name):
		"""
		``is_type_auto_defined`` queries the user type list of name. If name is not in the *user* type list then the name
		is considered an *auto* type.

		:param str name: Name of type to query
		:return: True if the type is not a *user* type. False if the type is a *user* type.
		:Example:
			>>> bv.is_type_auto_defined("foo")
			True
			>>> bv.define_user_type("foo", bv.parse_type_string("struct {int x,y;}")[0])
			>>> bv.is_type_auto_defined("foo")
			False
			>>>
		"""
		return core.BNIsAnalysisTypeAutoDefined(self.handle, name)

	def define_type(self, name, type_obj):
		"""
		``define_type`` registers a :py:Class:`Type` ``type_obj`` of the given ``name`` in the global list of types for
		the current :py:Class:`BinaryView`.

		:param str name: Name of the type to be registered
		:param Type type_obj: Type object to be registered
		:rtype: None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_type(name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
		"""
		core.BNDefineAnalysisType(self.handle, name, type_obj.handle)

	def define_user_type(self, name, type_obj):
		"""
		``define_user_type`` registers a :py:Class:`Type` ``type_obj`` of the given ``name`` in the global list of user
		types for the current :py:Class:`BinaryView`.

		:param str name: Name of the user type to be registered
		:param Type type_obj: Type object to be registered
		:rtype: None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_user_type(name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
		"""
		core.BNDefineUserAnalysisType(self.handle, name, type_obj.handle)

	def undefine_type(self, name):
		"""
		``undefine_type`` removes a :py:Class:`Type` from the global list of types for the current :py:Class:`BinaryView`

		:param str name: Name of type to be undefined
		:rtype: None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_type(name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
			>>> bv.undefine_type(name)
			>>> bv.get_type_by_name(name)
			>>>
		"""
		core.BNUndefineAnalysisType(self.handle, name)

	def undefine_user_type(self, name):
		"""
		``undefine_user_type`` removes a :py:Class:`Type` from the global list of user types for the current
		:py:Class:`BinaryView`

		:param str name: Name of user type to be undefined
		:rtype: None
		:Example:

			>>> type, name = bv.parse_type_string("int foo")
			>>> bv.define_type(name, type)
			>>> bv.get_type_by_name(name)
			<type: int32_t>
			>>> bv.undefine_type(name)
			>>> bv.get_type_by_name(name)
			>>>
		"""
		core.BNUndefineUserAnalysisType(self.handle, name)

	def find_next_data(self, start, data, flags = 0):
		"""
		``find_next_data`` searchs for the bytes in data starting at the virtual address ``start`` either, case-sensitive,
		or case-insensitive.

		:param int start: virtual address to start searching from.
		:param str data: bytes to search for
		:param FindFlags flags: case-sensitivity flag, one of the following:

			==================== ======================
			FindFlags            Description
			==================== ======================
			NoFindFlags          Case-sensitive find
			FindCaseInsensitive  Case-insensitive find
			==================== ======================
		"""
		buf = DataBuffer(str(data))
		result = ctypes.c_ulonglong()
		if not core.BNFindNextData(self.handle, start, buf.handle, result, flags):
			return None
		return result.value

	def reanalyze(self):
		"""
		``reanalyze`` causes all functions to be reanalyzed. This function does not wait for the analysis to finish.

		:rtype: None
		"""
		core.BNReanalyzeAllFunctions(self.handle)

	def show_plain_text_report(self, title, contents):
		core.BNShowPlainTextReport(self.handle, title, contents)

	def show_markdown_report(self, title, contents, plaintext = ""):
		core.BNShowMarkdownReport(self.handle, title, contents, plaintext)

	def show_html_report(self, title, contents, plaintext = ""):
		core.BNShowHTMLReport(self.handle, title, contents, plaintext)

	def get_address_input(self, prompt, title, current_address = None):
		if current_address is None:
			current_address = self.file.offset
		value = ctypes.c_ulonglong()
		if not core.BNGetAddressInput(value, prompt, title, self.handle, current_address):
			return None
		return value.value

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

class BinaryReader(object):
	"""
	``class BinaryReader`` is a convenience class for reading binary data.

	BinaryReader can be instantiated as follows and the rest of the document will start from this context ::

		>>> from binaryninja import *
		>>> bv = BinaryViewType['Mach-O'].open("/bin/ls")
		>>> br = BinaryReader(bv)
		>>> hex(br.read32())
		'0xfeedfacfL'
		>>>

	Or using the optional endian parameter ::

		>>> from binaryninja import *
		>>> br = BinaryReader(bv, core.BigEndian)
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
		``read8`` returns a one byte integer from offet incrementing the offset.

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
		``read16`` returns a two byte integer from offet incrementing the offset by two, using specified endianness.

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
		``read32`` returns a four byte integer from offet incrementing the offset by four, using specified endianness.

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
		``read64`` returns an eight byte integer from offet incrementing the offset by eight, using specified endianness.

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
		``read16le`` returns a two byte little endian integer from offet incrementing the offset by two.

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
		``read32le`` returns a four byte little endian integer from offet incrementing the offset by four.

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
		``read64le`` returns an eight byte little endian integer from offet incrementing the offset by eight.

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
		``read16be`` returns a two byte big endian integer from offet incrementing the offset by two.

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
		``read32be`` returns a four byte big endian integer from offet incrementing the offset by four.

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
		``read64be`` returns an eight byte big endian integer from offet incrementing the offset by eight.

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
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

class BinaryWriter(object):
	"""
	``class BinaryWriter`` is a convenience class for writing binary data.

	BinaryWriter can be instantiated as follows and the rest of the document will start from this context ::

		>>> from binaryninja import *
		>>> bv = BinaryViewType['Mach-O'].open("/bin/ls")
		>>> br = BinaryReader(bv)
		>>> bw = BinaryWriter(bv)
		>>>

	Or using the optional endian parameter ::

		>>> from binaryninja import *
		>>> br = BinaryReader(bv, core.BigEndian)
		>>> bw = BinaryWriter(bv, core.BigEndian)
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
		value = str(value)
		buf = ctypes.create_string_buffer(len(value))
		ctypes.memmove(buf, value, len(value))
		return core.BNWriteData(self.handle, buf, len(value))

	def write8(self, value):
		"""
		``write8`` lowest order byte from the integer ``value`` to the current offset.

		:param str value: bytes to be written at current offset
		:return: boolean
		:rtype: int
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
		```` writes the lowest order two bytes from the integer ``value`` to the current offset, using internal endianness.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		return core.BNWrite16(self.handle, value)

	def write32(self, value):
		"""
		```` writes the lowest order four bytes from the integer ``value`` to the current offset, using internal endianness.

		:param int value: integer value to write.
		:return: boolean True on success, False on failure.
		:rtype: bool
		"""
		return core.BNWrite32(self.handle, value)

	def write64(self, value):
		"""
		```` writes the lowest order eight bytes from the integer ``value`` to the current offset, using internal endianness.

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
			>>> hex(br.offset)
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
			>>> hex(br.offset)
			'0x100000000L'
			>>>
		"""
		core.BNSeekBinaryWriterRelative(self.handle, offset)

class Symbol(object):
	"""
	Symbols are defined as one of the following types:

		=========================== ==============================================================
		SymbolType                  Description
		=========================== ==============================================================
		FunctionSymbol              Symbol for Function that exists in the current binary
		ImportAddressSymbol         Symbol defined in the Import Address Table
		ImportedFunctionSymbol      Symbol for Function that is not defined in the current binary
		DataSymbol                  Symbol for Data in the current binary
		ImportedDataSymbol          Symbol for Data that is not defined in the current binary
		=========================== ==============================================================
	"""
	def __init__(self, sym_type, addr, short_name, full_name = None, raw_name = None, handle = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNSymbol)
		else:
			if isinstance(sym_type, str):
				sym_type = core.BNSymbolType_by_name[sym_type]
			if full_name is None:
				full_name = short_name
			if raw_name is None:
				raw_name = full_name
			self.handle = core.BNCreateSymbol(sym_type, short_name, full_name, raw_name, addr)

	def __del__(self):
		core.BNFreeSymbol(self.handle)

	@property
	def type(self):
		"""Symbol type (read-only)"""
		return core.BNSymbolType_names[core.BNGetSymbolType(self.handle)]

	@property
	def name(self):
		"""Symbol name (read-only)"""
		return core.BNGetSymbolRawName(self.handle)

	@property
	def short_name(self):
		"""Symbol short name (read-only)"""
		return core.BNGetSymbolShortName(self.handle)

	@property
	def full_name(self):
		"""Symbol full name (read-only)"""
		return core.BNGetSymbolFullName(self.handle)

	@property
	def raw_name(self):
		"""Symbol raw name (read-only)"""
		return core.BNGetSymbolRawName(self.handle)

	@property
	def address(self):
		"""Symbol address (read-only)"""
		return core.BNGetSymbolAddress(self.handle)

	@property
	def auto(self):
		return core.BNIsSymbolAutoDefined(self.handle)

	@auto.setter
	def auto(self, value):
		core.BNSetSymbolAutoDefined(self.handle, value)

	def __repr__(self):
		return "<%s: \"%s\" @ %#x>" % (self.type, self.full_name, self.address)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

class Type(object):
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		core.BNFreeType(self.handle)

	@property
	def type_class(self):
		"""Type class (read-only)"""
		return core.BNTypeClass_names[core.BNGetTypeClass(self.handle)]

	@property
	def width(self):
		"""Type width (read-only)"""
		return core.BNGetTypeWidth(self.handle)

	@property
	def alignment(self):
		"""Type alignment (read-only)"""
		return core.BNGetTypeAlignment(self.handle)

	@property
	def signed(self):
		"""Wether type is signed (read-only)"""
		return core.BNIsTypeSigned(self.handle)

	@property
	def const(self):
		"""Whether type is const (read-only)"""
		return core.BNIsTypeConst(self.handle)

	@property
	def modified(self):
		"""Whether type is modified (read-only)"""
		return core.BNIsTypeFloatingPoint(self.handle)

	@property
	def target(self):
		"""Target (read-only)"""
		result = core.BNGetChildType(self.handle)
		if result is None:
			return None
		return Type(result)

	@property
	def element_type(self):
		"""Target (read-only)"""
		result = core.BNGetChildType(self.handle)
		if result is None:
			return None
		return Type(result)

	@property
	def return_value(self):
		"""Return value (read-only)"""
		result = core.BNGetChildType(self.handle)
		if result is None:
			return None
		return Type(result)

	@property
	def calling_convention(self):
		"""Calling convention (read-only)"""
		result = core.BNGetTypeCallingConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@property
	def parameters(self):
		"""Type parameters list (read-only)"""
		count = ctypes.c_ulonglong()
		params = core.BNGetTypeParameters(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append((Type(core.BNNewTypeReference(params[i].type)), params[i].name))
		core.BNFreeTypeParameterList(params, count.value)
		return result

	@property
	def has_variable_arguments(self):
		"""Whether type has variable arguments (read-only)"""
		return core.BNTypeHasVariableArguments(self.handle)

	@property
	def can_return(self):
		"""Whether type can return (read-only)"""
		return core.BNFunctionTypeCanReturn(self.handle)

	@property
	def structure(self):
		"""Structure of the type (read-only)"""
		result = core.BNGetTypeStructure(self.handle)
		if result is None:
			return None
		return Structure(result)

	@property
	def enumeration(self):
		"""Type enumeration (read-only)"""
		result = core.BNGetTypeEnumeration(self.handle)
		if result is None:
			return None
		return Enumeration(result)

	@property
	def count(self):
		"""Type count (read-only)"""
		return core.BNGetTypeElementCount(self.handle)

	def __str__(self):
		return core.BNGetTypeString(self.handle)

	def __repr__(self):
		return "<type: %s>" % str(self)

	def get_string_before_name(self):
		return core.BNGetTypeStringBeforeName(self.handle)

	def get_string_after_name(self):
		return core.BNGetTypeStringAfterName(self.handle)

	@classmethod
	def void(cls):
		return Type(core.BNCreateVoidType())

	@classmethod
	def bool(self):
		return Type(core.BNCreateBoolType())

	@classmethod
	def int(self, width, sign = True):
		return Type(core.BNCreateIntegerType(width, sign))

	@classmethod
	def float(self, width):
		return Type(core.BNCreateFloatType(width))

	@classmethod
	def structure_type(self, structure_type):
		return Type(core.BNCreateStructureType(structure_type.handle))

	@classmethod
	def unknown_type(self, unknown_type):
		return Type(core.BNCreateUnknownType(unknown_type.handle))

	@classmethod
	def enumeration_type(self, arch, e, width = None):
		if width is None:
			width = arch.default_int_size
		return Type(core.BNCreateEnumerationType(e.handle, width))

	@classmethod
	def pointer(self, arch, t, const = False):
		return Type(core.BNCreatePointerType(arch.handle, t.handle, const))

	@classmethod
	def array(self, t, count):
		return Type(core.BNCreateArrayType(t.handle, count))

	@classmethod
	def function(self, ret, params, calling_convention = None, variable_arguments = False):
		param_buf = (core.BNNameAndType * len(params))()
		for i in xrange(0, len(params)):
			if isinstance(params[i], Type):
				param_buf[i].name = ""
				param_buf[i].type = params[i].handle
			else:
				param_buf[i].name = params[i][1]
				param_buf[i].type = params[i][0]
		if calling_convention is not None:
			calling_convention = calling_convention.handle
		return Type(core.BNCreateFunctionType(ret.handle, calling_convention, param_buf, len(params),
			  variable_arguments))

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name


class UnknownType(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = core.BNCreateUnknownType()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeUnknownType(self.handle)

	@property
	def name(self):
		count = ctypes.c_ulonglong()
		nameList = core.BNGetUnknownTypeName(self.handle, count)
		result = []
		for i in xrange(count.value):
			result.append(nameList[i])
		return get_qualified_name(result)

	@name.setter
	def name(self, value):
		core.BNSetUnknownTypeName(self.handle, value)


class StructureMember(object):
	def __init__(self, t, name, offset):
		self.type = t
		self.name = name
		self.offset = offset

	def __repr__(self):
		if len(name) == 0:
			return "<member: %s, offset %#x>" % (str(self.type), self.offset)
		return "<%s %s%s, offset %#x>" % (self.type.get_string_before_name(), self.name,
							 self.type.get_string_after_name(), self.offset)

class Structure(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = core.BNCreateStructure()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeStructure(self.handle)

	@property
	def name(self):
		count = ctypes.c_ulonglong()
		nameList = core.BNGetStructureName(self.handle, count)
		result = []
		for i in xrange(count.value):
			result.append(nameList[i])
		return get_qualified_name(result)

	@name.setter
	def name(self, value):
		core.BNSetStructureName(self.handle, value)

	@property
	def members(self):
		"""Structure member list (read-only)"""
		count = ctypes.c_ulonglong()
		members = core.BNGetStructureMembers(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(StructureMember(Type(core.BNNewTypeReference(members[i].type)),
				members[i].name, members[i].offset))
		core.BNFreeStructureMemberList(members, count.value)
		return result

	@property
	def width(self):
		"""Structure width (read-only)"""
		return core.BNGetStructureWidth(self.handle)

	@property
	def alignment(self):
		"""Structure alignment (read-only)"""
		return core.BNGetStructureAlignment(self.handle)

	@property
	def packed(self):
		return core.BNIsStructurePacked(self.handle)

	@packed.setter
	def packed(self, value):
		core.BNSetStructurePacked(self.handle, value)

	@property
	def union(self):
		return core.BNIsStructureUnion(self.handle)

	@union.setter
	def union(self, value):
		core.BNSetStructureUnion(self.handle, value)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __repr__(self):
		if len(self.name) > 0:
			return "<struct: %s>" % self.name
		return "<struct: size %#x>" % self.width

	def append(self, t, name = ""):
		core.BNAddStructureMember(self.handle, t.handle, name)

	def insert(self, offset, t, name = ""):
		core.BNAddStructureMemberAtOffset(self.handle, t.handle, name, offset)

	def remove(self, i):
		core.BNRemoveStructureMember(self.handle, i)

class EnumerationMember(object):
	def __init__(self, name, value, default):
		self.name = name
		self.value = value
		self.default = default

	def __repr__(self):
		return "<%s = %#x>" % (self.name, self.value)

class Enumeration(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = core.BNCreateEnumeration()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeEnumeration(self.handle)

	@property
	def name(self):
		return core.BNGetEnumerationName(self.handle)

	@name.setter
	def name(self, value):
		core.BNSetEnumerationName(self.handle, value)

	@property
	def members(self):
		"""Enumeration member list (read-only)"""
		count = ctypes.c_ulonglong()
		members = core.BNGetEnumerationMembers(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(EnumerationMember(members[i].name, members[i].value, members[i].isDefault))
		core.BNFreeEnumerationMemberList(members, count.value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __repr__(self):
		if len(self.name) > 0:
			return "<enum: %s>" % self.name
		return "<enum: %s>" % repr(self.members)

	def append(self, name, value = None):
		if value is None:
			core.BNAddEnumerationMember(self.handle, name)
		else:
			core.BNAddEnumerationMemberWithValue(self.handle, name, value)

class LookupTableEntry(object):
	def __init__(self, from_values, to_value):
		self.from_values = from_values
		self.to_value = to_value

	def __repr__(self):
		return "[%s] -> %#x" % (', '.join(["%#x" % i for i in self.from_values]), self.to_value)

class RegisterValue(object):
	def __init__(self, arch, value):
		self.type = value.state
		if value.state == core.EntryValue:
			self.reg = arch.get_reg_name(value.reg)
		elif value.state == core.OffsetFromEntryValue:
			self.reg = arch.get_reg_name(value.reg)
			self.offset = value.value
		elif value.state == core.ConstantValue:
			self.value = value.value
		elif value.state == core.StackFrameOffset:
			self.offset = value.value
		elif value.state == core.SignedRangeValue:
			self.offset = value.value
			self.start = value.rangeStart
			self.end = value.rangeEnd
			self.step = value.rangeStep
			if self.start & (1 << 63):
				self.start |= ~((1 << 63) - 1)
			if self.end & (1 << 63):
				self.end |= ~((1 << 63) - 1)
		elif value.state == core.UnsignedRangeValue:
			self.offset = value.value
			self.start = value.rangeStart
			self.end = value.rangeEnd
			self.step = value.rangeStep
		elif value.state == core.LookupTableValue:
			self.table = []
			self.mapping = {}
			for i in xrange(0, value.rangeEnd):
				from_list = []
				for j in xrange(0, value.table[i].fromCount):
					from_list.append(value.table[i].fromValues[j])
					self.mapping[value.table[i].fromValues[j]] = value.table[i].toValue
				self.table.append(LookupTableEntry(from_list, value.table[i].toValue))
		elif value.state == core.OffsetFromUndeterminedValue:
			self.offset = value.value

	def __repr__(self):
		if self.type == core.EntryValue:
			return "<entry %s>" % self.reg
		if self.type == core.OffsetFromEntryValue:
			return "<entry %s + %#x>" % (self.reg, self.offset)
		if self.type == core.ConstantValue:
			return "<const %#x>" % self.value
		if self.type == core.StackFrameOffset:
			return "<stack frame offset %#x>" % self.offset
		if (self.type == core.SignedRangeValue) or (self.type == core.UnsignedRangeValue):
			if self.step == 1:
				return "<range: %#x to %#x>" % (self.start, self.end)
			return "<range: %#x to %#x, step %#x>" % (self.start, self.end, self.step)
		if self.type == core.LookupTableValue:
			return "<table: %s>" % ', '.join([repr(i) for i in self.table])
		if self.type == core.OffsetFromUndeterminedValue:
			return "<undetermined with offset %#x>" % self.offset
		return "<undetermined>"

class StackVariable(object):
	def __init__(self, ofs, name, t):
		self.offset = ofs
		self.name = name
		self.type = t

	def __repr__(self):
		return "<var@%x: %s %s>" % (self.offset, self.type, self.name)

	def __str__(self):
		return self.name

class StackVariableReference:
	def __init__(self, src_operand, t, name, start_ofs, ref_ofs):
		self.source_operand = src_operand
		self.type = t
		self.name = name
		self.starting_offset = start_ofs
		self.referenced_offset = ref_ofs
		if self.source_operand == 0xffffffff:
			self.source_operand = None

	def __repr__(self):
		if self.source_operand is None:
			if self.referenced_offset != self.starting_offset:
				return "<ref to %s%+#x>" % (self.name, self.referenced_offset - self.starting_offset)
			return "<ref to %s>" % self.name
		if self.referenced_offset != self.starting_offset:
			return "<operand %d ref to %s%+#x>" % (self.source_operand, self.name, self.referenced_offset)
		return "<operand %d ref to %s>" % (self.source_operand, self.name)

class ConstantReference:
	def __init__(self, val, size):
		self.value = val
		self.size = size

	def __repr__(self):
		if self.size == 0:
			return "<constant %#x>" % self.value
		return "<constant %#x size %d>" % (self.value, self.size)

class IndirectBranchInfo:
	def __init__(self, source_arch, source_addr, dest_arch, dest_addr, auto_defined):
		self.source_arch = source_arch
		self.source_addr = source_addr
		self.dest_arch = dest_arch
		self.dest_addr = dest_addr
		self.auto_defined = auto_defined

	def __repr__(self):
		return "<branch %s:%#x -> %s:%#x>" % (self.source_arch.name, self.source_addr, self.dest_arch.name, self.dest_addr)

class HighlightColor(object):
	def __init__(self, color = None, mix_color = None, mix = None, red = None, green = None, blue = None, alpha = 255):
		if (red is not None) and (green is not None) and (blue is not None):
			self.style = core.CustomHighlightColor
			self.red = red
			self.green = green
			self.blue = blue
		elif (mix_color is not None) and (mix is not None):
			self.style = core.MixedHighlightColor
			if color is None:
				self.color = core.NoHighlightColor
			else:
				self.color = color
			self.mix_color = mix_color
			self.mix = mix
		else:
			self.style = core.StandardHighlightColor
			if color is None:
				self.color = core.NoHighlightColor
			else:
				self.color = color
		self.alpha = alpha

	def _standard_color_to_str(self, color):
		if color == core.NoHighlightColor:
			return "none"
		if color == core.BlueHighlightColor:
			return "blue"
		if color == core.GreenHighlightColor:
			return "green"
		if color == core.CyanHighlightColor:
			return "cyan"
		if color == core.RedHighlightColor:
			return "red"
		if color == core.MagentaHighlightColor:
			return "magenta"
		if color == core.YellowHighlightColor:
			return "yellow"
		if color == core.OrangeHighlightColor:
			return "orange"
		if color == core.WhiteHighlightColor:
			return "white"
		if color == core.BlackHighlightColor:
			return "black"
		return "%d" % color

	def __repr__(self):
		if self.style == core.StandardHighlightColor:
			if self.alpha == 255:
				return "<color: %s>" % self._standard_color_to_str(self.color)
			return "<color: %s, alpha %d>" % (self._standard_color_to_str(self.color), self.alpha)
		if self.style == core.MixedHighlightColor:
			if self.alpha == 255:
				return "<color: mix %s to %s factor %d>" % (self._standard_color_to_str(self.color),
					self._standard_color_to_str(self.mix_color), self.mix)
			return "<color: mix %s to %s factor %d, alpha %d>" % (self._standard_color_to_str(self.color),
				self._standard_color_to_str(self.mix_color), self.mix, self.alpha)
		if self.style == core.CustomHighlightColor:
			if self.alpha == 255:
				return "<color: #%.2x%.2x%.2x>" % (self.red, self.green, self.blue)
			return "<color: #%.2x%.2x%.2x, alpha %d>" % (self.red, self.green, self.blue, self.alpha)
		return "<color>"

	def _get_core_struct(self):
		result = core.BNHighlightColor()
		result.style = self.style
		result.color = core.NoHighlightColor
		result.mix_color = core.NoHighlightColor
		result.mix = 0
		result.r = 0
		result.g = 0
		result.b = 0
		result.alpha = self.alpha

		if self.style == core.StandardHighlightColor:
			result.color = self.color
		elif self.style == core.MixedHighlightColor:
			result.color = self.color
			result.mixColor = self.mix_color
			result.mix = self.mix
		elif self.style == core.CustomHighlightColor:
			result.r = self.red
			result.g = self.green
			result.b = self.blue

		return result

class Function(object):
	def __init__(self, view, handle):
		self._view = view
		self.handle = core.handle_of_type(handle, core.BNFunction)
		self._advanced_analysis_requests = 0

	def __del__(self):
		if self._advanced_analysis_requests > 0:
			core.BNReleaseAdvancedFunctionAnalysisDataMultiple(self.handle, self._advanced_analysis_requests)
		core.BNFreeFunction(self.handle)

	@property
	def name(self):
		"""Symbol name for the function"""
		return self.symbol.name

	@name.setter
	def name(self,value):
		if value is None:
			if self.symbol is not None:
				self.view.undefine_user_symbol(self.symbol)
		else:
			symbol = Symbol(core.FunctionSymbol,self.start,value)
			self.view.define_user_symbol(symbol)

	@property
	def view(self):
		"""Function view (read-only)"""
		return self._view

	@property
	def arch(self):
		"""Function architecture (read-only)"""
		arch = core.BNGetFunctionArchitecture(self.handle)
		if arch is None:
			return None
		return Architecture(arch)

	@property
	def start(self):
		"""Function start (read-only)"""
		return core.BNGetFunctionStart(self.handle)

	@property
	def symbol(self):
		"""Function symbol(read-only)"""
		sym = core.BNGetFunctionSymbol(self.handle)
		if sym is None:
			return None
		return Symbol(None, None, None, handle = sym)

	@property
	def auto(self):
		"""Whether function was automatically discovered (read-only)"""
		return core.BNWasFunctionAutomaticallyDiscovered(self.handle)

	@property
	def can_return(self):
		"""Whether function can return (read-only)"""
		return core.BNCanFunctionReturn(self.handle)

	@property
	def explicitly_defined_type(self):
		"""Whether function has explicitly defined types (read-only)"""
		return core.BNHasExplicitlyDefinedType(self.handle)

	@property
	def needs_update(self):
		"""Whether the function has analysis that needs to be updated (read-only)"""
		return core.BNIsFunctionUpdateNeeded(self.handle)

	@property
	def basic_blocks(self):
		"""List of basic blocks (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionBasicBlockList(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(BasicBlock(self._view, core.BNNewBasicBlockReference(blocks[i])))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def comments(self):
		"""Dict of comments (read-only)"""
		count = ctypes.c_ulonglong()
		addrs = core.BNGetCommentedAddresses(self.handle, count)
		result = {}
		for i in xrange(0, count.value):
			result[addrs[i]] = self.get_comment_at(addrs[i])
		core.BNFreeAddressList(addrs)
		return result

	@property
	def low_level_il(self):
		"""Function low level IL (read-only)"""
		return LowLevelILFunction(self.arch, core.BNGetFunctionLowLevelIL(self.handle), self)

	@property
	def lifted_il(self):
		"""Function lifted IL (read-only)"""
		return LowLevelILFunction(self.arch, core.BNGetFunctionLiftedIL(self.handle), self)

	@property
	def function_type(self):
		"""Function type"""
		return Type(core.BNGetFunctionType(self.handle))

	@function_type.setter
	def function_type(self, value):
		self.set_user_type(value)

	@property
	def stack_layout(self):
		"""List of function stack (read-only)"""
		count = ctypes.c_ulonglong()
		v = core.BNGetStackLayout(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(StackVariable(v[i].offset, v[i].name, Type(handle = core.BNNewTypeReference(v[i].type))))
		result.sort(key = lambda x: x.offset)
		core.BNFreeStackLayout(v, count.value)
		return result

	@property
	def indirect_branches(self):
		"""List of indirect branches (read-only)"""
		count = ctypes.c_ulonglong()
		branches = core.BNGetIndirectBranches(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(IndirectBranchInfo(Architecture(branches[i].sourceArch), branches[i].sourceAddr, Architecture(branches[i].destArch), branches[i].destAddr, branches[i].autoDefined))
		core.BNFreeIndirectBranchList(branches)
		return result

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionBasicBlockList(self.handle, count)
		try:
			for i in xrange(0, count.value):
				yield BasicBlock(self._view, core.BNNewBasicBlockReference(blocks[i]))
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<func: %s@%#x>" % (arch.name, self.start)
		else:
			return "<func: %#x>" % self.start

	def mark_recent_use(self):
		core.BNMarkFunctionAsRecentlyUsed(self.handle)

	def get_comment_at(self, addr):
		return core.BNGetCommentForAddress(self.handle, addr)

	def set_comment(self, addr, comment):
		core.BNSetCommentForAddress(self.handle, addr, comment)

	def get_low_level_il_at(self, arch, addr):
		return core.BNGetLowLevelILForInstruction(self.handle, arch.handle, addr)

	def get_low_level_il_exits_at(self, arch, addr):
		count = ctypes.c_ulonglong()
		exits = core.BNGetLowLevelILExitsForInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(exits[i])
		core.BNFreeLowLevelILInstructionList(exits)
		return result

	def get_reg_value_at(self, arch, addr, reg):
		if isinstance(reg, str):
			reg = arch.regs[reg].index
		value = core.BNGetRegisterValueAtInstruction(self.handle, arch.handle, addr, reg)
		result = RegisterValue(arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_reg_value_after(self, arch, addr, reg):
		if isinstance(reg, str):
			reg = arch.regs[reg].index
		value = core.BNGetRegisterValueAfterInstruction(self.handle, arch.handle, addr, reg)
		result = RegisterValue(arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_reg_value_at_low_level_il_instruction(self, i, reg):
		if isinstance(reg, str):
			reg = self.arch.regs[reg].index
		value = core.BNGetRegisterValueAtLowLevelILInstruction(self.handle, i, reg)
		result = RegisterValue(self.arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_reg_value_after_low_level_il_instruction(self, i, reg):
		if isinstance(reg, str):
			reg = self.arch.regs[reg].index
		value = core.BNGetRegisterValueAfterLowLevelILInstruction(self.handle, i, reg)
		result = RegisterValue(self.arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_stack_contents_at(self, arch, addr, offset, size):
		value = core.BNGetStackContentsAtInstruction(self.handle, arch.handle, addr, offset, size)
		result = RegisterValue(arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_stack_contents_after(self, arch, addr, offset, size):
		value = core.BNGetStackContentsAfterInstruction(self.handle, arch.handle, addr, offset, size)
		result = RegisterValue(arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_stack_contents_at_low_level_il_instruction(self, i, offset, size):
		value = core.BNGetStackContentsAtLowLevelILInstruction(self.handle, i, offset, size)
		result = RegisterValue(self.arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_stack_contents_after_low_level_il_instruction(self, i, offset, size):
		value = core.BNGetStackContentsAfterInstruction(self.handle, i, offset, size)
		result = RegisterValue(self.arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_parameter_at(self, arch, addr, func_type, i):
		if func_type is not None:
			func_type = func_type.handle
		value = core.BNGetParameterValueAtInstruction(self.handle, arch.handle, addr, func_type, i)
		result = RegisterValue(arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_parameter_at_low_level_il_instruction(self, instr, func_type, i):
		if func_type is not None:
			func_type = func_type.handle
		value = core.BNGetParameterValueAtLowLevelILInstruction(self.handle, instr, func_type, i)
		result = RegisterValue(self.arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_regs_read_by(self, arch, addr):
		count = ctypes.c_ulonglong()
		regs = core.BNGetRegistersReadByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_regs_written_by(self, arch, addr):
		count = ctypes.c_ulonglong()
		regs = core.BNGetRegistersWrittenByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_stack_vars_referenced_by(self, arch, addr):
		count = ctypes.c_ulonglong()
		refs = core.BNGetStackVariablesReferencedByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(StackVariableReference(refs[i].sourceOperand, Type(core.BNNewTypeReference(refs[i].type)),
				refs[i].name, refs[i].startingOffset, refs[i].referencedOffset))
		core.BNFreeStackVariableReferenceList(refs, count.value)
		return result

	def get_constants_referenced_by(self, arch, addr):
		count = ctypes.c_ulonglong()
		refs = core.BNGetConstantsReferencedByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(ConstantReference(refs[i].value, refs[i].size))
		core.BNFreeConstantReferenceList(refs)
		return result

	def get_lifted_il_at(self, arch, addr):
		return core.BNGetLiftedILForInstruction(self.handle, arch.handle, addr)

	def get_lifted_il_flag_uses_for_definition(self, i, flag):
		if isinstance(flag, str):
			flag = self.arch._flags[flag]
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILFlagUsesForDefinition(self.handle, i, flag, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeLowLevelILInstructionList(instrs)
		return result

	def get_lifted_il_flag_definitions_for_use(self, i, flag):
		if isinstance(flag, str):
			flag = self.arch._flags[flag]
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILFlagDefinitionsForUse(self.handle, i, flag, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeLowLevelILInstructionList(instrs)
		return result

	def get_flags_read_by_lifted_il_instruction(self, i):
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsReadByLiftedILInstruction(self.handle, i, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self.arch._flags_by_index[flags[i]])
		core.BNFreeRegisterList(flags)
		return result

	def get_flags_written_by_lifted_il_instruction(self, i):
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsWrittenByLiftedILInstruction(self.handle, i, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self.arch._flags_by_index[flags[i]])
		core.BNFreeRegisterList(flags)
		return result

	def create_graph(self):
		return FunctionGraph(self._view, core.BNCreateFunctionGraph(self.handle))

	def apply_imported_types(self, sym):
		core.BNApplyImportedTypes(self.handle, sym.handle)

	def apply_auto_discovered_type(self, func_type):
		core.BNApplyAutoDiscoveredFunctionType(self.handle, func_type.handle)

	def set_auto_indirect_branches(self, source_arch, source, branches):
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in xrange(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNSetAutoIndirectBranches(self.handle, source_arch.handle, source, branch_list, len(branches))

	def set_user_indirect_branches(self, source_arch, source, branches):
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in xrange(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNSetUserIndirectBranches(self.handle, source_arch.handle, source, branch_list, len(branches))

	def get_indirect_branches_at(self, arch, addr):
		count = ctypes.c_ulonglong()
		branches = core.BNGetIndirectBranchesAt(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(IndirectBranchInfo(Architecture(branches[i].sourceArch), branches[i].sourceAddr, Architecture(branches[i].destArch), branches[i].destAddr, branches[i].autoDefined))
		core.BNFreeIndirectBranchList(branches)
		return result

	def get_block_annotations(self, arch, addr):
		count = ctypes.c_ulonglong(0)
		lines = core.BNGetFunctionBlockAnnotations(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			tokens = []
			for j in xrange(0, lines[i].count):
				token_type = core.BNInstructionTextTokenType_names[lines[i].tokens[j].type]
				text = lines[i].tokens[j].text
				value = lines[i].tokens[j].value
				size = lines[i].tokens[j].size
				operand = lines[i].tokens[j].operand
				tokens.append(InstructionTextToken(token_type, text, value, size, operand))
			result.append(tokens)
		core.BNFreeInstructionTextLines(lines, count.value)
		return result

	def set_auto_type(self, value):
		core.BNSetFunctionAutoType(self.handle, value.handle)

	def set_user_type(self, value):
		core.BNSetFunctionUserType(self.handle, value.handle)

	def get_int_display_type(self, arch, instr_addr, value, operand):
		return core.BNGetIntegerConstantDisplayType(self.handle, arch.handle, instr_addr, value, operand)

	def set_int_display_type(self, arch, instr_addr, value, operand, display_type):
		if isinstance(display_type, str):
			display_type = core.BNIntegerDisplayType_by_name[display_type]
		core.BNSetIntegerConstantDisplayType(self.handle, arch.handle, instr_addr, value, operand, display_type)

	def reanalyze(self):
		"""
		``reanalyze`` causes this functions to be reanalyzed. This function does not wait for the analysis to finish.

		:rtype: None
		"""
		core.BNReanalyzeFunction(self.handle)

	def request_advanced_analysis_data(self):
		core.BNRequestAdvancedFunctionAnalysisData(self.handle)
		self._advanced_analysis_requests += 1

	def release_advanced_analysis_data(self):
		core.BNReleaseAdvancedFunctionAnalysisData(self.handle)
		self._advanced_analysis_requests -= 1

	def get_basic_block_at(self, arch, addr):
		block = core.BNGetFunctionBasicBlockAtAddress(self.handle, arch.handle, addr)
		if not block:
			return None
		return BasicBlock(self._view, handle = block)

	def get_instr_highlight(self, arch, addr):
		color = core.BNGetInstructionHighlight(self.handle, arch.handle, addr)
		if color.style == core.StandardHighlightColor:
			return HighlightColor(color = color.color, alpha = color.alpha)
		elif color.style == core.MixedHighlightColor:
			return HighlightColor(color = color.color, mix_color = color.mixColor, mix = color.mix, alpha = color.alpha)
		elif color.style == core.CustomHighlightColor:
			return HighlightColor(red = color.r, green = color.g, blue = color.b, alpha = color.alpha)
		return HighlightColor(color = core.NoHighlightColor)

	def set_auto_instr_highlight(self, arch, addr, color):
		if not isinstance(color, HighlightColor):
			color = HighlightColor(color = color)
		core.BNSetAutoInstructionHighlight(self.handle, arch.handle, addr, color._get_core_struct())

	def set_user_instr_highlight(self, arch, addr, color):
		if not isinstance(color, HighlightColor):
			color = HighlightColor(color = color)
		core.BNSetUserInstructionHighlight(self.handle, arch.handle, addr, color._get_core_struct())

class AdvancedFunctionAnalysisDataRequestor(object):
	def __init__(self, func = None):
		self._function = func
		if self._function is not None:
			self._function.request_advanced_analysis_data()

	def __del__(self):
		if self._function is not None:
			self._function.release_advanced_analysis_data()

	@property
	def function(self):
		return self._function

	@function.setter
	def function(self, func):
		if self._function is not None:
			self._function.release_advanced_analysis_data()
		self._function = func
		if self._function is not None:
			self._function.request_advanced_analysis_data()

	def close(self):
		if self._function is not None:
			self._function.release_advanced_analysis_data()
		self._function = None

class BasicBlockEdge(object):
	def __init__(self, branch_type, target, arch):
		self.type = core.BNBranchType_names[branch_type]
		if self.type != "UnresolvedBranch":
			self.target = target
			self.arch = arch

	def __repr__(self):
		if self.type == "UnresolvedBranch":
			return "<%s>" % self.type
		elif self.arch:
			return "<%s: %s@%#x>" % (self.type, self.arch.name, self.target)
		else:
			return "<%s: %#x>" % (self.type, self.target)

class BasicBlock(object):
	def __init__(self, view, handle):
		self.view = view
		self.handle = core.handle_of_type(handle, core.BNBasicBlock)

	def __del__(self):
		core.BNFreeBasicBlock(self.handle)

	@property
	def function(self):
		"""Basic block function (read-only)"""
		func = core.BNGetBasicBlockFunction(self.handle)
		if func is None:
			return None
		return Function(self.view, func)

	@property
	def arch(self):
		"""Basic block architecture (read-only)"""
		arch = core.BNGetBasicBlockArchitecture(self.handle)
		if arch is None:
			return None
		return Architecture(arch)

	@property
	def start(self):
		"""Basic block start (read-only)"""
		return core.BNGetBasicBlockStart(self.handle)

	@property
	def end(self):
		"""Basic block end (read-only)"""
		return core.BNGetBasicBlockEnd(self.handle)

	@property
	def length(self):
		"""Basic block length (read-only)"""
		return core.BNGetBasicBlockLength(self.handle)

	@property
	def outgoing_edges(self):
		"""List of basic block outgoing edges (read-only)"""
		count = ctypes.c_ulonglong(0)
		edges = core.BNGetBasicBlockOutgoingEdges(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			branch_type = edges[i].type
			target = edges[i].target
			if edges[i].arch:
				arch = Architecture(edges[i].arch)
			else:
				arch = None
			result.append(BasicBlockEdge(branch_type, target, arch))
		core.BNFreeBasicBlockOutgoingEdgeList(edges)
		return result

	@property
	def has_undetermined_outgoing_edges(self):
		"""Whether basic block has undetermined outgoing edges (read-only)"""
		return core.BNBasicBlockHasUndeterminedOutgoingEdges(self.handle)

	@property
	def annotations(self):
		"""List of automatic annotations for the start of this block (read-only)"""
		return self.function.get_block_annotations(self.arch, self.start)

	@property
	def disassembly_text(self):
		return self.get_disassembly_text()

	@property
	def highlight(self):
		"""Highlight color for basic block"""
		color = core.BNGetBasicBlockHighlight(self.handle)
		if color.style == core.StandardHighlightColor:
			return HighlightColor(color = color.color, alpha = color.alpha)
		elif color.style == core.MixedHighlightColor:
			return HighlightColor(color = color.color, mix_color = color.mixColor, mix = color.mix, alpha = color.alpha)
		elif color.style == core.CustomHighlightColor:
			return HighlightColor(red = color.r, green = color.g, blue = color.b, alpha = color.alpha)
		return HighlightColor(color = core.NoHighlightColor)

	@highlight.setter
	def highlight(self, value):
		self.set_user_highlight(value)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __len__(self):
		return int(core.BNGetBasicBlockLength(self.handle))

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<block: %s@%#x-%#x>" % (arch.name, self.start, self.end)
		else:
			return "<block: %#x-%#x>" % (self.start, self.end)

	def __iter__(self):
		start = self.start
		end = self.end

		idx = start
		while idx < end:
			data = self.view.read(idx, 16)
			inst_info = self.view.arch.get_instruction_info(data, idx)
			inst_text = self.view.arch.get_instruction_text(data, idx)

			yield inst_text
			idx += inst_info.length

	def mark_recent_use(self):
		core.BNMarkBasicBlockAsRecentlyUsed(self.handle)

	def get_disassembly_text(self, settings = None):
		settings_obj = None
		if settings:
			settings_obj = settings.handle

		count = ctypes.c_ulonglong()
		lines = core.BNGetBasicBlockDisassemblyText(self.handle, settings_obj, count)
		result = []
		for i in xrange(0, count.value):
			addr = lines[i].addr
			tokens = []
			for j in xrange(0, lines[i].count):
				token_type = core.BNInstructionTextTokenType_names[lines[i].tokens[j].type]
				text = lines[i].tokens[j].text
				value = lines[i].tokens[j].value
				size = lines[i].tokens[j].size
				operand = lines[i].tokens[j].operand
				tokens.append(InstructionTextToken(token_type, text, value, size, operand))
			result.append(DisassemblyTextLine(addr, tokens))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	def set_auto_highlight(self, color):
		if not isinstance(color, HighlightColor):
			color = HighlightColor(color = color)
		core.BNSetAutoBasicBlockHighlight(self.handle, color._get_core_struct())

	def set_user_highlight(self, color):
		if not isinstance(color, HighlightColor):
			color = HighlightColor(color = color)
		core.BNSetUserBasicBlockHighlight(self.handle, color._get_core_struct())

class LowLevelILBasicBlock(BasicBlock):
	def __init__(self, view, handle, owner):
		super(LowLevelILBasicBlock, self).__init__(view, handle)
		self.il_function = owner

	def __iter__(self):
		for idx in xrange(self.start, self.end):
			yield self.il_function[idx]

class DisassemblyTextLine(object):
	def __init__(self, addr, tokens):
		self.address = addr
		self.tokens = tokens

	def __str__(self):
		result = ""
		for token in self.tokens:
			result += token.text
		return result

	def __repr__(self):
		return "<%#x: %s>" % (self.address, str(self))

class FunctionGraphEdge:
	def __init__(self, branch_type, arch, target, points):
		self.type = branch_type
		self.arch = arch
		self.target = target
		self.points = points

	def __repr__(self):
		if self.arch:
			return "<%s: %s@%#x>" % (self.type, self.arch.name, self.target)
		return "<%s: %#x>" % (self.type, self.target)

class FunctionGraphBlock(object):
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		core.BNFreeFunctionGraphBlock(self.handle)

	@property
	def basic_block(self):
		"""Basic block associated with this part of the funciton graph (read-only)"""
		block = core.BNGetFunctionGraphBasicBlock(self.handle)
		func = core.BNGetBasicBlockFunction(block)
		if func is None:
			core.BNFreeBasicBlock(block)
			block = None
		else:
			block = BasicBlock(BinaryView(None, handle = core.BNGetFunctionData(func)), block)
			core.BNFreeFunction(func)
		return block

	@property
	def arch(self):
		"""Function graph block architecture (read-only)"""
		arch = core.BNGetFunctionGraphBlockArchitecture(self.handle)
		if arch is None:
			return None
		return Architecture(arch)

	@property
	def start(self):
		"""Function graph block start (read-only)"""
		return core.BNGetFunctionGraphBlockStart(self.handle)

	@property
	def end(self):
		"""Function graph block end (read-only)"""
		return core.BNGetFunctionGraphBlockEnd(self.handle)

	@property
	def x(self):
		"""Function graph block X (read-only)"""
		return core.BNGetFunctionGraphBlockX(self.handle)

	@property
	def y(self):
		"""Function graph block Y (read-only)"""
		return core.BNGetFunctionGraphBlockY(self.handle)

	@property
	def width(self):
		"""Function graph block width (read-only)"""
		return core.BNGetFunctionGraphBlockWidth(self.handle)

	@property
	def height(self):
		"""Function graph block height (read-only)"""
		return core.BNGetFunctionGraphBlockHeight(self.handle)

	@property
	def lines(self):
		"""Function graph block list of lines (read-only)"""
		count = ctypes.c_ulonglong()
		lines = core.BNGetFunctionGraphBlockLines(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			addr = lines[i].addr
			tokens = []
			for j in xrange(0, lines[i].count):
				token_type = core.BNInstructionTextTokenType_names[lines[i].tokens[j].type]
				text = lines[i].tokens[j].text
				value = lines[i].tokens[j].value
				size = lines[i].tokens[j].size
				operand = lines[i].tokens[j].operand
				tokens.append(InstructionTextToken(token_type, text, value, size, operand))
			result.append(DisassemblyTextLine(addr, tokens))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	@property
	def outgoing_edges(self):
		"""Function graph block list of outgoing edges (read-only)"""
		count = ctypes.c_ulonglong()
		edges = core.BNGetFunctionGraphBlockOutgoingEdges(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			branch_type = core.BNBranchType_names[edges[i].type]
			target = edges[i].target
			arch = None
			if edges[i].arch is not None:
				arch = Architecture(edges[i].arch)
			points = []
			for j in xrange(0, edges[i].pointCount):
				points.append((edges[i].points[j].x, edges[i].points[j].y))
			result.append(FunctionGraphEdge(branch_type, arch, target, points))
		core.BNFreeFunctionGraphBlockOutgoingEdgeList(edges, count.value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<graph block: %s@%#x-%#x>" % (arch.name, self.start, self.end)
		else:
			return "<graph block: %#x-%#x>" % (self.start, self.end)

	def __iter__(self):
		count = ctypes.c_ulonglong()
		lines = core.BNGetFunctionGraphBlockLines(self.handle, count)
		try:
			for i in xrange(0, count.value):
				addr = lines[i].addr
				tokens = []
				for j in xrange(0, lines[i].count):
					token_type = core.BNInstructionTextTokenType_names[lines[i].tokens[j].type]
					text = lines[i].tokens[j].text
					value = lines[i].tokens[j].value
					size = lines[i].tokens[j].size
					operand = lines[i].tokens[j].operand
					tokens.append(InstructionTextToken(token_type, text, value, size, operand))
				yield DisassemblyTextLine(addr, tokens)
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)

class DisassemblySettings(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = core.BNCreateDisassemblySettings()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeDisassemblySettings(self.handle)

	@property
	def width(self):
		return core.BNGetDisassemblyWidth(self.handle)

	@width.setter
	def width(self, value):
		core.BNSetDisassemblyWidth(self.handle, value)

	@property
	def max_symbol_width(self):
		return core.BNGetDisassemblyMaximumSymbolWidth(self.handle)

	@max_symbol_width.setter
	def max_symbol_width(self, value):
		core.BNSetDisassemblyMaximumSymbolWidth(self.handle, value)

	def is_option_set(self, option):
		if isinstance(option, str):
			option = core.BNDisassemblyOption_by_name[option]
		return core.BNIsDisassemblySettingsOptionSet(self.handle, option)

	def set_option(self, option, state = True):
		if isinstance(option, str):
			option = core.BNDisassemblyOption_by_name[option]
		core.BNSetDisassemblySettingsOption(self.handle, option, state)

class FunctionGraph(object):
	def __init__(self, view, handle):
		self.view = view
		self.handle = handle
		self._on_complete = None
		self._cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._complete)

	def __del__(self):
		self.abort()
		core.BNFreeFunctionGraph(self.handle)

	@property
	def function(self):
		"""Function for a function graph (read-only)"""
		func = core.BNGetFunctionForFunctionGraph(self.handle)
		if func is None:
			return None
		return Function(self.view, func)

	@property
	def complete(self):
		"""Whether function graph layout is complete (read-only)"""
		return core.BNIsFunctionGraphLayoutComplete(self.handle)

	@property
	def type(self):
		"""Function graph type (read-only)"""
		return core.BNFunctionGraphType_names[core.BNGetFunctionGraphType(self.handle)]

	@property
	def blocks(self):
		"""List of basic blocks in function (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionGraphBlocks(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(FunctionGraphBlock(core.BNNewFunctionGraphBlockReference(blocks[i])))
		core.BNFreeFunctionGraphBlockList(blocks, count.value)
		return result

	@property
	def width(self):
		"""Function graph width (read-only)"""
		return core.BNGetFunctionGraphWidth(self.handle)

	@property
	def height(self):
		"""Function graph height (read-only)"""
		return core.BNGetFunctionGraphHeight(self.handle)

	@property
	def horizontal_block_margin(self):
		return core.BNGetHorizontalFunctionGraphBlockMargin(self.handle)

	@horizontal_block_margin.setter
	def horizontal_block_margin(self, value):
		core.BNSetFunctionGraphBlockMargins(self.handle, value, self.vertical_block_margin)

	@property
	def vertical_block_margin(self):
		return core.BNGetVerticalFunctionGraphBlockMargin(self.handle)

	@vertical_block_margin.setter
	def vertical_block_margin(self, value):
		core.BNSetFunctionGraphBlockMargins(self.handle, self.horizontal_block_margin, value)

	@property
	def settings(self):
		return DisassemblySettings(core.BNGetFunctionGraphSettings(self.handle))

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __repr__(self):
		return "<graph of %s>" % repr(self.function)

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionGraphBlocks(self.handle, count)
		try:
			for i in xrange(0, count.value):
				yield FunctionGraphBlock(core.BNNewFunctionGraphBlockReference(blocks[i]))
		finally:
			core.BNFreeFunctionGraphBlockList(blocks, count.value)

	def _complete(self, ctxt):
		try:
			if self._on_complete is not None:
				self._on_complete()
		except:
			log_error(traceback.format_exc())

	def layout(self, graph_type = core.NormalFunctionGraph):
		if isinstance(graph_type, str):
			graph_type = core.BNFunctionGraphType_by_name[graph_type]
		core.BNStartFunctionGraphLayout(self.handle, graph_type)

	def _wait_complete(self):
		self._wait_cond.acquire()
		self._wait_cond.notify()
		self._wait_cond.release()

	def layout_and_wait(self, graph_type = core.NormalFunctionGraph):
		self._wait_cond = threading.Condition()
		self.on_complete(self._wait_complete)
		self.layout(graph_type)

		self._wait_cond.acquire()
		while not self.complete:
			self._wait_cond.wait()
		self._wait_cond.release()

	def on_complete(self, callback):
		self._on_complete = callback
		core.BNSetFunctionGraphCompleteCallback(self.handle, None, self._cb)

	def abort(self):
		core.BNAbortFunctionGraph(self.handle)

	def get_blocks_in_region(self, left, top, right, bottom):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionGraphBlocksInRegion(self.handle, left, top, right, bottom, count)
		result = []
		for i in xrange(0, count.value):
			result.append(FunctionGraphBlock(core.BNNewFunctionGraphBlockReference(blocks[i])))
		core.BNFreeFunctionGraphBlockList(blocks, count.value)
		return result

	def is_option_set(self, option):
		if isinstance(option, str):
			option = core.BNDisassemblyOption_by_name(option)
		return core.BNIsFunctionGraphOptionSet(self.handle, option)

	def set_option(self, option, state = True):
		if isinstance(option, str):
			option = core.BNDisassemblyOption_by_name(option)
		core.BNSetFunctionGraphOption(self.handle, option, state)

class RegisterInfo(object):
	def __init__(self, full_width_reg, size, offset = 0, extend = core.NoExtend, index = None):
		self.full_width_reg = full_width_reg
		self.offset = offset
		self.size = size
		self.extend = extend
		self.index = index

	def __repr__(self):
		if (self.extend == core.ZeroExtendToFullWidth) or (self.extend == "ZeroExtendToFullWidth"):
			extend = ", zero extend"
		elif (self.extend == core.SignExtendToFullWidth) or (self.extend == "SignExtendToFullWidth"):
			extend = ", sign extend"
		else:
			extend = ""
		return "<reg: size %d, offset %d in %s%s>" % (self.size, self.offset, self.full_width_reg, extend)

class InstructionBranch(object):
	def __init__(self, branch_type, target = 0, arch = None):
		self.type = branch_type
		self.target = target
		self.arch = arch

	def __repr__(self):
		branch_type = self.type
		if not isinstance(branch_type, str):
			branch_type = core.BNBranchType_names[branch_type]
		if self.arch is not None:
			return "<%s: %s@%#x>" % (branch_type, self.arch.name, self.target)
		return "<%s: %#x>" % (branch_type, self.target)

class InstructionInfo(object):
	def __init__(self):
		self.length = 0
		self.branch_delay = False
		self.branches = []

	def add_branch(self, branch_type, target = 0, arch = None):
		self.branches.append(InstructionBranch(branch_type, target, arch))

	def __repr__(self):
		branch_delay = ""
		if self.branch_delay:
			branch_delay = ", delay slot"
		return "<instr: %d bytes%s, %s>" % (self.length, branch_delay, repr(self.branches))

class InstructionTextToken(object):
	"""
	``class InstructionTextToken`` is used to tell the core about the various components in the disassembly views.

		======================== ============================================
		InstructionTextTokenType Description
		======================== ============================================
		TextToken                Text that doesn't fit into the other tokens
		InstructionToken         The instruction mnemonic
		OperandSeparatorToken    The comma or whatever else separates tokens
		RegisterToken            Registers
		IntegerToken             Integers
		PossibleAddressToken     Integers that are likely addresses
		BeginMemoryOperandToken  The start of memory operand
		EndMemoryOperandToken    The end of a memory operand
		FloatingPointToken       Floating point number
		AnnotationToken          **For internal use only**
		CodeRelativeAddressToken **For internal use only**
		StackVariableTypeToken   **For internal use only**
		DataVariableTypeToken    **For internal use only**
		FunctionReturnTypeToken  **For internal use only**
		FunctionAttributeToken   **For internal use only**
		ArgumentTypeToken        **For internal use only**
		ArgumentNameToken        **For internal use only**
		HexDumpByteValueToken    **For internal use only**
		HexDumpSkippedByteToken  **For internal use only**
		HexDumpInvalidByteToken  **For internal use only**
		HexDumpTextToken         **For internal use only**
		OpcodeToken              **For internal use only**
		StringToken              **For internal use only**
		CharacterConstantToken   **For internal use only**
		CodeSymbolToken          **For internal use only**
		DataSymbolToken          **For internal use only**
		StackVariableToken       **For internal use only**
		ImportToken              **For internal use only**
		AddressDisplayToken      **For internal use only**
		======================== ============================================

	"""
	def __init__(self, token_type, text, value = 0, size = 0, operand = 0xffffffff):
		self.type = token_type
		self.text = text
		self.value = value
		self.size = size
		self.operand = operand

	def __str__(self):
		return self.text

	def __repr__(self):
		return repr(self.text)

class _ArchitectureMetaClass(type):
	@property
	def list(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		archs = core.BNGetArchitectureList(count)
		result = []
		for i in xrange(0, count.value):
			result.append(Architecture(archs[i]))
		core.BNFreeArchitectureList(archs)
		return result

	def __iter__(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		archs = core.BNGetArchitectureList(count)
		try:
			for i in xrange(0, count.value):
				yield Architecture(archs[i])
		finally:
			core.BNFreeArchitectureList(archs)

	def __getitem__(cls, name):
		_init_plugins()
		arch = core.BNGetArchitectureByName(name)
		if arch is None:
			raise KeyError, "'%s' is not a valid architecture" % str(name)
		return Architecture(arch)

	def register(cls):
		_init_plugins()
		if cls.name is None:
			raise ValueError, "architecture 'name' is not defined"
		arch = cls()
		cls._registered_cb = arch._cb
		arch.handle = core.BNRegisterArchitecture(cls.name, arch._cb)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

class Architecture(object):
	"""
	``class Architecture`` is the parent class for all CPU architectures. Subclasses of Architecture implemnt assembly,
	disassembly, IL lifting, and patching.

	``class Architecture`` has a ``__metaclass__`` with the additional methods ``register``, and supports
	iteration::

		>>> #List the architectures
		>>> list(Architecture)
		[<arch: aarch64>, <arch: armv7>, <arch: armv7eb>, <arch: mipsel32>, <arch: mips32>, <arch: powerpc>,
		<arch: x86>, <arch: x86_64>]
		>>> #Register a new Architecture
		>>> class MyArch(Architecture):
		...  name = "MyArch"
		...
		>>> MyArch.register()
		>>> list(Architecture)
		[<arch: aarch64>, <arch: armv7>, <arch: armv7eb>, <arch: mipsel32>, <arch: mips32>, <arch: powerpc>,
		<arch: x86>, <arch: x86_64>, <arch: MyArch>]
		>>>

	For the purposes of this documentation the variable ``arch`` will be used in the following context ::

		>>> from binaryninja import *
		>>> arch = Architecture['x86']
	"""
	name = None
	endianness = core.LittleEndian
	address_size = 8
	default_int_size = 4
	max_instr_length = 16
	opcode_display_length = 8
	regs = {}
	stack_pointer = None
	link_reg = None
	flags = []
	flag_write_types = []
	flag_roles = {}
	flags_required_for_flag_condition = {}
	flags_written_by_flag_write_type = {}
	__metaclass__ = _ArchitectureMetaClass
	next_address = 0

	def __init__(self, handle = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNArchitecture)
			self.__dict__["name"] = core.BNGetArchitectureName(self.handle)
			self.__dict__["endianness"] = core.BNEndianness_names[core.BNGetArchitectureEndianness(self.handle)]
			self.__dict__["address_size"] = core.BNGetArchitectureAddressSize(self.handle)
			self.__dict__["default_int_size"] = core.BNGetArchitectureDefaultIntegerSize(self.handle)
			self.__dict__["max_instr_length"] = core.BNGetArchitectureMaxInstructionLength(self.handle)
			self.__dict__["opcode_display_length"] = core.BNGetArchitectureOpcodeDisplayLength(self.handle)
			self.__dict__["stack_pointer"] = core.BNGetArchitectureRegisterName(self.handle,
				core.BNGetArchitectureStackPointerRegister(self.handle))
			self.__dict__["link_reg"] = core.BNGetArchitectureRegisterName(self.handle,
				core.BNGetArchitectureLinkRegister(self.handle))

			count = ctypes.c_ulonglong()
			regs = core.BNGetAllArchitectureRegisters(self.handle, count)
			self.__dict__["regs"] = {}
			for i in xrange(0, count.value):
				name = core.BNGetArchitectureRegisterName(self.handle, regs[i])
				info = core.BNGetArchitectureRegisterInfo(self.handle, regs[i])
				full_width_reg = core.BNGetArchitectureRegisterName(self.handle, info.fullWidthRegister)
				self.regs[name] = RegisterInfo(full_width_reg, info.size, info.offset,
					core.BNImplicitRegisterExtend_names[info.extend], regs[i])
			core.BNFreeRegisterList(regs)

			count = ctypes.c_ulonglong()
			flags = core.BNGetAllArchitectureFlags(self.handle, count)
			self._flags = {}
			self._flags_by_index = {}
			self.__dict__["flags"] = []
			for i in xrange(0, count.value):
				name = core.BNGetArchitectureFlagName(self.handle, flags[i])
				self._flags[name] = flags[i]
				self._flags_by_index[flags[i]] = name
				self.flags.append(name)
			core.BNFreeRegisterList(flags)

			count = ctypes.c_ulonglong()
			types = core.BNGetAllArchitectureFlagWriteTypes(self.handle, count)
			self._flag_write_types = {}
			self._flag_write_types_by_index = {}
			self.__dict__["flag_write_types"] = []
			for i in xrange(0, count.value):
				name = core.BNGetArchitectureFlagWriteTypeName(self.handle, types[i])
				self._flag_write_types[name] = types[i]
				self._flag_write_types_by_index[types[i]] = name
				self.flag_write_types.append(name)
			core.BNFreeRegisterList(types)

			self._flag_roles = {}
			self.__dict__["flag_roles"] = {}
			for flag in self.__dict__["flags"]:
				role = core.BNGetArchitectureFlagRole(self.handle, self._flags[flag])
				self.__dict__["flag_roles"][flag] = role
				self._flag_roles[self._flags[flag]] = role

			self._flags_required_for_flag_condition = {}
			self.__dict__["flags_required_for_flag_condition"] = {}
			for cond in core.BNLowLevelILFlagCondition_names:
				count = ctypes.c_ulonglong()
				flags = core.BNGetArchitectureFlagsRequiredForFlagCondition(self.handle, cond, count)
				flag_indexes = []
				flag_names = []
				for i in xrange(0, count.value):
					flag_indexes.append(flags[i])
					flag_names.append(self._flags_by_index[flags[i]])
				core.BNFreeRegisterList(flags)
				self._flags_required_for_flag_condition[cond] = flag_indexes
				self.__dict__["flags_required_for_flag_condition"][cond] = flag_names

			self._flags_written_by_flag_write_type = {}
			self.__dict__["flags_written_by_flag_write_type"] = {}
			for write_type in self.flag_write_types:
				count = ctypes.c_ulonglong()
				flags = core.BNGetArchitectureFlagsWrittenByFlagWriteType(self.handle,
					self._flag_write_types[write_type], count)
				flag_indexes = []
				flag_names = []
				for i in xrange(0, count.value):
					flag_indexes.append(flags[i])
					flag_names.append(self._flags_by_index[flags[i]])
				core.BNFreeRegisterList(flags)
				self._flags_written_by_flag_write_type[self._flag_write_types[write_type]] = flag_indexes
				self.__dict__["flags_written_by_flag_write_type"][write_type] = flag_names
		else:
			_init_plugins()

			if self.__class__.opcode_display_length > self.__class__.max_instr_length:
				self.__class__.opcode_display_length = self.__class__.max_instr_length

			self._cb = core.BNCustomArchitecture()
			self._cb.context = 0
			self._cb.init = self._cb.init.__class__(self._init)
			self._cb.getEndianness = self._cb.getEndianness.__class__(self._get_endianness)
			self._cb.getAddressSize = self._cb.getAddressSize.__class__(self._get_address_size)
			self._cb.getDefaultIntegerSize = self._cb.getDefaultIntegerSize.__class__(self._get_default_integer_size)
			self._cb.getMaxInstructionLength = self._cb.getMaxInstructionLength.__class__(self._get_max_instruction_length)
			self._cb.getOpcodeDisplayLength = self._cb.getOpcodeDisplayLength.__class__(self._get_opcode_display_length)
			self._cb.getInstructionInfo = self._cb.getInstructionInfo.__class__(self._get_instruction_info)
			self._cb.getInstructionText = self._cb.getInstructionText.__class__(self._get_instruction_text)
			self._cb.freeInstructionText = self._cb.freeInstructionText.__class__(self._free_instruction_text)
			self._cb.getInstructionLowLevelIL = self._cb.getInstructionLowLevelIL.__class__(
				self._get_instruction_low_level_il)
			self._cb.getRegisterName = self._cb.getRegisterName.__class__(self._get_register_name)
			self._cb.getFlagName = self._cb.getFlagName.__class__(self._get_flag_name)
			self._cb.getFlagWriteTypeName = self._cb.getFlagWriteTypeName.__class__(self._get_flag_write_type_name)
			self._cb.getFullWidthRegisters = self._cb.getFullWidthRegisters.__class__(self._get_full_width_registers)
			self._cb.getAllRegisters = self._cb.getAllRegisters.__class__(self._get_all_registers)
			self._cb.getAllFlags = self._cb.getAllRegisters.__class__(self._get_all_flags)
			self._cb.getAllFlagWriteTypes = self._cb.getAllRegisters.__class__(self._get_all_flag_write_types)
			self._cb.getFlagRole = self._cb.getFlagRole.__class__(self._get_flag_role)
			self._cb.getFlagsRequiredForFlagCondition = self._cb.getFlagsRequiredForFlagCondition.__class__(
				self._get_flags_required_for_flag_condition)
			self._cb.getFlagsWrittenByFlagWriteType = self._cb.getFlagsWrittenByFlagWriteType.__class__(
				self._get_flags_written_by_flag_write_type)
			self._cb.getFlagWriteLowLevelIL = self._cb.getFlagWriteLowLevelIL.__class__(
				self._get_flag_write_low_level_il)
			self._cb.getFlagConditionLowLevelIL = self._cb.getFlagConditionLowLevelIL.__class__(
				self._get_flag_condition_low_level_il)
			self._cb.freeRegisterList = self._cb.freeRegisterList.__class__(self._free_register_list)
			self._cb.getRegisterInfo = self._cb.getRegisterInfo.__class__(self._get_register_info)
			self._cb.getStackPointerRegister = self._cb.getStackPointerRegister.__class__(
				self._get_stack_pointer_register)
			self._cb.getLinkRegister = self._cb.getLinkRegister.__class__(self._get_link_register)
			self._cb.assemble = self._cb.assemble.__class__(self._assemble)
			self._cb.isNeverBranchPatchAvailable = self._cb.isNeverBranchPatchAvailable.__class__(
				self._is_never_branch_patch_available)
			self._cb.isAlwaysBranchPatchAvailable = self._cb.isAlwaysBranchPatchAvailable.__class__(
				self._is_always_branch_patch_available)
			self._cb.isInvertBranchPatchAvailable = self._cb.isInvertBranchPatchAvailable.__class__(
				self._is_invert_branch_patch_available)
			self._cb.isSkipAndReturnZeroPatchAvailable = self._cb.isSkipAndReturnZeroPatchAvailable.__class__(
				self._is_skip_and_return_zero_patch_available)
			self._cb.isSkipAndReturnValuePatchAvailable = self._cb.isSkipAndReturnValuePatchAvailable.__class__(
				self._is_skip_and_return_value_patch_available)
			self._cb.convertToNop = self._cb.convertToNop.__class__(self._convert_to_nop)
			self._cb.alwaysBranch = self._cb.alwaysBranch.__class__(self._always_branch)
			self._cb.invertBranch = self._cb.invertBranch.__class__(self._invert_branch)
			self._cb.skipAndReturnValue = self._cb.skipAndReturnValue.__class__(self._skip_and_return_value)

			self._all_regs = {}
			self._full_width_regs = {}
			self._regs_by_index = {}
			self.__dict__["regs"] = self.__class__.regs
			reg_index = 0
			for reg in self.regs:
				info = self.regs[reg]
				if reg not in self._all_regs:
					self._all_regs[reg] = reg_index
					self._regs_by_index[reg_index] = reg
					self.regs[reg].index = reg_index
					reg_index += 1
				if info.full_width_reg not in self._all_regs:
					self._all_regs[info.full_width_reg] = reg_index
					self._regs_by_index[reg_index] = info.full_width_reg
					self.regs[info.full_width_reg].index = reg_index
					reg_index += 1
				if info.full_width_reg not in self._full_width_regs:
					self._full_width_regs[info.full_width_reg] = self._all_regs[info.full_width_reg]

			self._flags = {}
			self._flags_by_index = {}
			self.__dict__["flags"] = self.__class__.flags
			flag_index = 0
			for flag in self.__class__.flags:
				if flag not in self._flags:
					self._flags[flag] = flag_index
					self._flags_by_index[flag_index] = flag
					flag_index += 1

			self._flag_write_types = {}
			self._flag_write_types_by_index = {}
			self.__dict__["flag_write_types"] = self.__class__.flag_write_types
			write_type_index = 0
			for write_type in self.__class__.flag_write_types:
				if write_type not in self._flag_write_types:
					self._flag_write_types[write_type] = write_type_index
					self._flag_write_types_by_index[write_type_index] = write_type
					write_type_index += 1

			self._flag_roles = {}
			self.__dict__["flag_roles"] = self.__class__.flag_roles
			for flag in self.__class__.flag_roles:
				role = self.__class__.flag_roles[flag]
				if isinstance(role, str):
					role = core.BNFlagRole_by_name[role]
				self._flag_roles[self._flags[flag]] = role

			self._flags_required_for_flag_condition = {}
			self.__dict__["flags_required_for_flag_condition"] = self.__class__.flags_required_for_flag_condition
			for cond in self.__class__.flags_required_for_flag_condition:
				flags = []
				for flag in self.__class__.flags_required_for_flag_condition[cond]:
					flags.append(self._flags[flag])
				self._flags_required_for_flag_condition[cond] = flags

			self._flags_written_by_flag_write_type = {}
			self.__dict__["flags_written_by_flag_write_type"] = self.__class__.flags_written_by_flag_write_type
			for write_type in self.__class__.flags_written_by_flag_write_type:
				flags = []
				for flag in self.__class__.flags_written_by_flag_write_type[write_type]:
					flags.append(self._flags[flag])
				self._flags_written_by_flag_write_type[self._flag_write_types[write_type]] = flags

			self._pending_reg_lists = {}
			self._pending_token_lists = {}

	@property
	def full_width_regs(self):
		"""List of full width register strings (read-only)"""
		count = ctypes.c_ulonglong()
		regs = core.BNGetFullWidthArchitectureRegisters(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	@property
	def calling_conventions(self):
		"""Dict of CallingConvention objects (read-only)"""
		count = ctypes.c_ulonglong()
		cc = core.BNGetArchitectureCallingConventions(self.handle, count)
		result = {}
		for i in xrange(0, count.value):
			obj = CallingConvention(None, core.BNNewCallingConventionReference(cc[i]))
			result[obj.name] = obj
		core.BNFreeCallingConventionList(cc, count)
		return result

	@property
	def standalone_platform(self):
		"""Architecture standalone platform (read-only)"""
		pl = core.BNGetArchitectureStandalonePlatform(self.handle)
		return Platform(self, pl)

	def __setattr__(self, name, value):
		if ((name == "name") or (name == "endianness") or (name == "address_size") or
		    (name == "default_int_size") or (name == "regs") or (name == "get_max_instruction_length")):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			try:
				object.__setattr__(self,name,value)
			except AttributeError:
				raise AttributeError, "attribute '%s' is read only" % name

	def __repr__(self):
		return "<arch: %s>" % self.name

	def _init(self, ctxt, handle):
		self.handle = handle

	def _get_endianness(self, ctxt):
		try:
			return self.__class__.endianness
		except:
			log_error(traceback.format_exc())
			return core.LittleEndian

	def _get_address_size(self, ctxt):
		try:
			return self.__class__.address_size
		except:
			log_error(traceback.format_exc())
			return 8

	def _get_default_integer_size(self, ctxt):
		try:
			return self.__class__.default_int_size
		except:
			log_error(traceback.format_exc())
			return 4

	def _get_max_instruction_length(self, ctxt):
		try:
			return self.__class__.max_instr_length
		except:
			log_error(traceback.format_exc())
			return 16

	def _get_opcode_display_length(self, ctxt):
		try:
			return self.__class__.opcode_display_length
		except:
			log_error(traceback.format_exc())
			return 8

	def _get_instruction_info(self, ctxt, data, addr, max_len, result):
		try:
			buf = ctypes.create_string_buffer(max_len)
			ctypes.memmove(buf, data, max_len)
			info = self.perform_get_instruction_info(buf.raw, addr)
			if info is None:
				return False
			result[0].length = info.length
			result[0].branchDelay = info.branch_delay
			result[0].branchCount = len(info.branches)
			for i in xrange(0, len(info.branches)):
				if isinstance(info.branches[i].type, str):
					result[0].branchType[i] = core.BNBranchType_by_name[info.branches[i].type]
				else:
					result[0].branchType[i] = info.branches[i].type
				result[0].branchTarget[i] = info.branches[i].target
				if info.branches[i].arch is None:
					result[0].branchArch[i] = None
				else:
					result[0].branchArch[i] = info.branches[i].arch.handle
			return True
		except (KeyError, OSError):
			log_error(traceback.format_exc())
			return False

	def _get_instruction_text(self, ctxt, data, addr, length, result, count):
		try:
			buf = ctypes.create_string_buffer(length[0])
			ctypes.memmove(buf, data, length[0])
			info = self.perform_get_instruction_text(buf.raw, addr)
			if info is None:
				return False
			tokens = info[0]
			length[0] = info[1]
			count[0] = len(tokens)
			token_buf = (core.BNInstructionTextToken * len(tokens))()
			for i in xrange(0, len(tokens)):
				if isinstance(tokens[i].type, str):
					token_buf[i].type = core.BNInstructionTextTokenType_by_name[tokens[i].type]
				else:
					token_buf[i].type = tokens[i].type
				token_buf[i].text = tokens[i].text
				token_buf[i].value = tokens[i].value
				token_buf[i].size = tokens[i].size
				token_buf[i].operand = tokens[i].operand
			result[0] = token_buf
			ptr = ctypes.cast(token_buf, ctypes.c_void_p)
			self._pending_token_lists[ptr.value] = (ptr.value, token_buf)
			return True
		except (KeyError, OSError):
			log_error(traceback.format_exc())
			return False

	def _free_instruction_text(self, tokens, count):
		try:
			buf = ctypes.cast(tokens, ctypes.c_void_p)
			if buf.value not in self._pending_token_lists:
				raise ValueError, "freeing token list that wasn't allocated"
			del self._pending_token_lists[buf.value]
		except KeyError:
			log_error(traceback.format_exc())

	def _get_instruction_low_level_il(self, ctxt, data, addr, length, il):
		try:
			buf = ctypes.create_string_buffer(length[0])
			ctypes.memmove(buf, data, length[0])
			result = self.perform_get_instruction_low_level_il(buf.raw, addr,
				LowLevelILFunction(self, core.BNNewLowLevelILFunctionReference(il)))
			if result is None:
				return False
			length[0] = result
			return True
		except OSError:
			log_error(traceback.format_exc())
			return False

	def _get_register_name(self, ctxt, reg):
		try:
			if reg in self._regs_by_index:
				return core.BNAllocString(self._regs_by_index[reg])
			return core.BNAllocString("")
		except (KeyError, OSError):
			log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_flag_name(self, ctxt, flag):
		try:
			if flag in self._flags_by_index:
				return core.BNAllocString(self._flags_by_index[flag])
			return core.BNAllocString("")
		except (KeyError, OSError):
			log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_flag_write_type_name(self, ctxt, write_type):
		try:
			if write_type in self._flag_write_types_by_index:
				return core.BNAllocString(self._flag_write_types_by_index[write_type])
			return core.BNAllocString("")
		except (KeyError, OSError):
			log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_full_width_registers(self, ctxt, count):
		try:
			regs = self._full_width_regs.values()
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in xrange(0, len(regs)):
				reg_buf[i] = regs[i]
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except KeyError:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_all_registers(self, ctxt, count):
		try:
			regs = self._regs_by_index.keys()
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in xrange(0, len(regs)):
				reg_buf[i] = regs[i]
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except KeyError:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_all_flags(self, ctxt, count):
		try:
			flags = self._flags_by_index.keys()
			count[0] = len(flags)
			flag_buf = (ctypes.c_uint * len(flags))()
			for i in xrange(0, len(flags)):
				flag_buf[i] = flags[i]
			result = ctypes.cast(flag_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, flag_buf)
			return result.value
		except KeyError:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_all_flag_write_types(self, ctxt, count):
		try:
			types = self._flag_write_types_by_index.keys()
			count[0] = len(types)
			type_buf = (ctypes.c_uint * len(types))()
			for i in xrange(0, len(types)):
				type_buf[i] = types[i]
			result = ctypes.cast(type_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, type_buf)
			return result.value
		except KeyError:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flag_role(self, ctxt, flag):
		try:
			if flag in self._flag_roles:
				return self._flag_roles[flag]
			return core.SpecialFlagRole
		except KeyError:
			log_error(traceback.format_exc())
			return None

	def _get_flags_required_for_flag_condition(self, ctxt, cond, count):
		try:
			if cond in self._flags_required_for_flag_condition:
				flags = self._flags_required_for_flag_condition[cond]
			else:
				flags = []
			count[0] = len(flags)
			flag_buf = (ctypes.c_uint * len(flags))()
			for i in xrange(0, len(flags)):
				flag_buf[i] = flags[i]
			result = ctypes.cast(flag_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, flag_buf)
			return result.value
		except KeyError:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flags_written_by_flag_write_type(self, ctxt, write_type, count):
		try:
			if write_type in self._flags_written_by_flag_write_type:
				flags = self._flags_written_by_flag_write_type[write_type]
			else:
				flags = []
			count[0] = len(flags)
			flag_buf = (ctypes.c_uint * len(flags))()
			for i in xrange(0, len(flags)):
				flag_buf[i] = flags[i]
			result = ctypes.cast(flag_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, flag_buf)
			return result.value
		except (KeyError, OSError):
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flag_write_low_level_il(self, ctxt, op, size, write_type, flag, operands, operand_count, il):
		try:
			write_type_name = None
			if write_type != 0:
				write_type_name = self._flag_write_types_by_index[write_type]
			flag_name = self._flags_by_index[flag]
			operand_list = []
			for i in xrange(operand_count):
				if operands[i].constant:
					operand_list.append(("const", operands[i].value))
				elif LLIL_REG_IS_TEMP(operands[i].reg):
					operand_list.append(("reg", operands[i].reg))
				else:
					operand_list.append(("reg", self._regs_by_index[operands[i].reg]))
			return self.perform_get_flag_write_low_level_il(op, size, write_type_name, flag_name, operand_list,
				LowLevelILFunction(self, core.BNNewLowLevelILFunctionReference(il))).index
		except (KeyError, OSError):
			log_error(traceback.format_exc())
			return False

	def _get_flag_condition_low_level_il(self, ctxt, cond, il):
		try:
			return self.perform_get_flag_condition_low_level_il(cond,
				LowLevelILFunction(self, core.BNNewLowLevelILFunctionReference(il))).index
		except OSError:
			log_error(traceback.format_exc())
			return 0

	def _free_register_list(self, ctxt, regs):
		try:
			buf = ctypes.cast(regs, ctypes.c_void_p)
			if buf.value not in self._pending_reg_lists:
				raise ValueError, "freeing register list that wasn't allocated"
			del self._pending_reg_lists[buf.value]
		except (ValueError, KeyError):
			log_error(traceback.format_exc())

	def _get_register_info(self, ctxt, reg, result):
		try:
			if reg not in self._regs_by_index:
				result[0].fullWidthRegister = 0
				result[0].offset = 0
				result[0].size = 0
				result[0].extend = core.NoExtend
				return
			info = self.__class__.regs[self._regs_by_index[reg]]
			result[0].fullWidthRegister = self._all_regs[info.full_width_reg]
			result[0].offset = info.offset
			result[0].size = info.size
			if isinstance(info.extend, str):
				result[0].extend = core.BNImplicitRegisterExtend_by_name[info.extend]
			else:
				result[0].extend = info.extend
		except KeyError:
			log_error(traceback.format_exc())
			result[0].fullWidthRegister = 0
			result[0].offset = 0
			result[0].size = 0
			result[0].extend = core.NoExtend

	def _get_stack_pointer_register(self, ctxt):
		try:
			return self._all_regs[self.__class__.stack_pointer]
		except KeyError:
			log_error(traceback.format_exc())
			return 0

	def _get_link_register(self, ctxt):
		try:
			if self.__class__.link_reg is None:
				return 0xffffffff
			return self._all_regs[self.__class__.link_reg]
		except KeyError:
			log_error(traceback.format_exc())
			return 0

	def _assemble(self, ctxt, code, addr, result, errors):
		try:
			data, error_str = self.perform_assemble(code, addr)
			errors[0] = core.BNAllocString(str(error_str))
			if data is None:
				return False
			data = str(data)
			buf = ctypes.create_string_buffer(len(data))
			ctypes.memmove(buf, data, len(data))
			core.BNSetDataBufferContents(result, buf, len(data))
			return True
		except:
			log_error(traceback.format_exc())
			errors[0] = core.BNAllocString("Unhandled exception during assembly.\n")
			return False

	def _is_never_branch_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.perform_is_never_branch_patch_available(buf.raw, addr)
		except:
			log_error(traceback.format_exc())
			return False

	def _is_always_branch_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.perform_is_always_branch_patch_available(buf.raw, addr)
		except:
			log_error(traceback.format_exc())
			return False

	def _is_invert_branch_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.perform_is_invert_branch_patch_available(buf.raw, addr)
		except:
			log_error(traceback.format_exc())
			return False

	def _is_skip_and_return_zero_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.perform_is_skip_and_return_zero_patch_available(buf.raw, addr)
		except:
			log_error(traceback.format_exc())
			return False

	def _is_skip_and_return_value_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.perform_is_skip_and_return_value_patch_available(buf.raw, addr)
		except:
			log_error(traceback.format_exc())
			return False

	def _convert_to_nop(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			result = self.perform_convert_to_nop(buf.raw, addr)
			if result is None:
				return False
			result = str(result)
			if len(result) > length:
				result = result[0:length]
			ctypes.memmove(data, result, len(result))
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _always_branch(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			result = self.perform_always_branch(buf.raw, addr)
			if result is None:
				return False
			result = str(result)
			if len(result) > length:
				result = result[0:length]
			ctypes.memmove(data, result, len(result))
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _invert_branch(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			result = self.perform_invert_branch(buf.raw, addr)
			if result is None:
				return False
			result = str(result)
			if len(result) > length:
				result = result[0:length]
			ctypes.memmove(data, result, len(result))
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _skip_and_return_value(self, ctxt, data, addr, length, value):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			result = self.perform_skip_and_return_value(buf.raw, addr, value)
			if result is None:
				return False
			result = str(result)
			if len(result) > length:
				result = result[0:length]
			ctypes.memmove(data, result, len(result))
			return True
		except:
			log_error(traceback.format_exc())
			return False

	@abc.abstractmethod
	def perform_get_instruction_info(self, data, addr):
		"""
		``perform_get_instruction_info`` implements a method which interpretes the bytes passed in ``data`` as an
		:py:Class:`InstructionInfo` object. The InstructionInfo object should have the length of the current instruction.
		If the instruction is a branch instruction the method should add a branch of the proper type:

			===================== ===================================================
			BranchType            Description
			===================== ===================================================
			UnconditionalBranch   Branch will always be taken
			FalseBranch           False branch condition
			TrueBranch            True branch condition
			CallDestination       Branch is a call instruction (Branch with Link)
			FunctionReturn        Branch returns from a function
			SystemCall            System call instruction
			IndirectBranch        Branch destination is a memory address or register
			UnresolvedBranch      Call instruction that isn't
			===================== ===================================================

		:param str data: bytes to decode
		:param int addr: virtual address of the byte to be decoded
		:return: a :py:class:`InstructionInfo` object containing the length and branche types for the given instruction
		:rtype: InstructionInfo
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_instruction_text(self, data, addr):
		"""
		``perform_get_instruction_text`` implements a method which interpretes the bytes passed in ``data`` as a
		list of :py:class:`InstructionTextToken` objects.

		:param str data: bytes to decode
		:param int addr: virtual address of the byte to be decoded
		:return: a tuple of list(InstructionTextToken) and length of instruction decoded
		:rtype: tuple(list(InstructionTextToken), int)
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_instruction_low_level_il(self, data, addr, il):
		"""
		``perform_get_instruction_low_level_il`` implements a method to interpret the bytes passed in ``data`` to
		low-level IL instructions. The il instructions must be appended to the :py:class:`LowLevelILFunction`.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes to be interpreted as low-level IL instructions
		:param int addr: virtual address of start of ``data``
		:param LowLevelILFunction il: LowLevelILFunction object to append LowLevelILExpr objects to
		:rtype: None
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
		"""
		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param LowLevelILOperation op:
		:param int size:
		:param int write_type:
		:param int flag:
		:param list(int_or_str):
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		return il.unimplemented()

	@abc.abstractmethod
	def perform_get_flag_condition_low_level_il(self, cond, il):
		"""
		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param LowLevelILFlagCondition cond:
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		return il.unimplemented()

	@abc.abstractmethod
	def perform_assemble(self, code, addr):
		"""
		``perform_assemble`` implements a method to convert the string of assembly instructions ``code`` loaded at
		virtual address ``addr`` to the byte representation of those instructions. This can be done by simply shelling
		out to an assembler like yasm or llvm-mc, since this method isn't performance sensitive.

		.. note:: Architecture subclasses should implement this method.
		.. note :: It is important that the assembler used accepts a syntax identical to the one emitted by the \
		disassembler. This will prevent confusing the user.
		.. warning:: This method should never be called directly.

		:param str code: string representation of the instructions to be assembled
		:param int addr: virtual address that the instructions will be loaded at
		:return: the bytes for the assembled instructions or error string
		:rtype: (a tuple of instructions and empty string) or (or None and error string)
		"""
		return None, "Architecture does not implement an assembler.\n"

	@abc.abstractmethod
	def perform_is_never_branch_patch_available(self, data, addr):
		"""
		``perform_is_never_branch_patch_available`` implements a check to determine if the instruction represented by
		the bytes contained in ``data`` at address addr is a branch instruction that can be made to never branch.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_always_branch_patch_available(self, data, addr):
		"""
		``perform_is_always_branch_patch_available`` implements a check to determine if the instruction represented by
		the bytes contained in ``data`` at address addr is a conditional branch that can be made unconditional.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_invert_branch_patch_available(self, data, addr):
		"""
		``perform_is_invert_branch_patch_available`` implements a check to determine if the instruction represented by
		the bytes contained in ``data`` at address addr is a conditional branch which can be inverted.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_skip_and_return_zero_patch_available(self, data, addr):
		"""
		``perform_is_skip_and_return_zero_patch_available`` implements a check to determine if the instruction represented by
		the bytes contained in ``data`` at address addr is a *call-like* instruction which can made into instructions
		that are equivilent to "return 0". For example if ``data`` was the x86 instruction ``call eax`` which could be
		converted into ``xor eax,eax`` thus this function would return True.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_skip_and_return_value_patch_available(self, data, addr):
		"""
		``perform_is_skip_and_return_value_patch_available`` implements a check to determine if the instruction represented by
		the bytes contained in ``data`` at address addr is a *call-like* instruction which can made into instructions
		that are equivilent to "return 0". For example if ``data`` was the x86 instruction ``call 0xdeadbeef`` which could be
		converted into ``mov eax, 42`` thus this function would return True.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_convert_to_nop(self, data, addr):
		"""
		``perform_convert_to_nop`` implements a method which returns a nop sequence of len(data) bytes long.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes at virtual address ``addr``
		:param int addr: the virtual address of the instruction to be patched
		:return: nop sequence of same length as ``data`` or None
		:rtype: str or None
		"""
		return None

	@abc.abstractmethod
	def perform_always_branch(self, data, addr):
		"""
		``perform_always_branch`` implements a method which converts the branch represented by the bytes in ``data`` to
		at ``addr`` to an unconditional branch.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: The bytes of the replacement unconditional branch instruction
		:rtype: str
		"""
		return None

	@abc.abstractmethod
	def perform_invert_branch(self, data, addr):
		"""
		``perform_invert_branch`` implements a method which inverts the branch represented by the bytes in ``data`` to
		at ``addr``.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: The bytes of the replacement unconditional branch instruction
		:rtype: str
		"""
		return None

	@abc.abstractmethod
	def perform_skip_and_return_value(self, data, addr, value):
		"""
		``perform_skip_and_return_value`` implements a method which converts a *call-like* instruction represented by
		the bytes in ``data`` at ``addr`` to one or more instructions that are equivilent to a function returning a
		value.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:param int value: value to be returned
		:return: The bytes of the replacement unconditional branch instruction
		:rtype: str
		"""
		return None

	def get_instruction_info(self, data, addr):
		"""
		``get_instruction_info`` returns an InstructionInfo object for the instruction at the given virtual address
		``addr`` with data ``data``.

		.. note :: The instruction info object should always set the InstructionInfo.length to the instruction length, \
		and the branches of the proper types shoulde be added if the instruction is a branch.

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:return: the InstructionInfo for the current instruction
		:rtype: InstructionInfo
		"""
		info = core.BNInstructionInfo()
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNGetInstructionInfo(self.handle, buf, addr, len(data), info):
			return None
		result = InstructionInfo()
		result.length = info.length
		result.branch_delay = info.branchDelay
		for i in xrange(0, info.branchCount):
			branch_type = core.BNBranchType_names[info.branchType[i]]
			target = info.branchTarget[i]
			if info.branchArch[i]:
				arch = Architecture(info.branchArch[i])
			else:
				arch = None
			result.add_branch(branch_type, target, arch)
		return result

	def get_instruction_text(self, data, addr):
		"""
		``get_instruction_text`` returns a list of InstructionTextToken objects for the instruction at the given virtual
		address ``addr`` with data ``data``.

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:return: an InstructionTextToken list for the current instruction
		:rtype: list(InstructionTextToken)
		"""
		data = str(data)
		count = ctypes.c_ulonglong()
		length = ctypes.c_ulonglong()
		length.value = len(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		if not core.BNGetInstructionText(self.handle, buf, addr, length, tokens, count):
			return None, 0
		result = []
		for i in xrange(0, count.value):
			token_type = core.BNInstructionTextTokenType_names[tokens[i].type]
			text = tokens[i].text
			value = tokens[i].value
			size = tokens[i].size
			operand = tokens[i].operand
			result.append(InstructionTextToken(token_type, text, value, size, operand))
		core.BNFreeInstructionText(tokens, count.value)
		return result, length.value

	def get_instruction_low_level_il(self, data, addr, il):
		"""
		``get_instruction_low_level_il`` appends LowLevelILExpr objects for the instruction at the given virtual
		address ``addr`` with data ``data``.

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:param LowLevelILFunction il: The function the current instruction belongs to
		:return: the length of the current instruction
		:rtype: int
		"""
		data = str(data)
		length = ctypes.c_ulonglong()
		length.value = len(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		core.BNGetInstructionLowLevelIL(self.handle, buf, addr, length, il.handle)
		return length.value

	def get_reg_name(self, reg):
		"""
		``get_reg_name`` gets a register name from a register number.

		:param int reg: register number
		:return: the corresponding register string
		:rtype: str
		"""
		return core.BNGetArchitectureRegisterName(self.handle, reg)

	def get_flag_name(self, flag):
		"""
		``get_flag_name`` gets a flag name from a flag number.

		:param int reg: register number
		:return: the corresponding register string
		:rtype: str
		"""
		return core.BNGetArchitectureFlagName(self.handle, flag)

	def get_flag_write_type_name(self, write_type):
		"""
		``get_flag_write_type_name`` gets the flag write type name for the given flag.

		:param int write_type: flag
		:return: flag write type name
		:rtype: str
		"""
		return core.BNGetArchitectureFlagWriteTypeName(self.handle, write_type)

	def get_flag_by_name(self, flag):
		"""
		``get_flag_by_name`` get flag name for flag index.

		:param int flag: flag index
		:return: flag name for flag index
		:rtype: str
		"""
		return self._flags[flag]

	def get_flag_write_type_by_name(self, write_type):
		"""
		``get_flag_write_type_by_name`` gets the flag write type name for the flage write type.

		:param int write_type: flag write type
		:return: flag write type
		:rtype: str
		"""
		return self._flag_write_types[write_type]

	def get_flag_write_low_level_il(self, op, size, write_type, operands, il):
		"""
		:param LowLevelILOperation op:
		:param int size:
		:param str write_type:
		:param list(str or int) operands: a list of either items that are either string register names or constant \
		integer values
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		operand_list = (core.BNRegisterOrConstant * len(operands))()
		for i in xrange(len(operands)):
			if isinstance(operands[i], str):
				operand_list[i].constant = False
				operand_list[i].reg = self._flags[operands[i]]
			else:
				operand_list[i].constant = True
				operand_list[i].value = operands[i]
		return LowLevelILExpr(core.BNGetArchitectureFlagWriteLowLevelIL(self.handle, op, size,
		        self._flag_write_types[write_type], operand_list, len(operand_list), il.handle))

	def get_default_flag_write_low_level_il(self, op, size, write_type, operands, il):
		"""
		:param LowLevelILOperation op:
		:param int size:
		:param str write_type:
		:param list(str or int) operands: a list of either items that are either string register names or constant \
		integer values
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr index
		"""
		operand_list = (core.BNRegisterOrConstant * len(operands))()
		for i in xrange(len(operands)):
			if isinstance(operands[i], str):
				operand_list[i].constant = False
				operand_list[i].reg = self._flags[operands[i]]
			else:
				operand_list[i].constant = True
				operand_list[i].value = operands[i]
		return LowLevelILExpr(core.BNGetDefaultArchitectureFlagWriteLowLevelIL(self.handle, op, size,
		        self._flag_write_types[write_type], operand_list, len(operand_list), il.handle))

	def get_flag_condition_low_level_il(self, cond, il):
		"""
		:param LowLevelILFlagCondition cond:
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		return LowLevelILExpr(core.BNGetArchitectureFlagConditionLowLevelIL(self.handle, cond, il.handle))

	def get_modified_regs_on_write(self, reg):
		"""
		``get_modified_regs_on_write`` returns a list of register names that are modified when ``reg`` is written.

		:param str reg: string register name
		:return: list of register names
		:rtype: list(str)
		"""
		reg = core.BNGetArchitectureRegisterByName(self.handle, str(reg))
		count = ctypes.c_ulonglong()
		regs = core.BNGetModifiedArchitectureRegistersOnWrite(self.handle, reg, count)
		result = []
		for i in xrange(0, count.value):
			result.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def assemble(self, code, addr = 0):
		"""
		``assemble`` converts the string of assembly instructions ``code`` loaded at virtual address ``addr`` to the
		byte representation of those instructions.

		:param str code: string representation of the instructions to be assembled
		:param int addr: virtual address that the instructions will be loaded at
		:return: the bytes for the assembled instructions or error string
		:rtype: (a tuple of instructions and empty string) or (or None and error string)
		:Example:

			>>> arch.assemble("je 10")
			('\\x0f\\x84\\x04\\x00\\x00\\x00', '')
			>>>
		"""
		result = DataBuffer()
		errors = ctypes.c_char_p()
		if not core.BNAssemble(self.handle, code, addr, result.handle, errors):
			return None, errors.value
		return str(result), errors.value

	def is_never_branch_patch_available(self, data, addr):
		"""
		``is_never_branch_patch_available`` determines if the instruction ``data`` at ``addr`` can be made to **never branch**.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_never_branch_patch_available(arch.assemble("je 10")[0], 0)
			True
			>>> arch.is_never_branch_patch_available(arch.assemble("nop")[0], 0)
			False
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureNeverBranchPatchAvailable(self.handle, buf, addr, len(data))

	def is_always_branch_patch_available(self, data, addr):
		"""
		``is_always_branch_patch_available`` determines if the instruction ``data`` at ``addr`` can be made to
		**always branch**.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_always_branch_patch_available(arch.assemble("je 10")[0], 0)
			True
			>>> arch.is_always_branch_patch_available(arch.assemble("nop")[0], 0)
			False
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureAlwaysBranchPatchAvailable(self.handle, buf, addr, len(data))

	def is_invert_branch_patch_available(self, data, addr):
		"""
		``is_always_branch_patch_available`` determines if the instruction ``data`` at ``addr`` can be inverted.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_invert_branch_patch_available(arch.assemble("je 10")[0], 0)
			True
			>>> arch.is_invert_branch_patch_available(arch.assemble("nop")[0], 0)
			False
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureInvertBranchPatchAvailable(self.handle, buf, addr, len(data))

	def is_skip_and_return_zero_patch_available(self, data, addr):
		"""
		``is_skip_and_return_zero_patch_available`` determines if the instruction ``data`` at ``addr`` is a *call-like*
		instruction that can be made into an instruction *returns zero*.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("call 0")[0], 0)
			True
			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("call eax")[0], 0)
			True
			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("jmp eax")[0], 0)
			False
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureSkipAndReturnZeroPatchAvailable(self.handle, buf, addr, len(data))

	def is_skip_and_return_value_patch_available(self, data, addr):
		"""
		``is_skip_and_return_zero_patch_available`` determines if the instruction ``data`` at ``addr`` is a *call-like*
		instruction that can be made into an instruction *returns a value*.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("call 0")[0], 0)
			True
			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("jmp eax")[0], 0)
			False
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureSkipAndReturnValuePatchAvailable(self.handle, buf, addr, len(data))

	def convert_to_nop(self, data, addr):
		"""
		``convert_to_nop`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of nop
		instructions of the same length as data.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) worth of no-operation instructions
		:rtype: str
		:Example:

			>>> arch.convert_to_nop("\\x00\\x00", 0)
			'\\x90\\x90'
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureConvertToNop(self.handle, buf, addr, len(data)):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def always_branch(self, data, addr):
		"""
		``always_branch`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of bytes
		of the same length which always branches.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) which always branches to the same location as the provided instruction
		:rtype: str
		:Example:

			>>> bytes = arch.always_branch(arch.assemble("je 10")[0], 0)
			>>> arch.get_instruction_text(bytes, 0)
			(['nop     '], 1L)
			>>> arch.get_instruction_text(bytes[1:], 0)
			(['jmp     ', '0x9'], 5L)
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureAlwaysBranch(self.handle, buf, addr, len(data)):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def invert_branch(self, data, addr):
		"""
		``invert_branch`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of bytes
		of the same length which inverts the branch of provided instruction.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) which always branches to the same location as the provided instruction
		:rtype: str
		:Example:

			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("je 10")[0], 0), 0)
			(['jne     ', '0xa'], 6L)
			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("jo 10")[0], 0), 0)
			(['jno     ', '0xa'], 6L)
			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("jge 10")[0], 0), 0)
			(['jl      ', '0xa'], 6L)
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureInvertBranch(self.handle, buf, addr, len(data)):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def skip_and_return_value(self, data, addr, value):
		"""
		``skip_and_return_value`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of
		bytes of the same length which doesn't call and instead *return a value*.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) which always branches to the same location as the provided instruction
		:rtype: str
		:Example:

			>>> arch.get_instruction_text(arch.skip_and_return_value(arch.assemble("call 10")[0], 0, 0), 0)
			(['mov     ', 'eax', ', ', '0x0'], 5L)
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureSkipAndReturnValue(self.handle, buf, addr, len(data), value):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def is_view_type_constant_defined(self, type_name, const_name):
		"""

		:param str type_name: the BinaryView type name of the constant to query
		:param str const_name: the constant name to query
		:rtype: None
		:Example:

			>>> arch.set_view_type_constant("ELF", "R_COPY", ELF_RELOC_COPY)
			>>> arch.is_view_type_constant_defined("ELF", "R_COPY")
			True
			>>> arch.is_view_type_constant_defined("ELF", "NOT_THERE")
			False
			>>>
		"""
		return core.BNIsBinaryViewTypeArchitectureConstantDefined(self.handle, type_name, const_name)

	def get_view_type_constant(self, type_name, const_name, default_value = 0):
		"""
		``get_view_type_constant`` retrieves the view type constant for the given type_name and const_name.

		:param str type_name: the BinaryView type name of the constant to be retrieved
		:param str const_name: the constant name to retrieved
		:param int value: optional default value if the type_name is not present. default value is zero.
		:return: The BinaryView type constant or the default_value if not found
		:rtype: int
		:Example:

			>>> ELF_RELOC_COPY = 5
			>>> arch.set_view_type_constant("ELF", "R_COPY", ELF_RELOC_COPY)
			>>> arch.get_view_type_constant("ELF", "R_COPY")
			5L
			>>> arch.get_view_type_constant("ELF", "NOT_HERE", 100)
			100L
		"""
		return core.BNGetBinaryViewTypeArchitectureConstant(self.handle, type_name, const_name, default_value)

	def set_view_type_constant(self, type_name, const_name, value):
		"""
		``set_view_type_constant`` creates a new binaryview type constant.

		:param str type_name: the BinaryView type name of the constant to be registered
		:param str const_name: the constant name to register
		:param int value: the value of the constant
		:rtype: None
		:Example:

			>>> ELF_RELOC_COPY = 5
			>>> arch.set_view_type_constant("ELF", "R_COPY", ELF_RELOC_COPY)
			>>>
		"""
		core.BNSetBinaryViewTypeArchitectureConstant(self.handle, type_name, const_name, value)

	def parse_types_from_source(self, source, filename = None, include_dirs = []):
		"""
		``parse_types_from_source`` parses the source string and any needed headers searching for them in
		the optional list of directories provided in ``include_dirs``.

		:param str source: source string to be parsed
		:param str filename: optional source filename
		:param list(str) include_dirs: optional list of string filename include directories
		:return: a tuple of py:class:`TypeParserResult` and error string
		:rtype: tuple(TypeParserResult,str)
		:Example:

			>>> arch.parse_types_from_source('int foo;\\nint bar(int x);\\nstruct bas{int x,y;};\\n')
			({types: {'bas': <type: struct bas>}, variables: {'foo': <type: int32_t>}, functions:{'bar':
			<type: int32_t(int32_t x)>}}, '')
			>>>
		"""

		if filename is None:
			filename = "input"
		dir_buf = (ctypes.c_char_p * len(include_dirs))()
		for i in xrange(0, len(include_dirs)):
			dir_buf[i] = str(include_dirs[i])
		parse = core.BNTypeParserResult()
		errors = ctypes.c_char_p()
		result = core.BNParseTypesFromSource(self.handle, source, filename, parse, errors, dir_buf, len(include_dirs))
		error_str = errors.value
		core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
		if not result:
			return (None, error_str)
		types = {}
		variables = {}
		functions = {}
		for i in xrange(0, parse.typeCount):
			types[parse.types[i].name] = Type(core.BNNewTypeReference(parse.types[i].type))
		for i in xrange(0, parse.variableCount):
			variables[parse.variables[i].name] = Type(core.BNNewTypeReference(parse.variables[i].type))
		for i in xrange(0, parse.functionCount):
			functions[parse.functions[i].name] = Type(core.BNNewTypeReference(parse.functions[i].type))
		BNFreeTypeParserResult(parse)
		return (TypeParserResult(types, variables, functions), error_str)

	def parse_types_from_source_file(self, filename, include_dirs = []):
		"""
		``parse_types_from_source_file`` parses the source file ``filename`` and any needed headers searching for them in
		the optional list of directories provided in ``include_dirs``.

		:param str filename: filename of file to be parsed
		:param list(str) include_dirs: optional list of string filename include directories
		:return: a tuple of py:class:`TypeParserResult` and error string
		:rtype: tuple(TypeParserResult, str)
		:Example:

			>>> file = "/Users/binja/tmp.c"
			>>> open(file).read()
			'int foo;\\nint bar(int x);\\nstruct bas{int x,y;};\\n'
			>>> arch.parse_types_from_source_file(file)
			({types: {'bas': <type: struct bas>}, variables: {'foo': <type: int32_t>}, functions:
			{'bar': <type: int32_t(int32_t x)>}}, '')
			>>>
		"""
		dir_buf = (ctypes.c_char_p * len(include_dirs))()
		for i in xrange(0, len(include_dirs)):
			dir_buf[i] = str(include_dirs[i])
		parse = core.BNTypeParserResult()
		errors = ctypes.c_char_p()
		result = core.BNParseTypesFromSourceFile(self.handle, filename, parse, errors, dir_buf, len(include_dirs))
		error_str = errors.value
		core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
		if not result:
			return (None, error_str)
		types = {}
		variables = {}
		functions = {}
		for i in xrange(0, parse.typeCount):
			types[parse.types[i].name] = Type(core.BNNewTypeReference(parse.types[i].type))
		for i in xrange(0, parse.variableCount):
			variables[parse.variables[i].name] = Type(core.BNNewTypeReference(parse.variables[i].type))
		for i in xrange(0, parse.functionCount):
			functions[parse.functions[i].name] = Type(core.BNNewTypeReference(parse.functions[i].type))
		BNFreeTypeParserResult(parse)
		return (TypeParserResult(types, variables, functions), error_str)

	def register_calling_convention(self, cc):
		"""
		``register_calling_convention`` registers a new calling convention for the Architecture.

		:param CallingConvention cc: CallingConvention object to be registered
		:rtype: None
		"""
		core.BNRegisterCallingConvention(self.handle, cc.handle)

class ReferenceSource(object):
	def __init__(self, func, arch, addr):
		self.function = func
		self.arch = arch
		self.address = addr

	def __repr__(self):
		if self.arch:
			return "<ref: %s@%#x>" % (self.arch.name, self.address)
		else:
			return "<ref: %#x>" % self.address

class LowLevelILLabel(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = (core.BNLowLevelILLabel * 1)()
			core.BNLowLevelILInitLabel(self.handle)
		else:
			self.handle = handle

class LowLevelILInstruction(object):
	"""
	``class LowLevelILInstruction`` Low Level Intermediate Language Instructions are infinite length tree-based
	instructions. Tree-based instructions use infix notation with the left hand operand being the destination operand.
	Infix notation is thus more natural to read than other notations (e.g. x86 ``mov eax, 0`` vs. LLIL ``eax = 0``).
	"""

	ILOperations = {
		core.LLIL_NOP:           [],
		core.LLIL_SET_REG:       [("dest", "reg"), ("src", "expr")],
		core.LLIL_SET_REG_SPLIT: [("hi", "reg"), ("lo", "reg"), ("src", "expr")],
		core.LLIL_SET_FLAG:      [("dest", "flag"), ("src", "expr")],
		core.LLIL_LOAD:          [("src", "expr")],
		core.LLIL_STORE:         [("dest", "expr"), ("src", "expr")],
		core.LLIL_PUSH:          [("src", "expr")],
		core.LLIL_POP:           [],
		core.LLIL_REG:           [("src", "reg")],
		core.LLIL_CONST:         [("value", "int")],
		core.LLIL_FLAG:          [("src", "flag")],
		core.LLIL_FLAG_BIT:      [("src", "flag"), ("bit", "int")],
		core.LLIL_ADD:           [("left", "expr"), ("right", "expr")],
		core.LLIL_ADC:           [("left", "expr"), ("right", "expr")],
		core.LLIL_SUB:           [("left", "expr"), ("right", "expr")],
		core.LLIL_SBB:           [("left", "expr"), ("right", "expr")],
		core.LLIL_AND:           [("left", "expr"), ("right", "expr")],
		core.LLIL_OR:            [("left", "expr"), ("right", "expr")],
		core.LLIL_XOR:           [("left", "expr"), ("right", "expr")],
		core.LLIL_LSL:           [("left", "expr"), ("right", "expr")],
		core.LLIL_LSR:           [("left", "expr"), ("right", "expr")],
		core.LLIL_ASR:           [("left", "expr"), ("right", "expr")],
		core.LLIL_ROL:           [("left", "expr"), ("right", "expr")],
		core.LLIL_RLC:           [("left", "expr"), ("right", "expr")],
		core.LLIL_ROR:           [("left", "expr"), ("right", "expr")],
		core.LLIL_RRC:           [("left", "expr"), ("right", "expr")],
		core.LLIL_MUL:           [("left", "expr"), ("right", "expr")],
		core.LLIL_MULU_DP:       [("left", "expr"), ("right", "expr")],
		core.LLIL_MULS_DP:       [("left", "expr"), ("right", "expr")],
		core.LLIL_DIVU:          [("left", "expr"), ("right", "expr")],
		core.LLIL_DIVU_DP:       [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		core.LLIL_DIVS:          [("left", "expr"), ("right", "expr")],
		core.LLIL_DIVS_DP:       [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		core.LLIL_MODU:          [("left", "expr"), ("right", "expr")],
		core.LLIL_MODU_DP:       [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		core.LLIL_MODS:          [("left", "expr"), ("right", "expr")],
		core.LLIL_MODS_DP:       [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		core.LLIL_NEG:           [("src", "expr")],
		core.LLIL_NOT:           [("src", "expr")],
		core.LLIL_SX:            [("src", "expr")],
		core.LLIL_ZX:            [("src", "expr")],
		core.LLIL_JUMP:          [("dest", "expr")],
		core.LLIL_JUMP_TO:       [("dest", "expr"), ("targets", "int_list")],
		core.LLIL_CALL:          [("dest", "expr")],
		core.LLIL_RET:           [("dest", "expr")],
		core.LLIL_NORET:         [],
		core.LLIL_IF:            [("condition", "expr"), ("true", "int"), ("false", "int")],
		core.LLIL_GOTO:          [("dest", "int")],
		core.LLIL_FLAG_COND:     [("condition", "cond")],
		core.LLIL_CMP_E:         [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_NE:        [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_SLT:       [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_ULT:       [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_SLE:       [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_ULE:       [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_SGE:       [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_UGE:       [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_SGT:       [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_UGT:       [("left", "expr"), ("right", "expr")],
		core.LLIL_TEST_BIT:      [("left", "expr"), ("right", "expr")],
		core.LLIL_BOOL_TO_INT:   [("src", "expr")],
		core.LLIL_SYSCALL:       [],
		core.LLIL_BP:            [],
		core.LLIL_TRAP:          [("value", "int")],
		core.LLIL_UNDEF:         [],
		core.LLIL_UNIMPL:        [],
		core.LLIL_UNIMPL_MEM:    [("src", "expr")]
	}

	def __init__(self, func, expr_index, instr_index = None):
		instr = core.BNGetLowLevelILByIndex(func.handle, expr_index)
		self.function = func
		self.expr_index = expr_index
		self.instr_index = instr_index
		self.operation = instr.operation
		self.operation_name = core.BNLowLevelILOperation_names[instr.operation]
		self.size = instr.size
		self.address = instr.address
		self.source_operand = instr.sourceOperand
		if instr.flags == 0:
			self.flags = None
		else:
			self.flags = func.arch.get_flag_write_type_name(instr.flags)
		if self.source_operand == 0xffffffff:
			self.source_operand = None
		operands = LowLevelILInstruction.ILOperations[instr.operation]
		self.operands = []
		for i in xrange(0, len(operands)):
			name, operand_type = operands[i]
			if operand_type == "int":
				value = instr.operands[i]
			elif operand_type == "expr":
				value = LowLevelILInstruction(func, instr.operands[i])
			elif operand_type == "reg":
				if (instr.operands[i] & 0x80000000) != 0:
					value = instr.operands[i]
				else:
					value = func.arch.get_reg_name(instr.operands[i])
			elif operand_type == "flag":
				value = func.arch.get_flag_name(instr.operands[i])
			elif operand_type == "cond":
				value = core.BNLowLevelILFlagCondition_names[instr.operands[i]]
			elif operand_type == "int_list":
				count = ctypes.c_ulonglong()
				operands = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				value = []
				for i in xrange(count.value):
					value.append(operands[i])
				core.BNLowLevelILFreeOperandList(operands)
			self.operands.append(value)
			self.__dict__[name] = value

	def __str__(self):
		tokens = self.tokens
		if tokens is None:
			return "invalid"
		result = ""
		for token in tokens:
			result += token.text
		return result

	def __repr__(self):
		return "<il: %s>" % str(self)

	@property
	def tokens(self):
		"""LLIL tokens (read-only)"""
		count = ctypes.c_ulonglong()
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		if (self.instr_index is not None) and (self.function.source_function is not None):
			if not core.BNGetLowLevelILInstructionText(self.function.handle, self.function.source_function.handle,
				self.function.arch.handle, self.instr_index, tokens, count):
				return None
		else:
			if not core.BNGetLowLevelILExprText(self.function.handle, self.function.arch.handle,
				self.expr_index, tokens, count):
				return None
		result = []
		for i in xrange(0, count.value):
			token_type = core.BNInstructionTextTokenType_names[tokens[i].type]
			text = tokens[i].text
			value = tokens[i].value
			size = tokens[i].size
			operand = tokens[i].operand
			result.append(InstructionTextToken(token_type, text, value, size, operand))
		core.BNFreeInstructionText(tokens, count.value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

class LowLevelILExpr(object):
	"""
	``class LowLevelILExpr`` hold the index of IL Expressions.

	.. note:: This class shouldn't be instantiated directly. Rather the helper members of LowLevelILFunction should be \
	used instead.
	"""
	def __init__(self, index):
		self.index = index

class LowLevelILFunction(object):
	"""
	``class LowLevelILFunction`` contains the list of LowLevelILExpr objects that make up a function. LowLevelILExpr
	objects can be added to the LowLevelILFunction by calling ``append`` and passing the result of the various class
	methods which return LowLevelILExpr objects.


	LowLevelILFlagCondition values used as parameters in the ``flag_condition`` method.

		======================= ========== ===============================
		LowLevelILFlagCondition Operator   Description
		======================= ========== ===============================
		LLFC_E                  ==         Equal
		LLFC_NE                 !=         Not equal
		LLFC_SLT                s<         Signed less than
		LLFC_ULT                u<         Unsigned less than
		LLFC_SLE                s<=        Signed less than or equal
		LLFC_ULE                u<=        Unsigned less than or equal
		LLFC_SGE                s>=        Signed greater than or equal
		LLFC_UGE                u>=        Unsigned greater than or equal
		LLFC_SGT                s>         Signed greather than
		LLFC_UGT                u>         Unsigned greater than
		LLFC_NEG                -          Negative
		LLFC_POS                +          Positive
		LLFC_O                  overflow   Overflow
		LLFC_NO                 !overflow  No overflow
		======================= ========== ===============================
	"""
	def __init__(self, arch, handle = None, source_func = None):
		self.arch = arch
		self.source_function = source_func
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNLowLevelILFunction)
		else:
			func_handle = None
			if self.source_function is not None:
				func_handle = self.source_function.handle
			self.handle = core.BNCreateLowLevelILFunction(arch.handle, func_handle)

	def __del__(self):
		core.BNFreeLowLevelILFunction(self.handle)

	@property
	def current_address(self):
		"""Current IL Address (read/write)"""
		return core.BNLowLevelILGetCurrentAddress(self.handle)

	@current_address.setter
	def current_address(self, value):
		core.BNLowLevelILSetCurrentAddress(self.handle, value)

	@property
	def temp_reg_count(self):
		"""Number of temporary registers (read-only)"""
		return core.BNGetLowLevelILTemporaryRegisterCount(self.handle)

	@property
	def temp_flag_count(self):
		"""Number of temporary flags (read-only)"""
		return core.BNGetLowLevelILTemporaryFlagCount(self.handle)

	@property
	def basic_blocks(self):
		"""list of LowLevelILBasicBlock objects (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetLowLevelILBasicBlockList(self.handle, count)
		result = []
		view = None
		if self.source_function is not None:
			view = self.source_function.view
		for i in xrange(0, count.value):
			result.append(LowLevelILBasicBlock(view, core.BNNewBasicBlockReference(blocks[i]), self))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __len__(self):
		return int(core.BNGetLowLevelILInstructionCount(self.handle))

	def __getitem__(self, i):
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError, "expected integer instruction index"
		if isinstance(i, LowLevelILExpr):
			return LowLevelILInstruction(self, i.index)
		if (i < 0) or (i >= len(self)):
			raise IndexError, "index out of range"
		return LowLevelILInstruction(self, core.BNGetLowLevelILIndexForInstruction(self.handle, i), i)

	def __setitem__(self, i, j):
		raise IndexError, "instruction modification not implemented"

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetLowLevelILBasicBlockList(self.handle, count)
		view = None
		if self.source_function is not None:
			view = self.source_function.view
		try:
			for i in xrange(0, count.value):
				yield LowLevelILBasicBlock(view, core.BNNewBasicBlockReference(blocks[i]), self)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def clear_indirect_branches(self):
		core.BNLowLevelILClearIndirectBranches(self.handle)

	def set_indirect_branches(self, branches):
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in xrange(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNLowLevelILSetIndirectBranches(self.handle, branch_list, len(branches))

	def expr(self, operation, a = 0, b = 0, c = 0, d = 0, size = 0, flags = None):
		if isinstance(operation, str):
			operation = core.BNLowLevelILOperation_by_name[operation]
		if isinstance(flags, str):
			flags = self.arch.get_flag_write_type_by_name(flags)
		elif flags is None:
			flags = 0
		return LowLevelILExpr(core.BNLowLevelILAddExpr(self.handle, operation, size, flags, a, b, c, d))

	def append(self, expr):
		"""
		``append`` adds the LowLevelILExpr ``expr`` to the current LowLevelILFunction.

		:param LowLevelILExpr expr: the LowLevelILExpr to add to the current LowLevelILFunction
		:return: number of LowLevelILExpr in the current function
		:rtype: int
		"""
		return core.BNLowLevelILAddInstruction(self.handle, expr.index)

	def nop(self):
		"""
		``nop`` no operation, this instruction does nothing

		:return: The no operation expression
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_NOP)

	def set_reg(self, size, reg, value, flags = 0):
		"""
		``set_reg`` sets the register ``reg`` of size ``size`` to the expression ``value``

		:param int size: size of the register parameter in bytes
		:param str reg: the register name
		:param LowLevelILExpr value: an expression to set the register to
		:param str flags: which flags are set by this operation
		:return: The expression ``reg = value``
		:rtype: LowLevelILExpr
		"""
		if isinstance(reg, str):
			reg = self.arch.regs[reg].index
		return self.expr(core.LLIL_SET_REG, reg, value.index, size = size, flags = flags)

	def set_reg_split(self, size, hi, lo, value, flags = 0):
		"""
		``set_reg_split`` uses ``hi`` and ``lo`` as a single extended register setting ``hi:lo`` to the expression
		``value``.

		:param int size: size of the register parameter in bytes
		:param str hi: the high register name
		:param str lo: the low register name
		:param LowLevelILExpr value: an expression to set the split regiters to
		:param str flags: which flags are set by this operation
		:return: The expression ``hi:lo = value``
		:rtype: LowLevelILExpr
		"""
		if isinstance(hi, str):
			hi = self.arch.regs[hi].index
		if isinstance(lo, str):
			lo = self.arch.regs[lo].index
		return self.expr(core.LLIL_SET_REG_SPLIT, hi, lo, value.index, size = size, flags = flags)

	def set_flag(self, flag, value):
		"""
		``set_flag`` sets the flag ``flag`` to the LowLevelILExpr ``value``

		:param str flag: the low register name
		:param LowLevelILExpr value: an expression to set the flag to
		:return: The expression FLAG.flag = value
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_SET_FLAG, self.arch.get_flag_by_name(flag), value.index)

	def load(self, size, addr):
		"""
		``laod`` Reads ``size`` bytes from the expression ``addr``

		:param int size: number of bytes to read
		:param LowLevelILExpr addr: the expression to read memory from
		:return: The expression ``[addr].size``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_LOAD, addr.index, size = size)

	def store(self, size, addr, value):
		"""
		``store`` Writes ``size`` bytes to expression ``addr`` read from expression ``value``

		:param int size: number of bytes to write
		:param LowLevelILExpr addr: the expression to write to
		:param LowLevelILExpr value: the expression to be written
		:return: The expression ``[addr].size = value``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_STORE, addr.index, value.index, size = size)

	def push(self, size, value):
		"""
		``push`` writes ``size`` bytes from expression ``value`` to the stack, adjusting the stack by ``size``.

		:param int size: number of bytes to write and adjust the stack by
		:param LowLevelILExpr value: the expression to write
		:return: The expression push(value)
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_PUSH, value.index, size = size)

	def pop(self, size):
		"""
		``pop`` reads ``size`` bytes from the stack, adjusting the stack by ``size``.

		:param int size: number of bytes to read from the stack
		:return: The expression ``pop``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_POP, size = size)

	def reg(self, size, reg):
		"""
		``reg`` returns a register of size ``size`` with name ``name``

		:param int size: the size of the register in bytes
		:param str reg: the name of the register
		:return: A register expression for the given string
		:rtype: LowLevelILExpr
		"""
		if isinstance(reg, str):
			reg = self.arch.regs[reg].index
		return self.expr(core.LLIL_REG, reg, size = size)

	def const(self, size, value):
		"""
		``const`` returns an expression for the constant integer ``value`` with size ``size``

		:param int size: the size of the constant in bytes
		:param int value: integer value of the constant
		:return: A constant expression of given value and size
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CONST, value, size = size)

	def flag(self, reg):
		"""
		``flag`` returns a flag expression for the given flag name.

		:param str reg: name of the flag expression to retrieve
		:return: A flag expression of given flag name
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_FLAG, self.arch.get_flag_by_name(reg))

	def flag_bit(self, size, reg, bit):
		"""
		``flag_bit`` sets the flag named ``reg`` and size ``size`` to the constant integer value ``bit``

		:param int size: the size of the flag
		:param str reg: flag value
		:param int bit: integer value to set the bit to
		:return: A constant expression of given value and size ``FLAG.reg = bit``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_FLAG_BIT, self.arch.get_flag_by_name(reg), bit, size = size)

	def add(self, size, a, b, flags = None):
		"""
		``add`` adds expression ``a`` to expression ``b`` potentially setting flags ``flags`` and returning
		an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``add.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_ADD, a.index, b.index, size = size, flags = flags)

	def add_carry(self, size, a, b, flags = None):
		"""
		``add_carry`` adds with carry expression ``a`` to expression ``b`` potentially setting flags ``flags`` and returning
		an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``adc.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_ADC, a.index, b.index, size = size, flags = flags)

	def sub(self, size, a, b, flags = None):
		"""
		``sub`` subtracts expression ``b`` from expression ``a`` potentially setting flags ``flags`` and returning
		an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``sub.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_SUB, a.index, b.index, size = size, flags = flags)

	def sub_borrow(self, size, a, b, flags = None):
		"""
		``sub_borrow`` subtracts with borrow expression ``b`` from expression ``a`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``sbc.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_SBB, a.index, b.index, size = size, flags = flags)

	def and_expr(self, size, a, b, flags = None):
		"""
		``and_expr`` bitwise and's expression ``a`` and expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``and.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_AND, a.index, b.index, size = size, flags = flags)

	def or_expr(self, size, a, b, flags = None):
		"""
		``or_expr`` bitwise or's expression ``a`` and expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``or.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_OR, a.index, b.index, size = size, flags = flags)

	def xor_expr(self, size, a, b, flags = None):
		"""
		``xor_expr`` xor's expression ``a`` with expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``xor.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_XOR, a.index, b.index, size = size, flags = flags)

	def shift_left(self, size, a, b, flags = None):
		"""
		``shift_left`` subtracts with borrow expression ``b`` from expression ``a`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``lsl.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_LSL, a.index, b.index, size = size, flags = flags)

	def logical_shift_right(self, size, a, b, flags = None):
		"""
		``logical_shift_right`` shifts logically right expression ``a`` by expression ``b`` potentially setting flags
		``flags``and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``lsr.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_LSR, a.index, b.index, size = size, flags = flags)

	def arith_shift_right(self, size, a, b, flags = None):
		"""
		``arith_shift_right`` shifts arithmatic right expression ``a`` by expression ``b``  potentially setting flags
		``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``asr.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_ASR, a.index, b.index, size = size, flags = flags)

	def rotate_left(self, size, a, b, flags = None):
		"""
		``rotate_left`` bitwise rotates left expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``rol.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_ROL, a.index, b.index, size = size, flags = flags)

	def rotate_left_carry(self, size, a, b, flags = None):
		"""
		``rotate_left_carry`` bitwise rotates left with carry expression ``a`` by expression ``b`` potentially setting
		flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``rcl.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_RLC, a.index, b.index, size = size, flags = flags)

	def rotate_right(self, size, a, b, flags = None):
		"""
		``rotate_right`` bitwise rotates right expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``ror.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_ROR, a.index, b.index, size = size, flags = flags)

	def rotate_right_carry(self, size, a, b, flags = None):
		"""
		``rotate_right_carry`` bitwise rotates right with carry expression ``a`` by expression ``b`` potentially setting
		flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``rcr.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_RRC, a.index, b.index, size = size, flags = flags)

	def mult(self, size, a, b, flags = None):
		"""
		``mult`` multiplies expression ``a`` by expression ``b`` potentially setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``sbc.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_MUL, a.index, b.index, size = size, flags = flags)

	def mult_double_prec_signed(self, size, a, b, flags = None):
		"""
		``mult_double_prec_signed`` multiplies signed with double precision expression ``a`` by expression ``b``
		potentially setting flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``muls.dp.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_MULS_DP, a.index, b.index, size = size, flags = flags)

	def mult_double_prec_unsigned(self, size, a, b, flags = None):
		"""
		``mult_double_prec_unsigned`` multiplies unsigned with double precision expression ``a`` by expression ``b``
		potentially setting flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``muls.dp.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_MULU_DP, a.index, b.index, size = size, flags = flags)

	def div_signed(self, size, a, b, flags = None):
		"""
		``div_signed`` signed divide expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_DIVS, a.index, b.index, size = size, flags = flags)

	def div_double_prec_signed(self, size, hi, lo, b, flags = None):
		"""
		``div_double_prec_signed`` signed double precision divide using expression ``hi`` and expression ``lo`` as a single
		double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an expression
		of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr hi: high LHS expression
		:param LowLevelILExpr lo: low LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.dp.<size>{<flags>}(hi:lo, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_DIVS_DP, hi.index, lo.index, b.index, size = size, flags = flags)

	def div_unsigned(self, size, a, b, flags = None):
		"""
		``div_unsigned`` unsigned divide expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_DIVS, a.index, b.index, size = size, flags = flags)

	def div_double_prec_unsigned(self, size, hi, lo, b, flags = None):
		"""
		``div_double_prec_unsigned`` unsigned double precision divide using expression ``hi`` and expression ``lo`` as
		a single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr hi: high LHS expression
		:param LowLevelILExpr lo: low LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.dp.<size>{<flags>}(hi:lo, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_DIVS_DP, hi.index, lo.index, b.index, size = size, flags = flags)

	def mod_signed(self, size, a, b, flags = None):
		"""
		``mod_signed`` signed modulus expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``mods.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_MODS, a.index, b.index, size = size, flags = flags)

	def mod_double_prec_signed(self, size, hi, lo, b, flags = None):
		"""
		``mod_double_prec_signed`` signed double precision modulus using expression ``hi`` and expression ``lo`` as a single
		double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an expression
		of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr hi: high LHS expression
		:param LowLevelILExpr lo: low LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``mods.dp.<size>{<flags>}(hi:lo, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_MODS_DP, hi.index, lo.index, b.index, size = size, flags = flags)

	def mod_unsigned(self, size, a, b, flags = None):
		"""
		``mod_unsigned`` unsigned modulus expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``modu.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_MODS, a.index, b.index, size = size, flags = flags)

	def mod_double_prec_unsigned(self, size, hi, lo, b, flags = None):
		"""
		``mod_double_prec_unsigned`` unsigned double precision modulus using expression ``hi`` and expression ``lo`` as
		a single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr hi: high LHS expression
		:param LowLevelILExpr lo: low LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``modu.dp.<size>{<flags>}(hi:lo, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_MODS_DP, hi.index, lo.index, b.index, size = size, flags = flags)

	def neg_expr(self, size, value, flags = None):
		"""
		``neg_expr`` two's complement sign negation of expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``neg.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_NEG, value.index, size = size, flags = flags)

	def not_expr(self, size, value, flags = None):
		"""
		``not_expr`` bitwise inverse of expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to bitwise invert
		:param str flags: optional, flags to set
		:return: The expression ``not.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_NOT, value.index, size = size, flags = flags)

	def sign_extend(self, size, value):
		"""
		``sign_extend`` two's complement sign-extends the expression in ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to sign extend
		:return: The expression ``sx.<size>(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_SX, value.index, size = size)

	def zero_extend(self, size, value):
		"""
		``sign_extend`` zero-extends the expression in ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to zero extend
		:return: The expression ``sx.<size>(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_ZX, value.index, size = size)

	def jump(self, dest):
		"""
		``jump`` returns an expression which jumps (branches) to the expression ``dest``

		:param LowLevelILExpr dest: the expression to jump to
		:return: The expression ``jump(dest)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_JUMP, dest.index)

	def call(self, dest):
		"""
		``call`` returns an expression which first pushes the address of the next instruction onto the stack then jumps
		(branches) to the expression ``dest``

		:param LowLevelILExpr dest: the expression to call
		:return: The expression ``call(dest)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CALL, dest.index)

	def ret(self, dest):
		"""
		``ret`` returns an expression which jumps (branches) to the expression ``dest``. ``ret`` is a special alias for
		jump that makes the disassembler top disassembling.

		:param LowLevelILExpr dest: the expression to jump to
		:return: The expression ``jump(dest)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_RET, dest.index)

	def no_ret(self):
		"""
		``no_ret`` returns an expression halts disassembly

		:return: The expression ``noreturn``
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_NORET)

	def flag_condition(self, cond):
		"""
		``flag_condition`` returns a flag_condition expression for the given LowLevelILFlagCondition

		:param LowLevelILFlagCondition cond: Flag condition expression to retrieve
		:return: A flag_condition expression
		:rtype: LowLevelILExpr
		"""
		if isinstance(cond, str):
			cond = core.BNLowLevelILFlagCondition_by_name[cond]
		return self.expr(core.LLIL_FLAG_COND, cond)

	def compare_equal(self, size, a, b):
		"""
		``compare_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is equal to
		expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CMP_E, a.index, b.index, size = size)

	def compare_not_equal(self, size, a, b):
		"""
		``compare_not_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is not equal to
		expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CMP_NE, a.index, b.index, size = size)

	def compare_signed_less_than(self, size, a, b):
		"""
		``compare_signed_less_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed less than expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CMP_SLT, a.index, b.index, size = size)

	def compare_unsigned_less_than(self, size, a, b):
		"""
		``compare_unsigned_less_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned less than expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CMP_ULT, a.index, b.index, size = size)

	def compare_signed_less_equal(self, size, a, b):
		"""
		``compare_signed_less_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed less than or equal to expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CMP_SLE, a.index, b.index, size = size)

	def compare_unsigned_less_equal(self, size, a, b):
		"""
		``compare_unsigned_less_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned less than or equal to expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CMP_ULE, a.index, b.index, size = size)

	def compare_signed_greater_equal(self, size, a, b):
		"""
		``compare_signed_greater_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed greater than or equal toexpression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CMP_SGE, a.index, b.index, size = size)

	def compare_unsigned_greater_equal(self, size, a, b):
		"""
		``compare_unsigned_greater_equal`` returns comparison expression of size ``size`` checking if expression ``a``
		is unsigned greater than or equal to expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CMP_UGE, a.index, b.index, size = size)

	def compare_signed_greater_than(self, size, a, b):
		"""
		``compare_signed_greater_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed greater than or equal to expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CMP_SGT, a.index, b.index, size = size)

	def compare_unsigned_greater_than(self, size, a, b):
		"""
		``compare_unsigned_greater_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned greater than or equal to expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_CMP_UGT, a.index, b.index, size = size)

	def test_bit(self, size, a, b):
		return self.expr(core.LLIL_TEST_BIT, a.index, b.index, size = size)

	def system_call(self):
		"""
		``system_call`` return a system call expression.

		:return: a system call expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_SYSCALL)

	def breakpoint(self):
		"""
		``breakpoint`` returns a processor breakpoint expression.

		:return: a breakpoint expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_BP)

	def trap(self, value):
		"""
		``trap`` returns a processor trap (interrupt) expression of the given integer ``value``.

		:param int value: trap (interrupt) number
		:return: a trap expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_TRAP, value)

	def undefined(self):
		"""
		``undefined`` returns the undefined expression. This should be used for instructions which perform functions but
		aren't important for dataflow or partial emulation purposes.

		:return: the unimplemented expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_UNDEF)

	def unimplemented(self):
		"""
		``unimplemented`` returns the unimplemented expression. This should be used for all instructions which aren't
		implemented.

		:return: the unimplemented expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_UNIMPL)

	def unimplemented_memory_ref(self, size, addr):
		"""
		``unimplemented_memory_ref`` a memory reference to expression ``addr`` of size ``size`` with unimplemented operation.

		:param int size: size in bytes of the memory reference
		:param LowLevelILExpr addr: expression to reference memory
		:return: the unimplemented memory reference expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(core.LLIL_UNIMPL_MEM, addr.index, size = size)

	def goto(self, label):
		"""
		``goto`` returns a goto expression which jumps to the provided LowLevelILLabel.

		:param LowLevelILLabel label: Label to jump to
		:return: the LowLevelILExpr that jumps to the provided label
		:rtype: LowLevelILExpr
		"""
		return LowLevelILExpr(core.BNLowLevelILGoto(self.handle, label.handle))

	def if_expr(self, operand, t, f):
		"""
		``if_expr`` returns the ``if`` expression which depending on condition ``operand`` jumps to the LowLevelILLabel
		``t`` when the condition expression ``operand`` is non-zero and ``f`` when it's zero.

		:param LowLevelILExpr operand: comparison expression to evaluate.
		:param LowLevelILLabel t: Label for the true branch
		:param LowLevelILLabel f: Label for the false branch
		:return: the LowLevelILExpr for the if expression
		:rtype: LowLevelILExpr
		"""
		return LowLevelILExpr(core.BNLowLevelILIf(self.handle, operand.index, t.handle, f.handle))

	def mark_label(self, label):
		"""
		``mark_label`` assigns a LowLevelILLabel to the current IL address.

		:param LowLevelILLabel label:
		:rtype: None
		"""
		core.BNLowLevelILMarkLabel(self.handle, label.handle)

	def add_label_list(self, labels):
		"""
		``add_label_list`` returns a label list expression for the given list of LowLevelILLabel objects.

		:param list(LowLevelILLabel) lables: the list of LowLevelILLabel to get a label list expression from
		:return: the label list expression
		:rtype: LowLevelILExpr
		"""
		label_list = (ctypes.POINTER(core.BNLowLevelILLabel) * len(labels))()
		for i in xrange(len(labels)):
			label_list[i] = labels[i].handle
		return LowLevelILExpr(core.BNLowLevelILAddLabelList(self.handle, label_list, len(labels)))

	def add_operand_list(self, operands):
		"""
		``add_operand_list`` returns an operand list expression for the given list of integer operands.

		:param list(int) operands: list of operand numbers
		:return: an operand list expression
		:rtype: LowLevelILExpr
		"""
		operand_list = (ctypes.c_ulonglong * len(operands))()
		for i in xrange(len(operands)):
			operand_list[i] = operands[i]
		return LowLevelILExpr(core.BNLowLevelILAddOperandList(self.handle, operand_list, len(operands)))

	def operand(self, n, expr):
		"""
		``operand`` sets the operand number of the expression ``expr`` and passes back ``expr`` without modification.

		:param int n:
		:param LowLevelILExpr expr:
		:return: returns the expression ``expr`` unmodified
		:rtype: LowLevelILExpr
		"""
		core.BNLowLevelILSetExprSourceOperand(self.handle, expr.index, n)
		return expr

	def finalize(self):
		"""
		``finalize`` ends the function and computes the list of basic blocks.

		:rtype: None
		"""
		core.BNFinalizeLowLevelILFunction(self.handle)

	def add_label_for_address(self, arch, addr):
		"""
		``add_label_for_address`` adds a low-level IL label for the given architecture ``arch`` at the given virtual
		address ``addr``

		:param Architecture arch: Architecture to add labels for
		:param int addr: the IL address to add a label at
		"""
		if arch is not None:
			arch = arch.handle
		core.BNAddLowLevelILLabelForAddress(self.handle, arch, addr)

	def get_label_for_address(self, arch, addr):
		"""
		``get_label_for_address`` returns the LowLevelILLabel for the given Architecture ``arch`` and IL address ``addr``.

		:param Architecture arch:
		:param int addr: IL Address label to retrieve
		:return: the LowLevelILLabel for the given IL address
		:rtype: LowLevelILLabel
		"""
		if arch is not None:
			arch = arch.handle
		label = core.BNGetLowLevelILLabelForAddress(self.handle, arch, addr)
		if label is None:
			return None
		return LowLevelILLabel(label)

class TypeParserResult(object):
	def __init__(self, types, variables, functions):
		self.types = types
		self.variables = variables
		self.functions = functions

	def __repr__(self):
		return "{types: %s, variables: %s, functions: %s}" % (self.types, self.variables, self.functions)

class _TransformMetaClass(type):
	@property
	def list(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		xforms = core.BNGetTransformTypeList(count)
		result = []
		for i in xrange(0, count.value):
			result.append(Transform(xforms[i]))
		core.BNFreeTransformTypeList(xforms)
		return result

	def __iter__(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		xforms = core.BNGetTransformTypeList(count)
		try:
			for i in xrange(0, count.value):
				yield Transform(xforms[i])
		finally:
			core.BNFreeTransformTypeList(xforms)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __getitem__(cls, name):
		_init_plugins()
		xform = core.BNGetTransformByName(name)
		if xform is None:
			raise KeyError, "'%s' is not a valid transform" % str(name)
		return Transform(xform)

	def register(cls):
		_init_plugins()
		if cls.name is None:
			raise ValueError, "transform 'name' is not defined"
		if cls.long_name is None:
			cls.long_name = cls.name
		if cls.transform_type is None:
			raise ValueError, "transform 'transform_type' is not defined"
		if cls.group is None:
			cls.group = ""
		xform = cls(None)
		cls._registered_cb = xform._cb
		xform.handle = core.BNRegisterTransformType(cls.transform_type, cls.name, cls.long_name, cls.group, xform._cb)

class TransformParameter(object):
	def __init__(self, name, long_name = None, fixed_length = 0):
		self.name = name
		if long_name is None:
			self.long_name = name
		else:
			self.long_name = long_name
		self.fixed_length = fixed_length

class Transform:
	transform_type = None
	name = None
	long_name = None
	group = None
	parameters = []
	_registered_cb = None
	__metaclass__ = _TransformMetaClass

	def __init__(self, handle):
		if handle is None:
			self._cb = core.BNCustomTransform()
			self._cb.context = 0
			self._cb.getParameters = self._cb.getParameters.__class__(self._get_parameters)
			self._cb.freeParameters = self._cb.freeParameters.__class__(self._free_parameters)
			self._cb.decode = self._cb.decode.__class__(self._decode)
			self._cb.encode = self._cb.encode.__class__(self._encode)
			self._pending_param_lists = {}
			self.type = self.__class__.transform_type
			if not isinstance(self.type, str):
				self.type = core.BNTransformType_names[self.type]
			self.name = self.__class__.name
			self.long_name = self.__class__.long_name
			self.group = self.__class__.group
			self.parameters = self.__class__.parameters
		else:
			self.handle = handle
			self.type = core.BNTransformType_names[core.BNGetTransformType(self.handle)]
			self.name = core.BNGetTransformName(self.handle)
			self.long_name = core.BNGetTransformLongName(self.handle)
			self.group = core.BNGetTransformGroup(self.handle)
			count = ctypes.c_ulonglong()
			params = core.BNGetTransformParameterList(self.handle, count)
			self.parameters = []
			for i in xrange(0, count.value):
				self.parameters.append(TransformParameter(params[i].name, params[i].longName, params[i].fixedLength))
			core.BNFreeTransformParameterList(params, count.value)

	def __repr__(self):
		return "<transform: %s>" % self.name

	def _get_parameters(self, ctxt, count):
		try:
			count[0] = len(self.parameters)
			param_buf = (core.BNTransformParameterInfo * len(self.parameters))()
			for i in xrange(0, len(self.parameters)):
				param_buf[i].name = self.parameters[i].name
				param_buf[i].longName = self.parameters[i].long_name
				param_buf[i].fixedLength = self.parameters[i].fixed_length
			result = ctypes.cast(param_buf, ctypes.c_void_p)
			self._pending_param_lists[result.value] = (result, param_buf)
			return result.value
		except:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _free_parameters(self, params, count):
		try:
			buf = ctypes.cast(params, ctypes.c_void_p)
			if buf.value not in self._pending_param_lists:
				raise ValueError, "freeing parameter list that wasn't allocated"
			del self._pending_param_lists[buf.value]
		except:
			log_error(traceback.format_exc())

	def _decode(self, ctxt, input_buf, output_buf, params, count):
		try:
			input_obj = DataBuffer(handle = core.BNDuplicateDataBuffer(input_buf))
			param_map = {}
			for i in xrange(0, count):
				data = DataBuffer(handle = core.BNDuplicateDataBuffer(params[i].value))
				param_map[params[i].name] = str(data)
			result = self.perform_decode(str(input_obj), param_map)
			if result is None:
				return False
			result = str(result)
			core.BNSetDataBufferContents(output_buf, result, len(result))
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _encode(self, ctxt, input_buf, output_buf, params, count):
		try:
			input_obj = DataBuffer(handle = core.BNDuplicateDataBuffer(input_buf))
			param_map = {}
			for i in xrange(0, count):
				data = DataBuffer(handle = core.BNDuplicateDataBuffer(params[i].value))
				param_map[params[i].name] = str(data)
			result = self.perform_encode(str(input_obj), param_map)
			if result is None:
				return False
			result = str(result)
			core.BNSetDataBufferContents(output_buf, result, len(result))
			return True
		except:
			log_error(traceback.format_exc())
			return False

	@abc.abstractmethod
	def perform_decode(self, data, params):
		if self.type == "InvertingTransform":
			return self.perform_encode(data, params)
		return None

	@abc.abstractmethod
	def perform_encode(self, data, params):
		return None

	def decode(self, input_buf, params = {}):
		input_buf = DataBuffer(input_buf)
		output_buf = DataBuffer()
		keys = params.keys()
		param_buf = (core.BNTransformParameter * len(keys))()
		param_data = []
		for i in xrange(0, len(keys)):
			data = DataBuffer(params[keys[i]])
			param_buf[i].name = keys[i]
			param_buf[i].value = data.handle
		if not core.BNDecode(self.handle, input_buf.handle, output_buf.handle, param_buf, len(keys)):
			return None
		return str(output_buf)

	def encode(self, input_buf, params = {}):
		input_buf = DataBuffer(input_buf)
		output_buf = DataBuffer()
		keys = params.keys()
		param_buf = (core.BNTransformParameter * len(keys))()
		param_data = []
		for i in xrange(0, len(keys)):
			data = DataBuffer(params[keys[i]])
			param_buf[i].name = keys[i]
			param_buf[i].value = data.handle
		if not core.BNEncode(self.handle, input_buf.handle, output_buf.handle, param_buf, len(keys)):
			return None
		return str(output_buf)

class FunctionRecognizer(object):
	_instance = None

	def __init__(self):
		self._cb = core.BNFunctionRecognizer()
		self._cb.context = 0
		self._cb.recognizeLowLevelIL = self._cb.recognizeLowLevelIL.__class__(self._recognize_low_level_il)

	@classmethod
	def register_global(cls):
		if cls._instance is None:
			cls._instance = cls()
		core.BNRegisterGlobalFunctionRecognizer(cls._instance._cb)

	@classmethod
	def register_arch(cls, arch):
		if cls._instance is None:
			cls._instance = cls()
		core.BNRegisterArchitectureFunctionRecognizer(arch.handle, cls._instance._cb)

	def _recognize_low_level_il(self, ctxt, data, func, il):
		try:
			file_metadata = FileMetadata(handle = core.BNGetFileForView(data))
			view = BinaryView(file_metadata, handle = core.BNNewViewReference(data))
			func = Function(view, handle = core.BNNewFunctionReference(func))
			il = LowLevelILFunction(func.arch, handle = core.BNNewLowLevelILFunctionReference(il))
			return self.recognize_low_level_il(view, func, il)
		except:
			log_error(traceback.format_exc())
			return False

	def recognize_low_level_il(self, data, func, il):
		return False

class _UpdateChannelMetaClass(type):
	@property
	def list(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		channels = core.BNGetUpdateChannels(count, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError, error_str
		result = []
		for i in xrange(0, count.value):
			result.append(UpdateChannel(channels[i].name, channels[i].description, channels[i].latestVersion))
		core.BNFreeUpdateChannelList(channels, count.value)
		return result

	@property
	def active(self):
		return core.BNGetActiveUpdateChannel()

	@active.setter
	def active(self, value):
		return core.BNSetActiveUpdateChannel(value)

	def __iter__(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		channels = core.BNGetUpdateChannels(count, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError, error_str
		try:
			for i in xrange(0, count.value):
				yield UpdateChannel(channels[i].name, channels[i].description, channels[i].latestVersion)
		finally:
			core.BNFreeUpdateChannelList(channels, count.value)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __getitem__(cls, name):
		_init_plugins()
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		channels = core.BNGetUpdateChannels(count, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError, error_str
		result = None
		for i in xrange(0, count.value):
			if channels[i].name == str(name):
				result = UpdateChannel(channels[i].name, channels[i].description, channels[i].latestVersion)
				break
		core.BNFreeUpdateChannelList(channels, count.value)
		if result is None:
			raise KeyError, "'%s' is not a valid channel" % str(name)
		return result

class UpdateProgressCallback(object):
	def __init__(self, func):
		self.cb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong)(self.callback)
		self.func = func

	def callback(self, ctxt, progress, total):
		try:
			if self.func is not None:
				return self.func(progress, total)
			return True
		except:
			log_error(traceback.format_exc())

class UpdateChannel(object):
	__metaclass__ = _UpdateChannelMetaClass

	def __init__(self, name, desc, ver):
		self.name = name
		self.description = desc
		self.latest_version_num = ver

	@property
	def versions(self):
		"""List of versions (read-only)"""
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		versions = core.BNGetUpdateChannelVersions(self.name, count, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError, error_str
		result = []
		for i in xrange(0, count.value):
			result.append(UpdateVersion(self, versions[i].version, versions[i].notes, versions[i].time))
		core.BNFreeUpdateChannelVersionList(versions, count.value)
		return result

	@property
	def latest_version(self):
		"""Latest version (read-only)"""
		count = ctypes.c_ulonglong()
		errors = ctypes.c_char_p()
		versions = core.BNGetUpdateChannelVersions(self.name, count, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError, error_str
		result = None
		for i in xrange(0, count.value):
			if versions[i].version == self.latest_version_num:
				result = UpdateVersion(self, versions[i].version, versions[i].notes, versions[i].time)
				break
		core.BNFreeUpdateChannelVersionList(versions, count.value)
		return result

	@property
	def updates_available(self):
		"""Whether updates are available (read-only)"""
		errors = ctypes.c_char_p()
		result = core.BNAreUpdatesAvailable(self.name, errors)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError, error_str
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __repr__(self):
		return "<channel: %s>" % self.name

	def __str__(self):
		return self.name

	def update_to_latest(self, progress = None):
		cb = UpdateProgressCallback(progress)
		errors = ctypes.c_char_p()
		result = core.BNUpdateToLatestVersion(self.name, errors, cb.cb, None)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError, error_str
		return core.BNUpdateResult_names[result]

class UpdateVersion(object):
	def __init__(self, channel, ver, notes, t):
		self.channel = channel
		self.version = ver
		self.notes = notes
		self.time = t

	def __repr__(self):
		return "<version: %s>" % self.version

	def __str__(self):
		return self.version

	def update(self, progress = None):
		cb = UpdateProgressCallback(progress)
		errors = ctypes.c_char_p()
		result = core.BNUpdateToVersion(self.channel.name, self.version, errors, cb.cb, None)
		if errors:
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise IOError, error_str
		return core.BNUpdateResult_names[result]

class PluginCommandContext(object):
	def __init__(self, view):
		self.view = view
		self.address = 0
		self.length = 0
		self.function = None

class _PluginCommandMetaClass(type):
	@property
	def list(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		commands = core.BNGetAllPluginCommands(count)
		result = []
		for i in xrange(0, count.value):
			result.append(PluginCommand(commands[i]))
		core.BNFreePluginCommandList(commands)
		return result

	def __iter__(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		commands = core.BNGetAllPluginCommands(count)
		try:
			for i in xrange(0, count.value):
				yield PluginCommand(commands[i])
		finally:
			core.BNFreePluginCommandList(commands)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

class PluginCommand:
	_registered_commands = []
	__metaclass__ = _PluginCommandMetaClass

	def __init__(self, cmd):
		self.command = core.BNPluginCommand()
		ctypes.memmove(ctypes.byref(self.command), ctypes.byref(cmd), ctypes.sizeof(core.BNPluginCommand))
		self.name = str(cmd.name)
		self.description = str(cmd.description)
		self.type = core.BNPluginCommandType_names[cmd.type]

	@classmethod
	def _default_action(cls, view, action):
		try:
			file_metadata = FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = BinaryView(file_metadata, handle = core.BNNewViewReference(view))
			action(view_obj)
		except:
			log_error(traceback.format_exc())

	@classmethod
	def _address_action(cls, view, addr, action):
		try:
			file_metadata = FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = BinaryView(file_metadata, handle = core.BNNewViewReference(view))
			action(view_obj, addr)
		except:
			log_error(traceback.format_exc())

	@classmethod
	def _range_action(cls, view, addr, length, action):
		try:
			file_metadata = FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = BinaryView(file_metadata, handle = core.BNNewViewReference(view))
			action(view_obj, addr, length)
		except:
			log_error(traceback.format_exc())

	@classmethod
	def _function_action(cls, view, func, action):
		try:
			file_metadata = FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = BinaryView(file_metadata, handle = core.BNNewViewReference(view))
			func_obj = Function(view_obj, core.BNNewFunctionReference(func))
			action(view_obj, func_obj)
		except:
			log_error(traceback.format_exc())

	@classmethod
	def _default_is_valid(cls, view, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = BinaryView(file_metadata, handle = core.BNNewViewReference(view))
			return is_valid(view_obj)
		except:
			log_error(traceback.format_exc())
			return False

	@classmethod
	def _address_is_valid(cls, view, addr, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = BinaryView(file_metadata, handle = core.BNNewViewReference(view))
			return is_valid(view_obj, addr)
		except:
			log_error(traceback.format_exc())
			return False

	@classmethod
	def _range_is_valid(cls, view, addr, length, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = BinaryView(file_metadata, handle = core.BNNewViewReference(view))
			return is_valid(view_obj, addr, length)
		except:
			log_error(traceback.format_exc())
			return False

	@classmethod
	def _function_is_valid(cls, view, func, is_valid):
		try:
			if is_valid is None:
				return True
			file_metadata = FileMetadata(handle = core.BNGetFileForView(view))
			view_obj = BinaryView(file_metadata, handle = core.BNNewViewReference(view))
			func_obj = Function(view_obj, core.BNNewFunctionReference(func))
			return is_valid(view_obj, func_obj)
		except:
			log_error(traceback.format_exc())
			return False

	@classmethod
	def register(cls, name, description, action, is_valid = None):
		_init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView))(lambda ctxt, view: cls._default_action(view, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView))(lambda ctxt, view: cls._default_is_valid(view, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommand(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_address(cls, name, description, action, is_valid = None):
		_init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong)(lambda ctxt, view, addr: cls._address_action(view, addr, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong)(lambda ctxt, view, addr: cls._address_is_valid(view, addr, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForAddress(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_range(cls, name, description, action, is_valid = None):
		_init_plugins()
		action_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong, ctypes.c_ulonglong)(lambda ctxt, view, addr, length: cls._range_action(view, addr, length, action))
		is_valid_obj = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(core.BNBinaryView), ctypes.c_ulonglong, ctypes.c_ulonglong)(lambda ctxt, view, addr, length: cls._range_is_valid(view, addr, length, is_valid))
		cls._registered_commands.append((action_obj, is_valid_obj))
		core.BNRegisterPluginCommandForRange(name, description, action_obj, is_valid_obj, None)

	@classmethod
	def register_for_function(cls, name, description, action, is_valid = None):
		_init_plugins()
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
		if self.command.type == core.DefaultPluginCommand:
			if not self.command.defaultIsValid:
				return True
			return self.command.defaultIsValid(self.command.context, context.view.handle)
		elif self.command.type == core.AddressPluginCommand:
			if not self.command.addressIsValid:
				return True
			return self.command.addressIsValid(self.command.context, context.view.handle, context.address)
		elif self.command.type == core.RangePluginCommand:
			if context.length == 0:
				return False
			if not self.command.rangeIsValid:
				return True
			return self.command.rangeIsValid(self.command.context, context.view.handle, context.address, context.length)
		elif self.command.type == core.FunctionPluginCommand:
			if context.function is None:
				return False
			if not self.command.functionIsValid:
				return True
			return self.command.functionIsValid(self.command.context, context.view.handle, context.function.handle)
		return False

	def execute(self, context):
		if not self.is_valid(context):
			return
		if self.command.type == core.DefaultPluginCommand:
			self.command.defaultCommand(self.command.context, context.view.handle)
		elif self.command.type == core.AddressPluginCommand:
			self.command.addressCommand(self.command.context, context.view.handle, context.address)
		elif self.command.type == core.RangePluginCommand:
			self.command.rangeCommand(self.command.context, context.view.handle, context.address, context.length)
		elif self.command.type == core.FunctionPluginCommand:
			self.command.functionCommand(self.command.context, context.view.handle, context.function.handle)

	def __repr__(self):
		return "<PluginCommand: %s>" % self.name

class CallingConvention(object):
	name = None
	caller_saved_regs = []
	int_arg_regs = []
	float_arg_regs = []
	arg_regs_share_index = False
	stack_reserved_for_arg_regs = False
	int_return_reg = None
	high_int_return_reg = None
	float_return_reg = None

	_registered_calling_conventions = []

	def __init__(self, arch, handle = None):
		if handle is None:
			self.arch = arch
			self._pending_reg_lists = {}
			self._cb = core.BNCustomCallingConvention()
			self._cb.context = 0
			self._cb.getCallerSavedRegisters = self._cb.getCallerSavedRegisters.__class__(self._get_caller_saved_regs)
			self._cb.getIntegerArgumentRegisters = self._cb.getIntegerArgumentRegisters.__class__(self._get_int_arg_regs)
			self._cb.getFloatArgumentRegisters = self._cb.getFloatArgumentRegisters.__class__(self._get_float_arg_regs)
			self._cb.freeRegisterList = self._cb.freeRegisterList.__class__(self._free_register_list)
			self._cb.areArgumentRegistersSharedIndex = self._cb.areArgumentRegistersSharedIndex.__class__(self._arg_regs_share_index)
			self._cb.isStackReservedForArgumentRegisters = self._cb.isStackReservedForArgumentRegisters.__class__(self._stack_reserved_for_arg_regs)
			self._cb.getIntegerReturnValueRegister = self._cb.getIntegerReturnValueRegister.__class__(self._get_int_return_reg)
			self._cb.getHighIntegerReturnValueRegister = self._cb.getHighIntegerReturnValueRegister.__class__(self._get_high_int_return_reg)
			self._cb.getFloatReturnValueRegister = self._cb.getFloatReturnValueRegister.__class__(self._get_float_return_reg)
			self.handle = core.BNCreateCallingConvention(arch.handle, self.__class__.name, self._cb)
			self.__class__._registered_calling_conventions.append(self)
		else:
			self.handle = handle
			self.arch = Architecture(core.BNGetCallingConventionArchitecture(self.handle))
			self.__dict__["name"] = core.BNGetCallingConventionName(self.handle)
			self.__dict__["arg_regs_share_index"] = core.BNAreArgumentRegistersSharedIndex(self.handle)
			self.__dict__["stack_reserved_for_arg_regs"] = core.BNIsStackReservedForArgumentRegisters(self.handle)

			count = ctypes.c_ulonglong()
			regs = core.BNGetCallerSavedRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in xrange(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["caller_saved_regs"] = result

			count = ctypes.c_ulonglong()
			regs = core.BNGetIntegerArgumentRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in xrange(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["int_arg_regs"] = result

			count = ctypes.c_ulonglong()
			regs = core.BNGetFloatArgumentRegisters(self.handle, count)
			result = []
			arch = self.arch
			for i in xrange(0, count.value):
				result.append(arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs, count.value)
			self.__dict__["float_arg_regs"] = result

			reg = core.BNGetIntegerReturnValueRegister(self.handle)
			if reg == 0xffffffff:
				self.__dict__["int_return_reg"] = None
			else:
				self.__dict__["int_return_reg"] = self.arch.get_reg_name(reg)

			reg = core.BNGetHighIntegerReturnValueRegister(self.handle)
			if reg == 0xffffffff:
				self.__dict__["high_int_return_reg"] = None
			else:
				self.__dict__["high_int_return_reg"] = self.arch.get_reg_name(reg)

			reg = core.BNGetFloatReturnValueRegister(self.handle)
			if reg == 0xffffffff:
				self.__dict__["float_return_reg"] = None
			else:
				self.__dict__["float_return_reg"] = self.arch.get_reg_name(reg)

	def __del__(self):
		core.BNFreeCallingConvention(self.handle)

	def _get_caller_saved_regs(self, ctxt, count):
		try:
			regs = self.__class__.caller_saved_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in xrange(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_int_arg_regs(self, ctxt, count):
		try:
			regs = self.__class__.int_arg_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in xrange(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_float_arg_regs(self, ctxt, count):
		try:
			regs = self.__class__.float_arg_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in xrange(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _free_register_list(self, ctxt, regs):
		try:
			buf = ctypes.cast(regs, ctypes.c_void_p)
			if buf.value not in self._pending_reg_lists:
				raise ValueError, "freeing register list that wasn't allocated"
			del self._pending_reg_lists[buf.value]
		except:
			log_error(traceback.format_exc())

	def _arg_regs_share_index(self, ctxt):
		try:
			return self.__class__.arg_regs_share_index
		except:
			log_error(traceback.format_exc())
			return False

	def _stack_reserved_for_arg_regs(self, ctxt):
		try:
			return self.__class__.stack_reserved_for_arg_regs
		except:
			log_error(traceback.format_exc())
			return False

	def _get_int_return_reg(self, ctxt):
		try:
			return self.arch.regs[self.__class__.int_return_reg].index
		except:
			log_error(traceback.format_exc())
			return False

	def _get_high_int_return_reg(self, ctxt):
		try:
			if self.__class__.high_int_return_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.high_int_return_reg].index
		except:
			log_error(traceback.format_exc())
			return False

	def _get_float_return_reg(self, ctxt):
		try:
			if self.__class__.float_return_reg is None:
				return 0xffffffff
			return self.arch.regs[self.__class__.float_int_return_reg].index
		except:
			log_error(traceback.format_exc())
			return False

	def __repr__(self):
		return "<calling convention: %s %s>" % (self.arch.name, self.name)

	def __str__(self):
		return self.name

class _PlatformMetaClass(type):
	@property
	def list(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformList(count)
		result = []
		for i in xrange(0, count.value):
			result.append(Platform(None, core.BNNewPlatformReference(platforms[i])))
		core.BNFreePlatformList(platforms, count.value)
		return result

	@property
	def os_list(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformOSList(count)
		result = []
		for i in xrange(0, count.value):
			result.append(str(platforms[i]))
		core.BNFreePlatformOSList(platforms, count.value)
		return result

	def __iter__(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformList(count)
		try:
			for i in xrange(0, count.value):
				yield Platform(None, core.BNNewPlatformReference(platforms[i]))
		finally:
			core.BNFreePlatformList(platforms, count.value)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __getitem__(cls, value):
		_init_plugins()
		platform = core.BNGetPlatformByName(str(value))
		if platform is None:
			raise KeyError, "'%s' is not a valid platform" % str(value)
		return Platform(None, platform)

	def get_list(cls, os = None, arch = None):
		_init_plugins()
		count = ctypes.c_ulonglong()
		if os is None:
			platforms = core.BNGetPlatformList(count)
		elif arch is None:
			platforms = core.BNGetPlatformListByOS(os)
		else:
			platforms = core.BNGetPlatformListByArchitecture(os, arch.handle)
		result = []
		for i in xrange(0, count.value):
			result.append(Platform(None, core.BNNewPlatformReference(platforms[i])))
		core.BNFreePlatformList(platforms, count.value)
		return result

class Platform(object):
	"""
	``class Platform`` contains all information releated to the execution environment of the binary, mainly the
	calling conventions used.
	"""
	__metaclass__ = _PlatformMetaClass
	name = None

	def __init__(self, arch, handle = None):
		if handle is None:
			self.arch = arch
			self.handle = core.BNCreatePlatform(arch.handle, self.__class__.name)
		else:
			self.handle = handle
			self.__dict__["name"] = core.BNGetPlatformName(self.handle)
			self.arch = Architecture(core.BNGetPlatformArchitecture(self.handle))

	def __del__(self):
		core.BNFreePlatform(self.handle)

	@property
	def default_calling_convention(self):
		"""
		Default calling convention.

		:getter: returns a CallingConvention object for the default calling convention.
		:setter: sets the default calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformDefaultCallingConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@default_calling_convention.setter
	def default_calling_convention(self, value):
		core.BNRegisterPlatformDefaultCallingConvention(self.handle, value.handle)

	@property
	def cdecl_calling_convention(self):
		"""
		Cdecl calling convention.

		:getter: returns a CallingConvention object for the cdecl calling convention.
		:setter sets the cdecl calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformCdeclCallingConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@cdecl_calling_convention.setter
	def cdecl_calling_convention(self, value):
		core.BNRegisterPlatformCdeclCallingConvention(self.handle, value.handle)

	@property
	def stdcall_calling_convention(self):
		"""
		Stdcall calling convention.

		:getter: returns a CallingConvention object for the stdcall calling convention.
		:setter sets the stdcall calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformStdcallCallingConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@stdcall_calling_convention.setter
	def stdcall_calling_convention(self, value):
		core.BNRegisterPlatformStdcallCallingConvention(self.handle, value.handle)

	@property
	def fastcall_calling_convention(self):
		"""
		Fastcall calling convention.

		:getter: returns a CallingConvention object for the fastcall calling convention.
		:setter sets the fastcall calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformFastcallCallingConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@fastcall_calling_convention.setter
	def fastcall_calling_convention(self, value):
		core.BNRegisterPlatformFastcallCallingConvention(self.handle, value.handle)

	@property
	def system_call_convention(self):
		"""
		System call convention.

		:getter: returns a CallingConvention object for the system call convention.
		:setter sets the system call convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformSystemCallConvention(self.handle)
		if result is None:
			return None
		return CallingConvention(None, result)

	@system_call_convention.setter
	def system_call_convention(self, value):
		core.BNSetPlatformSystemCallConvention(self.handle, value.handle)

	@property
	def calling_conventions(self):
		"""
		List of platform CallingConvention objects (read-only)

		:getter: returns the list of supported CallingConvention objects
		:type: list(CallingConvention)
		"""
		count = ctypes.c_ulonglong()
		cc = core.BNGetPlatformCallingConventions(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(CallingConvention(None, core.BNNewCallingConventionReference(cc[i])))
		core.BNFreeCallingConventionList(cc, count.value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

	def __repr__(self):
		return "<platform: %s>" % self.name

	def __str__(self):
		return self.name

	def register(self, os):
		"""
		``register`` registers the platform for given OS name.

		:param str os: OS name to register
		:rtype: None
		"""
		core.BNRegisterPlatform(os, self.handle)

	def register_calling_convention(self, cc):
		"""
		``register_calling_convention`` register a new calling convention.

		:param CallingConvention cc: a CallingConvention object to register
		:rtype: None
		"""
		core.BNRegisterPlatformCallingConvention(self.handle, cc.handle)

class ScriptingOutputListener(object):
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

class ScriptingInstance(object):
	def __init__(self, provider, handle = None):
		if handle is None:
			self._cb = core.BNScriptingInstanceCallbacks()
			self._cb.context = 0
			self._cb.destroyInstance = self._cb.destroyInstance.__class__(self._destroy_instance)
			self._cb.executeScriptInput = self._cb.executeScriptInput.__class__(self._execute_script_input)
			self._cb.setCurrentBinaryView = self._cb.setCurrentBinaryView.__class__(self._set_current_binary_view)
			self._cb.setCurrentFunction = self._cb.setCurrentFunction.__class__(self._set_current_function)
			self._cb.setCurrentBasicBlock = self._cb.setCurrentBasicBlock.__class__(self._set_current_basic_block)
			self._cb.setCurrentAddress = self._cb.setCurrentAddress.__class__(self._set_current_address)
			self._cb.setCurrentSelection = self._cb.setCurrentSelection.__class__(self._set_current_selection)
			self.handle = core.BNInitScriptingInstance(provider.handle, self._cb)
		else:
			self.handle = core.handle_of_type(handle, core.BNScriptingInstance)
		self.listeners = []

	def __del__(self):
		core.BNFreeScriptingInstance(self.handle)

	def _destroy_instance(self, ctxt):
		try:
			self.perform_destroy_instance()
		except:
			log_error(traceback.format_exc())

	def _execute_script_input(self, ctxt, text):
		try:
			return self.perform_execute_script_input(text)
		except:
			log_error(traceback.format_exc())
			return core.InvalidScriptInput

	def _set_current_binary_view(self, ctxt, view):
		try:
			if view:
				view = BinaryView(None, handle = core.BNNewViewReference(view))
			else:
				view = None
			self.perform_set_current_binary_view(view)
		except:
			log_error(traceback.format_exc())

	def _set_current_function(self, ctxt, func):
		try:
			if func:
				func = Function(BinaryView(None, handle = core.BNGetFunctionData(func)), core.BNNewFunctionReference(func))
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
					block = BasicBlock(BinaryView(None, handle = core.BNGetFunctionData(func)), core.BNNewBasicBlockReference(block))
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

	@abc.abstractmethod
	def perform_destroy_instance(self):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_execute_script_input(self, text):
		return core.InvalidScriptInput

	@abc.abstractmethod
	def perform_set_current_binary_view(self, view):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_set_current_function(self, func):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_set_current_basic_block(self, block):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_set_current_address(self, addr):
		raise NotImplementedError

	@abc.abstractmethod
	def perform_set_current_selection(self, begin, end):
		raise NotImplementedError

	@property
	def input_ready_state(self):
		return core.BNGetScriptingInstanceInputReadyState(self.handle)

	@input_ready_state.setter
	def input_ready_state(self, value):
		core.BNNotifyInputReadyStateForScriptingInstance(self.handle, value)

	def output(self, text):
		core.BNNotifyOutputForScriptingInstance(self.handle, text)

	def error(self, text):
		core.BNNotifyErrorForScriptingInstance(self.handle, text)

	def execute_script_input(self, text):
		return core.BNExecuteScriptInput(self.handle, text)

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

	def register_output_listener(self, listener):
		listener._register(self.handle)
		self.listeners.append(listener)

	def unregister_output_listener(self, listener):
		if listener in self.listeners:
			listener._unregister(self.handle)
			self.listeners.remove(listener)

class _ScriptingProviderMetaclass(type):
	@property
	def list(self):
		"""List all ScriptingProvider types (read-only)"""
		_init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetScriptingProviderList(count)
		result = []
		for i in xrange(0, count.value):
			result.append(ScriptingProvider(types[i]))
		core.BNFreeScriptingProviderList(types)
		return result

	def __iter__(self):
		_init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetScriptingProviderList(count)
		try:
			for i in xrange(0, count.value):
				yield ScriptingProvider(types[i])
		finally:
			core.BNFreeScriptingProviderList(types)

	def __getitem__(self, value):
		_init_plugins()
		provider = core.BNGetScriptingProviderByName(str(value))
		if provider is None:
			raise KeyError, "'%s' is not a valid scripting provider" % str(value)
		return ScriptingProvider(provider)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self,name,value)
		except AttributeError:
			raise AttributeError, "attribute '%s' is read only" % name

class ScriptingProvider(object):
	__metaclass__ = _ScriptingProviderMetaclass

	name = None
	instance_class = None
	_registered_providers = []

	def __init__(self, handle = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNScriptingProvider)
			self.__dict__["name"] = core.BNGetScriptingProviderName(handle)

	def register(self):
		self._cb = core.BNScriptingProviderCallbacks()
		self._cb.context = 0
		self._cb.createInstance = self._cb.createInstance.__class__(self._create_instance)
		self.handle = core.BNRegisterScriptingProvider(self.__class__.name, self._cb)
		self.__class__._registered_providers.append(self)

	def _create_instance(self, ctxt):
		try:
			result = self.__class__.instance_class(self)
			if result is None:
				return None
			return ctypes.cast(core.BNNewScriptingInstanceReference(result.handle), ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	def create_instance(self):
		result = core.BNCreateScriptingProviderInstance(self.handle)
		if result is None:
			return None
		return ScriptingInstance(self, handle = result)

class _PythonScriptingInstanceOutput(object):
	def __init__(self, orig, is_error):
		self.orig = orig
		self.is_error = is_error
		self.buffer = ""

	def write(self, data):
		global _output_to_log

		interpreter = None
		if "value" in dir(PythonScriptingInstance._interpreter):
			interpreter = PythonScriptingInstance._interpreter.value

		if interpreter is None:
			if _output_to_log:
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

class _PythonScriptingInstanceInput(object):
	def __init__(self, orig):
		self.orig = orig

	def read(self, size):
		interpreter = None
		if "value" in dir(PythonScriptingInstance._interpreter):
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
		if "value" in dir(PythonScriptingInstance._interpreter):
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

class PythonScriptingInstance(ScriptingInstance):
	_interpreter = threading.local()

	class InterpreterThread(threading.Thread):
		def __init__(self, instance):
			super(PythonScriptingInstance.InterpreterThread, self).__init__()
			self.instance = instance
			self.locals = {"__name__": "__console__", "__doc__": None, "binaryninja": sys.modules[__name__]}
			self.interpreter = code.InteractiveInterpreter(self.locals)
			self.event = threading.Event()
			self.daemon = True

			# Latest selections from UI
			self.current_view = None
			self.current_func = None
			self.current_block = None
			self.current_addr = 0
			self.current_selection_begin = 0
			self.current_selection_end = 0

			# Selections that were current as of last issued command
			self.active_view = None
			self.active_func = None
			self.active_block = None
			self.active_addr = 0
			self.active_selection_begin = 0
			self.active_selection_end = 0

			self.locals["get_selected_data"] = self.get_selected_data
			self.locals["write_at_cursor"] = self.write_at_cursor

			self.exit = False
			self.code = None
			self.input = ""

			self.interpreter.runsource("from binaryninja import *\n")

		def execute(self, code):
			self.code = code
			self.event.set()

		def add_input(self, data):
			self.input += data
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
				self.instance.input_ready_state = core.ReadyForScriptProgramInput
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
					self.instance.input_ready_state = core.NotReadyForInput
					code = self.code
					self.code = None

					PythonScriptingInstance._interpreter.value = self
					try:
						self.active_view = self.current_view
						self.active_func = self.current_func
						self.active_block = self.current_block
						self.active_addr = self.current_addr
						self.active_selection_begin = self.current_selection_begin
						self.active_selection_end = self.current_selection_end

						self.locals["current_view"] = self.active_view
						self.locals["bv"] = self.active_view
						self.locals["current_function"] = self.active_func
						self.locals["current_basic_block"] = self.active_block
						self.locals["current_address"] = self.active_addr
						self.locals["here"] = self.active_addr
						self.locals["current_selection"] = (self.active_selection_begin, self.active_selection_end)

						self.interpreter.runsource(code)

						if self.locals["here"] != self.active_addr:
							if not self.active_view.file.navigate(self.active_view.file.view, self.locals["here"]):
								sys.stderr.write("Address 0x%x is not valid for the current view\n" % self.locals["here"])
						elif self.locals["current_address"] != self.active_addr:
							if not self.active_view.file.navigate(self.active_view.file.view, self.locals["current_address"]):
								sys.stderr.write("Address 0x%x is not valid for the current view\n" % self.locals["current_address"])
					except:
						traceback.print_exc()
					finally:
						PythonScriptingInstance._interpreter.value = None
						self.instance.input_ready_state = core.ReadyForScriptExecution

		def get_selected_data(self):
			if self.active_view is None:
				return None
			length = self.active_selection_end - self.active_selection_begin
			return self.active_view.read(self.active_selection_begin, length)

		def write_at_cursor(self, data):
			if self.active_view is None:
				return 0
			selected_length = self.active_selection_end - self.active_selection_begin
			data = str(data)
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
		self.input_ready_state = core.ReadyForScriptExecution

	@abc.abstractmethod
	def perform_destroy_instance(self):
		self.interpreter.end()

	@abc.abstractmethod
	def perform_execute_script_input(self, text):
		if self.input_ready_state == core.NotReadyForInput:
			return core.InvalidScriptInput

		if self.input_ready_state == core.ReadyForScriptProgramInput:
			if len(text) == 0:
				return core.SuccessfulScriptExecution
			self.input_ready_state = core.NotReadyForInput
			self.interpreter.add_input(text)
			return core.SuccessfulScriptExecution

		try:
			result = code.compile_command(text)
		except:
			result = False

		if result is None:
			# Command is not complete, ask for more input
			return core.IncompleteScriptInput

		self.input_ready_state = core.NotReadyForInput
		self.interpreter.execute(text)
		return core.SuccessfulScriptExecution

	@abc.abstractmethod
	def perform_set_current_binary_view(self, view):
		self.interpreter.current_view = view

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

class PythonScriptingProvider(ScriptingProvider):
	name = "Python"
	instance_class = PythonScriptingInstance

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
			log_error(traceback.format_exc())

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
		_init_plugins()
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

class InteractionHandler(object):
	_interaction_handler = None

	def __init__(self):
		self._cb = core.BNInteractionHandlerCallbacks()
		self._cb.context = 0
		self._cb.showPlainTextReport = self._cb.showPlainTextReport.__class__(self._show_plain_text_report)
		self._cb.showMarkdownReport = self._cb.showMarkdownReport.__class__(self._show_markdown_report)
		self._cb.showHTMLReport = self._cb.showHTMLReport.__class__(self._show_html_report)
		self._cb.getTextLineInput = self._cb.getTextLineInput.__class__(self._get_text_line_input)
		self._cb.getIntegerInput = self._cb.getIntegerInput.__class__(self._get_int_input)
		self._cb.getAddressInput = self._cb.getAddressInput.__class__(self._get_address_input)
		self._cb.getChoiceInput = self._cb.getChoiceInput.__class__(self._get_choice_input)
		self._cb.getOpenFileNameInput = self._cb.getOpenFileNameInput.__class__(self._get_open_filename_input)
		self._cb.getSaveFileNameInput = self._cb.getSaveFileNameInput.__class__(self._get_save_filename_input)
		self._cb.getDirectoryNameInput = self._cb.getDirectoryNameInput.__class__(self._get_directory_name_input)

	def register(self):
		self.__class__._interaction_handler = self
		core.BNRegisterInteractionHandler(self._cb)

	def _show_plain_text_report(self, ctxt, view, title, contents):
		try:
			if view:
				view = BinaryView(None, handle = core.BNNewViewReference(view))
			else:
				view = None
			self.show_plain_text_report(view, title, contents)
		except:
			log_error(traceback.format_exc())

	def _show_markdown_report(self, ctxt, view, title, contents, plaintext):
		try:
			if view:
				view = BinaryView(None, handle = core.BNNewViewReference(view))
			else:
				view = None
			self.show_markdown_report(view, title, contents, plaintext)
		except:
			log_error(traceback.format_exc())

	def _show_html_report(self, ctxt, view, title, contents, plaintext):
		try:
			if view:
				view = BinaryView(None, handle = core.BNNewViewReference(view))
			else:
				view = None
			self.show_html_report(view, title, contents, plaintext)
		except:
			log_error(traceback.format_exc())

	def _get_text_line_input(self, ctxt, result, prompt, title):
		try:
			value = self.get_text_line_input(prompt, title)
			if value is None:
				return False
			result[0] = core.BNAllocString(str(value))
			return True
		except:
			log_error(traceback.format_exc())

	def _get_int_input(self, ctxt, result, prompt, title):
		try:
			value = self.get_int_input(prompt, title)
			if value is None:
				return False
			result[0] = value
			return True
		except:
			log_error(traceback.format_exc())

	def _get_address_input(self, ctxt, result, prompt, title, view, current_address):
		try:
			if view:
				view = BinaryView(None, handle = core.BNNewViewReference(view))
			else:
				view = None
			value = self.get_address_input(prompt, title, view, current_address)
			if value is None:
				return False
			result[0] = value
			return True
		except:
			log_error(traceback.format_exc())

	def _get_choice_input(self, ctxt, result, prompt, title, choice_buf, count):
		try:
			choices = []
			for i in xrange(0, count):
				choices.append(choice_buf[i])
			value = self.get_choice_input(prompt, title, choices)
			if value is None:
				return False
			result[0] = value
			return True
		except:
			log_error(traceback.format_exc())

	def _get_open_filename_input(self, ctxt, result, prompt, ext):
		try:
			value = self.get_open_filename_input(prompt, ext)
			if value is None:
				return False
			result[0] = core.BNAllocString(str(value))
			return True
		except:
			log_error(traceback.format_exc())

	def _get_save_filename_input(self, ctxt, result, prompt, ext, default_name):
		try:
			value = self.get_save_filename_input(prompt, ext, default_name)
			if value is None:
				return False
			result[0] = core.BNAllocString(str(value))
			return True
		except:
			log_error(traceback.format_exc())

	def _get_directory_name_input(self, ctxt, result, prompt, default_name):
		try:
			value = self.get_directory_name_input(prompt, default_name)
			if value is None:
				return False
			result[0] = core.BNAllocString(str(value))
			return True
		except:
			log_error(traceback.format_exc())

	def show_plain_text_report(self, view, title, contents):
		pass

	def show_markdown_report(self, view, title, contents, plaintext):
		self.show_html_report(view, title, markdown_to_html(contents), plaintext)

	def show_html_report(self, view, title, contents, plaintext):
		if len(plaintext) != 0:
			self.show_plain_text_report(view, title, plaintext)

	def get_text_line_input(self, prompt, title):
		return None

	def get_int_input(self, prompt, title):
		while True:
			text = self.get_text_line_input(prompt, title)
			if len(text) == 0:
				return False
			try:
				return int(text)
			except:
				continue

	def get_address_input(self, prompt, title, view, current_address):
		return get_int_input(prompt, title)

	def get_choice_input(self, prompt, title, choices):
		return None

	def get_open_filename_input(self, prompt, ext):
		return get_text_line_input(prompt, "Open File")

	def get_save_filename_input(self, prompt, ext, default_name):
		return get_text_line_input(title, "Save File")

	def get_directory_name_input(self, prompt, default_name):
		return get_text_line_input(title, "Select Directory")

def LLIL_TEMP(n):
	return n | 0x80000000

def LLIL_REG_IS_TEMP(n):
	return (n & 0x80000000) != 0

def LLIL_GET_TEMP_REG_INDEX(n):
	return n & 0x7fffffff

def shutdown():
	core.BNShutdown()

def log(level, text):
	"""
	``log`` writes messages to the log console for the given log level.

		============ ======== =======================================================================
		LogLevelName LogLevel  Description
		============ ======== =======================================================================
		DebugLog        0     Logs debuging information messages to the console.
		InfoLog         1     Logs general information messages to the console.
		WarningLog      2     Logs message to console with **Warning** icon.
		ErrorLog        3     Logs message to console with **Error** icon, focusing the error console.
		AlertLog        4     Logs message to pop up window.
		============ ======== =======================================================================

	:param LogLevel level: Log level to use
	:param str text: message to print
	:rtype: None
	"""
	core.BNLog(level, "%s", str(text))

def log_debug(text):
	"""
	``log_debug`` Logs debuging information messages to the console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(core.DebugLog)
		>>> log_debug("Hotdogs!")
		Hotdogs!
	"""
	core.BNLogDebug("%s", str(text))

def log_info(text):
	"""
	``log_info`` Logs general information messages to the console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_info("Saucisson!")
		Saucisson!
		>>>
	"""
	core.BNLogInfo("%s", str(text))

def log_warn(text):
	"""
	``log_warn`` Logs message to console, if run through the GUI it logs with **Warning** icon.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(core.DebugLog)
		>>> log_info("Chilidogs!")
		Chilidogs!
		>>>
	"""
	core.BNLogWarn("%s", str(text))

def log_error(text):
	"""
	``log_error`` Logs message to console, if run through the GUI it logs with **Error** icon, focusing the error console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(core.DebugLog)
		>>> log_error("Spanferkel!")
		Spanferkel!
		>>>
	"""
	core.BNLogError("%s", str(text))

def log_alert(text):
	"""
	``log_alert`` Logs message console and to a pop up window if run through the GUI.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(core.DebugLog)
		>>> log_alert("Kielbasa!")
		Kielbasa!
		>>>
	"""
	core.BNLogAlert("%s", str(text))

def log_to_stdout(min_level):
	"""
	``log_to_stdout`` redirects minimum log level to standard out.

	:param int min_level: minimum level to log to
	:rtype: None
	:Example:

		>>> log_debug("Hotdogs!")
		>>> log_to_stdout(core.DebugLog)
		>>> log_debug("Hotdogs!")
		Hotdogs!
		>>>
	"""
	core.BNLogToStdout(min_level)

def log_to_stderr(min_level):
	"""
	``log_to_stderr`` redirects minimum log level to standard error.

	:param int min_level: minimum level to log to
	:rtype: None
	"""
	core.BNLogToStderr(min_level)

def log_to_file(min_level, path, append = False):
	"""
	``log_to_file`` redirects minimum log level to a file named ``path``, optionally appending rather than overwritting.

	:param int min_level: minimum level to log to
	:param str path: path to log to
	:param bool append: optional flag for specifying appending. True = append, False = overwrite.
	:rtype: None
	"""
	core.BNLogToFile(min_level, str(path), append)

def close_logs():
	"""
	``close_logs`` close all log files.

	:rtype: None
	"""
	core.BNCloseLogs()

def escape_string(text):
	return DataBuffer(text).escape()

def unescape_string(text):
	return DataBuffer(text).unescape()

def preprocess_source(source, filename = None, include_dirs = []):
	"""
	``preprocess_source`` run the C preprocessor on the given source or source filename.

	:param str source: source to preprocess
	:param str filename: optional filename to preprocess
	:param list(str) include_dirs: list of string directorires to use as include directories.
	:return: returns a tuple of (preprocessed_source, error_string)
	:rtype: tuple(str,str)
	:Example:

		>>> source = "#define TEN 10\\nint x[TEN];\\n"
		>>> preprocess_source(source)
		('#line 1 "input"\\n\\n#line 2 "input"\\n int x [ 10 ] ;\\n', '')
		>>>
	"""
	if filename is None:
		filename = "input"
	dir_buf = (ctypes.c_char_p * len(include_dirs))()
	for i in xrange(0, len(include_dirs)):
		dir_buf[i] = str(include_dirs[i])
	output = ctypes.c_char_p()
	errors = ctypes.c_char_p()
	result = core.BNPreprocessSource(source, filename, output, errors, dir_buf, len(include_dirs))
	output_str = output.value
	error_str = errors.value
	core.BNFreeString(ctypes.cast(output, ctypes.POINTER(ctypes.c_byte)))
	core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
	if result:
		return (output_str, error_str)
	return (None, error_str)

def are_auto_updates_enabled():
	"""
	``are_auto_updates_enabled`` queries if auto updates are enabled.

	:return: boolean True if auto updates are enabled. False if they are disabled.
	:rtype: bool
	"""
	return core.BNAreAutoUpdatesEnabled()

def set_auto_updates_enabled(enabled):
	"""
	``set_auto_updates_enabled`` sets auto update enabled status.

	:param bool enabled: True to enable update, Flase to disable updates.
	:rtype: None
	"""
	core.BNSetAutoUpdatesEnabled(enabled)

def get_time_since_last_update_check():
	"""
	``get_time_since_last_update_check`` returns the time stamp for the last time updates were checked.

	:return: time stacmp for last update check
	:rtype: int
	"""
	return core.BNGetTimeSinceLastUpdateCheck()

def updates_checked():
	core.BNUpdatesChecked()

def get_qualified_name(names):
	"""
	``get_qualified_name`` gets a qualified name for the provied name list.

	:param list(str) names: name list to qualify
	:return: a qualified name
	:rtype: str
	:Example:

		>>> type, name = demangle_ms(Architecture["x86_64"], "?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		>>> get_qualified_name(name)
		'Foobar::testf'
		>>>
	"""
	return "::".join(names)

def demangle_ms(arch, mangled_name):
	"""
	``demangle_ms`` demangles a mangled Microsoft Visual Studio C++ name to a Type object.

	:param Architecture arch: Architecture for the symbol. Required for pointer and integer sizes.
	:param str mangled_name: a mangled Microsoft Visual Studio C++ name
	:return: returns a Type object for the mangled name
	:rtype: Type
	:Example:

		>>> demangle_ms(Architecture["x86_64"], "?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		(<type: public: static enum Foobar::foo __cdecl (enum Foobar::foo)>, ['Foobar', 'testf'])
		>>>
	"""
	handle = ctypes.POINTER(core.BNType)()
	outName = ctypes.POINTER(ctypes.c_char_p)()
	outSize = ctypes.c_ulonglong()
	names = []
	if core.BNDemangleMS(arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize)):
		for i in xrange(outSize.value):
			names.append(outName[i])
		#core.BNFreeDemangledName(outName.value, outSize.value)
		return (Type(handle), names)
	return (None, mangled_name)


_output_to_log = False
def redirect_output_to_log():
	global _output_to_log
	_output_to_log = True

class _ThreadActionContext(object):
	_actions = []

	def __init__(self, func):
		self.func = func
		self.interpreter = None
		if "value" in dir(PythonScriptingInstance._interpreter):
			self.interpreter = PythonScriptingInstance._interpreter.value
		self.__class__._actions.append(self)
		self.callback = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(lambda ctxt: self.execute())

	def execute(self):
		old_interpreter = None
		if "value" in dir(PythonScriptingInstance._interpreter):
			old_interpreter = PythonScriptingInstance._interpreter.value
		PythonScriptingInstance._interpreter.value = self.interpreter
		try:
			self.func()
		finally:
			PythonScriptingInstance._interpreter.value = old_interpreter
			self.__class__._actions.remove(self)

def execute_on_main_thread(func):
	action = _ThreadActionContext(func)
	obj = core.BNExecuteOnMainThread(0, action.callback)
	if obj:
		return MainThreadAction(obj)
	return None

def execute_on_main_thread_and_wait(func):
	action = _ThreadActionContext(func)
	core.BNExecuteOnMainThreadAndWait(0, action.callback)

def worker_enqueue(func):
	action = _ThreadActionContext(func)
	core.BNWorkerEnqueue(0, action.callback)

def worker_priority_enqueue(func):
	action = _ThreadActionContext(func)
	core.BNWorkerPriorityEnqueue(0, action.callback)

def worker_interactive_enqueue(func):
	action = _ThreadActionContext(func)
	core.BNWorkerInteractiveEnqueue(0, action.callback)

def get_worker_thread_count():
	return core.BNGetWorkerThreadCount()

def set_worker_thread_count(count):
	core.BNSetWorkerThreadCount(count)

def markdown_to_html(contents):
	return core.BNMarkdownToHTML(contents)

def show_plain_text_report(title, contents):
	core.BNShowPlainTextReport(None, title, contents)

def show_markdown_report(title, contents, plaintext = ""):
	core.BNShowMarkdownReport(None, title, contents, plaintext)

def show_html_report(title, contents, plaintext = ""):
	core.BNShowHTMLReport(None, title, contents, plaintext)

def get_text_line_input(prompt, title):
	value = ctypes.c_char_p()
	if not core.BNGetTextLineInput(value, prompt, title):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result

def get_int_input(prompt, title):
	value = ctypes.c_longlong()
	if not core.BNGetIntegerInput(value, prompt, title):
		return None
	return value.value

def get_address_input(prompt, title):
	value = ctypes.c_ulonglong()
	if not core.BNGetAddressInput(value, prompt, title, None, 0):
		return None
	return value.value

def get_choice_input(prompt, title, choices):
	choice_buf = (ctypes.c_char_p * len(choices))()
	for i in xrange(0, len(choices)):
		choice_buf[i] = str(choices[i])
	value = ctypes.c_ulonglong()
	if not core.BNGetChoiceInput(value, prompt, title, choice_buf, len(choices)):
		return None
	return value.value

def get_open_filename_input(prompt, ext = ""):
	value = ctypes.c_char_p()
	if not core.BNGetOpenFileNameInput(value, prompt, ext):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result

def get_save_filename_input(prompt, ext = "", default_name = ""):
	value = ctypes.c_char_p()
	if not core.BNGetSaveFileNameInput(value, prompt, ext, default_name):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result

def get_directory_name_input(prompt, default_name = ""):
	value = ctypes.c_char_p()
	if not core.BNGetDirectoryNameInput(value, prompt, default_name):
		return None
	result = value.value
	core.BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))
	return result

bundled_plugin_path = core.BNGetBundledPluginDirectory()
user_plugin_path = core.BNGetUserPluginDirectory()

core_version = core.BNGetVersionString()
core_build_id = core.BNGetBuildId()

# Ensure all enumeration constants from the core are exposed by this module
for name in core.all_enum_values:
	globals()[name] = core.all_enum_values[name]

PythonScriptingProvider().register()

# Wrap stdin/stdout/stderr for Python scripting provider implementation
sys.stdin = _PythonScriptingInstanceInput(sys.stdin)
sys.stdout = _PythonScriptingInstanceOutput(sys.stdout, False)
sys.stderr = _PythonScriptingInstanceOutput(sys.stderr, True)
