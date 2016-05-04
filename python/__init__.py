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
import ctypes, traceback, json, struct, threading

_plugin_init = False
def _init_plugins():
	global _plugin_init
	if not _plugin_init:
		_plugin_init = True
		core.BNInitCorePlugins()
		core.BNInitUserPlugins()
	if not core.BNIsLicenseValidated():
		raise RuntimeError, "License is not valid. Please supply a valid license."

class DataBuffer:
	def __init__(self, contents = "", handle = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNDataBuffer)
		elif (type(contents) is int) or (type(contents) is long):
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
				buf = ctypes.create_string_buffer(alue)
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
		return DataBuffer(handle = core.BNDecodeEscapedString(str(self)))

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

class NavigationHandler:
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

class FileMetadata:
	def __init__(self, filename = None, handle = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNFileMetadata)
		else:
			_init_plugins()
			self.handle = core.BNCreateFileMetadata()
			if filename is not None:
				core.BNSetFilename(self.handle, str(filename))
		self.__dict__['navigation'] = None

	def __del__(self):
		if self.navigation is not None:
			core.BNSetFileMetadataNavigationHandler(self.handle, None)
		core.BNFreeFileMetadata(self.handle)

	def __getattr__(self, name):
		if name == "filename":
			return core.BNGetFilename(self.handle)
		elif name == "modified":
			return core.BNIsFileModified(self.handle)
		elif name == "analysis_changed":
			return core.BNIsAnalysisChanged(self.handle)
		elif name == "has_database":
			return core.BNIsBackedByDatabase(self.handle)
		elif name == "view":
			return core.BNGetCurrentView(self.handle)
		elif name == "offset":
			return core.BNGetCurrentOffset(self.handle)
		elif name == "raw":
			view = core.BNGetFileViewOfType(self.handle, "Raw")
			if view is None:
				return None
			return BinaryView(self, handle = view)
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if name == "filename":
			core.BNSetFilename(self.handle, str(value))
		elif name == "navigation":
			value._register(self.handle)
			self.__dict__[name] = value
		elif name == "modified":
			if value:
				core.BNMarkFileModified(self.handle)
			else:
				core.BNMarkFileSaved(self.handle)
		elif name == "saved":
			if value:
				core.BNMarkFileSaved(self.handle)
			else:
				core.BNMarkFileModified(self.handle)
		elif name == "view":
			core.BNNavigate(self.handle, str(value), core.BNGetCurrentOffset(self.handle))
		elif name == "offset":
			core.BNNavigate(self.handle, core.BNGetCurrentView(self.handle), value)
		elif (name == "analysis_changed") or (name == "has_database"):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["filename", "modified", "analysis_changed", "has_database", "view", "offset"]

	def close(self):
		core.BNCloseFile(self.handle)

	def begin_undo_actions(self):
		core.BNBeginUndoActions(self.handle)

	def commit_undo_actions(self):
		core.BNCommitUndoActions(self.handle)

	def undo(self):
		core.BNUndo(self.handle)

	def redo(self):
		core.BNRedo(self.handle)

	def navigate(self, view, offset):
		return core.BNNavigate(self.handle, str(view), offset)

	def create_database(self, filename):
		return core.BNCreateDatabase(self.raw.handle, str(filename))

	def open_existing_database(self, filename):
		view = core.BNOpenExistingDatabase(self.handle, str(filename))
		if view is None:
			return None
		return BinaryView(self, handle = view)

	def save_auto_snapshot(self):
		return core.BNSaveAutoSnapshot(self.raw.handle)

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
			self._cb.type = BNActionType_by_name[action_type]
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

class StringReference:
	def __init__(self, string_type, start, length):
		self.type = string_type
		self.start = start
		self.length = length

	def __repr__(self):
		return "<%s: 0x%x, len 0x%x>" % (self.type, self.start, self.length)

class BinaryDataNotificationCallbacks:
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
		self._cb.stringFound = self._cb.stringFound.__class__(self._string_found)
		self._cb.stringRemoved = self._cb.stringRemoved.__class__(self._string_removed)

	def _register(self):
		core.BNRegisterDataNotification(self.view.handle, self._cb)

	def _unregister(self):
		core.BNUnregisterDataNotification(self.view.handle, self._cb)

	def _data_written(self, ctxt, view, offset, length):
		try:
			self.notify.data_written(self.view, offset, length)
		except:
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
	def __getattr__(cls, name):
		if name == "list":
			_init_plugins()
			count = ctypes.c_ulonglong()
			types = core.BNGetBinaryViewTypes(count)
			result = []
			for i in xrange(0, count.value):
				result.append(BinaryViewType(types[i]))
			core.BNFreeBinaryViewTypeList(types)
			return result
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if name == "list":
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["list"]

	def __getitem__(self, value):
		_init_plugins()
		view_type = core.BNGetBinaryViewTypeByName(str(value))
		if view_type is None:
			raise KeyError, "'%s' is not a valid view type" % str(value)
		return BinaryViewType(view_type)

class BinaryViewType:
	__metaclass__ = _BinaryViewTypeMetaclass

	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNBinaryViewType)

	def __getattr__(self, name):
		if name == "name":
			return core.BNGetBinaryViewTypeName(self.handle)
		elif name == "long_name":
			return core.BNGetBinaryViewTypeLongName(self.handle)
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if (name == "name") or (name == "long_name"):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["name","long_name"]

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

	def register_arch(self, ident, arch):
		core.BNRegisterArchitectureForViewType(self.handle, ident, arch.handle)

	def get_arch(self, ident):
		arch = core.BNGetArchitectureForViewType(self.handle, ident)
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

class BinaryView:
	name = None
	long_name = None
	_registered = False
	_registered_cb = None
	view_type = None

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
		cls.view_type = BinaryViewType(core.BNRegisterBinaryViewType(cls.name, cls.long_name, cls._registered_cb))
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

	def __getattr__(self, name):
		if name == "modified":
			return self.file.modified
		elif name == "analysis_changed":
			return self.file.analysis_changed
		elif name == "has_database":
			return self.file.has_database
		elif name == "view":
			return self.file.view
		elif name == "offset":
			return self.file.offset
		elif name == "start":
			return core.BNGetStartOffset(self.handle)
		elif name == "end":
			return core.BNGetEndOffset(self.handle)
		elif name == "entry_point":
			return core.BNGetEntryPoint(self.handle)
		elif name == "arch":
			arch = core.BNGetDefaultArchitecture(self.handle)
			if arch is None:
				return None
			return Architecture(handle = arch)
		elif name == "platform":
			platform = core.BNGetDefaultPlatform(self.handle)
			if platform is None:
				return None
			return Platform(self.arch, handle = platform)
		elif name == "endianness":
			return core.BNGetDefaultEndianness(self.handle)
		elif name == "address_size":
			return core.BNGetViewAddressSize(self.handle)
		elif name == "executable":
			return core.BNIsExecutableView(self.handle)
		elif name == "functions":
			count = ctypes.c_ulonglong(0)
			funcs = core.BNGetAnalysisFunctionList(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(Function(self, core.BNNewFunctionReference(funcs[i])))
			core.BNFreeFunctionList(funcs, count.value)
			return result
		elif name == "has_functions":
			return core.BNHasFunctions(self.handle)
		elif name == "entry_function":
			func = core.BNGetAnalysisEntryPoint(self.handle)
			if func is None:
				return None
			return Function(self, func)
		elif name == "symbols":
			count = ctypes.c_ulonglong(0)
			syms = core.BNGetSymbols(self.handle, count)
			result = {}
			for i in xrange(0, count.value):
				sym = Symbol(None, None, None, handle = core.BNNewSymbolReference(syms[i]))
				result[sym.raw_name] = sym
			core.BNFreeSymbolList(syms, count.value)
			return result
		elif name == "type":
			return core.BNGetViewType(self.handle)
		elif name == "available_types":
			count = ctypes.c_ulonglong(0)
			types = core.BNGetBinaryViewTypesForData(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(BinaryViewType(types[i]))
			core.BNFreeBinaryViewTypeList(types)
			return result
		elif name == "strings":
			return self.get_strings()
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if name == "modified":
			self.file.modified = value
		elif name == "saved":
			self.file.saved = value
		elif name == "view":
			self.file.view = value
		elif name == "offset":
			self.file.offset = value
		elif name == "arch":
			if value is None:
				core.BNSetDefaultArchitecture(self.handle, None)
			else:
				core.BNSetDefaultArchitecture(self.handle, value.handle)
		elif name == "platform":
			  if value is None:
				core.BNSetDefaultPlatform(self.handle, None)
			  else:
				core.BNSetDefaultPlatform(self.handle, value.handle)
		elif ((name == "analysis_changed") or (name == "has_database") or (name == "start") or (name == "end") or
		  (name == "entry_point") or (name == "endianness") or (name == "address_size") or
		  (name == "executable") or (name == "functions") or (name == "has_functions") or
		  (name == "entry_function") or (name == "symbols") or (name == "type") or (name == "available_types") or
		  (name == "strings")):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["modified", "analysis_changed", "has_database", "view", "offset", "start", "end", "entry_point", "arch", "platform", "endianness", "address_size", "executable", "functions", "has_functions", "entry_function", "symbols", "type", "available_types", "strings"]

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
			size = "start 0x%x, len 0x%x" % (start, length)
		else:
			size = "len 0x%x" % length
		filename = self.file.filename
		if len(filename) > 0:
			return "<%s view: '%s', %s>" % (self.type, filename, size)
		return "<%s view: %s>" % (self.type, size)

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

	def perform_write(self, offset, data):
		return 0

	def perform_insert(self, offset, data):
		return 0

	def perform_remove(self, offset, length):
		return 0

	def perform_get_modification(self, offset):
		return core.Original

	def perform_is_valid_offset(self, offset):
		data = self.read(offset, 1)
		return (data is not None) and (len(data) == 1)

	def perform_is_offset_readable(self, offset):
		return self.is_valid_offset(offset)

	def perform_is_offset_writable(self, offset):
		return self.is_valid_offset(offset)

	def perform_is_offset_executable(self, offset):
		return self.is_valid_offset(offset)

	def perform_get_next_valid_offset(self, offset):
		if offset < self.perform_get_start():
			return self.perform_get_start()
		return offset

	def perform_get_start(self):
		return 0

	def perform_get_entry_point(self):
		return 0

	def perform_is_executable(self):
		return False

	def perform_get_default_endianness(self):
		return core.LittleEndian

	def create_database(self, filename):
		return self.file.create_database(filename)

	def save_auto_snapshot(self):
		return self.file.save_auto_snapshot()

	def get_view_of_type(self, name):
		return self.file.get_view_of_type(name)

	def begin_undo_actions(self):
		self.file.begin_undo_actions()

	def add_undo_action(self, action):
		core.BNAddUndoAction(self.handle, action.__class__.name, action._cb)

	def commit_undo_actions(self):
		self.file.commit_undo_actions()

	def undo(self):
		self.file.undo()

	def redo(self):
		self.file.redo()

	def navigate(self, view, offset):
		self.file.navigate(view, offset)

	def read(self, offset, length):
		buf = DataBuffer(handle = core.BNReadViewBuffer(self.handle, offset, length))
		return str(buf)

	def write(self, offset, data):
		buf = DataBuffer(data)
		return core.BNWriteViewBuffer(self.handle, offset, buf.handle)

	def insert(self, offset, data):
		buf = DataBuffer(data)
		return core.BNInsertViewBuffer(self.handle, offset, buf.handle)

	def remove(self, offset, length):
		return core.BNRemoveViewData(self.handle, offset, length)

	def get_modification(self, offset, length = None):
		if length is None:
			return core.BNGetModification(self.handle, offset)
		data = (core.BNModificationStatus * length)()
		length = core.BNGetModificationArray(self.handle, offset, data, length);
		return data[0:length]

	def is_valid_offset(self, offset):
		return core.BNIsValidOffset(self.handle, offset)

	def is_offset_readable(self, offset):
		return core.BNIsOffsetReadable(self.handle, offset)

	def is_offset_writable(self, offset):
		return core.BNIsOffsetWritable(self.handle, offset)

	def is_offset_executable(self, offset):
		return core.BNIsOffsetExecutable(self.handle, offset)

	def save(self, dest):
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
		core.BNAddFunctionForAnalysis(self.handle, platform.handle, addr)

	def add_entry_point(self, platform, addr):
		core.BNAddEntryPointForAnalysis(self.handle, platform.handle, addr)

	def remove_function(self, func):
		core.BNRemoveAnalysisFunction(self.handle, func.handle)

	def create_user_function(self, arch, addr):
		core.BNCreateUserFunction(self.handle, arch.handle, addr)

	def update_analysis(self):
		core.BNUpdateAnalysis(self.handle)

	def abort_analysis(self):
		core.BNAbortAnalysis(self.handle)

	def get_function_at(self, arch, addr):
		func = core.BNGetAnalysisFunction(self.handle, arch.handle, addr)
		if func is None:
			return None
		return Function(self, func)

	def get_functions_at(self, addr):
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
		count = ctypes.c_ulonglong(0)
		blocks = core.BNGetBasicBlocksForAddress(self.handle, addr, count)
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
		sym = core.BNGetSymbolByAddress(self.handle, addr)
		if sym is None:
			return None
		return Symbol(None, None, None, handle = sym)

	def get_symbol_by_raw_name(self, name):
		sym = core.BNGetSymbolByRawName(self.handle, name)
		if sym is None:
			return None
		return Symbol(None, None, None, handle = sym)

	def get_symbols_by_name(self, name):
		count = ctypes.c_ulonglong(0)
		syms = core.BNGetSymbolsByName(self.handle, name, count)
		result = []
		for i in xrange(0, count.value):
			result.append(Symbol(None, None, None, handle = core.BNNewSymbolReference(syms[i])))
		core.BNFreeSymbolList(syms, count.value)
		return result

	def get_symbols(self, start = None, length = None):
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
		core.BNDefineAutoSymbol(self.handle, sym.handle)

	def undefine_auto_symbol(self, sym):
		core.BNUndefineAutoSymbol(self.handle, sym.handle)

	def define_user_symbol(self, sym):
		core.BNDefineUserSymbol(self.handle, sym.handle)

	def undefine_user_symbol(self, sym):
		core.BNUndefineUserSymbol(self.handle, sym.handle)

	def define_imported_function(self, import_addr_sym, func):
		core.BNDefineImportedFunction(self.handle, import_addr_sym.handle, func.handle)

	def is_never_branch_patch_available(self, arch, addr):
		return core.BNIsNeverBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_always_branch_patch_available(self, arch, addr):
		return core.BNIsAlwaysBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_invert_branch_patch_available(self, arch, addr):
		return core.BNIsInvertBranchPatchAvailable(self.handle, arch.handle, addr)

	def is_skip_and_return_zero_patch_available(self, arch, addr):
		return core.BNIsSkipAndReturnZeroPatchAvailable(self.handle, arch.handle, addr)

	def is_skip_and_return_value_patch_available(self, arch, addr):
		return core.BNIsSkipAndReturnValuePatchAvailable(self.handle, arch.handle, addr)

	def convert_to_nop(self, arch, addr):
		return core.BNConvertToNop(self.handle, arch.handle, addr)

	def always_branch(self, arch, addr):
		return core.BNAlwaysBranch(self.handle, arch.handle, addr)

	def never_branch(self, arch, addr):
		return core.BNConvertToNop(self.handle, arch.handle, addr)

	def invert_branch(self, arch, addr):
		return core.BNInvertBranch(self.handle, arch.handle, addr)

	def skip_and_return_value(self, arch, addr, value):
		return core.BNSkipAndReturnValue(self.handle, arch.handle, addr, value)

	def get_instruction_length(self, arch, addr):
		return core.BNGetInstructionLength(self.handle, arch.handle, addr)

	def notify_data_written(self, offset, length):
		core.BNNotifyDataWritten(self.handle, offset, length)

	def notify_data_inserted(self, offset, length):
		core.BNNotifyDataInserted(self.handle, offset, length)

	def notify_data_removed(self, offset, length):
		core.BNNotifyDataRemoved(self.handle, offset, length)

	def get_strings(self, start = None, length = None):
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

class BinaryReader:
	def __init__(self, data, endian = None):
		self.handle = core.BNCreateBinaryReader(data.handle)
		if endian is None:
			core.BNSetBinaryReaderEndianness(self.handle, data.endianness)
		else:
			core.BNSetBinaryReaderEndianness(self.handle, endian)

	def __del__(self):
		core.BNFreeBinaryReader(self.handle)

	def __getattr__(self, name):
		if name == "endianness":
			return core.BNGetBinaryReaderEndianness(self.handle)
		elif name == "offset":
			return core.BNGetReaderPosition(self.handle)
		elif name == "eof":
			return core.BNIsEndOfFile(self.handle)
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if (name == "eof"):
			raise AttributeError, "attribute '%s' is read only" % name
		elif name == "endianness":
			core.BNSetBinaryReaderEndianness(self.handle, value)
		elif name == "offset":
			core.BNSeekBinaryReader(self.handle, value)
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["endianness","offset", "eof"]

	def read(self, length):
		dest = ctypes.create_string_buffer(length)
		if not core.BNReadData(self.handle, dest, length):
			return None
		return dest.raw

	def read8(self):
		result = ctypes.c_ubyte()
		if not core.BNRead8(self.handle, result):
			return None
		return result.value

	def read16(self):
		result = ctypes.c_ushort()
		if not core.BNRead16(self.handle, result):
			return None
		return result.value

	def read32(self):
		result = ctypes.c_uint()
		if not core.BNRead32(self.handle, result):
			return None
		return result.value

	def read64(self):
		result = ctypes.c_ulonglong()
		if not core.BNRead64(self.handle, result):
			return None
		return result.value

	def read16le(self):
		result = self.read(2)
		if (result is None) or (len(result) != 2):
			return None
		return struct.unpack("<H", result)[0]

	def read32le(self):
		result = self.read(4)
		if (result is None) or (len(result) != 4):
			return None
		return struct.unpack("<I", result)[0]

	def read64le(self):
		result = self.read(8)
		if (result is None) or (len(result) != 8):
			return None
		return struct.unpack("<Q", result)[0]

	def read16be(self):
		result = self.read(2)
		if (result is None) or (len(result) != 2):
			return None
		return struct.unpack(">H", result)[0]

	def read32be(self):
		result = self.read(4)
		if (result is None) or (len(result) != 4):
			return None
		return struct.unpack(">I", result)[0]

	def read64be(self):
		result = self.read(8)
		if (result is None) or (len(result) != 8):
			return None
		return struct.unpack(">Q", result)[0]

	def seek(self, offset):
		core.BNSeekBinaryReader(self.handle, offset)

	def seek_relative(self, offset):
		core.BNSeekBinaryReaderRelative(self.handle, offset)

class BinaryWriter:
	def __init__(self, data, endian = None):
		self.handle = core.BNCreateBinaryWriter(data.handle)
		if endian is None:
			core.BNSetBinaryWriterEndianness(self.handle, data.endianness)
		else:
			core.BNSetBinaryWriterEndianness(self.handle, endian)

	def __del__(self):
		core.BNFreeBinaryWriter(self.handle)

	def __getattr__(self, name):
		if name == "endianness":
			return core.BNGetBinaryWriterEndianness(self.handle)
		elif name == "offset":
			return core.BNGetWriterPosition(self.handle)
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if name == "endianness":
			core.BNSetBinaryWriterEndianness(self.handle, value)
		elif name == "offset":
			core.BNSeekBinaryWriter(self.handle, value)
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["endianness","offset"]

	def write(self, value):
		value = str(value)
		buf = ctypes.create_string_buffer(len(value))
		ctypes.memmove(buf, value, len(value))
		return core.BNWriteData(self.handle, buf, len(value))

	def write8(self, value):
		return core.BNWrite8(self.handle, value)

	def write16(self, value):
		return core.BNWrite16(self.handle, value)

	def write32(self, value):
		return core.BNWrite32(self.handle, value)

	def write64(self, value):
		return core.BNWrite64(self.handle, value)

	def write16le(self, value):
		value = struct.pack("<H", value)
		return self.write(value)

	def write32le(self, value):
		value = struct.pack("<I", value)
		return self.write(value)

	def write64le(self, value):
		value = struct.pack("<Q", value)
		return self.write(value)

	def write16be(self, value):
		value = struct.pack(">H", value)
		return self.write(value)

	def write32be(self, value):
		value = struct.pack(">I", value)
		return self.write(value)

	def write64be(self, value):
		value = struct.pack(">Q", value)
		return self.write(value)

	def seek(self, offset):
		core.BNSeekBinaryWriter(self.handle, offset)

	def seek_relative(self, offset):
		core.BNSeekBinaryWriterRelative(self.handle, offset)

class Symbol:
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

	def __getattr__(self, name):
		if name == "type":
			return core.BNSymbolType_names[core.BNGetSymbolType(self.handle)]
		elif name == "name":
			return core.BNGetSymbolRawName(self.handle)
		elif name == "short_name":
			return core.BNGetSymbolShortName(self.handle)
		elif name == "full_name":
			return core.BNGetSymbolFullName(self.handle)
		elif name == "raw_name":
			return core.BNGetSymbolRawName(self.handle)
		elif name == "address":
			return core.BNGetSymbolAddress(self.handle)
		elif name == "auto":
			return core.BNIsSymbolAutoDefined(self.handle)
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if ((name == "type") or (name == "name") or (name == "short_name") or (name == "full_name") or
			(name == "raw_name") or (name == "address")):
			raise AttributeError, "attribute '%s' is read only" % name
		elif name == "auto":
			core.BNSetSymbolAutoDefined(self.handle, value)
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["type","name", "short_name", "full_name", "raw_name", "address", "auto"]

	def __repr__(self):
		return "<%s: \"%s\" @ 0x%x>" % (self.type, self.full_name, self.address)

class Type:
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		core.BNFreeType(self.handle)

	def __getattr__(self, name):
		if name == "type_class":
			return BNTypeClass_names[core.BNGetTypeClass(self.handle)]
		elif name == "width":
			return core.BNGetTypeWidth(self.handle)
		elif name == "alignment":
			return core.BNGetTypeAlignment(self.handle)
		elif name == "signed":
			return core.BNIsTypeSigned(self.handle)
		elif name == "const":
			return core.BNIsTypeConst(self.handle)
		elif name == "float":
			return core.BNIsTypeFloatingPoint(self.handle)
		elif (name == "target") or (name == "element_type") or (name == "return_value"):
			result = core.BNGetChildType(self.handle)
			if result is None:
				return None
			return Type(result)
		elif name == "calling_convention":
			result = core.BNGetTypeCallingConvention(self.handle)
			if result is None:
				return None
			return CallingConvention(None, result)
		elif name == "parameters":
			count = ctypes.c_ulonglong()
			params = core.BNGetTypeParameters(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append((Type(core.BNNewTypeReference(params[i].type)), params[i].name))
			core.BNFreeTypeParameterList(params, count.value)
			return result
		elif name == "has_variable_arguments":
			return core.BNTypeHasVariableArguments(self.handle)
		elif name == "can_return":
			return core.BNFunctionTypeCanReturn(self.handle)
		elif name == "structure":
			result = core.BNGetTypeStructure(self.handle)
			if result is None:
				return None
			return Structure(result)
		elif name == "enumeration":
			result = core.BNGetTypeEnumeration(self.handle)
			if result is None:
				return None
			return Enumeration(result)
		elif name == "count":
			return core.BNGetTypeElementCount(self.handle)
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if ((name == "type_class") or (name == "width") or (name == "alignment") or (name == "signed") or
			(name == "const") or (name == "float") or (name == "target") or (name == "element_type") or
			(name == "return_value") or (name == "parameters") or (name == "has_variable_arguments") or
			(name == "can_return") or (name == "structure") or (name == "enumeration") or (name == "count")):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["type_class", "width", "alignment", "signed", "const", "float", "target", "element_type", "return_value", "calling_convention", "parameters", "has_variable_arguments", "can_return", "structure", "enumeration", "count"]

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
	def structure_type(self, s):
		return Type(core.BNCreateStructureType(s.handle))

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
				param_buf[i].name = "";
				param_buf[i].type = params[i].handle
			else:
				param_buf[i].name = params[i][1]
				param_buf[i].type = params[i][0]
		if calling_convention is not None:
			calling_convention = calling_convention.handle
		return Type(core.BNCreateFunctionType(ret.handle, calling_convention, param_buf, len(params),
			  variable_arguments))

class StructureMember:
	def __init__(self, t, name, offset):
		self.type = t
		self.name = name
		self.offset = offset

	def __repr__(self):
		if len(name) == 0:
			return "<member: %s, offset 0x%x>" % (str(self.type), self.offset)
		return "<%s %s%s, offset 0x%x>" % (self.type.get_string_before_name(), self.name,
							 self.type.get_string_after_name(), self.offset)

class Structure:
	def __init__(self, handle = None):
		if handle is None:
			self.handle = core.BNCreateStructure()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeStructure(self.handle)

	def __getattr__(self, name):
		if name == "name":
			return core.BNGetStructureName(self.handle)
		elif name == "members":
			count = ctypes.c_ulonglong()
			members = core.BNGetStructureMembers(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(StructureMember(Type(core.BNNewTypeReference(members[i].type)),
					members[i].name, members[i].offset))
			core.BNFreeStructureMemberList(members, count.value)
			return result
		elif name == "width":
			return core.BNGetStructureWidth(self.handle)
		elif name == "alignment":
			return core.BNGetStructureAlignment(self.handle)
		elif name == "packed":
			return core.BNIsStructurePacked(self.handle)
		elif name == "union":
			return core.BNIsStructureUnion(self.handle)
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if (name == "members") or (name == "width") or (name == "alignment"):
			raise AttributeError, "attribute '%s' is read only" % name
		elif name == "name":
			core.BNSetStructureName(self.handle, value)
		elif name == "packed":
			core.BNSetStructurePacked(self.handle, value)
		elif name == "union":
			core.BNSetStructureUnion(self.handle, value)
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["name","members", "width", "alignment", "packed", "union"]

	def __repr__(self):
		if len(self.name) > 0:
			return "<struct: %s>" % self.name
		return "<struct: size 0x%x>" % self.width

	def append(self, t, name = ""):
		core.BNAddStructureMember(self.handle, t.handle, name)

	def insert(self, offset, t, name = ""):
		core.BNAddStructureMemberAtOffset(self.handle, t.handle, name, offset)

	def remove(self, i):
		core.BNRemoveStructureMember(self.handle, i)

class EnumerationMember:
	def __init__(self, name, value, default):
		self.name = name
		self.value = value
		self.default = default

	def __repr__(self):
		return "<%s = 0x%x>" % (self.name, self.value)

class Enumeration:
	def __init__(self, handle = None):
		if handle is None:
			self.handle = core.BNCreateEnumeration()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeEnumeration(self.handle)

	def __getattr__(self, name):
		if name == "name":
			return core.BNGetEnumerationName(self.handle)
		elif name == "members":
			count = ctypes.c_ulonglong()
			members = core.BNGetEnumerationMembers(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(EnumerationMember(members[i].name, members[i].value, members[i].isDefault))
			core.BNFreeEnumerationMemberList(members, count.value)
			return result
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if name == "members":
			raise AttributeError, "attribute '%s' is read only" % name
		elif name == "name":
			core.BNSetEnumerationName(self.handle, value)
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["name", "members"]

	def __repr__(self):
		if len(self.name) > 0:
			return "<enum: %s>" % self.name
		return "<enum: %s>" % repr(self.members)

	def append(self, name, value = None):
		if value is None:
			core.BNAddEnumerationMember(self.handle, name)
		else:
			core.BNAddEnumerationMemberWithValue(self.handle, name, value)

class RegisterValue:
	def __init__(self, arch, value_type, reg, value):
		self.type = core.BNRegisterValueType_names[value_type]
		if value_type == EntryValue:
			self.reg = arch.get_reg_name(reg)
		elif value_type == OffsetFromEntryValue:
			self.reg = arch.get_reg_name(reg)
			self.offset = value
		elif value_type == ConstantValue:
			self.value = value
		elif value_type == StackFrameOffset:
			self.offset = value

	def __repr__(self):
		if self.type == "EntryValue":
			return "<entry %s>" % self.reg
		if self.type == "OffsetFromEntryValue":
			return "<entry %s + 0x%x>" % (self.reg, self.offset)
		if self.type == "ConstantValue":
			return "<const 0x%x>" % self.value
		if self.type == "StackFrameOffset":
			return "<stack frame offset 0x%x>" % self.offset
		return "<undetermined>"

class StackVariable:
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
				return "<ref to %s%+x>" % (self.name, self.referenced_offset - self.starting_offset)
			return "<ref to %s>" % self.name
		if self.referenced_offset != self.starting_offset:
			return "<operand %d ref to %s%+x>" % (self.source_operand, self.name, self.referenced_offset)
		return "<operand %d ref to %s>" % (self.source_operand, self.name)

class IndirectBranchInfo:
	def __init__(self, source_arch, source_addr, dest_arch, dest_addr, auto_defined):
		self.source_arch = source_arch
		self.source_addr = source_addr
		self.dest_arch = dest_arch
		self.dest_addr = dest_addr
		self.auto_defined = auto_defined

	def __repr__(self):
		return "<branch %s:0x%x -> %s:0x%x>" % (self.source_arch.name, self.source_addr, self.dest_arch.name, self.dest_addr)

class Function:
	def __init__(self, view, handle):
		self._view = view
		self.handle = core.handle_of_type(handle, core.BNFunction)

	def __del__(self):
		core.BNFreeFunction(self.handle)

	def __getattr__(self, name):
		if name == "view":
			return self._view
		elif name == "arch":
			arch = core.BNGetFunctionArchitecture(self.handle)
			if arch is None:
				return None
			return Architecture(arch)
		elif name == "start":
			return core.BNGetFunctionStart(self.handle)
		elif name == "symbol":
			sym = core.BNGetFunctionSymbol(self.handle)
			if sym is None:
				return None
			return Symbol(None, None, None, handle = sym)
		elif name == "auto":
			return core.BNWasFunctionAutomaticallyDiscovered(self.handle)
		elif name == "can_return":
			return core.BNCanFunctionReturn(self.handle)
		elif name == "explicitly_defined_type":
			return core.BNHasExplicitlyDefinedType(self.handle)
		elif name == "basic_blocks":
			count = ctypes.c_ulonglong()
			blocks = core.BNGetFunctionBasicBlockList(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(BasicBlock(self._view, core.BNNewBasicBlockReference(blocks[i])))
			core.BNFreeBasicBlockList(blocks, count.value)
			return result
		elif name == "comments":
			count = ctypes.c_ulonglong()
			addrs = core.BNGetCommentedAddresses(self.handle, count)
			result = {}
			for i in xrange(0, count.value):
				result[addrs[i]] = self.get_comment_at(addrs[i])
			core.BNFreeAddressList(addrs)
			return result
		elif name == "low_level_il":
			return LowLevelILFunction(self.arch, core.BNNewLowLevelILFunctionReference(
						core.BNGetFunctionLowLevelIL(self.handle)))
		elif name == "low_level_il_basic_blocks":
			count = ctypes.c_ulonglong()
			blocks = core.BNGetFunctionLowLevelILBasicBlockList(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(BasicBlock(self._view, core.BNNewBasicBlockReference(blocks[i])))
			core.BNFreeBasicBlockList(blocks, count.value)
			return result
		elif name == "type":
			return Type(core.BNGetFunctionType(self.handle))
		elif name == "stack_layout":
			count = ctypes.c_ulonglong()
			v = core.BNGetStackLayout(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(StackVariable(v[i].offset, v[i].name, Type(handle = core.BNNewTypeReference(v[i].type))))
			result.sort(key = lambda x: x.offset)
			core.BNFreeStackLayout(v, count.value)
			return result
		elif name == "indirect_branches":
			count = ctypes.c_ulonglong()
			branches = core.BNGetIndirectBranches(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(IndirectBranchInfo(Architecture(branches[i].sourceArch), branches[i].sourceAddr, Architecture(branches[i].destArch), branches[i].destAddr, branches[i].autoDefined))
			core.BNFreeIndirectBranchList(branches)
			return result
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if ((name == "view") or (name == "arch") or (name == "start") or (name == "symbol") or (name == "auto") or
		(name == "can_return") or (name == "basic_blocks") or (name == "comments") or (name == "low_level_il") or
		(name == "low_level_il_basic_blocks") or (name == "type") or (name == "explicitly_defined_type") or
		(name == "stack_layout") or (name == "indirect_branches")):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["view", "arch", "start", "symbol", "auto", "can_return", "explicitly_defined_type", "basic_blocks", "comments", "low_level_il", "low_level_il_basic_blocks", "type", "stack_layout"]

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<func: %s@0x%x>" % (arch.name, self.start)
		else:
			return "<func: 0x%x>" % self.start

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
		return RegisterValue(arch, value.state, value.reg, value.value)

	def get_reg_value_after(self, arch, addr, reg):
		if isinstance(reg, str):
			reg = arch.regs[reg].index
		value = core.BNGetRegisterValueAfterInstruction(self.handle, arch.handle, addr, reg)
		return RegisterValue(arch, value.state, value.reg, value.value)

	def get_reg_value_at_low_level_il_instruction(self, i, reg):
		if isinstance(reg, str):
			reg = self.arch.regs[reg].index
		value = core.BNGetRegisterValueAtInstruction(self.handle, self.arch.handle, i, reg)
		return RegisterValue(self.arch, value.state, value.reg, value.value)

	def get_reg_value_after_low_level_il_instruction(self, i, reg):
		if isinstance(reg, str):
			reg = self.arch.regs[reg].index
		value = core.BNGetRegisterValueAfterInstruction(self.handle, self.arch.handle, i, reg)
		return RegisterValue(self.arch, value.state, value.reg, value.value)

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

	def get_low_level_il_flag_uses_for_definition(self, i, flag):
		if isinstance(flag, str):
			flag = self.arch._flags[flag]
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILFlagUsesForDefinition(self.handle, i, flag, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeLowLevelILInstructionList(instrs)
		return result

	def get_low_level_il_flag_definitions_for_use(self, i, flag):
		if isinstance(flag, str):
			flag = self.arch._flags[flag]
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILFlagDefinitionsForUse(self.handle, i, flag, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeLowLevelILInstructionList(instrs)
		return result

	def get_flags_read_by_low_level_il_instruction(self, i):
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsReadByLowLevelILInstruction(self.handle, i, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self.arch._flags_by_index[flags[i]])
		core.BNFreeRegisterList(flags)
		return result

	def get_flags_written_by_low_level_il_instruction(self, i):
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsWrittenByLowLevelILInstruction(self.handle, i, count)
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

class BasicBlockEdge:
	def __init__(self, branch_type, target, arch):
		self.type = core.BNBranchType_names[branch_type]
		if self.type != "UnresolvedBranch":
			self.target = target
			self.arch = arch

	def __repr__(self):
		if self.type == "UnresolvedBranch":
			return "<%s>" % self.type
		elif self.arch:
			return "<%s: %s@0x%x>" % (self.type, self.arch.name, self.target)
		else:
			return "<%s: 0x%x>" % (self.type, self.target)

class BasicBlock:
	def __init__(self, view, handle):
		self.view = view
		self.handle = core.handle_of_type(handle, core.BNBasicBlock)

	def __del__(self):
		core.BNFreeBasicBlock(self.handle)

	def __getattr__(self, name):
		if name == "function":
			func = core.BNGetBasicBlockFunction(self.handle)
			if func is None:
				return None
			return Function(self.view, func)
		elif name == "arch":
			arch = core.BNGetBasicBlockArchitecture(self.handle)
			if arch is None:
				return None
			return Architecture(arch)
		elif name == "start":
			return core.BNGetBasicBlockStart(self.handle)
		elif name == "end":
			return core.BNGetBasicBlockEnd(self.handle)
		elif name == "length":
			return core.BNGetBasicBlockLength(self.handle)
		elif name == "outgoing_edges":
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
		elif name == "has_undetermined_outgoing_edges":
			return core.BNBasicBlockHasUndeterminedOutgoingEdges(self.handle)
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if ((name == "function") or (name == "arch") or (name == "start") or (name == "end") or
			(name == "length") or (name == "outgoing_edges") or (name == "has_undetermined_outgoing_edges")):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["function", "arch", "start", "end", "length", "outgoing_edges", "has_undetermined_outgoing_edges"]

	def __len__(self):
		return int(core.BNGetBasicBlockLength(self.handle))

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<block: %s@0x%x-0x%x>" % (arch.name, self.start, self.end)
		else:
			return "<block: 0x%x-0x%x>" % (self.start, self.end)

	def mark_recent_use():
		core.BNMarkBasicBlockAsRecentlyUsed(self.handle)

class FunctionGraphTextLine:
	def __init__(self, addr, tokens):
		self.address = addr
		self.tokens = tokens

	def __str__(self):
		result = ""
		for token in self.tokens:
			result += token.text
		return result

	def __repr__(self):
		result = "<0x%x: %s>" % (self.address, str(self))

class FunctionGraphEdge:
	def __init__(self, branch_type, arch, target, points):
		self.type = branch_type
		self.arch = arch
		self.target = target
		self.points = points

	def __repr__(self):
		if self.arch:
			return "<%s: %s@0x%x>" % (self.type, self.arch.name, self.target)
		return "<%s: 0x%x>" % (self.type, self.target)

class FunctionGraphBlock:
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		core.BNFreeFunctionGraphBlock(self.handle)

	def __getattr__(self, name):
		if name == "arch":
			arch = core.BNGetFunctionGraphBlockArchitecture(self.handle)
			if arch is None:
				return None
			return Architecture(arch)
		elif name == "start":
			return core.BNGetFunctionGraphBlockStart(self.handle)
		elif name == "end":
			return core.BNGetFunctionGraphBlockEnd(self.handle)
		elif name == "x":
			return core.BNGetFunctionGraphBlockX(self.handle)
		elif name == "y":
			return core.BNGetFunctionGraphBlockY(self.handle)
		elif name == "width":
			return core.BNGetFunctionGraphBlockWidth(self.handle)
		elif name == "height":
			return core.BNGetFunctionGraphBlockHeight(self.handle)
		elif name == "lines":
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
					tokens.append(InstructionTextToken(token_type, text, value))
				result.append(FunctionGraphTextLine(addr, tokens))
			core.BNFreeFunctionGraphBlockLines(lines, count.value)
			return result
		elif name == "outgoing_edges":
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
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if ((name == "arch") or (name == "start") or (name == "end") or (name == "x") or (name == "y") or
			(name == "width") or (name == "height") or (name == "lines") or (name == "outgoing_edges")):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["arch", "start", "end", "x", "y", "width", "height", "lines", "outgoing_edges"]

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<graph block: %s@0x%x-0x%x>" % (arch.name, self.start, self.end)
		else:
			return "<graph block: 0x%x-0x%x>" % (self.start, self.end)

class FunctionGraph:
	def __init__(self, view, handle):
		self.view = view
		self.handle = handle
		self._on_complete = None
		self._cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._complete)

	def __del__(self):
		self.abort()
		core.BNFreeFunctionGraph(self.handle)

	def __getattr__(self, name):
		if name == "function":
			func = core.BNGetFunctionForFunctionGraph(self.handle)
			if func is None:
				return None
			return Function(self.view, func)
		elif name == "horizontal_block_margin":
			return core.BNGetHorizontalFunctionGraphBlockMargin(self.handle)
		elif name == "vertical_block_margin":
			return core.BNGetVerticalFunctionGraphBlockMargin(self.handle)
		elif name == "max_symbol_width":
			return core.BNGetFunctionGraphMaximumSymbolWidth(self.handle)
		elif name == "complete":
			return core.BNIsFunctionGraphLayoutComplete(self.handle)
		elif name == "type":
			return core.BNFunctionGraphType_names[core.BNGetFunctionGraphType(self.handle)]
		elif name == "blocks":
			count = ctypes.c_ulonglong()
			blocks = core.BNGetFunctionGraphBlocks(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(FunctionGraphBlock(core.BNNewFunctionGraphBlockReference(blocks[i])))
			core.BNFreeFunctionGraphBlockList(blocks, count.value)
			return result
		elif name == "width":
			return core.BNGetFunctionGraphWidth(self.handle)
		elif name == "height":
			return core.BNGetFunctionGraphHeight(self.handle)
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if ((name == "function") or (name == "complete") or (name == "type") or (name == "blocks") or
			(name == "width") or (name == "height")):
			raise AttributeError, "attribute '%s' is read only" % name
		elif name == "horizontal_block_margin":
			core.BNSetFunctionGraphBlockMargins(self.handle, value, self.vertical_block_margin)
		elif name == "vertical_block_margin":
			core.BNSetFunctionGraphBlockMargins(self.handle, self.horizontal_block_margin, value)
		elif name == "max_symbol_width":
			core.BNSetFunctionGraphMaximumSymbolWidth(self.handle, value)
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["function", "horizontal_block_margin", "vertical_block_margin", "max_symbol_width", "complete", "type", "blocks", "width", "height"]

	def __repr__(self):
		return "<graph of %s>" % repr(self.function)

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
			option = core.BNFunctionGraphOption_by_name(option)
		return core.BNIsFunctionGraphOptionSet(self.handle, option)

	def set_option(self, option, state = True):
		if isinstance(option, str):
			option = core.BNFunctionGraphOption_by_name(option)
		core.BNSetFunctionGraphOption(self.handle, option, state)

class RegisterInfo:
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

class InstructionBranch:
	def __init__(self, branch_type, target = 0, arch = None):
		self.type = branch_type
		self.target = target
		self.arch = arch

	def __repr__(self):
		branch_type = self.type
		if not isinstance(branch_type, str):
			branch_type = core.BNBranchType_names[branch_type]
		if self.arch is not None:
			return "<%s: %s@0x%x>" % (branch_type, self.arch.name, self.target)
		return "<%s: 0x%x>" % (branch_type, self.target)

class InstructionInfo:
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

class InstructionTextToken:
	def __init__(self, token_type, text, value = 0):
		self.type = token_type
		self.text = text
		self.value = value

	def __str__(self):
		return self.text

	def __repr__(self):
		return repr(self.text)

class _ArchitectureMetaClass(type):
	def __getattr__(cls, name):
		if name == "list":
			_init_plugins()
			count = ctypes.c_ulonglong()
			archs = core.BNGetArchitectureList(count)
			result = []
			for i in xrange(0, count.value):
				result.append(Architecture(archs[i]))
			core.BNFreeArchitectureList(archs)
			return result
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(cls, name, value):
		if (name == "list"):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			type.__setattr__(cls, name, value)

	def __dir__(self):
		return dir(self.__class__) + ["list"]

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

class Architecture:
	name = None
	endianness = core.LittleEndian
	address_size = 8
	default_int_size = 4
	regs = {}
	stack_pointer = None
	link_reg = None
	flags = []
	flag_write_types = []
	flag_roles = {}
	flags_required_for_flag_condition = {}
	flags_written_by_flag_write_type = {}
	__metaclass__ = _ArchitectureMetaClass

	def __init__(self, handle = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNArchitecture)
			self.__dict__["name"] = core.BNGetArchitectureName(self.handle)
			self.__dict__["endianness"] = core.BNEndianness_names[core.BNGetArchitectureEndianness(self.handle)]
			self.__dict__["address_size"] = core.BNGetArchitectureAddressSize(self.handle)
			self.__dict__["default_int_size"] = core.BNGetArchitectureDefaultIntegerSize(self.handle)
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
			for cond in core.BNLowLevelILFlagCondition_names.keys():
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
			self._cb = core.BNCustomArchitecture()
			self._cb.context = 0
			self._cb.init = self._cb.init.__class__(self._init)
			self._cb.getEndianness = self._cb.getEndianness.__class__(self._get_endianness)
			self._cb.getAddressSize = self._cb.getAddressSize.__class__(self._get_address_size)
			self._cb.getDefaultIntegerSize = self._cb.getDefaultIntegerSize.__class__(self._get_default_integer_size)
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
			for reg in self.regs.keys():
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
			for flag in self.__class__.flag_roles.keys():
				role = self.__class__.flag_roles[flag]
				if isinstance(role, str):
					role = core.BNFlagRole_by_name[role]
				self._flag_roles[self._flags[flag]] = role

			self._flags_required_for_flag_condition = {}
			self.__dict__["flags_required_for_flag_condition"] = self.__class__.flags_required_for_flag_condition
			for cond in self.__class__.flags_required_for_flag_condition.keys():
				flags = []
				for flag in self.__class__.flags_required_for_flag_condition[cond]:
					flags.append(self._flags[flag])
				self._flags_required_for_flag_condition[cond] = flags

			self._flags_written_by_flag_write_type = {}
			self.__dict__["flags_written_by_flag_write_type"] = self.__class__.flags_written_by_flag_write_type
			for write_type in self.__class__.flags_written_by_flag_write_type.keys():
				flags = []
				for flag in self.__class__.flags_written_by_flag_write_type[write_type]:
					flags.append(self._flags[flag])
				self._flags_written_by_flag_write_type[self._flag_write_types[write_type]] = flags

			self._pending_reg_lists = {}
			self._pending_token_lists = {}


	def __getattr__(self, name):
		if name == "full_width_regs":
			count = ctypes.c_ulonglong()
			regs = core.BNGetFullWidthArchitectureRegisters(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
			core.BNFreeRegisterList(regs)
			return result
		elif name == "calling_conventions":
			count = ctypes.c_ulonglong()
			cc = core.BNGetArchitectureCallingConventions(self.handle, count)
			result = {}
			for i in xrange(0, count.value):
				obj = CallingConvention(None, core.BNNewCallingConventionReference(cc[i]))
				result[obj.name] = obj
			core.BNFreeCallingConventionList(cc, count)
			return result
		elif name == "standalone_platform":
			pl = core.BNGetArchitectureStandalonePlatform(self.handle)
			return Platform(self, pl)

		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if ((name == "name") or (name == "endianness") or (name == "address_size") or (name == "default_int_size") or
			(name == "regs") or (name == "full_width_regs") or (name == "calling_conventions")):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["full_width_regs","calling_conventions"]

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
		except:
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
					token_buf[i].type = BNInstructionTextTokenType_by_name[tokens[i].type]
				else:
					token_buf[i].type = tokens[i].type
				token_buf[i].text = tokens[i].text
				token_buf[i].value = tokens[i].value
			result[0] = token_buf
			ptr = ctypes.cast(token_buf, ctypes.c_void_p)
			self._pending_token_lists[ptr.value] = (ptr.value, token_buf)
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _free_instruction_text(self, tokens, count):
		try:
			buf = ctypes.cast(tokens, ctypes.c_void_p)
			if buf.value not in self._pending_token_lists:
				raise ValueError, "freeing token list that wasn't allocated"
			del self._pending_token_lists[buf.value]
		except:
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
		except:
			log_error(traceback.format_exc())
			return False

	def _get_register_name(self, ctxt, reg):
		try:
			if reg in self._regs_by_index:
				return core.BNAllocString(self._regs_by_index[reg])
			return core.BNAllocString("")
		except:
			log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_flag_name(self, ctxt, flag):
		try:
			if flag in self._flags_by_index:
				return core.BNAllocString(self._flags_by_index[flag])
			return core.BNAllocString("")
		except:
			log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_flag_write_type_name(self, ctxt, write_type):
		try:
			if write_type in self._flag_write_types_by_index:
				return core.BNAllocString(self._flag_write_types_by_index[write_type])
			return core.BNAllocString("")
		except:
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
		except:
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
		except:
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
		except:
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
		except:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flag_role(self, ctxt, flag):
		try:
			if flag in self._flag_roles:
				return self._flag_roles[flag]
			return core.SpecialFlagRole
		except:
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
		except:
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
		except:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flag_write_low_level_il(self, ctxt, op, size, write_type, operands, operand_count, il):
		try:
			write_type_name = None
			if write_type != 0:
				write_type_name = self._flag_write_types_by_index[write_type]
			operand_list = []
			for i in xrange(operand_count):
				if operands[i].constant:
					operand_list.append(operands[i].value)
				else:
					operand_list.append(self._regs_by_index[operands[i].reg])
			return self.perform_get_flag_write_low_level_il(op, size, write_type_name, operand_list,
				LowLevelILFunction(self, core.BNNewLowLevelILFunctionReference(il)))
		except:
			log_error(traceback.format_exc())
			return False

	def _get_flag_condition_low_level_il(self, ctxt, cond, il):
		try:
			return self.perform_get_flag_condition_low_level_il(cond,
				LowLevelILFunction(self, core.BNNewLowLevelILFunctionReference(il)))
		except:
			log_error(traceback.format_exc())
			return 0

	def _free_register_list(self, ctxt, regs):
		try:
			buf = ctypes.cast(regs, ctypes.c_void_p)
			if buf.value not in self._pending_reg_lists:
				raise ValueError, "freeing register list that wasn't allocated"
			del self._pending_reg_lists[buf.value]
		except:
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
		except:
			log_error(traceback.format_exc())
			result[0].fullWidthRegister = 0
			result[0].offset = 0
			result[0].size = 0
			result[0].extend = core.NoExtend

	def _get_stack_pointer_register(self, ctxt):
		try:
			return self._all_regs[self.__class__.stack_pointer]
		except:
			log_error(traceback.format_exc())
			return 0

	def _get_link_register(self, ctxt):
		try:
			if self.__class__.link_reg is None:
				return 0xffffffff
			return self._all_regs[self.__class__.link_reg]
		except:
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

	def perform_get_instruction_low_level_il(self, data, addr, il):
		return None

	def perform_get_flag_write_low_level_il(self, op, size, write_type, operands, il):
		return False

	def perform_get_flag_condition_low_level_il(self, cond, il):
		return il.unimplemented()

	def perform_assemble(self, code, addr):
		return None, "Architecture does not implement an assembler.\n"

	def perform_is_never_branch_patch_available(self, data, addr):
		return False

	def perform_is_always_branch_patch_available(self, data, addr):
		return False

	def perform_is_invert_branch_patch_available(self, data, addr):
		return False

	def perform_is_skip_and_return_zero_patch_available(self, data, addr):
		return False

	def perform_is_skip_and_return_value_patch_available(self, data, addr):
		return False

	def perform_convert_to_nop(self, data, addr):
		return None

	def perform_always_branch(self, data, addr):
		return None

	def perform_invert_branch(self, data, addr):
		return None

	def perform_skip_and_return_value(self, data, addr, value):
		return None

	def get_instruction_info(self, data, addr):
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
			result.append(InstructionTextToken(token_type, text, value))
		core.BNFreeInstructionText(tokens, count.value)
		return result, length.value

	def get_instruction_low_level_il(self, data, addr, il):
		data = str(data)
		length = ctypes.c_ulonglong()
		length.value = len(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		core.BNGetInstructionLowLevelIL(self.handle, buf, addr, length, il.handle)
		return length.value

	def get_reg_name(self, reg):
		return core.BNGetArchitectureRegisterName(self.handle, reg)

	def get_flag_name(self, flag):
		return core.BNGetArchitectureFlagName(self.handle, flag)

	def get_flag_write_type_name(self, write_type):
		return core.BNGetArchitectureFlagWriteTypeName(self.handle, write_type)

	def get_flag_by_name(self, flag):
		return self._flags[flag]

	def get_flag_write_type_by_name(self, write_type):
		return self._flag_write_types[write_type]

	def get_flag_write_low_level_il(self, op, size, write_type, operands, il):
		operand_list = (core.BNRegisterOrConstant * len(operands))()
		for i in xrange(len(operands)):
			if isinstance(operands[i], str):
				operand_list[i].constant = False
				operand_list[i].reg = self._flags[operands[i]]
			else:
				operand_list[i].constant = True
				operand_list[i].value = operands[i]
		return core.BNGetArchitectureFlagWriteLowLevelIL(self.handle, op, size, self._flag_write_types[write_type],
			operand_list, len(operand_list), il.handle)

	def get_default_flag_write_low_level_il(self, op, size, write_type, operands, il):
		operand_list = (core.BNRegisterOrConstant * len(operands))()
		for i in xrange(len(operands)):
			if isinstance(operands[i], str):
				operand_list[i].constant = False
				operand_list[i].reg = self._flags[operands[i]]
			else:
				operand_list[i].constant = True
				operand_list[i].value = operands[i]
		return core.BNGetDefaultArchitectureFlagWriteLowLevelIL(self.handle, op, size, self._flag_write_types[write_type],
			operand_list, len(operand_list), il.handle)

	def get_flag_condition_low_level_il(self, cond, il):
		return core.BNGetArchitectureFlagConditionLowLevelIL(self.handle, cond, il.handle)

	def get_modified_regs_on_write(self, reg):
		reg = core.BNGetArchitectureRegisterByName(self.handle, str(reg))
		count = ctypes.c_ulonglong()
		regs = core.BNGetModifiedArchitectureRegistersOnWrite(self.handle, reg, count)
		result = []
		for i in xrange(0, count.value):
			result.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def assemble(self, code, addr = 0):
		result = DataBuffer()
		errors = ctypes.c_char_p()
		if not core.BNAssemble(self.handle, code, addr, result.handle, errors):
			return None, errors.value
		return str(result), errors.value

	def is_never_branch_patch_available(self, data, addr):
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureNeverBranchPatchAvailable(self.handle, buf, addr, len(data))

	def is_always_branch_patch_available(self, data, addr):
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureAlwaysBranchPatchAvailable(self.handle, buf, addr, len(data))

	def is_invert_branch_patch_available(self, data, addr):
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureInvertBranchPatchAvailable(self.handle, buf, addr, len(data))

	def is_skip_and_return_zero_patch_available(self, data, addr):
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureSkipAndReturnZeroPatchAvailable(self.handle, buf, addr, len(data))

	def is_skip_and_return_value_patch_available(self, data, addr):
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureSkipAndReturnValuePatchAvailable(self.handle, buf, addr, len(data))

	def convert_to_nop(self, data, addr):
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureConvertToNop(self.handle, buf, addr, len(data)):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def always_branch(self, data, addr):
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureAlwaysBranch(self.handle, buf, addr, len(data)):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def invert_branch(self, data, addr):
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureInvertBranch(self.handle, buf, addr, len(data)):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def skip_and_return_value(self, data, addr, value):
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureSkipAndReturnValue(self.handle, buf, addr, len(data), value):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def is_view_type_constant_defined(self, type_name, const_name):
		return core.BNIsBinaryViewTypeArchitectureConstantDefined(self.handle, type_name, const_name)

	def get_view_type_constant(self, type_name, const_name, default_value = 0):
		return core.BNGetBinaryViewTypeArchitectureConstant(self.handle, type_name, const_name, default_value)

	def set_view_type_constant(self, type_name, const_name, value):
		core.BNSetBinaryViewTypeArchitectureConstant(self.handle, type_name, const_name, value)

	def parse_types_from_source(self, source, filename = None, include_dirs = []):
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
		return (TypeParserResult(types, variables, functions), error_str)

	def parse_types_from_source_file(self, filename, include_dirs = []):
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
		return (TypeParserResult(types, variables, functions), error_str)

	def register_calling_convention(self, cc):
		core.BNRegisterCallingConvention(self.handle, cc.handle)

class ReferenceSource:
	def __init__(self, func, arch, addr):
		self.function = func
		self.arch = arch
		self.address = addr

	def __repr__(self):
		if self.arch:
			return "<ref: %s@0x%x>" % (self.arch.name, self.address)
		else:
			return "<ref: 0x%x>" % self.address

class LowLevelILLabel:
	def __init__(self, handle = None):
		if handle is None:
			self.handle = (core.BNLowLevelILLabel * 1)()
			core.BNLowLevelILInitLabel(self.handle)
		else:
			self.handle = handle

class LowLevelILInstruction:
	ILOperations = {
		core.LLIL_NOP: [],
		core.LLIL_SET_REG: [("dest", "reg"), ("src", "expr")],
		core.LLIL_SET_REG_SPLIT: [("hi", "reg"), ("lo", "reg"), ("src", "expr")],
		core.LLIL_SET_FLAG: [("dest", "flag"), ("src", "expr")],
		core.LLIL_LOAD: [("src", "expr")],
		core.LLIL_STORE: [("dest", "expr"), ("src", "expr")],
		core.LLIL_PUSH: [("src", "expr")],
		core.LLIL_POP: [],
		core.LLIL_REG: [("src", "reg")],
		core.LLIL_CONST: [("value", "int")],
		core.LLIL_FLAG: [("src", "flag")],
		core.LLIL_FLAG_BIT: [("src", "flag"), ("bit", "int")],
		core.LLIL_ADD: [("left", "expr"), ("right", "expr")],
		core.LLIL_ADC: [("left", "expr"), ("right", "expr")],
		core.LLIL_SUB: [("left", "expr"), ("right", "expr")],
		core.LLIL_SBB: [("left", "expr"), ("right", "expr")],
		core.LLIL_AND: [("left", "expr"), ("right", "expr")],
		core.LLIL_OR: [("left", "expr"), ("right", "expr")],
		core.LLIL_XOR: [("left", "expr"), ("right", "expr")],
		core.LLIL_LSL: [("left", "expr"), ("right", "expr")],
		core.LLIL_LSR: [("left", "expr"), ("right", "expr")],
		core.LLIL_ASR: [("left", "expr"), ("right", "expr")],
		core.LLIL_ROL: [("left", "expr"), ("right", "expr")],
		core.LLIL_RLC: [("left", "expr"), ("right", "expr")],
		core.LLIL_ROR: [("left", "expr"), ("right", "expr")],
		core.LLIL_RRC: [("left", "expr"), ("right", "expr")],
		core.LLIL_MUL: [("left", "expr"), ("right", "expr")],
		core.LLIL_MULU_DP: [("left", "expr"), ("right", "expr")],
		core.LLIL_MULS_DP: [("left", "expr"), ("right", "expr")],
		core.LLIL_DIVU: [("left", "expr"), ("right", "expr")],
		core.LLIL_DIVU_DP: [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		core.LLIL_DIVS: [("left", "expr"), ("right", "expr")],
		core.LLIL_DIVS_DP: [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		core.LLIL_MODU: [("left", "expr"), ("right", "expr")],
		core.LLIL_MODU_DP: [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		core.LLIL_MODS: [("left", "expr"), ("right", "expr")],
		core.LLIL_MODS_DP: [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		core.LLIL_NEG: [("src", "expr")],
		core.LLIL_NOT: [("src", "expr")],
		core.LLIL_SX: [("src", "expr")],
		core.LLIL_ZX: [("src", "expr")],
		core.LLIL_JUMP: [("dest", "expr")],
		core.LLIL_JUMP_TO: [("dest", "expr"), ("targets", "int_list")],
		core.LLIL_CALL: [("dest", "expr")],
		core.LLIL_RET: [("dest", "expr")],
		core.LLIL_NORET: [],
		core.LLIL_IF: [("condition", "expr"), ("true", "int"), ("false", "int")],
		core.LLIL_GOTO: [("dest", "int")],
		core.LLIL_FLAG_COND: [("condition", "cond")],
		core.LLIL_CMP_E: [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_NE: [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_SLT: [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_ULT: [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_SLE: [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_ULE: [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_SGE: [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_UGE: [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_SGT: [("left", "expr"), ("right", "expr")],
		core.LLIL_CMP_UGT: [("left", "expr"), ("right", "expr")],
		core.LLIL_TEST_BIT: [("left", "expr"), ("right", "expr")],
		core.LLIL_SYSCALL: [],
		core.LLIL_BP: [],
		core.LLIL_TRAP: [("value", "int")],
		core.LLIL_UNDEF: [],
		core.LLIL_UNIMPL: [],
		core.LLIL_UNIMPL_MEM: [("src", "expr")]
	}

	def __init__(self, func, i):
		instr = core.BNGetLowLevelILByIndex(func.handle, i)
		self.function = func
		self.index = i
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
				operands = core.BNLowLevelILGetOperandList(func.handle, self.index, i, count)
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

	def __getattr__(self, name):
		if name == "tokens":
			count = ctypes.c_ulonglong()
			tokens = ctypes.POINTER(core.BNInstructionTextToken)()
			if not core.BNGetLowLevelILExprText(self.function.handle, self.function.arch.handle,
								  self.index, tokens, count):
				return None
			result = []
			for i in xrange(0, count.value):
				token_type = core.BNInstructionTextTokenType_names[tokens[i].type]
				text = tokens[i].text
				value = tokens[i].value
				result.append(InstructionTextToken(token_type, text, value))
			core.BNFreeInstructionText(tokens, count.value)
			return result
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if name == "tokens":
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["tokens"]

class LowLevelILExpr:
	def __init__(self, index):
		self.index = index

class LowLevelILFunction:
	def __init__(self, arch, handle = None):
		self.arch = arch
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNLowLevelILFunction)
		else:
			self.handle = core.BNCreateLowLevelILFunction()

	def __del__(self):
		core.BNFreeLowLevelILFunction(self.handle)

	def __getattr__(self, name):
		if name == "current_address":
			return core.BNLowLevelILGetCurrentAddress(self.handle)
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if name == "current_address":
			core.BNLowLevelILSetCurrentAddress(self.handle, value)
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["current_address"]

	def __len__(self):
		return int(core.BNGetLowLevelILInstructionCount(self.handle))

	def __getitem__(self, i):
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError, "expected integer instruction index"
		if isinstance(i, LowLevelILExpr):
			return LowLevelILInstruction(self, i.index)
		if (i < 0) or (i >= len(self)):
			raise IndexError, "index out of range"
		return LowLevelILInstruction(self, core.BNGetLowLevelILIndexForInstruction(self.handle, i))

	def __setitem__(self, i):
		raise IndexError, "instruction modification not implemented"

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
			operation = BNLowLevelILOperation_by_name[operation]
		if isinstance(flags, str):
			flags = self.arch.get_flag_write_type_by_name(flags)
		elif flags is None:
			flags = 0
		return LowLevelILExpr(core.BNLowLevelILAddExpr(self.handle, operation, size, flags, a, b, c, d))

	def append(self, expr):
		return core.BNLowLevelILAddInstruction(self.handle, expr.index)

	def nop(self):
		return self.expr(core.LLIL_NOP)

	def set_reg(self, size, reg, value, flags = 0):
		if isinstance(reg, str):
			reg = self.arch.regs[reg].index
		return self.expr(core.LLIL_SET_REG, reg, value.index, size = size, flags = flags)

	def set_reg_split(self, size, hi, lo, value, flags = 0):
		if isinstance(hi, str):
			hi = self.arch.regs[hi].index
		if isinstance(lo, str):
			lo = self.arch.regs[lo].index
		return self.expr(core.LLIL_SET_REG_SPLIT, hi, lo, value.index, size = size, flags = flags)

	def set_flag(self, flag, value):
		return self.expr(core.LLIL_SET_FLAG, self.arch.get_flag_by_name(flag), value.index)

	def load(self, size, addr):
		return self.expr(core.LLIL_LOAD, addr.index, size = size)

	def store(self, size, addr, value):
		return self.expr(core.LLIL_STORE, addr.index, value.index, size = size)

	def push(self, size, value):
		return self.expr(core.LLIL_PUSH, value.index, size = size)

	def pop(self, size):
		return self.expr(core.LLIL_POP, size = size)

	def reg(self, size, reg):
		if isinstance(reg, str):
			reg = self.arch.regs[reg].index
		return self.expr(core.LLIL_REG, reg, size = size)

	def const(self, size, value):
		return self.expr(core.LLIL_CONST, value, size = size)

	def flag(self, reg):
		return self.expr(core.LLIL_FLAG, self.arch.get_flag_by_name(reg))

	def flag_bit(self, size, reg, bit):
		return self.expr(core.LLIL_FLAG_BIT, self.arch.get_flag_by_name(reg), bit, size = size)

	def add(self, size, a, b, flags = None):
		return self.expr(core.LLIL_ADD, a.index, b.index, size = size, flags = flags)

	def add_carry(self, size, a, b, flags = None):
		return self.expr(core.LLIL_ADC, a.index, b.index, size = size, flags = flags)

	def sub(self, size, a, b, flags = None):
		return self.expr(core.LLIL_SUB, a.index, b.index, size = size, flags = flags)

	def sub_borrow(self, size, a, b, flags = None):
		return self.expr(core.LLIL_SBB, a.index, b.index, size = size, flags = flags)

	def and_expr(self, size, a, b, flags = None):
		return self.expr(core.LLIL_AND, a.index, b.index, size = size, flags = flags)

	def or_expr(self, size, a, b, flags = None):
		return self.expr(core.LLIL_OR, a.index, b.index, size = size, flags = flags)

	def xor_expr(self, size, a, b, flags = None):
		return self.expr(core.LLIL_XOR, a.index, b.index, size = size, flags = flags)

	def shift_left(self, size, a, b, flags = None):
		return self.expr(core.LLIL_LSL, a.index, b.index, size = size, flags = flags)

	def logical_shift_right(self, size, a, b, flags = None):
		return self.expr(core.LLIL_LSR, a.index, b.index, size = size, flags = flags)

	def arith_shift_right(self, size, a, b, flags = None):
		return self.expr(core.LLIL_ASR, a.index, b.index, size = size, flags = flags)

	def rotate_left(self, size, a, b, flags = None):
		return self.expr(core.LLIL_ROL, a.index, b.index, size = size, flags = flags)

	def rotate_left_carry(self, size, a, b, flags = None):
		return self.expr(core.LLIL_RLC, a.index, b.index, size = size, flags = flags)

	def rotate_right(self, size, a, b, flags = None):
		return self.expr(core.LLIL_ROR, a.index, b.index, size = size, flags = flags)

	def rotate_right_carry(self, size, a, b, flags = None):
		return self.expr(core.LLIL_RRC, a.index, b.index, size = size, flags = flags)

	def mult(self, size, a, b, flags = None):
		return self.expr(core.LLIL_MUL, a.index, b.index, size = size, flags = flags)

	def mult_double_prec_signed(self, size, a, b, flags = None):
		return self.expr(core.LLIL_MULS_DP, a.index, b.index, size = size, flags = flags)

	def mult_double_prec_unsigned(self, size, a, b, flags = None):
		return self.expr(core.LLIL_MULU_DP, a.index, b.index, size = size, flags = flags)

	def div_signed(self, size, a, b, flags = None):
		return self.expr(core.LLIL_DIVS, a.index, b.index, size = size, flags = flags)

	def div_double_prec_signed(self, size, hi, lo, b, flags = None):
		return self.expr(core.LLIL_DIVS_DP, hi.index, lo.index, b.index, size = size, flags = flags)

	def div_unsigned(self, size, a, b, flags = None):
		return self.expr(core.LLIL_DIVS, a.index, b.index, size = size, flags = flags)

	def div_double_prec_unsigned(self, size, hi, lo, b, flags = None):
		return self.expr(core.LLIL_DIVS_DP, hi.index, lo.index, b.index, size = size, flags = flags)

	def mod_signed(self, size, a, b, flags = None):
		return self.expr(core.LLIL_MODS, a.index, b.index, size = size, flags = flags)

	def mod_double_prec_signed(self, size, hi, lo, b, flags = None):
		return self.expr(core.LLIL_MODS_DP, hi.index, lo.index, b.index, size = size, flags = flags)

	def mod_unsigned(self, size, a, b, flags = None):
		return self.expr(core.LLIL_MODS, a.index, b.index, size = size, flags = flags)

	def mod_double_prec_unsigned(self, size, hi, lo, b, flags = None):
		return self.expr(core.LLIL_MODS_DP, hi.index, lo.index, b.index, size = size, flags = flags)

	def neg_expr(self, size, value, flags = None):
		return self.expr(core.LLIL_NEG, value.index, size = size, flags = flags)

	def not_expr(self, size, value, flags = None):
		return self.expr(core.LLIL_NOT, value.index, size = size, flags = flags)

	def sign_extend(self, size, value):
		return self.expr(core.LLIL_SX, value.index, size = size)

	def zero_extend(self, size, value):
		return self.expr(core.LLIL_ZX, value.index, size = size)

	def jump(self, dest):
		return self.expr(core.LLIL_JUMP, dest.index)

	def call(self, dest):
		return self.expr(core.LLIL_CALL, dest.index)

	def ret(self, dest):
		return self.expr(core.LLIL_RET, dest.index)

	def no_ret(self, dest):
		return self.expr(core.LLIL_NORET, dest.index)

	def flag_condition(self, cond):
		if isinstance(cond, str):
			cond = BNLowLevelILFlagCondition_by_name[cond]
		return self.expr(core.LLIL_FLAG_COND, cond)

	def compare_equal(self, size, a, b):
		return self.expr(core.LLIL_CMP_E, a.index, b.index, size = size)

	def compare_not_equal(self, size, a, b):
		return self.expr(core.LLIL_CMP_NE, a.index, b.index, size = size)

	def compare_signed_less_than(self, size, a, b):
		return self.expr(core.LLIL_CMP_SLT, a.index, b.index, size = size)

	def compare_unsigned_less_than(self, size, a, b):
		return self.expr(core.LLIL_CMP_ULT, a.index, b.index, size = size)

	def compare_signed_less_equal(self, size, a, b):
		return self.expr(core.LLIL_CMP_SLE, a.index, b.index, size = size)

	def compare_unsigned_less_equal(self, size, a, b):
		return self.expr(core.LLIL_CMP_ULE, a.index, b.index, size = size)

	def compare_signed_greater_equal(self, size, a, b):
		return self.expr(core.LLIL_CMP_SGE, a.index, b.index, size = size)

	def compare_unsigned_greater_equal(self, size, a, b):
		return self.expr(core.LLIL_CMP_UGE, a.index, b.index, size = size)

	def compare_signed_greater_than(self, size, a, b):
		return self.expr(core.LLIL_CMP_SGT, a.index, b.index, size = size)

	def compare_unsigned_greater_than(self, size, a, b):
		return self.expr(core.LLIL_CMP_UGT, a.index, b.index, size = size)

	def test_bit(self, size, a, b):
		return self.expr(core.LLIL_TEST_BIT, a.index, b.index, size = size)

	def system_call(self):
		return self.expr(core.LLIL_SYSCALL)

	def breakpoint(self):
		return self.expr(core.LLIL_BP)

	def trap(self, value):
		return self.expr(core.LLIL_TRAP, value)

	def undefined(self):
		return self.expr(core.LLIL_UNDEF)

	def unimplemented(self):
		return self.expr(core.LLIL_UNIMPL)

	def unimplemented_memory_ref(self, size, addr):
		return self.expr(core.LLIL_UNIMPL_MEM, addr.index, size = size)

	def goto(self, label):
		return LowLevelILExpr(core.BNLowLevelILGoto(self.handle, label.handle))

	def if_expr(self, operand, t, f):
		return LowLevelILExpr(core.BNLowLevelILIf(self.handle, operand.index, t.handle, f.handle))

	def mark_label(self, label):
		core.BNLowLevelILMarkLabel(self.handle, label.handle)

	def add_label_list(self, labels):
		label_list = (ctypes.POINTER(BNLowLevelILLabel) * len(labels))()
		for i in xrange(len(labels)):
			label_list[i] = labels[i].handle
		return LowLevelILExpr(core.BNLowLevelILAddLabelList(self.handle, label_list, len(labels)))

	def add_operand_list(self, operands):
		operand_list = (ctypes.c_ulonglong * len(operands))()
		for i in xrange(len(operands)):
			operand_list[i] = operands[i]
		return LowLevelILExpr(core.BNLowLevelILAddOperandList(self.handle, operand_list, len(operands)))

	def operand(self, n, expr):
		core.BNLowLevelILSetExprSourceOperand(self.handle, expr.index, n)
		return expr

	def finalize(self):
		core.BNFinalizeLowLevelILFunction(self.handle)

	def add_label_for_address(self, arch, addr):
		if arch is not None:
			arch = arch.handle
		core.BNAddLowLevelILLabelForAddress(self.handle, arch, addr)

	def get_label_for_address(self, arch, addr):
		if arch is not None:
			arch = arch.handle
		label = core.BNGetLowLevelILLabelForAddress(self.handle, arch, addr)
		if label is None:
			return None
		return LowLevelILLabel(label)

class TypeParserResult:
	def __init__(self, types, variables, functions):
		self.types = types
		self.variables = variables
		self.functions = functions

	def __repr__(self):
		return "{types: %s, variables: %s, functions: %s}" % (self.types, self.variables, self.functions)

class _TransformMetaClass(type):
	def __getattr__(cls, name):
		if name == "list":
			_init_plugins()
			count = ctypes.c_ulonglong()
			xforms = core.BNGetTransformTypeList(count)
			result = []
			for i in xrange(0, count.value):
				result.append(Transform(xforms[i]))
			core.BNFreeTransformTypeList(xforms)
			return result
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(cls, name, value):
		if (name == "list"):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			type.__setattr__(cls, name, value)

	def __dir__(self):
		return dir(self.__class__) + ["list"]

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

class TransformParameter:
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

	def perform_decode(self, data, params):
		if self.type == "InvertingTransform":
			return perform_encode(data, params)
		return None

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

class FunctionRecognizer:
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
	def __getattr__(cls, name):
		if name == "list":
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
		elif name == "active":
			return core.BNGetActiveUpdateChannel()
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(cls, name, value):
		if (name == "list"):
			raise AttributeError, "attribute '%s' is read only" % name
		elif name == "active":
			return core.BNSetActiveUpdateChannel(value)
		else:
			type.__setattr__(cls, name, value)

	def __dir__(self):
		return dir(self.__class__) + ["list","active"]

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

class UpdateProgressCallback:
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

class UpdateChannel:
	__metaclass__ = _UpdateChannelMetaClass

	def __init__(self, name, desc, ver):
		self.name = name
		self.description = desc
		self.latest_version_num = ver

	def __getattr__(self, name):
		if name == "versions":
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
		elif name == "latest_version":
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
		elif name == "updates_available":
			errors = ctypes.c_char_p()
			result = core.BNAreUpdatesAvailable(self.name, errors)
			if errors:
				error_str = errors.value
				core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
				raise IOError, error_str
			return result
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if (name == "versions") or (name == "latest_version"):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["versions","latest_version", "updates_available"]

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

class UpdateVersion:
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

class PluginCommandContext:
	def __init__(self, view):
		self.view = view
		self.address = 0
		self.length = 0
		self.function = None

class _PluginCommandMetaClass(type):
	def __getattr__(cls, name):
		if name == "list":
			_init_plugins()
			count = ctypes.c_ulonglong()
			commands = core.BNGetAllPluginCommands(count)
			result = []
			for i in xrange(0, count.value):
				result.append(PluginCommand(commands[i]))
			core.BNFreePluginCommandList(commands)
			return result
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(cls, name, value):
		if (name == "list"):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			type.__setattr__(cls, name, value)

	def __dir__(self):
		return dir(self.__class__) + ["list"]

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

class CallingConvention:
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
	def __getattr__(cls, name):
		if name == "list":
			_init_plugins()
			count = ctypes.c_ulonglong()
			platforms = core.BNGetPlatformList(count)
			result = []
			for i in xrange(0, count.value):
				result.append(Platform(None, core.BNNewPlatformReference(platforms[i])))
			core.BNFreePlatformList(platforms, count.value)
			return result
		elif name == "os_list":
			_init_plugins()
			count = ctypes.c_ulonglong()
			platforms = core.BNGetPlatformOSList(count)
			result = []
			for i in xrange(0, count.value):
				result.append(str(platforms[i]))
			core.BNFreePlatformOSList(platforms, count.value)
			return result
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(cls, name, value):
		if (name == "list") or (name == "os_list"):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			type.__setattr__(cls, name, value)

	def __dir__(self):
		return dir(self.__class__) + ["list","os_list"]

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

class Platform:
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

	def __getattr__(self, name):
		if name == "default_calling_convention":
			result = core.BNGetPlatformDefaultCallingConvention(self.handle)
			if result is None:
				return None
			return CallingConvention(None, result)
		elif name == "cdecl_calling_convention":
			result = core.BNGetPlatformCdeclCallingConvention(self.handle)
			if result is None:
				return None
			return CallingConvention(None, result)
		elif name == "stdcall_calling_convention":
			result = core.BNGetPlatformStdcallCallingConvention(self.handle)
			if result is None:
				return None
			return CallingConvention(None, result)
		elif name == "fastcall_calling_convention":
			result = core.BNGetPlatformFastcallCallingConvention(self.handle)
			if result is None:
				return None
			return CallingConvention(None, result)
		elif name == "system_call_convention":
			  result = core.BNGetPlatformSystemCallConvention(self.handle)
			  if result is None:
				return None
			  return CallingConvention(None, result)
		elif name == "calling_conventions":
			count = ctypes.c_ulonglong()
			cc = core.BNGetPlatformCallingConventions(self.handle, count)
			result = []
			for i in xrange(0, count.value):
				result.append(CallingConvention(None, core.BNNewCallingConventionReference(cc[i])))
			core.BNFreeCallingConventionList(cc, count.value)
			return result
		raise AttributeError, "no attribute '%s'" % name

	def __setattr__(self, name, value):
		if name == "default_calling_convention":
			core.BNRegisterPlatformDefaultCallingConvention(self.handle, value.handle)
		elif name == "cdecl_calling_convention":
			core.BNRegisterPlatformCdeclCallingConvention(self.handle, value.handle)
		elif name == "stdcall_calling_convention":
			core.BNRegisterPlatformStdcallCallingConvention(self.handle, value.handle)
		elif name == "fastcall_calling_convention":
			core.BNRegisterPlatformFastcallCallingConvention(self.handle, value.handle)
		elif name == "system_call_convention":
			  core.BNSetPlatformSystemCallConvention(self.handle, value.handle)
		elif (name == "calling_conventions"):
			raise AttributeError, "attribute '%s' is read only" % name
		else:
			self.__dict__[name] = value

	def __dir__(self):
		return dir(self.__class__) + ["default_calling_convention", "cdecl_calling_convention",
				"stdcall_calling_convention", "fastcall_calling_convention", "system_call_convention", "calling_conventions"]

	def __repr__(self):
		return "<platform: %s>" % self.name

	def __str__(self):
		return self.name

	def register(self, os):
		core.BNRegisterPlatform(os, self.handle)

	def register_calling_convention(self, cc):
		core.BNRegisterPlatformCallingConvention(self.handle, cc.handle)

def LLIL_TEMP(n):
	return n | 0x80000000

def LLIL_REG_IS_TEMP(n):
	return (n & 0x80000000) != 0

def LLIL_GET_TEMP_REG_INDEX(n):
	return n & 0x7fffffff

def shutdown():
	core.BNShutdown()

def log(level, text):
	core.BNLog(level, "%s", str(text))

def log_debug(text):
	core.BNLogDebug("%s", str(text))

def log_info(text):
	core.BNLogInfo("%s", str(text))

def log_warn(text):
	core.BNLogWarn("%s", str(text))

def log_error(text):
	core.BNLogError("%s", str(text))

def log_alert(text):
	core.BNLogAlert("%s", str(text))

def log_to_stdout(min_level):
	core.BNLogToStdout(min_level)

def log_to_stderr(min_level):
	core.BNLogToStderr(min_level)

def log_to_file(min_level, path, append = False):
	core.BNLogToFile(min_level, str(path), append)

def close_logs():
	core.BNCloseLogs()

def escape_string(text):
	return DataBuffer(text).escape()

def unescape_string(text):
	return DataBuffer(text).unescape()

def preprocess_source(source, filename = None, include_dirs = []):
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
	return core.BNAreAutoUpdatesEnabled()

def set_auto_updates_enabled(enabled):
	core.BNSetAutoUpdatesEnabled(enabled)

def get_time_since_last_update_check():
	return core.BNGetTimeSinceLastUpdateCheck()

def updates_checked():
	core.BNUpdatesChecked()

bundled_plugin_path = core.BNGetBundledPluginDirectory()
user_plugin_path = core.BNGetUserPluginDirectory()

core_version = core.BNGetVersionString()
core_build_id = core.BNGetBuildId()

# Ensure all enumeration constants from the core are exposed by this module
for name in core.all_enum_values:
	globals()[name] = core.all_enum_values[name]
