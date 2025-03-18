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

import ctypes
from typing import Optional, List

import binaryninja
from . import _binaryninjacore as core
from . import highlight
from . import function as _function
from . import basicblock
from . import binaryview
from .enums import (LinearDisassemblyLineType, LinearViewObjectIdentifierType)


class LinearDisassemblyLine:
	def __init__(self, line_type, func, block, contents):
		self.type = line_type
		self.function = func
		self.block = block
		self.contents = contents

	def __repr__(self):
		return repr(self.contents)

	def __str__(self):
		return str(self.contents)

	@classmethod
	def _from_core_struct(cls, struct: core.BNLinearDisassemblyLine, obj: Optional['LinearViewObject'] = None) -> 'LinearDisassemblyLine':
		function = None
		if struct.function:
			function = _function.Function(handle=core.BNNewFunctionReference(struct.function))
		block = None
		if struct.block:
			block = basicblock.BasicBlock._from_core_block(core.BNNewBasicBlockReference(struct.block))
		il_func = None
		if block is not None:
			il_func = block.il_function
		if obj is not None and function is not None:
			# Hack: HLIL bodies don't have basic blocks
			if obj.identifier.name == "HLIL Function Body":
				il_func = function.hlil
			elif obj.identifier.name == "HLIL SSA Function Body":
				il_func = function.hlil.ssa_form
			elif obj.identifier.name == "Language Representation Function Body":
				il_func = function.hlil

		contents = _function.DisassemblyTextLine._from_core_struct(struct.contents, il_func)
		return LinearDisassemblyLine(LinearDisassemblyLineType(struct.type), function, block, contents)

	def _to_core_struct(self) -> core.BNLinearDisassemblyLine:
		result = core.BNLinearDisassemblyLine()
		result.type = self.type
		result.function = None
		if self.function is not None:
			result.function = self.function.handle
		result.block = None
		if self.block is not None:
			result.block = self.block.handle
		result.contents = _function.DisassemblyTextLine._to_core_struct(self.contents)
		return result


class LinearViewObjectIdentifier:
	def __init__(self, name, start=None, end=None):
		self._name = name
		self._start = start
		self._end = end

	def __repr__(self):
		return "<LinearViewObjectIdentifier: " + str(self) + ">"

	def __str__(self):
		if not self.has_address:
			return self._name
		if self.has_range:
			return "%s 0x%x-0x%x" % (self._name, self._start, self._end)
		return "%s 0x%x" % (self._name, self._start)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._name, self._start, self._end) == (other._name, other._start, other._end)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._name, self._start, self._end))

	def _to_core_struct(self, obj=None):
		if obj is None:
			result = core.BNLinearViewObjectIdentifier()
		else:
			result = obj
		result.name = self.name
		if self.has_range:
			result.type = LinearViewObjectIdentifierType.AddressRangeLinearViewObject
			result.start = self.start
			result.end = self.end
		elif self.has_address:
			result.type = LinearViewObjectIdentifierType.AddressLinearViewObject
			result.start = self.start
			result.end = self.start
		else:
			result.type = LinearViewObjectIdentifierType.SingleLinearViewObject
			result.start = 0
			result.end = 0
		return result

	@property
	def name(self):
		return self._name

	@property
	def address(self):
		return self._start

	@property
	def start(self):
		return self._start

	@property
	def end(self):
		return self._end

	@property
	def has_address(self):
		return self._start is not None

	@property
	def has_range(self):
		return self._start is not None and self._end is not None

	@staticmethod
	def _from_api_object(obj):
		if obj.type == LinearViewObjectIdentifierType.AddressLinearViewObject:
			result = LinearViewObjectIdentifier(obj.name, obj.start)
		elif obj.type == LinearViewObjectIdentifierType.AddressRangeLinearViewObject:
			result = LinearViewObjectIdentifier(obj.name, obj.start, obj.end)
		else:
			result = LinearViewObjectIdentifier(obj.name)
		return result


class LinearViewObject:
	def __init__(self, handle, parent=None):
		self.handle = handle
		self._parent = parent

	def __del__(self):
		if core is not None:
			core.BNFreeLinearViewObject(self.handle)

	def __repr__(self):
		return "<LinearViewObject: " + str(self) + ">"

	def __len__(self):
		return self.end - self.start

	def __str__(self):
		result = str(self.identifier)
		if self._parent is not None:
			result = str(self._parent) + "/" + result
		return result

	@property
	def first_child(self):
		result = core.BNGetFirstLinearViewObjectChild(self.handle)
		if not result:
			return None
		return LinearViewObject(result, self)

	@property
	def last_child(self):
		result = core.BNGetLastLinearViewObjectChild(self.handle)
		if not result:
			return None
		return LinearViewObject(result, self)

	@property
	def previous(self):
		if self._parent is None:
			return None
		result = core.BNGetPreviousLinearViewObjectChild(self._parent.handle, self.handle)
		if not result:
			return None
		return LinearViewObject(result, self._parent)

	@property
	def next(self):
		if self._parent is None:
			return None
		result = core.BNGetNextLinearViewObjectChild(self._parent.handle, self.handle)
		if not result:
			return None
		return LinearViewObject(result, self._parent)

	@property
	def start(self):
		return core.BNGetLinearViewObjectStart(self.handle)

	@property
	def end(self):
		return core.BNGetLinearViewObjectEnd(self.handle)

	@property
	def parent(self):
		return self._parent

	@property
	def identifier(self):
		ident = core.BNGetLinearViewObjectIdentifier(self.handle)
		result = LinearViewObjectIdentifier._from_api_object(ident)
		core.BNFreeLinearViewObjectIdentifier(ident)
		return result

	@property
	def cursor(self):
		root = self
		while root.parent is not None:
			root = root.parent
		return LinearViewCursor(root)

	@property
	def ordering_index(self):
		if self.parent is None:
			return 0
		return self.parent.ordering_index_for_child(self)

	@property
	def ordering_index_total(self):
		return core.BNGetLinearViewObjectOrderingIndexTotal(self.handle)

	def child_for_address(self, addr):
		result = core.BNGetLinearViewObjectChildForAddress(self.handle, addr)
		if not result:
			return None
		return LinearViewObject(result, self)

	def child_for_identifier(self, ident):
		ident_obj = ident._to_core_struct()
		result = core.BNGetLinearViewObjectChildForIdentifier(self.handle, ident_obj)
		if not result:
			return None
		return LinearViewObject(result, self)

	def child_for_ordering_index(self, idx):
		result = core.BNGetLinearViewObjectChildForOrderingIndex(self.handle, idx)
		if not result:
			return None
		return LinearViewObject(result, self)

	def compare_children(self, a, b):
		return core.BNCompareLinearViewObjectChildren(self.handle, a.handle, b.handle)

	def get_lines(self, prev_obj, next_obj) -> List['LinearDisassemblyLine']:
		if prev_obj is not None:
			prev_obj = prev_obj.handle
		if next_obj is not None:
			next_obj = next_obj.handle

		count = ctypes.c_ulonglong(0)
		return LinearViewCursor._make_lines(
		    core.BNGetLinearViewObjectLines(self.handle, prev_obj, next_obj, count), count.value, self
		)

	def ordering_index_for_child(self, child):
		return core.BNGetLinearViewObjectOrderingIndexForChild(self.handle, child.handle)

	@staticmethod
	def disassembly(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewDisassembly(view.handle, _settings))

	@staticmethod
	def lifted_il(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewLiftedIL(view.handle, _settings))

	@staticmethod
	def llil(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewLowLevelIL(view.handle, _settings))

	@staticmethod
	def llil_ssa_form(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewLowLevelILSSAForm(view.handle, _settings))

	@staticmethod
	def mlil(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewMediumLevelIL(view.handle, _settings))

	@staticmethod
	def mlil_ssa_form(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewMediumLevelILSSAForm(view.handle, _settings))

	@staticmethod
	def mmlil(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewMappedMediumLevelIL(view.handle, _settings))

	@staticmethod
	def mmlil_ssa_form(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewMappedMediumLevelILSSAForm(view.handle, _settings))

	@staticmethod
	def hlil(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewHighLevelIL(view.handle, _settings))

	@staticmethod
	def hlil_ssa_form(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewHighLevelILSSAForm(view.handle, _settings))

	@staticmethod
	def language_representation(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None,
	    language: str = "Pseudo C"
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewLanguageRepresentation(view.handle, _settings, language))

	@staticmethod
	def data_only(
	    view: 'binaryview.BinaryView', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewDataOnly(view.handle, _settings))

	@staticmethod
	def single_function_disassembly(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionDisassembly(func.handle, _settings))

	@staticmethod
	def single_function_lifted_il(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionLiftedIL(func.handle, _settings))

	@staticmethod
	def single_function_llil(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionLowLevelIL(func.handle, _settings))

	@staticmethod
	def single_function_llil_ssa_form(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionLowLevelILSSAForm(func.handle, _settings))

	@staticmethod
	def single_function_mlil(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionMediumLevelIL(func.handle, _settings))

	@staticmethod
	def single_function_mlil_ssa_form(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionMediumLevelILSSAForm(func.handle, _settings))

	@staticmethod
	def single_function_mmlil(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionMappedMediumLevelIL(func.handle, _settings))

	@staticmethod
	def single_function_mmlil_ssa_form(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionMappedMediumLevelILSSAForm(func.handle, _settings))

	@staticmethod
	def single_function_hlil(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionHighLevelIL(func.handle, _settings))

	@staticmethod
	def single_function_hlil_ssa_form(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionHighLevelILSSAForm(func.handle, _settings))

	@staticmethod
	def single_function_language_representation(
	    func: '_function.Function', settings: Optional['_function.DisassemblySettings'] = None,
	    language: str = "Pseudo C"
	) -> 'LinearViewObject':
		_settings = settings
		if _settings is not None:
			_settings = _settings.handle
		return LinearViewObject(core.BNCreateLinearViewSingleFunctionLanguageRepresentation(func.handle, _settings, language))


class LinearViewCursor:
	def __init__(self, root_object, handle=None):
		if handle is not None:
			self.handle = handle
		else:
			self.handle = core.BNCreateLinearViewCursor(root_object.handle)

	def __del__(self):
		if core is not None:
			core.BNFreeLinearViewCursor(self.handle)

	def __repr__(self):
		return "<LinearViewCursor: " + str(self.current_object) + ">"

	def __str__(self):
		return str(self.current_object)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return LinearViewCursor.compare(self, other) == 0

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return LinearViewCursor.compare(self, other) != 0

	def __lt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return LinearViewCursor.compare(self, other) < 0

	def __le__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return LinearViewCursor.compare(self, other) <= 0

	def __gt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return LinearViewCursor.compare(self, other) > 0

	def __ge__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return LinearViewCursor.compare(self, other) >= 0

	def __cmp__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return LinearViewCursor.compare(self, other)

	@property
	def before_begin(self):
		return core.BNIsLinearViewCursorBeforeBegin(self.handle)

	@property
	def after_end(self):
		return core.BNIsLinearViewCursorAfterEnd(self.handle)

	@property
	def valid(self):
		return not (self.before_begin or self.after_end)

	@property
	def current_object(self):
		count = ctypes.c_ulonglong(0)
		path = core.BNGetLinearViewCursorPathObjects(self.handle, count)
		assert path is not None, "core.BNGetLinearViewCursorPathObjects returned None"
		result = None
		for i in range(0, count.value):
			result = LinearViewObject(core.BNNewLinearViewObjectReference(path[i]), result)
		core.BNFreeLinearViewCursorPathObjects(path, count.value)
		return result

	@property
	def path(self):
		count = ctypes.c_ulonglong(0)
		path = core.BNGetLinearViewCursorPath(self.handle, count)
		assert path is not None, "core.BNGetLinearViewCursorPath returned None"
		result = []
		for i in range(0, count.value):
			result.append(LinearViewObjectIdentifier._from_api_object(path[i]))
		core.BNFreeLinearViewCursorPath(path, count.value)
		return result

	@property
	def path_objects(self):
		count = ctypes.c_ulonglong(0)
		path = core.BNGetLinearViewCursorPathObjects(self.handle, count)
		assert path is not None, "core.BNGetLinearViewCursorPathObjects returned None"
		result = []
		parent = None
		for i in range(0, count.value):
			obj = LinearViewObject(core.BNNewLinearViewObjectReference(path[i]), parent)
			result.append(obj)
			parent = obj
		core.BNFreeLinearViewCursorPathObjects(path, count.value)
		return result

	@property
	def ordering_index(self):
		return core.BNGetLinearViewCursorOrderingIndex(self.handle)

	@property
	def ordering_index_total(self):
		return core.BNGetLinearViewCursorOrderingIndexTotal(self.handle)

	def seek_to_begin(self):
		core.BNSeekLinearViewCursorToBegin(self.handle)

	def seek_to_end(self):
		core.BNSeekLinearViewCursorToEnd(self.handle)

	def seek_to_address(self, addr):
		core.BNSeekLinearViewCursorToAddress(self.handle, addr)

	def seek_to_path(self, path, addr=None):
		if isinstance(path, LinearViewCursor):
			if addr is None:
				return core.BNSeekLinearViewCursorToCursorPath(self.handle, path.handle)
			return core.BNSeekLinearViewCursorToCursorPathAndAddress(self.handle, path.handle, addr)
		path_objs = (core.BNLinearViewObjectIdentifier * len(path))()
		for i in range(0, len(path)):
			path[i]._to_core_struct(path_objs[i])
		if addr is None:
			return core.BNSeekLinearViewCursorToPath(self.handle, path_objs, len(path))
		return core.BNSeekLinearViewCursorToPathAndAddress(self.handle, path_objs, len(path), addr)

	def seek_to_ordering_index(self, idx):
		core.BNSeekLinearViewCursorToOrderingIndex(self.handle, idx)

	def previous(self):
		return core.BNLinearViewCursorPrevious(self.handle)

	def next(self):
		return core.BNLinearViewCursorNext(self.handle)

	@staticmethod
	def _make_lines(lines, count: int, object) -> List['LinearDisassemblyLine']:
		assert lines is not None, "core returned None for LinearDisassembly lines"
		try:
			result = []
			for i in range(0, count):
				result.append(LinearDisassemblyLine._from_core_struct(lines[i], obj=object))
			return result
		finally:
			core.BNFreeLinearDisassemblyLines(lines, count)

	@property
	def lines(self):
		current = self.current_object
		count = ctypes.c_ulonglong(0)
		return LinearViewCursor._make_lines(core.BNGetLinearViewCursorLines(self.handle, count), count.value, current)

	def duplicate(self):
		return LinearViewCursor(None, handle=core.BNDuplicateLinearViewCursor(self.handle))

	@staticmethod
	def compare(a, b):
		return core.BNCompareLinearViewCursors(a.handle, b.handle)

	@property
	def render_layers(self) -> List['binaryninja.RenderLayer']:
		"""
		Get the list of Render Layers which will be applied to this cursor, at the
		end of calls to lines().

		:return: List of Render Layers
		"""
		count = ctypes.c_size_t(0)
		layers = core.BNGetLinearViewCursorRenderLayers(self.handle, count)
		assert layers is not None, "core.BNGetLinearViewCursorRenderLayers returned None"

		try:
			result = []
			for i in range(0, count.value):
				result.append(binaryninja.RenderLayer(handle=layers[i]))

			return result
		finally:
			core.BNFreeRenderLayerList(layers)

	@render_layers.setter
	def render_layers(self, render_layers: List['binaryninja.RenderLayer']):
		for layer in self.render_layers:
			self.remove_render_layer(layer)
		for layer in render_layers:
			self.add_render_layer(layer)

	def add_render_layer(self, layer: 'binaryninja.RenderLayer'):
		"""
		Add a Render Layer to be applied to this cursor. Note that layers will
		be applied in the order in which they are added.

		:param layer: Render Layer to add
		"""
		core.BNAddLinearViewCursorRenderLayer(self.handle, layer.handle)

	def remove_render_layer(self, layer: 'binaryninja.RenderLayer'):
		"""
		Remove a Render Layer from being applied to this cursor

		:param layer: Render Layer to remove
		"""
		core.BNRemoveLinearViewCursorRenderLayer(self.handle, layer.handle)
