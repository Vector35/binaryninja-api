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
from typing import List

from . import _binaryninjacore as core


class UndoAction:
	"""
	Class representing an action in an UndoEntry
	"""
	def __init__(self, handle: core.BNUndoActionHandle):
		self._handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeUndoAction(self._handle)

	def __repr__(self) -> str:
		return f"<UndoAction: {self}>"

	def __str__(self):
		return self.summary_text

	@property
	def summary_text(self) -> str:
		return core.BNUndoActionGetSummaryText(self._handle) # type: ignore

class UndoEntry:
	"""
	Class representing an entry in undo/redo history
	"""
	def __init__(self, handle: core.BNUndoEntryHandle):
		self._handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeUndoEntry(self._handle)

	@property
	def actions(self) -> List[UndoAction]:
		"""
		Get the list of actions in this entry

		:return: List of UndoAction in this UndoEntry
		"""

		count = ctypes.c_size_t()
		value = core.BNUndoEntryGetActions(self._handle, count)
		if value is None:
			raise Exception("Failed to get list undo actions")
		result = []
		try:
			for i in range(count.value):
				folder_handle = core.BNNewUndoActionReference(value[i])
				if folder_handle is None:
					raise Exception("core.BNNewUndoActionReference returned None")
				result.append(UndoAction(folder_handle))
			return result
		finally:
			core.BNFreeUndoActionList(value, count.value)
