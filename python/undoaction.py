# Copyright (c) 2015-2017 Vector 35 LLC
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

import traceback
import json
import ctypes

# Binary Ninja components
import _binaryninjacore as core
from enums import ActionType
import startup
import log


class UndoAction(object):
	name = None
	action_type = None
	_registered = False
	_registered_cb = None

	def __init__(self, view):
		self._cb = core.BNUndoAction()
		if not self.__class__._registered:
			raise TypeError("undo action type not registered")
		action_type = self.__class__.action_type
		if isinstance(action_type, str):
			self._cb.type = ActionType[action_type]
		else:
			self._cb.type = action_type
		self._cb.context = 0
		self._cb.undo = self._cb.undo.__class__(self._undo)
		self._cb.redo = self._cb.redo.__class__(self._redo)
		self._cb.serialize = self._cb.serialize.__class__(self._serialize)
		self.view = view

	@classmethod
	def register(cls):
		startup._init_plugins()
		if cls.name is None:
			raise ValueError("undo action 'name' not defined")
		if cls.action_type is None:
			raise ValueError("undo action 'action_type' not defined")
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
			log.log_error(traceback.format_exc())
			return False

	def _undo(self, ctxt, view):
		try:
			self.undo()
		except:
			log.log_error(traceback.format_exc())
			return False

	def _redo(self, ctxt, view):
		try:
			self.redo()
		except:
			log.log_error(traceback.format_exc())
			return False

	def _serialize(self, ctxt):
		try:
			return json.dumps(self.serialize())
		except:
			log.log_error(traceback.format_exc())
			return "null"
