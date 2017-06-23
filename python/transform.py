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
import ctypes
import abc

# Binary Ninja components
import _binaryninjacore as core
from enums import TransformType
import startup
import log
import databuffer


class _TransformMetaClass(type):
	@property
	def list(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		xforms = core.BNGetTransformTypeList(count)
		result = []
		for i in xrange(0, count.value):
			result.append(Transform(xforms[i]))
		core.BNFreeTransformTypeList(xforms)
		return result

	def __iter__(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		xforms = core.BNGetTransformTypeList(count)
		try:
			for i in xrange(0, count.value):
				yield Transform(xforms[i])
		finally:
			core.BNFreeTransformTypeList(xforms)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __getitem__(cls, name):
		startup._init_plugins()
		xform = core.BNGetTransformByName(name)
		if xform is None:
			raise KeyError("'%s' is not a valid transform" % str(name))
		return Transform(xform)

	def register(cls):
		startup._init_plugins()
		if cls.name is None:
			raise ValueError("transform 'name' is not defined")
		if cls.long_name is None:
			cls.long_name = cls.name
		if cls.transform_type is None:
			raise ValueError("transform 'transform_type' is not defined")
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


class Transform(object):
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
				self.type = TransformType(self.type)
			self.name = self.__class__.name
			self.long_name = self.__class__.long_name
			self.group = self.__class__.group
			self.parameters = self.__class__.parameters
		else:
			self.handle = handle
			self.type = TransformType(core.BNGetTransformType(self.handle))
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

	def __eq__(self, value):
		if not isinstance(value, Transform):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, Transform):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

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
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _free_parameters(self, params, count):
		try:
			buf = ctypes.cast(params, ctypes.c_void_p)
			if buf.value not in self._pending_param_lists:
				raise ValueError("freeing parameter list that wasn't allocated")
			del self._pending_param_lists[buf.value]
		except:
			log.log_error(traceback.format_exc())

	def _decode(self, ctxt, input_buf, output_buf, params, count):
		try:
			input_obj = databuffer.DataBuffer(handle = core.BNDuplicateDataBuffer(input_buf))
			param_map = {}
			for i in xrange(0, count):
				data = databuffer.DataBuffer(handle = core.BNDuplicateDataBuffer(params[i].value))
				param_map[params[i].name] = str(data)
			result = self.perform_decode(str(input_obj), param_map)
			if result is None:
				return False
			result = str(result)
			core.BNSetDataBufferContents(output_buf, result, len(result))
			return True
		except:
			log.log_error(traceback.format_exc())
			return False

	def _encode(self, ctxt, input_buf, output_buf, params, count):
		try:
			input_obj = databuffer.DataBuffer(handle = core.BNDuplicateDataBuffer(input_buf))
			param_map = {}
			for i in xrange(0, count):
				data = databuffer.DataBuffer(handle = core.BNDuplicateDataBuffer(params[i].value))
				param_map[params[i].name] = str(data)
			result = self.perform_encode(str(input_obj), param_map)
			if result is None:
				return False
			result = str(result)
			core.BNSetDataBufferContents(output_buf, result, len(result))
			return True
		except:
			log.log_error(traceback.format_exc())
			return False

	@abc.abstractmethod
	def perform_decode(self, data, params):
		if self.type == TransformType.InvertingTransform:
			return self.perform_encode(data, params)
		return None

	@abc.abstractmethod
	def perform_encode(self, data, params):
		return None

	def decode(self, input_buf, params = {}):
		input_buf = databuffer.DataBuffer(input_buf)
		output_buf = databuffer.DataBuffer()
		keys = params.keys()
		param_buf = (core.BNTransformParameter * len(keys))()
		for i in xrange(0, len(keys)):
			data = databuffer.DataBuffer(params[keys[i]])
			param_buf[i].name = keys[i]
			param_buf[i].value = data.handle
		if not core.BNDecode(self.handle, input_buf.handle, output_buf.handle, param_buf, len(keys)):
			return None
		return str(output_buf)

	def encode(self, input_buf, params = {}):
		input_buf = databuffer.DataBuffer(input_buf)
		output_buf = databuffer.DataBuffer()
		keys = params.keys()
		param_buf = (core.BNTransformParameter * len(keys))()
		for i in xrange(0, len(keys)):
			data = databuffer.DataBuffer(params[keys[i]])
			param_buf[i].name = keys[i]
			param_buf[i].value = data.handle
		if not core.BNEncode(self.handle, input_buf.handle, output_buf.handle, param_buf, len(keys)):
			return None
		return str(output_buf)
