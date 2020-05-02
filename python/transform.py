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

import traceback
import ctypes
import abc

# Binary Ninja components
import binaryninja
from binaryninja import log
from binaryninja import databuffer
from binaryninja import _binaryninjacore as core
from binaryninja.enums import TransformType

# 2-3 compatibility
import numbers
from binaryninja import range
from binaryninja import with_metaclass


class _TransformMetaClass(type):
	@property
	def list(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		xforms = core.BNGetTransformTypeList(count)
		result = []
		for i in range(0, count.value):
			result.append(Transform(xforms[i]))
		core.BNFreeTransformTypeList(xforms)
		return result

	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		xforms = core.BNGetTransformTypeList(count)
		try:
			for i in range(0, count.value):
				yield Transform(xforms[i])
		finally:
			core.BNFreeTransformTypeList(xforms)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __getitem__(cls, name):
		binaryninja._init_plugins()
		xform = core.BNGetTransformByName(name)
		if xform is None:
			raise KeyError("'%s' is not a valid transform" % str(name))
		return Transform(xform)

	def register(cls):
		binaryninja._init_plugins()
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
		self._name = name
		if long_name is None:
			self._long_name = name
		else:
			self._long_name = long_name
		self._fixed_length = fixed_length

	def __repr__(self):
		return "<TransformParameter: {} fixed length: {}>".format(
			self._long_name, self._fixed_length
		)

	@property
	def name(self):
		"""(read-only)"""
		return self._name

	@property
	def long_name(self):
		"""(read-only)"""
		return self._long_name

	@property
	def fixed_length(self):
		"""(read-only)"""
		return self._fixed_length


class Transform(with_metaclass(_TransformMetaClass, object)):
	"""
	``class Transform`` is an implementation of the TransformMetaClass that implements custom transformations. New 
	transformations may be added at runtime, so an instance of a transform is created like::

		>>> list(Transform)
		[<transform: Zlib>, <transform: StringEscape>, <transform: RawHex>, <transform: HexDump>, <transform: Base64>, <transform: Reverse>, <transform: CArray08>, <transform: CArrayA16>, <transform: CArrayA32>, <transform: CArrayA64>, <transform: CArrayB16>, <transform: CArrayB32>, <transform: CArrayB64>, <transform: IntList08>, <transform: IntListA16>, <transform: IntListA32>, <transform: IntListA64>, <transform: IntListB16>, <transform: IntListB32>, <transform: IntListB64>, <transform: MD4>, <transform: MD5>, <transform: SHA1>, <transform: SHA224>, <transform: SHA256>, <transform: SHA384>, <transform: SHA512>, <transform: AES-128 ECB>, <transform: AES-128 CBC>, <transform: AES-256 ECB>, <transform: AES-256 CBC>, <transform: DES ECB>, <transform: DES CBC>, <transform: Triple DES ECB>, <transform: Triple DES CBC>, <transform: RC2 ECB>, <transform: RC2 CBC>, <transform: Blowfish ECB>, <transform: Blowfish CBC>, <transform: CAST ECB>, <transform: CAST CBC>, <transform: RC4>, <transform: XOR>]
		>>> sha512=Transform['SHA512']
		>>> rawhex=Transform['RawHex']
		>>> rawhex.encode(sha512.encode("test string"))
		'10e6d647af44624442f388c2c14a787ff8b17e6165b83d767ec047768d8cbcb71a1a3226e7cc7816bc79c0427d94a9da688c41a3992c7bf5e4d7cc3e0be5dbac'
	"""
	transform_type = None
	name = None
	long_name = None
	group = None
	parameters = []
	_registered_cb = None

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
			for i in range(0, count.value):
				self.parameters.append(TransformParameter(params[i].name, params[i].longName, params[i].fixedLength))
			core.BNFreeTransformParameterList(params, count.value)

	def __repr__(self):
		return "<transform: %s>" % self.name

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

	def _get_parameters(self, ctxt, count):
		try:
			count[0] = len(self.parameters)
			param_buf = (core.BNTransformParameterInfo * len(self.parameters))()
			for i in range(0, len(self.parameters)):
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
			for i in range(0, count):
				data = databuffer.DataBuffer(handle = core.BNDuplicateDataBuffer(params[i].value))
				param_map[params[i].name] = bytes(data)
			result = self.perform_decode(bytes(input_obj), param_map)
			if result is None:
				return False
			result = bytes(result)
			core.BNSetDataBufferContents(output_buf, result, len(result))
			return True
		except:
			log.log_error(traceback.format_exc())
			return False

	def _encode(self, ctxt, input_buf, output_buf, params, count):
		try:
			input_obj = databuffer.DataBuffer(handle = core.BNDuplicateDataBuffer(input_buf))
			param_map = {}
			for i in range(0, count):
				data = databuffer.DataBuffer(handle = core.BNDuplicateDataBuffer(params[i].value))
				param_map[params[i].name] = bytes(data)
			result = self.perform_encode(bytes(input_obj), param_map)
			if result is None:
				return False
			result = bytes(result)
			core.BNSetDataBufferContents(output_buf, result, len(result))
			return True
		except:
			log.log_error(traceback.format_exc())
			return False

	@property
	def list(self):
		"""Allow tab completion to discover metaclass list property"""
		pass

	@abc.abstractmethod
	def perform_decode(self, data, params):
		if self.type == TransformType.InvertingTransform:
			return self.perform_encode(data, params)
		return None

	@abc.abstractmethod
	def perform_encode(self, data, params):
		return None

	def decode(self, input_buf, params = {}):
		if isinstance(input_buf, int) or isinstance(input_buf, numbers.Integral):
			return None
		input_buf = databuffer.DataBuffer(input_buf)
		output_buf = databuffer.DataBuffer()
		keys = list(params.keys())
		param_buf = (core.BNTransformParameter * len(keys))()
		data = []
		for i in range(0, len(keys)):
			data.append(databuffer.DataBuffer(params[keys[i]]))
			param_buf[i].name = keys[i]
			param_buf[i].value = data[i].handle
		if not core.BNDecode(self.handle, input_buf.handle, output_buf.handle, param_buf, len(keys)):
			return None
		return str(output_buf)

	def encode(self, input_buf, params = {}):
		if isinstance(input_buf, int) or isinstance(input_buf, numbers.Integral):
			return None
		input_buf = databuffer.DataBuffer(input_buf)
		output_buf = databuffer.DataBuffer()
		keys = list(params.keys())
		param_buf = (core.BNTransformParameter * len(keys))()
		data = []
		for i in range(0, len(keys)):
			data.append(databuffer.DataBuffer(params[keys[i]]))
			param_buf[i].name = keys[i]
			param_buf[i].value = data[i].handle
		if not core.BNEncode(self.handle, input_buf.handle, output_buf.handle, param_buf, len(keys)):
			return None
		return str(output_buf)
