# Copyright (c) 2015-2026 Vector 35 Inc
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
import io
import json
import zipfile
from typing import List, Mapping, Optional, Union, Any

# Binary Ninja components
import binaryninja
from .log import log_error_for_exception, log_error
from . import databuffer
from . import binaryview
from . import metadata
from . import _binaryninjacore as core
from .enums import TransformCapabilities, TransformResult, TransformType
from .settings import Settings


class _TransformMetaClass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		xforms = core.BNGetTransformTypeList(count)
		assert xforms is not None, "core.BNGetTransformTypeList returned None"
		result = []
		for i in range(0, count.value):
			ptr_addr = ctypes.cast(xforms[i], ctypes.c_void_p).value
			handle = ctypes.cast(ptr_addr, type(xforms[i]))
			result.append(Transform(handle))
		core.BNFreeTransformTypeList(xforms)
		for xform in result:
			yield xform

	def __getitem__(cls, name):
		binaryninja._init_plugins()
		xform = core.BNGetTransformByName(name)
		if xform is None:
			raise KeyError("'%s' is not a valid transform" % str(name))
		return Transform(xform)

	def __contains__(cls: '_TransformMetaClass', name: object) -> bool:
		if not isinstance(name, str):
			return False
		try:
			cls[name]
			return True
		except KeyError:
			return False

	def get(cls: '_TransformMetaClass', name: str, default: Any = None) -> Optional['Transform']:
		try:
			return cls[name]
		except KeyError:
			if default is not None:
				return default
			return None


class TransformParameter:
	def __init__(self, name, long_name=None, fixed_length=0):
		self._name = name
		if long_name is None:
			self._long_name = name
		else:
			self._long_name = long_name
		self._fixed_length = fixed_length

	def __repr__(self):
		return "<TransformParameter: {} fixed length: {}>".format(self._long_name, self._fixed_length)

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


class Transform(metaclass=_TransformMetaClass):
	"""
	``class Transform`` allows users to implement custom transformations. New transformations may be added at runtime,
	so an instance of a transform is created like::

		>>> list(Transform)
		[<transform: Zlib>, <transform: StringEscape>, <transform: RawHex>, <transform: HexDump>, <transform: Base64>, <transform: Reverse>, <transform: CArray08>, <transform: CArrayA16>, <transform: CArrayA32>, <transform: CArrayA64>, <transform: CArrayB16>, <transform: CArrayB32>, <transform: CArrayB64>, <transform: IntList08>, <transform: IntListA16>, <transform: IntListA32>, <transform: IntListA64>, <transform: IntListB16>, <transform: IntListB32>, <transform: IntListB64>, <transform: MD4>, <transform: MD5>, <transform: SHA1>, <transform: SHA224>, <transform: SHA256>, <transform: SHA384>, <transform: SHA512>, <transform: AES-128 ECB>, <transform: AES-128 CBC>, <transform: AES-256 ECB>, <transform: AES-256 CBC>, <transform: DES ECB>, <transform: DES CBC>, <transform: Triple DES ECB>, <transform: Triple DES CBC>, <transform: RC2 ECB>, <transform: RC2 CBC>, <transform: Blowfish ECB>, <transform: Blowfish CBC>, <transform: CAST ECB>, <transform: CAST CBC>, <transform: RC4>, <transform: XOR>]
		>>> sha512=Transform['SHA512']
		>>> rawhex=Transform['RawHex']
		>>> rawhex.encode(sha512.encode("test string"))
		'10e6d647af44624442f388c2c14a787ff8b17e6165b83d767ec047768d8cbcb71a1a3226e7cc7816bc79c0427d94a9da688c41a3992c7bf5e4d7cc3e0be5dbac'

	Note that some transformations take additional parameters (most notably encryption ones that require a 'key' parameter passed via a dict):

		>>> xor=Transform['XOR']
		>>> rawhex=Transform['RawHex']
		>>> xor.encode("Original Data", {'key':'XORKEY'})
		>>> rawhex.encode(xor.encode("Original Data", {'key':'XORKEY'}))
		b'173d3b2c2c373923720f242d39'
	"""
	transform_type = None
	capabilities = 0
	supports_detection = False
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
			self._cb.decodeWithContext = self._cb.decodeWithContext.__class__(self._decode_with_context)
			self._cb.canDecode = self._cb.canDecode.__class__(self._can_decode)
			self._pending_param_lists = {}
			self.type = self.__class__.transform_type
			if not isinstance(self.type, str):
				assert self.type is not None, "Transform Type is None"
				self.type = TransformType(self.type)
			self.name = self.__class__.name
			self.long_name = self.__class__.long_name
			self.group = self.__class__.group
			self.parameters = self.__class__.parameters
		else:
			self.handle = handle
			self.type = TransformType(core.BNGetTransformType(self.handle))
			self.capabilities = core.BNGetTransformCapabilities(self.handle)
			self.supports_detection = core.BNTransformSupportsDetection(self.handle)
			self.supports_context = core.BNTransformSupportsContext(self.handle)
			self.name = core.BNGetTransformName(self.handle)
			self.long_name = core.BNGetTransformLongName(self.handle)
			self.group = core.BNGetTransformGroup(self.handle)
			count = ctypes.c_ulonglong()
			params = core.BNGetTransformParameterList(self.handle, count)
			assert params is not None, "core.BNGetTransformParameterList returned None"
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

	@classmethod
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
		xform.handle = core.BNRegisterTransformTypeWithCapabilities(cls.transform_type, cls.capabilities, cls.name, cls.long_name, cls.group, xform._cb)

	def _get_parameters(self, ctxt, count):
		try:
			count[0] = len(self.parameters)
			param_buf = (core.BNTransformParameterInfo * len(self.parameters))()
			for i in range(0, len(self.parameters)):
				param_buf[i].name = core.cstr(self.parameters[i].name)
				param_buf[i].longName = core.cstr(self.parameters[i].long_name)
				param_buf[i].fixedLength = self.parameters[i].fixed_length
			result = ctypes.cast(param_buf, ctypes.c_void_p)
			self._pending_param_lists[result.value] = (result, param_buf)
			return result.value
		except Exception:
			log_error_for_exception("Unhandled Python exception in Transform._get_parameters")
			count[0] = 0
			return None

	def _free_parameters(self, params, count):
		try:
			buf = ctypes.cast(params, ctypes.c_void_p)
			if buf.value not in self._pending_param_lists:
				raise ValueError("freeing parameter list that wasn't allocated")
			del self._pending_param_lists[buf.value]
		except Exception:
			log_error_for_exception("Unhandled Python exception in Transform._free_parameters")

	def _decode(self, ctxt, input_buf, output_buf, params, count):
		try:
			input_obj = databuffer.DataBuffer(handle=core.BNDuplicateDataBuffer(input_buf))
			param_map = {}
			for i in range(0, count):
				data = databuffer.DataBuffer(handle=core.BNDuplicateDataBuffer(params[i].value))
				param_map[params[i].name] = bytes(data)
			result = self.perform_decode(bytes(input_obj), param_map)
			if result is None:
				return False
			result = bytes(result)
			core.BNSetDataBufferContents(output_buf, result, len(result))
			return True
		except Exception:
			log_error_for_exception("Unhandled Python exception in Transform._decode")
			return False

	def _encode(self, ctxt, input_buf, output_buf, params, count):
		try:
			input_obj = databuffer.DataBuffer(handle=core.BNDuplicateDataBuffer(input_buf))
			param_map = {}
			for i in range(0, count):
				data = databuffer.DataBuffer(handle=core.BNDuplicateDataBuffer(params[i].value))
				param_map[params[i].name] = bytes(data)
			result = self.perform_encode(bytes(input_obj), param_map)
			if result is None:
				return False
			result = bytes(result)
			core.BNSetDataBufferContents(output_buf, result, len(result))
			return True
		except Exception:
			log_error_for_exception("Unhandled Python exception in Transform._encode")
			return False

	def _decode_with_context(self, ctxt, context, params, count):
		try:
			context_obj = TransformContext(context)
			param_map = {}
			for i in range(0, count):
				data = databuffer.DataBuffer(handle=core.BNDuplicateDataBuffer(params[i].value))
				param_map[params[i].name] = bytes(data)
			result = self.perform_decode_with_context(context_obj, param_map)
			return result if result is not None else False
		except Exception:
			log_error_for_exception("Unhandled Python exception in Transform._decode_with_context")
			return False

	def _can_decode(self, ctxt, input):
		try:
			input_obj = binaryview.BinaryView(handle=input)
			return self.can_decode(input_obj)
		except Exception:
			log_error_for_exception("Unhandled Python exception in Transform._can_decode")
			return False

	@abc.abstractmethod
	def perform_decode(self, data, params):
		if self.type == TransformType.InvertingTransform:
			return self.perform_encode(data, params)
		return None

	@abc.abstractmethod
	def perform_encode(self, data, params):
		return None

	def perform_decode_with_context(self, context, params):
		return False

	def decode(self, input_buf, params={}):
		if isinstance(input_buf, int):
			raise TypeError("input_buf cannot be an integer")
		input_buf = databuffer.DataBuffer(input_buf)
		output_buf = databuffer.DataBuffer()
		keys = list(params.keys())
		param_buf = (core.BNTransformParameter * len(keys))()
		data = []
		for i in range(0, len(keys)):
			param_value = params[keys[i]]
			# Validate parameter type
			if not isinstance(param_value, (bytes, bytearray, str, databuffer.DataBuffer)):
				raise TypeError(f"Transform parameter '{keys[i]}' must be bytes, bytearray, str, or DataBuffer, not {type(param_value).__name__}. "
				                f"If you need to pass an integer like 0x{param_value:x} as a key, convert it to bytes first: bytes([0x{param_value:x}])"
				                if isinstance(param_value, int) else
				                f"Transform parameter '{keys[i]}' must be bytes, bytearray, str, or DataBuffer, not {type(param_value).__name__}")
			data.append(databuffer.DataBuffer(param_value))
			param_buf[i].name = keys[i]
			param_buf[i].value = data[i].handle
		if not core.BNDecode(self.handle, input_buf.handle, output_buf.handle, param_buf, len(keys)):
			return None
		return bytes(output_buf)

	def encode(self, input_buf, params={}):
		if isinstance(input_buf, int):
			raise TypeError("input_buf cannot be an integer")
		input_buf = databuffer.DataBuffer(input_buf)
		output_buf = databuffer.DataBuffer()
		keys = list(params.keys())
		param_buf = (core.BNTransformParameter * len(keys))()
		data = []
		for i in range(0, len(keys)):
			param_value = params[keys[i]]
			# Validate parameter type
			if not isinstance(param_value, (bytes, bytearray, str, databuffer.DataBuffer)):
				raise TypeError(f"Transform parameter '{keys[i]}' must be bytes, bytearray, str, or DataBuffer, not {type(param_value).__name__}. "
				                f"If you need to pass an integer like 0x{param_value:x} as a key, convert it to bytes first: bytes([0x{param_value:x}])"
				                if isinstance(param_value, int) else
				                f"Transform parameter '{keys[i]}' must be bytes, bytearray, str, or DataBuffer, not {type(param_value).__name__}")
			data.append(databuffer.DataBuffer(param_value))
			param_buf[i].name = keys[i]
			param_buf[i].value = data[i].handle
		if not core.BNEncode(self.handle, input_buf.handle, output_buf.handle, param_buf, len(keys)):
			return None
		return bytes(output_buf)

	def decode_with_context(self, context, params={}):
		"""
		``decode_with_context`` performs context-aware transformation for container formats,
		enabling multi-file extraction

		**Processing Protocol:**

		Container transforms typically operate in two phases:

		1. **Discovery Phase**: Transform enumerates available files and populates
		   ``context.available_files``. Returns ``False`` to indicate user file selection
		   is required.

		2. **Extraction Phase**: Transform processes ``context.requested_files`` and
		   creates child contexts for each file with extraction results. Returns ``True``
		   when extraction is complete.

		**Return Value Semantics:**

		- ``True``: Processing complete, no more user interaction needed
		- ``False``: Processing incomplete, requires user input or session management
		  (e.g., file selection after discovery)

		**Error Reporting:**

		Extraction results and messages are accessible via context properties:

		- **Context-level** (transformation/extraction status):
		  - ``context.extraction_result``: Result of parent producing input
		  - ``context.extraction_message``: Human-readable extraction message
		  - ``context.transform_result``: Result of applying transform to input

		Common error scenarios:

		  - Archive encrypted, password required
		  - Corrupt archive structure
		  - Unsupported archive format
		  - Individual file extraction failures

		**Usage Examples:**

		.. code-block:: python

			from binaryninja import TransformSession

			# Full mode - automatically extracts all files
			session = TransformSession("archive.zip")
			if session.process(): # All extraction complete, no interaction needed
				# Select the intended context(s) for loading
				session.set_selected_contexts(session.current_context)
				# Load the resulting BinaryView(s)
				loaded_view = load(session.current_view)
			else:
				# Extraction incomplete - user input required
				print("Extraction requires user input")

			# Interactive mode - requires manual processing for each step
			session = TransformSession("nested.zip")
			while not session.process():
				# Process returned False - user input needed
				ctx = session.current_context

				# Check if parent has available files for selection
				if ctx.parent and ctx.parent.has_available_files:
					# Show files to user and let them select
					available = ctx.parent.available_files
					print(f"Available files: {available}")

					# Select files to extract (or all)
					ctx.parent.set_requested_files(available)

					# Continue processing from parent
					session.process_from(ctx.parent)

			# Extraction complete - select and load the final context
			session.set_selected_contexts(session.current_context)
			final_view = session.current_view

		:param TransformContext context: Transform context containing input data and state
		:param dict params: Optional transform parameters (e.g., passwords, settings)
		:return: True if processing complete, False if user input required
		:rtype: bool
		"""
		if not isinstance(context, TransformContext):
			return None
		keys = list(params.keys())
		param_buf = (core.BNTransformParameter * len(keys))()
		data = []
		for i in range(0, len(keys)):
			param_value = params[keys[i]]
			# Validate parameter type
			if not isinstance(param_value, (bytes, bytearray, str, databuffer.DataBuffer)):
				raise TypeError(f"Transform parameter '{keys[i]}' must be bytes, bytearray, str, or DataBuffer, not {type(param_value).__name__}. "
				                f"If you need to pass an integer like 0x{param_value:x} as a key, convert it to bytes first: bytes([0x{param_value:x}])"
				                if isinstance(param_value, int) else
				                f"Transform parameter '{keys[i]}' must be bytes, bytearray, str, or DataBuffer, not {type(param_value).__name__}")
			data.append(databuffer.DataBuffer(param_value))
			param_buf[i].name = keys[i]
			param_buf[i].value = data[i].handle
		if not core.BNDecodeWithContext(self.handle, context.handle, param_buf, len(keys)):
			return False
		return True

	def can_decode(self, input):
		"""
		``can_decode`` checks if this transform can decode the given input.

		:param input: can be a :py:class:`bytes`, :py:class:`bytearray`, :py:class:`DataBuffer`, or :py:class:`BinaryView`
		:return: :py:class:`bool` indicating whether the transform can decode the input
		:rtype: bool
		"""
		if isinstance(input, bytes) or isinstance(input, bytearray) or isinstance(input, databuffer.DataBuffer):
			with binaryview.BinaryView.new(input) as view:
				return core.BNCanDecode(self.handle, view.handle)
		elif isinstance(input, binaryview.BinaryView):
				return core.BNCanDecode(self.handle, input.handle)
		return False


class TransformContext:
	"""
	``TransformContext`` represents a node in the container extraction tree, containing the input data,
	transformation state, and relationships to parent/child contexts.

	Each context can have:

		- Input data (BinaryView)
		- Transform information (name, parameters, results)
		- File selection state (available_files, requested_files)
		- Parent/child relationships for nested containers
		- Extraction status and error messages

	Contexts are typically accessed through a ``TransformSession`` rather than created directly.

	**Example:**

	.. code-block:: python

		session = TransformSession("archive.zip")
		session.process()

		# Access context properties
		ctx = session.current_context
		print(f"Filename: {ctx.filename}")
		print(f"Transform: {ctx.transform_name}")
		print(f"Size: {ctx.input.length}")

		# Navigate the tree
		if ctx.parent:
			print(f"Parent files: {ctx.parent.available_files}")

		# Check extraction status
		if ctx.extraction_result != 0:
			print(f"Error: {ctx.extraction_message}")
	"""
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNTransformContext)

	def __del__(self):
		if core is not None:
			core.BNFreeTransformContext(self.handle)

	@property
	def available_transforms(self) -> List[str]:
		"""
		Get the list of transforms that can decode this context's input.

		Binary Ninja auto-detects which transforms can handle the current data by checking each
		transform's ``can_decode()`` method. This property returns the names of all transforms
		that reported they can decode this context's input.

		:return: List of transform names that can decode this data
		:rtype: List[str]
		"""
		count = ctypes.c_size_t()
		transforms = core.BNTransformContextGetAvailableTransforms(self.handle, ctypes.byref(count))
		if transforms is None:
			return []
		result = []
		for i in range(count.value):
			result.append(transforms[i].decode('utf-8'))
		core.BNFreeStringList(transforms, count.value)
		return result

	@property
	def transform_name(self) -> str:
		"""Get the name of the transform that created this context"""
		return core.BNTransformContextGetTransformName(self.handle)

	def set_transform_name(self, transform_name: str):
		"""
		Manually specify which transform to apply to this context.

		Use this when auto-detection is not possible or when you want to override the detected transform.
		This is commonly needed for formats without magic bytes (like Base64) or when forcing a specific decoder.

		After setting the transform name, call ``session.process_from(context)`` to apply the transform.

		:param transform_name: Name of the transform to apply (e.g., "Base64", "Gzip", "XOR")

		**Example:**

		.. code-block:: python

			# Base64 has no magic bytes, so it's not auto-detected
			session = TransformSession("data.zip")
			session.process()

			ctx = session.current_context
			ctx.set_transform_name("Base64") # Manually specify Base64

			# Now apply the Base64 transform
			if session.process_from(ctx):
				print("Base64 decoded successfully")
		"""
		core.BNTransformContextSetTransformName(self.handle, transform_name)

	@property
	def filename(self) -> str:
		"""Get the filename for this context"""
		return core.BNTransformContextGetFileName(self.handle)

	@property
	def input(self) -> Optional['binaryview.BinaryView']:
		"""Get the input BinaryView for this context"""
		view = core.BNTransformContextGetInput(self.handle)
		if view is None:
			return None
		return binaryview.BinaryView(handle=view)

	@property
	def metadata_obj(self) -> Optional['metadata.Metadata']:
		"""
		Get the metadata associated with this extraction context.

		Container transforms can store format-specific metadata during extraction (e.g., timestamps,
		permissions, compression ratios, archive structure). This metadata is preserved in the context
		tree and can be accessed for analysis or debugging.

		:return: Metadata object containing transform-specific key-value pairs, or None if no metadata
		:rtype: Metadata or None
		"""
		meta = core.BNTransformContextGetMetadata(self.handle)
		if meta is None:
			return None
		return metadata.Metadata(handle=meta)

	def set_transform_parameter(self, name: str, data: databuffer.DataBuffer):
		"""
		Set a parameter for the transform (e.g., password, encryption key).

		Transform parameters provide additional input required for decoding, such as passwords for
		encrypted archives or keys for encryption transforms. Parameters are passed to the transform's
		decode operation.

		:param name: Parameter name (e.g., "password", "key")
		:param data: Parameter value as a DataBuffer

		**Example:**

		.. code-block:: python

			# Create session and attempt extraction
			session = TransformSession("encrypted.zip")
			session.process() # Returns False - processing incomplete

			# Check why extraction failed
			if session.current_context.extraction_result == TransformResult.TransformRequiresPassword:
				# Password is set on the parent context (the one doing extraction)
				parent = session.current_context.parent
				parent.set_transform_parameter("password", DataBuffer("secret_password"))

				# Retry extraction from parent
				if session.process_from(parent):
					# Verify successful extraction
					assert parent.children[0].extraction_result == TransformResult.TransformSuccess
					print("Archive decrypted successfully")
		"""
		core.BNTransformContextSetTransformParameter(self.handle, name, data.handle)

	def has_transform_parameter(self, name: str) -> bool:
		"""Check if a transform parameter exists"""
		return core.BNTransformContextHasTransformParameter(self.handle, name)

	def clear_transform_parameter(self, name: str):
		"""Clear a transform parameter"""
		core.BNTransformContextClearTransformParameter(self.handle, name)

	@property
	def extraction_message(self) -> str:
		"""Get the extraction message"""
		return core.BNTransformContextGetExtractionMessage(self.handle)

	@property
	def extraction_result(self) -> TransformResult:
		"""Get the extraction result"""
		return TransformResult(core.BNTransformContextGetExtractionResult(self.handle))

	@property
	def transform_result(self) -> TransformResult:
		"""Get the transform result"""
		return TransformResult(core.BNTransformContextGetTransformResult(self.handle))

	@transform_result.setter
	def transform_result(self, result: TransformResult):
		"""Set the transform result"""
		core.BNTransformContextSetTransformResult(self.handle, result)

	@property
	def parent(self) -> Optional['TransformContext']:
		"""Get the parent context"""
		parent = core.BNTransformContextGetParent(self.handle)
		if parent is None:
			return None
		return TransformContext(parent)

	@property
	def child_count(self) -> int:
		"""Get the number of child contexts"""
		return core.BNTransformContextGetChildCount(self.handle)

	@property
	def children(self) -> List['TransformContext']:
		"""Get all child contexts"""
		count = ctypes.c_size_t()
		children = core.BNTransformContextGetChildren(self.handle, ctypes.byref(count))
		if children is None:
			return []
		result = []
		for i in range(count.value):
			result.append(TransformContext(core.BNNewTransformContextReference(children[i])))
		core.BNFreeTransformContextList(children, count.value)
		return result

	def get_child(self, filename: str) -> Optional['TransformContext']:
		"""Get a child context by filename"""
		child = core.BNTransformContextGetChild(self.handle, filename)
		if child is None:
			return None
		return TransformContext(child)

	def create_child(self, data: databuffer.DataBuffer, filename: str = "", result: TransformResult = TransformResult.TransformSuccess, message: str = "", filename_is_descriptor: bool = False) -> 'TransformContext':
		"""Create a new child context with the given data, filename, result status, and message

		:param data: The data for the child context
		:param filename: The filename for the child context (default: "")
		:param result: Transform result for the child (default: TransformResult.TransformSuccess)
		:param message: Extraction message for the child (default: "")
		:param filename_is_descriptor: Whether the filename is a descriptor that should be combined with parent (default: False)
		"""
		child = core.BNTransformContextSetChild(self.handle, data.handle, filename, result, message, filename_is_descriptor)
		if child is None:
			raise RuntimeError("Failed to create child context")
		return TransformContext(child)

	@property
	def is_leaf(self) -> bool:
		"""Check if this context is a leaf (has no children)"""
		return core.BNTransformContextIsLeaf(self.handle)

	@property
	def is_root(self) -> bool:
		"""Check if this context is the root (has no parent)"""
		return core.BNTransformContextIsRoot(self.handle)

	@property
	def available_files(self) -> List[str]:
		"""
		Get the list of files available for extraction from this container.

		This property is populated during the **Discovery Phase** of container extraction, when a transform
		enumerates the contents of an archive without extracting them.

		**Mode Behavior:**

		- **Full Mode (default)**: Discovery and extraction happen automatically in one pass. After ``process()``,
		  ``available_files`` will be populated on the container context (the one with the archive transform),
		  and all files will already be extracted.
		- **Interactive Mode**: Discovery pauses for user selection. After first ``process()``, ``available_files``
		  is populated on the parent context (the container), and you must call ``set_requested_files()`` before extraction proceeds.

		:return: List of filenames that can be extracted from this container
		:rtype: List[str]

		**Example (Full Mode - Automatic):**

		.. code-block:: python

			# Full mode (default) - all files extracted automatically
			session = TransformSession("archive.zip")
			session.process() # Discovery + extraction in one pass

			# After processing, available_files shows what was discovered on the container
			# For a root-level archive, this is the root context
			container = session.root_context
			print(f"Extracted {len(container.available_files)} files")
			print(f"Files: {container.available_files[:5]}...")

		**Example (Interactive Mode - User Selection):**

		.. code-block:: python

			# Interactive mode - user selects files
			session = TransformSession("archive.zip", mode=TransformSessionMode.TransformSessionModeInteractive)
			session.process() # Discovery phase only - returns False

			# available_files is on the parent (the container doing extraction)
			container = session.current_context.parent
			if container.has_available_files:
				print(f"Archive contains {len(container.available_files)} files")
				print(f"Files: {container.available_files[:5]}...")

				# User selects which files to extract
				container.set_requested_files(["important.bin", "config.txt"])

				# Extract selected files
				session.process_from(container)
		"""
		count = ctypes.c_size_t()
		files = core.BNTransformContextGetAvailableFiles(self.handle, ctypes.byref(count))
		if files is None:
			return []
		result = []
		for i in range(count.value):
			result.append(files[i].decode('utf-8'))
		core.BNFreeStringList(files, count.value)
		return result

	def set_available_files(self, files: List[str]):
		"""
		Populate the list of files available for extraction (Discovery Phase).

		Container transforms call this during the **Discovery Phase** to enumerate files without extracting them.
		After calling this, the transform should return ``False`` to indicate user selection is needed.

		**Session Mode Handling:**

		- **Full Mode**: Session automatically calls ``set_requested_files(available_files)`` and re-invokes
		  the transform for extraction, so all files are extracted in one pass.
		- **Interactive Mode**: Transform returns ``False``, user must call ``set_requested_files()`` manually,
		  then call ``process_from()`` to continue.

		:param files: List of filenames that can be extracted from this container
		"""
		file_array = (ctypes.c_char_p * len(files))()
		for i, f in enumerate(files):
			file_array[i] = core.cstr(f)
		core.BNTransformContextSetAvailableFiles(self.handle, file_array, len(files))

	@property
	def has_available_files(self) -> bool:
		"""Check if this context has available files for selection"""
		return core.BNTransformContextHasAvailableFiles(self.handle)

	@property
	def requested_files(self) -> List[str]:
		"""
		Get the list of files requested for extraction from this container.

		This property contains the filenames that have been selected for extraction during the **Extraction Phase**.
		Container transforms read this property to determine which files to extract and create child contexts for.

		:return: List of filenames requested for extraction
		:rtype: List[str]
		"""
		count = ctypes.c_size_t()
		files = core.BNTransformContextGetRequestedFiles(self.handle, ctypes.byref(count))
		if files is None:
			return []
		result = []
		for i in range(count.value):
			result.append(files[i].decode('utf-8'))
		core.BNFreeStringList(files, count.value)
		return result

	def set_requested_files(self, files: List[str]):
		"""
		Specify which files to extract from this container (Extraction Phase).

		Call this after ``available_files`` has been populated to indicate which files should be extracted.
		After setting this, call ``session.process_from(context)`` to perform the extraction.

		**Mode Behavior:**

		- **Full Mode**: Called automatically by the session with all available files, you rarely need to call this.
		- **Interactive Mode**: You must call this manually to select which files to extract.

		:param files: List of filenames to extract (must be subset of ``available_files``)
		"""
		file_array = (ctypes.c_char_p * len(files))()
		for i, f in enumerate(files):
			file_array[i] = core.cstr(f)
		core.BNTransformContextSetRequestedFiles(self.handle, file_array, len(files))

	@property
	def has_requested_files(self) -> bool:
		"""Check if this context has requested files"""
		return core.BNTransformContextHasRequestedFiles(self.handle)

	@property
	def is_database(self) -> bool:
		"""Check if this context represents a database file"""
		return core.BNTransformContextIsDatabase(self.handle)

	@property
	def is_interactive(self) -> bool:
		"""
		Check if this context is in interactive mode.

		This flag indicates whether the transform session is operating in interactive mode (e.g., UI with
		user dialogs) or non-interactive mode (e.g., headless/auto-open). Transforms can use this to
		adjust their behavior. For example, filtering children in non-interactive mode while showing
		all children in interactive mode.

		:return: True if in interactive mode, False otherwise
		:rtype: bool
		"""
		return core.BNTransformContextIsInteractive(self.handle)

	@property
	def settings(self) -> 'Settings':
		"""
		Get the settings object for this transform context.

		This provides access to session-time settings overrides passed via the ``TransformSession`` ``options``
		parameter. These ephemeral settings override global settings for this session only. Transforms should
		use this `Settings` object instead of ``Settings()`` to read settings values that may have been
		overridden for the session.

		:return: Settings object
		:rtype: Settings
		"""
		handle = core.BNTransformContextGetSettings(self.handle)
		if handle is None:
			return None
		return Settings(handle=handle)


class TransformSession:
	"""
	``TransformSession`` manages the extraction workflow for container files (ZIP, TAR, IMG4, etc.),
	handling multi-stage extraction, file selection, and transform application.

	Sessions automatically detect and apply appropriate transforms to navigate through nested containers,
	maintaining a tree of ``TransformContext`` objects representing each extraction stage.

	:param Union[str, 'binaryview.BinaryView'] filename_or_view: Path to the file to process, or an existing BinaryView to start from.
	:param TransformSessionMode mode: Session mode controlling extraction behavior. Can be ``TransformSessionMode.Full`` (automatic), ``TransformSessionMode.Interactive`` (requires user selection), or None to use the default mode from settings. Defaults to None.
	:param dict options: Dictionary of session-time settings overrides that apply only to this session. These ephemeral settings override global settings and are accessible to transforms via ``TransformContext.settings``. For example, ``{'files.universal.architecturePreference': ['x86_64']}`` to prefer x86_64 when opening universal binaries. Defaults to empty dict.

	**Modes:**

	- **Full Mode** (default): Automatically extracts all files through nested containers
	- **Interactive Mode**: Requires user file selection at each stage

	**Basic Usage:**

	.. code-block:: python

		from binaryninja import TransformSession

		# Full automatic extraction
		session = TransformSession("archive.zip")
		if session.process():
			final_data = session.current_view
			load(final_data)

	**Interactive Extraction:**

	.. code-block:: python

		session = TransformSession("nested_archive.zip")
		while not session.process():
			# User input needed
			ctx = session.current_context
			if ctx.parent and ctx.parent.has_available_files:
				# Show file choices to user
				print(f"Available: {ctx.parent.available_files}")

				# User selects files
				ctx.parent.set_requested_files(["important_file.bin"])

				# Continue extraction
				session.process_from(ctx.parent)

		# Access final extracted data
		session.set_selected_contexts(session.current_context)
		final_view = session.current_view

	**Key Methods:**

	- ``process()``: Process the next extraction stage
	- ``process_from(context)``: Resume processing from a specific context
	- ``set_selected_contexts(contexts)``: Mark contexts for final access

	**Key Properties:**

	- ``current_context``: The current point in the extraction tree
	- ``current_view``: The current BinaryView (after processing)
	- ``root_context``: The root of the extraction tree
	"""
	def __init__(self, filename_or_view: Union[str, 'binaryview.BinaryView'], mode=None, options: Mapping[str, Any]={}, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNTransformSession)
		elif isinstance(filename_or_view, str):
			if mode is None:
				self.handle = core.BNCreateTransformSession(filename_or_view, json.dumps(options))
			else:
				self.handle = core.BNCreateTransformSessionWithMode(filename_or_view, mode, json.dumps(options))
		elif hasattr(filename_or_view, 'handle'):  # BinaryView
			if mode is None:
				self.handle = core.BNCreateTransformSessionFromBinaryView(filename_or_view.handle, json.dumps(options))
			else:
				self.handle = core.BNCreateTransformSessionFromBinaryViewWithMode(filename_or_view.handle, mode, json.dumps(options))
		else:
			raise TypeError("filename_or_view must be a string filename or BinaryView")

		if self.handle is None:
			raise RuntimeError("Failed to create TransformSession")

	def __del__(self):
		if core is not None:
			core.BNFreeTransformSession(self.handle)

	@property
	def current_view(self) -> Optional['binaryview.BinaryView']:
		"""Get the current BinaryView for this session"""
		view = core.BNTransformSessionGetCurrentView(self.handle)
		if view is None:
			return None
		return binaryview.BinaryView(handle=view)

	@property
	def root_context(self) -> Optional['TransformContext']:
		"""Get the root transform context"""
		context = core.BNTransformSessionGetRootContext(self.handle)
		if context is None:
			return None
		return TransformContext(context)

	@property
	def current_context(self) -> Optional['TransformContext']:
		"""Get the current transform context"""
		context = core.BNTransformSessionGetCurrentContext(self.handle)
		if context is None:
			return None
		return TransformContext(context)

	def process_from(self, context: 'TransformContext') -> bool:
		"""
		Process the transform session starting from a specific context.

		:return: ``True`` if processing completed successfully (all transforms applied and no user input required). \
		         ``False`` if processing is incomplete and requires user input (file selection, password), \
		         additional parameters, or if an error occurred during transformation.
		:rtype: bool

		In **Interactive Mode**, this returns ``False`` when user selection is needed at the current stage.
		In **Full Mode**, this recursively processes all child contexts and returns ``False`` if any stage is incomplete.
		"""
		if not isinstance(context, TransformContext):
			raise TypeError("context must be a TransformContext")
		return core.BNTransformSessionProcessFrom(self.handle, context.handle)

	def process(self) -> bool:
		"""
		Process the transform session from the root context.

		:return: ``True`` if processing completed successfully (all transforms applied and no user input required). \
		         ``False`` if processing is incomplete and requires user input (file selection, password), \
		         additional parameters, or if an error occurred during transformation.
		:rtype: bool

		In **Full Mode** (default), automatically processes the entire container tree.
		In **Interactive Mode**, processes one stage at a time, returning ``False`` when user input is needed.
		In **Disabled Mode**, immediately returns ``True`` without processing.

		Common reasons for returning ``False``:

		- Container has multiple files and user must select which to extract
		- Archive is password-protected and no valid password was provided
		- Transform requires additional parameters
		- Transform encountered an error during processing
		"""
		return core.BNTransformSessionProcess(self.handle)

	@property
	def has_any_stages(self) -> bool:
		"""Check if this session has any processing stages"""
		return core.BNTransformSessionHasAnyStages(self.handle)

	@property
	def has_single_path(self) -> bool:
		"""Check if this session has a single processing path"""
		return core.BNTransformSessionHasSinglePath(self.handle)

	@property
	def selected_contexts(self) -> List['TransformContext']:
		"""
		Get the currently selected contexts.

		Selected contexts are the extraction outputs that will be loaded into Binary Ninja for analysis.
		Use ``set_selected_contexts()`` to mark which contexts should be kept active.
		"""
		count = ctypes.c_size_t()
		contexts = core.BNTransformSessionGetSelectedContexts(self.handle, ctypes.byref(count))
		if contexts is None:
			return []
		result = []
		for i in range(count.value):
			result.append(TransformContext(core.BNNewTransformContextReference(contexts[i])))
		core.BNFreeTransformContextList(contexts, count.value)
		return result

	def set_selected_contexts(self, contexts: Union[List['TransformContext'], 'TransformContext']):
		"""
		Mark contexts as selected for analysis and resource management. This allows Binary Ninja to release
		resources for unselected branches of the extraction tree.

		:param contexts: Single context or list of contexts to mark as selected. All other contexts will be unselected.
		:type contexts: TransformContext or List[TransformContext]

		**Example:**

		.. code-block:: python

			session = TransformSession("archive.tar.gz")
			if session.process():
				# Mark the final extracted file for loading
				session.set_selected_contexts(session.current_context)

				# Now load it
				with load(session.current_view) as bv:
					print(f"Loaded: {bv.file.virtual_path}")

		"""
		if isinstance(contexts, TransformContext):
			contexts = [contexts]
		context_array = (ctypes.POINTER(core.BNTransformContext) * len(contexts))()
		for i, ctx in enumerate(contexts):
			context_array[i] = ctx.handle
		core.BNTransformSessionSetSelectedContexts(self.handle, context_array, len(contexts))

	def set_interactive(self, interactive: bool):
		"""
		Set whether this session is running in interactive mode.

		This flag allows transforms to adjust their behavior: in interactive mode, transforms typically
		expose all available children and options. In non-interactive mode, transforms may filter children
		based on settings preferences or apply automatic selections.

		Call this before ``process()`` to establish the session's mode.

		:param interactive: True for interactive mode (UI), False for non-interactive (headless/scripting)
		:type interactive: bool
		"""
		core.BNTransformSessionSetInteractive(self.handle, interactive)


class ZipPython(Transform):
	"""
	Reference implementation of a ZIP container transform using Python's zipfile module.

	This transform demonstrates the Container Transform API including two-phase extraction
	(discovery and extraction), multi-file support, password handling, and result reporting.

	>>> from binaryninja.transform import ZipPython
	>>> ZipPython.register()
	>>> session = TransformSession("Archive.zip")
	>>> session.root_context.available_transforms
	>>> ['Zip', 'ZipPython']
	"""
	transform_type = TransformType.DecodeTransform
	capabilities = TransformCapabilities.TransformSupportsDetection | TransformCapabilities.TransformSupportsContext
	name = "ZipPython"
	long_name = "Zip (Python)"
	group = "Container"

	def can_decode(self, input) -> bool:
		"""
		Detect ZIP archives by checking for "PK" magic bytes and valid ZIP signature.

		Checks the first 4 bytes for ZIP file signatures (local file header, central directory, etc.).

		:param input: BinaryView to check
		:return: True if valid ZIP archive
		"""
		try:
			head = input.read(0, 4)
			if len(head) < 4 or head[0:2] != b"PK":
				return False
			signature = head[2] | (head[3] << 8)
			return signature in (0x0403, 0x0201, 0x0605, 0x0708, 0x0606, 0x0706, 0x0505)
		except Exception:
			log_error("ZipPython: failed to read from BinaryView for signature check")
			return False

	def perform_decode(self, data: bytes, params: dict) -> Optional[bytes]:
		"""
		Extract a single file from a ZIP archive.

		Extracts the file specified in params['filename'], or the first file if not specified.
		For multi-file extraction and password handling, use ``perform_decode_with_context()``.

		:param data: Raw ZIP archive bytes
		:param params: May contain 'filename' key
		:return: Extracted file data, or None on failure
		"""
		try:
			zf = zipfile.ZipFile(io.BytesIO(data), "r")
		except Exception:
			log_error("ZipPython: failed to open data as ZIP")
			return None

		filename = None
		if "filename" in params:
			p = params["filename"]
			filename = p.decode("utf-8", "replace") if isinstance(p, (bytes, bytearray)) else str(p)
		elif zf.namelist():
			filename = zf.namelist()[0]
		try:
			if filename:
				with zf.open(filename, "r") as f:
					return f.read()
		except (KeyError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
			log_error(f"ZipPython: failed to extract member '{filename}' from ZIP")
			return None

	def perform_encode(self, data, params):
		return None

	def perform_decode_with_context(self, context, params) -> bool:
		"""
		Extract files from a ZIP archive using two-phase container extraction.

		**Phase 1 (Discovery):** Enumerates files and populates ``context.available_files``.
		Returns False for user file selection.

		**Phase 2 (Extraction):** Extracts files from ``context.requested_files``, trying passwords
		from params['password'] and ``files.container.defaultPasswords`` setting. Creates child
		contexts for each file with appropriate result codes.

		:param context: Transform context with input data and file selection state
		:param params: May contain 'password' key for encrypted archives
		:return: True if all extractions succeeded, False if user input needed or extraction failed
		"""
		try:
			zf = zipfile.ZipFile(io.BytesIO(context.input.read(0, context.input.length)), "r")
		except Exception:
			context.transform_result = TransformResult.TransformFailure
			log_error(f"ZipPython: failed to open context input as ZIP: len={context.input.length}")
			return False

		# Build the file list (non-directories only)
		files: List[str] = [n for n in zf.namelist() if not n.endswith("/")]

		# Phase 1: discovery
		if not context.has_available_files:
			context.set_available_files(files)
			return False

		# Phase 2: extraction
		requested = context.requested_files
		if not requested:
			return False

		passwords = Settings().get_string_list('files.container.defaultPasswords')
		if "password" in params:
			p = params["password"]
			passwords.insert(0, p.decode("utf-8", "replace") if isinstance(p, (bytes, bytearray)) else str(p))
		passwords = [None] + passwords

		complete = True
		for name in requested:
			if name not in files:
				msg = f"Requested file '{name}' not found in ZIP"
				context.create_child(databuffer.DataBuffer(b""), name, result=TransformResult.TransformFailure, message=msg)
				complete = False
				continue

			content = None
			error = None
			successful_password = None
			for password in passwords:
				try:
					if password is None:
						with zf.open(name, "r") as f:
							content = f.read()
					else:
						pwd = password.encode('utf-8') if isinstance(password, str) else password
						with zf.open(name, "r", pwd=pwd) as f:
							content = f.read()
					successful_password = password
					break

				except RuntimeError as e:
					error = e
					if 'password' not in str(e).lower() and 'encrypted' not in str(e).lower():
						break
				except Exception as e:
					error = e
					break

			if successful_password is not None and successful_password in passwords:
				passwords.remove(successful_password)
				passwords.insert(0, successful_password)

			if content is not None:
				context.create_child(databuffer.DataBuffer(content), name)
			else:
				if error is None:
					error = RuntimeError(f"Failed to decrypt '{name}' with any provided password")
				if isinstance(error, RuntimeError) and 'password' in str(error).lower():
					transformresult = TransformResult.TransformRequiresPassword
				else:
					transformresult = TransformResult.TransformFailure
					log_error(f"ZipPython: failed to extract requested file '{name}': {error}")

				context.create_child(databuffer.DataBuffer(b""), name, result=transformresult, message=str(error))
				complete = False

		return complete
