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

import ctypes
import warnings

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import binaryview
from . import deprecation
from . import types
from .log import log_error_for_exception
from .architecture import Architecture
from .platform import Platform
from .settings import Settings
from typing import Any, Callable, Iterable, List, NamedTuple, Optional, Tuple, Union


class DemangleResult(NamedTuple):
	"""
	Tuple-compatible demangle result. A successful result always has a QualifiedName;
	the type may be None when the demangler can recover only a name.
	"""

	type: Optional['types.Type']
	name: 'types.QualifiedName'

	@classmethod
	def _from_core_struct(cls, result: core.BNDemanglerResult) -> 'DemangleResult':
		if hasattr(result, "contents"):
			result = result.contents

		result_var_name = types.QualifiedName._from_core_struct(result.name)
		out_type = None
		if result.type:
			out_type = core.BNNewTypeReference(result.type)
		try:
			result_type = None
			if out_type:
				result_type = types.Type.create(handle=out_type)
				out_type = None
			return cls(result_type, result_var_name)
		finally:
			if out_type:
				core.BNFreeType(out_type)


class DemanglerConfig:
	"""
	Platform, view, and simplification options used by demangler APIs.

	Use ``default``, ``for_platform``, or ``for_binary_view`` when the configuration
	should inherit the corresponding core defaults.
	"""

	def __init__(
			self,
			arch_or_platform: Optional[Union[Architecture, Platform]] = None,
			view: Optional['binaryview.BinaryView'] = None,
			simplify: bool = False
	):
		if not isinstance(simplify, bool):
			raise TypeError("simplify must be a bool")
		if isinstance(arch_or_platform, Architecture):
			platform_obj = arch_or_platform.standalone_platform
		elif isinstance(arch_or_platform, Platform):
			platform_obj = arch_or_platform
		elif arch_or_platform is None:
			platform_obj = view.platform if view is not None else None
		else:
			raise TypeError("Unexpected arch or platform type")

		self.platform = platform_obj
		self.view = view
		self.simplify_templates = simplify

	@classmethod
	def default(cls) -> 'DemanglerConfig':
		"""Create the core default demangler configuration."""
		return cls._from_core_struct(core.BNGetDefaultDemanglerConfig())

	@classmethod
	def for_platform(cls, platform: Platform, simplify: bool = False) -> 'DemanglerConfig':
		"""Create a configuration for a platform."""
		if not isinstance(platform, Platform):
			raise TypeError("platform must be a Platform")
		if not isinstance(simplify, bool):
			raise TypeError("simplify must be a bool")
		return cls._from_core_struct(core.BNGetDemanglerConfigForPlatform(platform.handle, simplify))

	@classmethod
	def for_binary_view(cls, view: 'binaryview.BinaryView') -> 'DemanglerConfig':
		"""Create a configuration using a view's platform and template-simplifier setting."""
		if not isinstance(view, binaryview.BinaryView):
			raise TypeError("view must be a BinaryView")
		return cls._from_core_struct(core.BNGetDemanglerConfigForBinaryView(view.handle))

	def _to_core_struct(self) -> core.BNDemanglerConfig:
		config = core.BNDemanglerConfig()
		config.platform = self.platform.handle if self.platform is not None else None
		config.view = self.view.handle if self.view is not None else None
		config.simplifyTemplates = self.simplify_templates
		return config

	@classmethod
	def _from_core_struct(cls, config: core.BNDemanglerConfig) -> 'DemanglerConfig':
		if hasattr(config, "contents"):
			config = config.contents

		platform = None
		if config.platform:
			platform = Platform(handle=core.BNNewPlatformReference(config.platform))

		view = None
		if config.view:
			view = binaryview.BinaryView(handle=core.BNNewViewReference(config.view))

		return cls(platform, view, config.simplifyTemplates)


@deprecation.deprecated(deprecated_in="5.4", details="Use `demangle_any` with a `DemanglerConfig` instead.")
def demangle_generic(
		archOrPlatform: Union[Architecture, Platform],
		mangled_name: str,
		view: Optional['binaryview.BinaryView'] = None,
		simplify: bool = False
) -> Optional[Tuple[Optional['types.Type'], List[str]]]:
	"""Compatibility wrapper for the legacy generic demangler API."""
	if isinstance(archOrPlatform, Architecture):
		arch = archOrPlatform
	elif isinstance(archOrPlatform, Platform):
		arch = archOrPlatform.arch
	else:
		raise TypeError("Unexpected arch or platform type")
	if view is not None and not isinstance(view, binaryview.BinaryView):
		raise TypeError("view must be a BinaryView")
	if not isinstance(simplify, bool):
		raise TypeError("simplify must be a bool")

	platform = arch.standalone_platform
	if platform is not None:
		config = DemanglerConfig.for_platform(platform, simplify)
	else:
		config = DemanglerConfig.default()
	config.view = view
	config.simplify_templates = simplify

	result = demangle_any(mangled_name, config)
	if result is None:
		return None, [mangled_name]
	return result.type, result.name.name


def demangle_any(
		mangled_name: str,
		config: Optional[DemanglerConfig] = None
	) -> Optional[DemangleResult]:
	"""
	Attempt to demangle a mangled name, trying all relevant demanglers and using whichever one accepts it.

	:param str mangled_name: a mangled symbol name
	:param Optional[DemanglerConfig] config: Platform/view/options used while demangling. If omitted,
		the core default standalone platform is used.
	:return: returns a DemangleResult with type and name fields, or None on error. DemangleResult can be unpacked as (type, name).
	:rtype: Optional[DemangleResult]
	:Example:

		>>> result = demangle_any("?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		>>> result.type
		<type: immutable:FunctionTypeClass 'enum Foobar::foo __cdecl(enum Foobar::foo)'>
		>>> result.name
		'Foobar::testf'
	"""
	if config is not None and not isinstance(config, DemanglerConfig):
		raise TypeError("config must be a DemanglerConfig")

	result = core.BNDemanglerResult()
	api_config = (config or DemanglerConfig.default())._to_core_struct()
	if not core.BNDemangle(mangled_name, api_config, result):
		return None

	try:
		return DemangleResult._from_core_struct(result)
	except UnicodeDecodeError:
		return None
	finally:
		core.BNFreeDemanglerResult(result)


def _config_from_options(
		arch_or_platform: Optional[Union[Architecture, Platform, DemanglerConfig]],
		options: Any
) -> DemanglerConfig:
	"""
	Normalize the documented DemanglerConfig form and legacy named-helper arguments.

	The bool and BinaryView branches preserve the historical call shapes. They are
	intentionally omitted from the public API documentation so new callers construct
	and reuse a DemanglerConfig instead of querying BinaryView settings per call.
	"""
	if isinstance(arch_or_platform, DemanglerConfig):
		return arch_or_platform
	if isinstance(options, DemanglerConfig):
		return options
	if options is not None and not isinstance(options, bool):
		if not isinstance(options, binaryview.BinaryView):
			raise TypeError("options must be a bool, BinaryView, DemanglerConfig, or None")

	view = options if isinstance(options, binaryview.BinaryView) else None
	simplify = (
		options if isinstance(options, bool)
		else Settings().get_bool("analysis.types.templateSimplifier", view)
	)
	if isinstance(arch_or_platform, Architecture):
		platform = arch_or_platform.standalone_platform
	elif isinstance(arch_or_platform, Platform):
		platform = arch_or_platform
	elif arch_or_platform is None:
		platform = None
	else:
		raise TypeError("arch_or_platform must be an Architecture, Platform, or DemanglerConfig")

	if platform is not None:
		config = DemanglerConfig.for_platform(platform, simplify)
	else:
		config = DemanglerConfig.default()
	config.view = view
	config.simplify_templates = simplify
	return config


def _demangle_with_demangler(
		mangled_name: str,
		config: DemanglerConfig,
		demangler_getter: Callable[[], Any]
) -> Optional[DemangleResult]:
	binaryninja._init_plugins()
	demangler = demangler_getter()
	if demangler is None:
		return None

	result = core.BNDemanglerResult()
	if not core.BNDemangleWithDemangler(
			demangler, mangled_name, config._to_core_struct(), result
	):
		return None

	try:
		return DemangleResult._from_core_struct(result)
	finally:
		core.BNFreeDemanglerResult(result)


def demangle_llvm(
		mangled_name: str,
		options: Optional[DemanglerConfig] = None
) -> Optional[DemangleResult]:
	"""
	``demangle_llvm`` demangles a mangled name using the LLVM demangler.

	.. warning::
		Passing a BinaryView through the legacy ``options`` compatibility path queries
		its template-simplifier setting on every call. This is very slow and should not
		be used in an inner loop. Create one ``DemanglerConfig`` with
		``DemanglerConfig.for_binary_view(view)`` and pass it to ``demangle_any`` instead.

	:param str mangled_name: a mangled (msvc/gnu3/rust/dlang) name
	:param Optional[DemanglerConfig] options: a prebuilt demangler configuration
	:return: returns a DemangleResult with type and name fields, or None on error
	:rtype: Optional[DemangleResult]
	:Example:

		>>> config = DemanglerConfig.default()
		>>> demangle_llvm("?testf@Foobar@@SA?AW4foo@1@W421@@Z", config)
		DemangleResult(type=None, name='public: static enum Foobar::foo __cdecl Foobar::testf(enum Foobar::foo)')
		>>>
	"""
	modern_result = isinstance(options, DemanglerConfig)
	config = _config_from_options(None, options)
	result = _demangle_with_demangler(mangled_name, config, core.BNGetLLVMDemangler)
	if modern_result:
		return result
	return result.name.name if result is not None else None


def demangle_ms(
		archOrPlatform: Union[Architecture, Platform, DemanglerConfig],
		mangled_name: str,
		options=False
	) -> Optional[DemangleResult]:
	"""
	``demangle_ms`` demangles a mangled Microsoft Visual Studio C++ name to a Type object.

	.. warning::
		Passing a BinaryView through the legacy ``options`` compatibility path queries
		its template-simplifier setting on every call. This is very slow and should not
		be used in an inner loop. Create one ``DemanglerConfig`` with
		``DemanglerConfig.for_binary_view(view)`` and pass it to ``demangle_any`` instead.

	:param Union[Architecture, Platform, DemanglerConfig] archOrPlatform: A prebuilt configuration,
		or an Architecture or Platform for the symbol
	:param str mangled_name: a mangled Microsoft Visual Studio C++ name
	:return: returns a DemangleResult with type and name fields, or None on error
	:rtype: Optional[DemangleResult]
	:Example:

		>>> config = DemanglerConfig.for_platform(Architecture["x86_64"].standalone_platform)
		>>> demangle_ms(config, "?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		DemangleResult(type=<type: immutable:FunctionTypeClass 'enum Foobar::foo __cdecl(enum Foobar::foo)'>, name='Foobar::testf')
		>>>
	"""
	modern_result = isinstance(archOrPlatform, DemanglerConfig) or isinstance(options, DemanglerConfig)
	config = _config_from_options(archOrPlatform, options)
	result = _demangle_with_demangler(mangled_name, config, core.BNGetMSVCDemangler)
	if modern_result:
		return result
	if result is None:
		return None, mangled_name
	return result.type, result.name.name


def demangle_gnu3(
		arch: Union[Architecture, Platform, DemanglerConfig],
		mangled_name: str,
		options=None
	) -> Optional[DemangleResult]:
	"""
	``demangle_gnu3`` demangles a mangled name to a Type object.

	.. warning::
		Passing a BinaryView through the legacy ``options`` compatibility path queries
		its template-simplifier setting on every call. This is very slow and should not
		be used in an inner loop. Create one ``DemanglerConfig`` with
		``DemanglerConfig.for_binary_view(view)`` and pass it to ``demangle_any`` instead.

	:param Union[Architecture, Platform, DemanglerConfig] arch: A prebuilt configuration,
		or an Architecture or Platform for the symbol
	:param str mangled_name: a mangled GNU3 name
	:return: returns a DemangleResult with type and name fields, or None on error
	:rtype: Optional[DemangleResult]
	"""
	modern_result = isinstance(arch, DemanglerConfig) or isinstance(options, DemanglerConfig)
	config = _config_from_options(arch, options)
	result = _demangle_with_demangler(mangled_name, config, core.BNGetGNU3Demangler)
	if modern_result:
		return result
	if result is None:
		return None, mangled_name
	return result.type, result.name.name


def simplify_demangled_template_name(
		name: Union[str, Iterable[str], types.QualifiedName]) -> types.QualifiedName:
	"""
	``simplify_demangled_template_name`` simplifies standard-library template spelling in
	an already demangled qualified name.
	"""
	if isinstance(name, types.QualifiedName):
		qualified_name = name
	elif isinstance(name, str):
		qualified_name = types.QualifiedName(name)
	else:
		qualified_name = types.QualifiedName(list(name))

	api_name = qualified_name._to_core_struct()
	result = core.BNQualifiedName()
	if not core.BNSimplifyDemangledTemplateName(ctypes.byref(api_name), ctypes.byref(result)):
		return qualified_name
	try:
		return types.QualifiedName._from_core_struct(result)
	finally:
		core.BNFreeQualifiedName(result)


class _DemanglerMetaclass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetDemanglerList(count)
		try:
			for i in range(0, count.value):
				yield CoreDemangler(types[i])
		finally:
			core.BNFreeDemanglerList(types)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		handle = core.BNGetDemanglerByName(str(value))
		if handle is None:
			raise KeyError(f"'{value}' is not a valid Demangler")
		return CoreDemangler(handle)

	def __contains__(cls: '_DemanglerMetaclass', name: object) -> bool:
		if not isinstance(name, str):
			return False
		try:
			cls[name]
			return True
		except KeyError:
			return False

	def get(cls: '_DemanglerMetaclass', name: str, default: Any = None) -> Optional['Demangler']:
		try:
			return cls[name]
		except KeyError:
			if default is not None:
				return default
			return None


class Demangler(metaclass=_DemanglerMetaclass):
	"""
	Pluggable name demangling interface. See :py:func:`register` and :py:func:`demangle`
	for details on the process of this interface.

	Custom Demangler subclasses can be registered and promoted at runtime.

	The list of Demanglers can be queried:

		>>> list(Demangler)
		[<Demangler: MS>, <Demangler: GNU3>, <Demangler: LLVM>]
	"""

	name = None
	_registered_demanglers = []
	_cached_name = None

	def __init__(self, handle=None):
		self._uses_legacy_demangle_signature = False
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNDemangler)
			self.__dict__["name"] = core.BNGetDemanglerName(handle)
		else:
			self.handle = None

	@classmethod
	def register(cls):
		"""
		Register a custom Demangler. Newly registered demanglers will get priority over
		previously registered demanglers and built-in demanglers.

		:return: True if registration succeeded; False if the demangler was invalid.
		"""
		demangler = cls()

		assert demangler.__class__.name is not None
		assert demangler.handle is None

		try:
			parameter_count = binaryninja._get_parameter_count(demangler.demangle)
		except (TypeError, ValueError):
			parameter_count = 2
		demangler._uses_legacy_demangle_signature = parameter_count == 3
		if demangler._uses_legacy_demangle_signature:
			warnings.warn(
				deprecation.DeprecatedWarning(
					"Custom Demangler.demangle(arch, name, view)",
					"5.4",
					None,
					"Use Demangler.demangle(name, config) instead."
				),
				stacklevel=2
			)

		demangler._cb = core.BNDemanglerCallbacks()
		demangler._cb.context = 0
		demangler._cb.isMangledString = demangler._cb.isMangledString.__class__(demangler._is_mangled_string)
		demangler._cb.demangle = demangler._cb.demangle.__class__(demangler._demangle)
		demangler._cb.freeResult = demangler._cb.freeResult.__class__(demangler._free_result)
		demangler.handle = core.BNRegisterDemangler(cls.name, demangler._cb)
		if not demangler.handle:
			return False

		cls._registered_demanglers.append(demangler)
		return True

	@classmethod
	def promote(cls, demangler):
		"""
		Promote a demangler to the highest-priority position.

			>>> list(Demangler)
			[<Demangler: MS>, <Demangler: GNU3>, <Demangler: LLVM>]
			>>> Demangler.promote(list(Demangler)[0])
			True
			>>> list(Demangler)
			[<Demangler: GNU3>, <Demangler: LLVM>, <Demangler: MS>]

		:param demangler: Demangler to promote
		:return: True if promotion succeeded; False if the demangler was invalid or not registered.
		"""
		if demangler is None or demangler.handle is None:
			return False
		return core.BNPromoteDemangler(demangler.handle)

	def __eq__(self, other):
		if not isinstance(other, Demangler):
			return False
		return self.name == other.name

	def __str__(self):
		return f'<Demangler: {self.name}>'

	def __repr__(self):
		return f'<Demangler: {self.name}>'

	def _is_mangled_string(self, ctxt, name):
		try:
			return self.is_mangled_string(core.pyNativeStr(name))
		except Exception:
			log_error_for_exception("Unhandled Python exception in Demangler._is_mangled_string")
			return False

	def _demangle(self, ctxt, name, config, result):
		try:
			api_config = DemanglerConfig._from_core_struct(config)

			demangle = self.demangle
			if self._uses_legacy_demangle_signature:
				arch = api_config.platform.arch if api_config.platform is not None else None
				demangle_result = demangle(arch, core.pyNativeStr(name), api_config.view)
			else:
				demangle_result = demangle(core.pyNativeStr(name), api_config)
			if demangle_result is None:
				return False
			type, var_name = demangle_result

			if not isinstance(var_name, types.QualifiedName):
				var_name = types.QualifiedName(var_name)

			Demangler._cached_name = core.BNDemanglerResult()
			Demangler._cached_name.name = var_name._to_core_struct()
			if type is not None:
				Demangler._cached_name.type = core.BNNewTypeReference(type.handle)
			else:
				Demangler._cached_name.type = None
			result[0] = Demangler._cached_name
			return True
		except Exception:
			log_error_for_exception("Unhandled Python exception in Demangler._demangle")
			return False

	def _free_result(self, ctxt, result):
		try:
			if result is not None and result.contents.type:
				core.BNFreeType(result.contents.type)
			Demangler._cached_name = None
		except Exception:
			log_error_for_exception("Unhandled Python exception in Demangler._free_result")

	def is_mangled_string(self, name: str) -> bool:
		"""
		Determine if a given name is mangled and this demangler can process it

		The most recently registered demangler that claims a name is a mangled string
		(returns true from this function), and then returns a value from
		:py:func:`demangle` will determine the result of a call to :py:func:`demangle_any`.
		Returning True from this does not require the demangler to succeed the call to
		:py:func:`demangle`, but simply implies that it may succeed.

		:param name: Raw mangled name string
		:return: True if the demangler thinks it can handle the name
		"""
		raise NotImplementedError()

	def demangle(
			self,
			name: str,
			config: DemanglerConfig
	) -> Optional[DemangleResult]:
		"""
		Demangle a raw name into a Type and QualifiedName.

		The result of this function is a DemangleResult with Type and QualifiedName
		fields for the demangled name's details. DemangleResult can be unpacked as
		(type, name).

		Any unresolved named types referenced by the resulting Type will be created as
		empty structures or void typedefs in the view, if the result is used on
		a data structure in the view. Given this, the call to :py:func:`demangle`
		should NOT cause any side-effects creating types in the view trying to resolve this
		and instead just return a type with unresolved named type references.

		The most recently registered demangler that claims a name is a mangled string
		(returns true from :py:func:`is_mangled_string`), and then returns a value from
		this function will determine the result of a call to :py:func:`demangle_any`.
		If this call returns None, the next most recently used demangler(s) will be tried instead.

		If the mangled name has no type information, but a name is still possible to extract,
		this function may return a successful DemangleResult(None, <name>), which will be accepted.

		Custom demanglers using the legacy ``demangle(arch, name, view)`` signature remain
		supported for one deprecation cycle.

		:param name: Raw mangled name
		:param config: Platform/view/options used while demangling
		:return: DemangleResult with type and name fields if successful, None if not.
		         Type may be None if only a demangled name can be recovered from the raw name.
		"""
		raise NotImplementedError()

	@staticmethod
	def demangle_any(name: str, config: Optional[DemanglerConfig] = None) -> Optional[DemangleResult]:
		"""
		Demangle a raw name using an optional prebuilt DemanglerConfig.
		"""
		return demangle_any(name, config)


class CoreDemangler(Demangler):

	def is_mangled_string(self, name: str) -> bool:
		return core.BNIsDemanglerMangledName(self.handle, name)

	def demangle(self, name: str, config: DemanglerConfig) -> Optional[DemangleResult]:
		result = core.BNDemanglerResult()
		api_config = config._to_core_struct()

		if not core.BNDemangleWithDemangler(self.handle, name, api_config, result):
			return None

		try:
			return DemangleResult._from_core_struct(result)
		finally:
			core.BNFreeDemanglerResult(result)
