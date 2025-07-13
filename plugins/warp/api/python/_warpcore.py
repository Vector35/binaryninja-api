import binaryninja
import ctypes, os

from typing import Optional
from . import warp_enums
# Load core module
import platform
core = None
core_platform = platform.system()

from binaryninja import Settings
if Settings().get_bool("corePlugins.warp"):
    from binaryninja._binaryninjacore import BNGetBundledPluginDirectory
    if core_platform == "Darwin":
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libwarp_ninja.dylib"))

    elif core_platform == "Linux":
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libwarp_ninja.so"))

    elif (core_platform == "Windows") or (core_platform.find("CYGWIN_NT") == 0):
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "warp_ninja.dll"))
    else:
        raise Exception("OS not supported")
else:
    from binaryninja._binaryninjacore import BNGetUserPluginDirectory
    if core_platform == "Darwin":
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libwarp_ninja.dylib"))

    elif core_platform == "Linux":
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libwarp_ninja.so"))

    elif (core_platform == "Windows") or (core_platform.find("CYGWIN_NT") == 0):
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "warp_ninja.dll"))
    else:
        raise Exception("OS not supported")

def cstr(var) -> Optional[ctypes.c_char_p]:
    if var is None:
        return None
    if isinstance(var, bytes):
        return var
    return var.encode("utf-8")

def pyNativeStr(arg):
    if isinstance(arg, str):
        return arg
    else:
        return arg.decode('utf8')

def free_string(value:ctypes.c_char_p) -> None:
    BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))

from binaryninja._binaryninjacore import BNFreeString
# Type definitions
from binaryninja._binaryninjacore import BNArchitecture, BNArchitectureHandle
from binaryninja._binaryninjacore import BNBasicBlock, BNBasicBlockHandle
from binaryninja._binaryninjacore import BNBinaryView, BNBinaryViewHandle
from binaryninja._binaryninjacore import BNFunction, BNFunctionHandle
from binaryninja._binaryninjacore import BNLowLevelILFunction, BNLowLevelILFunctionHandle
from binaryninja._binaryninjacore import BNPlatform, BNPlatformHandle
from binaryninja._binaryninjacore import BNSymbol, BNSymbolHandle
from binaryninja._binaryninjacore import BNType, BNTypeHandle
class BNWARPConstraint(ctypes.Structure):
	pass
BNWARPConstraintHandle = ctypes.POINTER(BNWARPConstraint)
class BNWARPContainer(ctypes.Structure):
	pass
BNWARPContainerHandle = ctypes.POINTER(BNWARPContainer)
class BNWARPFunction(ctypes.Structure):
	pass
BNWARPFunctionHandle = ctypes.POINTER(BNWARPFunction)
class BNWARPFunctionComment(ctypes.Structure):
	@property
	def text(self):
		return pyNativeStr(self._text)
	@text.setter
	def text(self, value):
		self._text = cstr(value)
BNWARPFunctionCommentHandle = ctypes.POINTER(BNWARPFunctionComment)
class BNWARPTarget(ctypes.Structure):
	pass
BNWARPTargetHandle = ctypes.POINTER(BNWARPTarget)
class BNWARPUUID(ctypes.Structure):
	pass
BNWARPUUIDHandle = ctypes.POINTER(BNWARPUUID)

# Structure definitions
BNWARPBasicBlockGUID = BNWARPUUID
BNWARPBasicBlockGUIDHandle = BNWARPUUIDHandle
BNWARPConstraintGUID = BNWARPUUID
BNWARPConstraintGUIDHandle = BNWARPUUIDHandle
BNWARPFunctionComment._fields_ = [
		("_text", ctypes.c_char_p),
		("offset", ctypes.c_longlong),
	]
BNWARPFunctionGUID = BNWARPUUID
BNWARPFunctionGUIDHandle = BNWARPUUIDHandle
BNWARPSource = BNWARPUUID
BNWARPSourceHandle = BNWARPUUIDHandle
BNWARPTypeGUID = BNWARPUUID
BNWARPTypeGUIDHandle = BNWARPUUIDHandle
BNWARPUUID._fields_ = [
		("uuid", ctypes.c_ubyte * 16),
	]
BNWARPConstraint._fields_ = [
		("guid", BNWARPConstraintGUID),
		("offset", ctypes.c_longlong),
	]

# Function definitions
# -------------------------------------------------------
# _BNWARPContainerAddFunctions

_BNWARPContainerAddFunctions = core.BNWARPContainerAddFunctions
_BNWARPContainerAddFunctions.restype = ctypes.c_bool
_BNWARPContainerAddFunctions.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPTarget),
		ctypes.POINTER(BNWARPSource),
		ctypes.POINTER(ctypes.POINTER(BNWARPFunction)),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPContainerAddFunctions(
		container: ctypes.POINTER(BNWARPContainer), 
		target: ctypes.POINTER(BNWARPTarget), 
		source: ctypes.POINTER(BNWARPSource), 
		functions: ctypes.POINTER(ctypes.POINTER(BNWARPFunction)), 
		count: int
		) -> bool:
	return _BNWARPContainerAddFunctions(container, target, source, functions, count)


# -------------------------------------------------------
# _BNWARPContainerAddSource

_BNWARPContainerAddSource = core.BNWARPContainerAddSource
_BNWARPContainerAddSource.restype = ctypes.c_bool
_BNWARPContainerAddSource.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.c_char_p,
		ctypes.POINTER(BNWARPSource),
	]


# noinspection PyPep8Naming
def BNWARPContainerAddSource(
		container: ctypes.POINTER(BNWARPContainer), 
		sourcePath: Optional[str], 
		result: ctypes.POINTER(BNWARPSource)
		) -> bool:
	return _BNWARPContainerAddSource(container, cstr(sourcePath), result)


# -------------------------------------------------------
# _BNWARPContainerAddTypes

_BNWARPContainerAddTypes = core.BNWARPContainerAddTypes
_BNWARPContainerAddTypes.restype = ctypes.c_bool
_BNWARPContainerAddTypes.argtypes = [
		ctypes.POINTER(BNBinaryView),
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPSource),
		ctypes.POINTER(ctypes.POINTER(BNType)),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPContainerAddTypes(
		view: ctypes.POINTER(BNBinaryView), 
		container: ctypes.POINTER(BNWARPContainer), 
		source: ctypes.POINTER(BNWARPSource), 
		types: ctypes.POINTER(ctypes.POINTER(BNType)), 
		count: int
		) -> bool:
	return _BNWARPContainerAddTypes(view, container, source, types, count)


# -------------------------------------------------------
# _BNWARPContainerCommitSource

_BNWARPContainerCommitSource = core.BNWARPContainerCommitSource
_BNWARPContainerCommitSource.restype = ctypes.c_bool
_BNWARPContainerCommitSource.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPSource),
	]


# noinspection PyPep8Naming
def BNWARPContainerCommitSource(
		container: ctypes.POINTER(BNWARPContainer), 
		source: ctypes.POINTER(BNWARPSource)
		) -> bool:
	return _BNWARPContainerCommitSource(container, source)


# -------------------------------------------------------
# _BNWARPContainerFetchFunctions

_BNWARPContainerFetchFunctions = core.BNWARPContainerFetchFunctions
_BNWARPContainerFetchFunctions.restype = None
_BNWARPContainerFetchFunctions.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPTarget),
		ctypes.POINTER(BNWARPTypeGUID),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPContainerFetchFunctions(
		container: ctypes.POINTER(BNWARPContainer), 
		target: ctypes.POINTER(BNWARPTarget), 
		guids: ctypes.POINTER(BNWARPTypeGUID), 
		count: int
		) -> None:
	return _BNWARPContainerFetchFunctions(container, target, guids, count)


# -------------------------------------------------------
# _BNWARPContainerGetFunctionsWithGUID

_BNWARPContainerGetFunctionsWithGUID = core.BNWARPContainerGetFunctionsWithGUID
_BNWARPContainerGetFunctionsWithGUID.restype = ctypes.POINTER(ctypes.POINTER(BNWARPFunction))
_BNWARPContainerGetFunctionsWithGUID.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPTarget),
		ctypes.POINTER(BNWARPSource),
		ctypes.POINTER(BNWARPFunctionGUID),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNWARPContainerGetFunctionsWithGUID(
		container: ctypes.POINTER(BNWARPContainer), 
		target: ctypes.POINTER(BNWARPTarget), 
		source: ctypes.POINTER(BNWARPSource), 
		guid: ctypes.POINTER(BNWARPFunctionGUID), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(ctypes.POINTER(BNWARPFunction))]:
	result = _BNWARPContainerGetFunctionsWithGUID(container, target, source, guid, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPContainerGetName

_BNWARPContainerGetName = core.BNWARPContainerGetName
_BNWARPContainerGetName.restype = ctypes.POINTER(ctypes.c_byte)
_BNWARPContainerGetName.argtypes = [
		ctypes.POINTER(BNWARPContainer),
	]


# noinspection PyPep8Naming
def BNWARPContainerGetName(
		container: ctypes.POINTER(BNWARPContainer)
		) -> Optional[Optional[str]]:
	result = _BNWARPContainerGetName(container)
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNWARPContainerGetSourcePath

_BNWARPContainerGetSourcePath = core.BNWARPContainerGetSourcePath
_BNWARPContainerGetSourcePath.restype = ctypes.POINTER(ctypes.c_byte)
_BNWARPContainerGetSourcePath.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPSource),
	]


# noinspection PyPep8Naming
def BNWARPContainerGetSourcePath(
		container: ctypes.POINTER(BNWARPContainer), 
		source: ctypes.POINTER(BNWARPSource)
		) -> Optional[Optional[str]]:
	result = _BNWARPContainerGetSourcePath(container, source)
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNWARPContainerGetSources

_BNWARPContainerGetSources = core.BNWARPContainerGetSources
_BNWARPContainerGetSources.restype = ctypes.POINTER(BNWARPSource)
_BNWARPContainerGetSources.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNWARPContainerGetSources(
		container: ctypes.POINTER(BNWARPContainer), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNWARPSource)]:
	result = _BNWARPContainerGetSources(container, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPContainerGetSourcesWithFunctionGUID

_BNWARPContainerGetSourcesWithFunctionGUID = core.BNWARPContainerGetSourcesWithFunctionGUID
_BNWARPContainerGetSourcesWithFunctionGUID.restype = ctypes.POINTER(BNWARPSource)
_BNWARPContainerGetSourcesWithFunctionGUID.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPTarget),
		ctypes.POINTER(BNWARPFunctionGUID),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNWARPContainerGetSourcesWithFunctionGUID(
		container: ctypes.POINTER(BNWARPContainer), 
		target: ctypes.POINTER(BNWARPTarget), 
		guid: ctypes.POINTER(BNWARPFunctionGUID), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNWARPSource)]:
	result = _BNWARPContainerGetSourcesWithFunctionGUID(container, target, guid, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPContainerGetSourcesWithTypeGUID

_BNWARPContainerGetSourcesWithTypeGUID = core.BNWARPContainerGetSourcesWithTypeGUID
_BNWARPContainerGetSourcesWithTypeGUID.restype = ctypes.POINTER(BNWARPSource)
_BNWARPContainerGetSourcesWithTypeGUID.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPTypeGUID),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNWARPContainerGetSourcesWithTypeGUID(
		container: ctypes.POINTER(BNWARPContainer), 
		guid: ctypes.POINTER(BNWARPTypeGUID), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNWARPSource)]:
	result = _BNWARPContainerGetSourcesWithTypeGUID(container, guid, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPContainerGetTypeGUIDsWithName

_BNWARPContainerGetTypeGUIDsWithName = core.BNWARPContainerGetTypeGUIDsWithName
_BNWARPContainerGetTypeGUIDsWithName.restype = ctypes.POINTER(BNWARPTypeGUID)
_BNWARPContainerGetTypeGUIDsWithName.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPSource),
		ctypes.c_char_p,
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNWARPContainerGetTypeGUIDsWithName(
		container: ctypes.POINTER(BNWARPContainer), 
		source: ctypes.POINTER(BNWARPSource), 
		name: Optional[str], 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNWARPTypeGUID)]:
	result = _BNWARPContainerGetTypeGUIDsWithName(container, source, cstr(name), count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPContainerGetTypeWithGUID

_BNWARPContainerGetTypeWithGUID = core.BNWARPContainerGetTypeWithGUID
_BNWARPContainerGetTypeWithGUID.restype = ctypes.POINTER(BNType)
_BNWARPContainerGetTypeWithGUID.argtypes = [
		ctypes.POINTER(BNArchitecture),
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPSource),
		ctypes.POINTER(BNWARPTypeGUID),
	]


# noinspection PyPep8Naming
def BNWARPContainerGetTypeWithGUID(
		arch: ctypes.POINTER(BNArchitecture), 
		container: ctypes.POINTER(BNWARPContainer), 
		source: ctypes.POINTER(BNWARPSource), 
		guid: ctypes.POINTER(BNWARPTypeGUID)
		) -> Optional[ctypes.POINTER(BNType)]:
	result = _BNWARPContainerGetTypeWithGUID(arch, container, source, guid)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPContainerIsSourceUncommitted

_BNWARPContainerIsSourceUncommitted = core.BNWARPContainerIsSourceUncommitted
_BNWARPContainerIsSourceUncommitted.restype = ctypes.c_bool
_BNWARPContainerIsSourceUncommitted.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPSource),
	]


# noinspection PyPep8Naming
def BNWARPContainerIsSourceUncommitted(
		container: ctypes.POINTER(BNWARPContainer), 
		source: ctypes.POINTER(BNWARPSource)
		) -> bool:
	return _BNWARPContainerIsSourceUncommitted(container, source)


# -------------------------------------------------------
# _BNWARPContainerIsSourceWritable

_BNWARPContainerIsSourceWritable = core.BNWARPContainerIsSourceWritable
_BNWARPContainerIsSourceWritable.restype = ctypes.c_bool
_BNWARPContainerIsSourceWritable.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPSource),
	]


# noinspection PyPep8Naming
def BNWARPContainerIsSourceWritable(
		container: ctypes.POINTER(BNWARPContainer), 
		source: ctypes.POINTER(BNWARPSource)
		) -> bool:
	return _BNWARPContainerIsSourceWritable(container, source)


# -------------------------------------------------------
# _BNWARPContainerRemoveFunctions

_BNWARPContainerRemoveFunctions = core.BNWARPContainerRemoveFunctions
_BNWARPContainerRemoveFunctions.restype = ctypes.c_bool
_BNWARPContainerRemoveFunctions.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPTarget),
		ctypes.POINTER(BNWARPSource),
		ctypes.POINTER(ctypes.POINTER(BNWARPFunction)),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPContainerRemoveFunctions(
		container: ctypes.POINTER(BNWARPContainer), 
		target: ctypes.POINTER(BNWARPTarget), 
		source: ctypes.POINTER(BNWARPSource), 
		functions: ctypes.POINTER(ctypes.POINTER(BNWARPFunction)), 
		count: int
		) -> bool:
	return _BNWARPContainerRemoveFunctions(container, target, source, functions, count)


# -------------------------------------------------------
# _BNWARPContainerRemoveTypes

_BNWARPContainerRemoveTypes = core.BNWARPContainerRemoveTypes
_BNWARPContainerRemoveTypes.restype = ctypes.c_bool
_BNWARPContainerRemoveTypes.argtypes = [
		ctypes.POINTER(BNWARPContainer),
		ctypes.POINTER(BNWARPSource),
		ctypes.POINTER(BNWARPTypeGUID),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPContainerRemoveTypes(
		container: ctypes.POINTER(BNWARPContainer), 
		source: ctypes.POINTER(BNWARPSource), 
		types: ctypes.POINTER(BNWARPTypeGUID), 
		count: int
		) -> bool:
	return _BNWARPContainerRemoveTypes(container, source, types, count)


# -------------------------------------------------------
# _BNWARPFreeConstraintList

_BNWARPFreeConstraintList = core.BNWARPFreeConstraintList
_BNWARPFreeConstraintList.restype = None
_BNWARPFreeConstraintList.argtypes = [
		ctypes.POINTER(BNWARPConstraint),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPFreeConstraintList(
		constraints: ctypes.POINTER(BNWARPConstraint), 
		count: int
		) -> None:
	return _BNWARPFreeConstraintList(constraints, count)


# -------------------------------------------------------
# _BNWARPFreeContainerList

_BNWARPFreeContainerList = core.BNWARPFreeContainerList
_BNWARPFreeContainerList.restype = None
_BNWARPFreeContainerList.argtypes = [
		ctypes.POINTER(ctypes.POINTER(BNWARPContainer)),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPFreeContainerList(
		containers: ctypes.POINTER(ctypes.POINTER(BNWARPContainer)), 
		count: int
		) -> None:
	return _BNWARPFreeContainerList(containers, count)


# -------------------------------------------------------
# _BNWARPFreeContainerReference

_BNWARPFreeContainerReference = core.BNWARPFreeContainerReference
_BNWARPFreeContainerReference.restype = None
_BNWARPFreeContainerReference.argtypes = [
		ctypes.POINTER(BNWARPContainer),
	]


# noinspection PyPep8Naming
def BNWARPFreeContainerReference(
		container: ctypes.POINTER(BNWARPContainer)
		) -> None:
	return _BNWARPFreeContainerReference(container)


# -------------------------------------------------------
# _BNWARPFreeFunctionCommentList

_BNWARPFreeFunctionCommentList = core.BNWARPFreeFunctionCommentList
_BNWARPFreeFunctionCommentList.restype = None
_BNWARPFreeFunctionCommentList.argtypes = [
		ctypes.POINTER(BNWARPFunctionComment),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPFreeFunctionCommentList(
		comments: ctypes.POINTER(BNWARPFunctionComment), 
		count: int
		) -> None:
	return _BNWARPFreeFunctionCommentList(comments, count)


# -------------------------------------------------------
# _BNWARPFreeFunctionList

_BNWARPFreeFunctionList = core.BNWARPFreeFunctionList
_BNWARPFreeFunctionList.restype = None
_BNWARPFreeFunctionList.argtypes = [
		ctypes.POINTER(ctypes.POINTER(BNWARPFunction)),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPFreeFunctionList(
		functions: ctypes.POINTER(ctypes.POINTER(BNWARPFunction)), 
		count: int
		) -> None:
	return _BNWARPFreeFunctionList(functions, count)


# -------------------------------------------------------
# _BNWARPFreeFunctionReference

_BNWARPFreeFunctionReference = core.BNWARPFreeFunctionReference
_BNWARPFreeFunctionReference.restype = None
_BNWARPFreeFunctionReference.argtypes = [
		ctypes.POINTER(BNWARPFunction),
	]


# noinspection PyPep8Naming
def BNWARPFreeFunctionReference(
		function: ctypes.POINTER(BNWARPFunction)
		) -> None:
	return _BNWARPFreeFunctionReference(function)


# -------------------------------------------------------
# _BNWARPFreeTargetReference

_BNWARPFreeTargetReference = core.BNWARPFreeTargetReference
_BNWARPFreeTargetReference.restype = None
_BNWARPFreeTargetReference.argtypes = [
		ctypes.POINTER(BNWARPTarget),
	]


# noinspection PyPep8Naming
def BNWARPFreeTargetReference(
		target: ctypes.POINTER(BNWARPTarget)
		) -> None:
	return _BNWARPFreeTargetReference(target)


# -------------------------------------------------------
# _BNWARPFreeUUIDList

_BNWARPFreeUUIDList = core.BNWARPFreeUUIDList
_BNWARPFreeUUIDList.restype = None
_BNWARPFreeUUIDList.argtypes = [
		ctypes.POINTER(BNWARPUUID),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPFreeUUIDList(
		uuids: ctypes.POINTER(BNWARPUUID), 
		count: int
		) -> None:
	return _BNWARPFreeUUIDList(uuids, count)


# -------------------------------------------------------
# _BNWARPFunctionApply

_BNWARPFunctionApply = core.BNWARPFunctionApply
_BNWARPFunctionApply.restype = None
_BNWARPFunctionApply.argtypes = [
		ctypes.POINTER(BNWARPFunction),
		ctypes.POINTER(BNFunction),
	]


# noinspection PyPep8Naming
def BNWARPFunctionApply(
		function: ctypes.POINTER(BNWARPFunction), 
		analysisFunction: ctypes.POINTER(BNFunction)
		) -> None:
	return _BNWARPFunctionApply(function, analysisFunction)


# -------------------------------------------------------
# _BNWARPFunctionGetComments

_BNWARPFunctionGetComments = core.BNWARPFunctionGetComments
_BNWARPFunctionGetComments.restype = ctypes.POINTER(BNWARPFunctionComment)
_BNWARPFunctionGetComments.argtypes = [
		ctypes.POINTER(BNWARPFunction),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNWARPFunctionGetComments(
		function: ctypes.POINTER(BNWARPFunction), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNWARPFunctionComment)]:
	result = _BNWARPFunctionGetComments(function, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPFunctionGetConstraints

_BNWARPFunctionGetConstraints = core.BNWARPFunctionGetConstraints
_BNWARPFunctionGetConstraints.restype = ctypes.POINTER(BNWARPConstraint)
_BNWARPFunctionGetConstraints.argtypes = [
		ctypes.POINTER(BNWARPFunction),
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNWARPFunctionGetConstraints(
		function: ctypes.POINTER(BNWARPFunction), 
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(BNWARPConstraint)]:
	result = _BNWARPFunctionGetConstraints(function, count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPFunctionGetGUID

_BNWARPFunctionGetGUID = core.BNWARPFunctionGetGUID
_BNWARPFunctionGetGUID.restype = BNWARPFunctionGUID
_BNWARPFunctionGetGUID.argtypes = [
		ctypes.POINTER(BNWARPFunction),
	]


# noinspection PyPep8Naming
def BNWARPFunctionGetGUID(
		function: ctypes.POINTER(BNWARPFunction)
		) -> BNWARPFunctionGUID:
	return _BNWARPFunctionGetGUID(function)


# -------------------------------------------------------
# _BNWARPFunctionGetSymbol

_BNWARPFunctionGetSymbol = core.BNWARPFunctionGetSymbol
_BNWARPFunctionGetSymbol.restype = ctypes.POINTER(BNSymbol)
_BNWARPFunctionGetSymbol.argtypes = [
		ctypes.POINTER(BNWARPFunction),
		ctypes.POINTER(BNFunction),
	]


# noinspection PyPep8Naming
def BNWARPFunctionGetSymbol(
		function: ctypes.POINTER(BNWARPFunction), 
		analysisFunction: ctypes.POINTER(BNFunction)
		) -> Optional[ctypes.POINTER(BNSymbol)]:
	result = _BNWARPFunctionGetSymbol(function, analysisFunction)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPFunctionGetSymbolName

_BNWARPFunctionGetSymbolName = core.BNWARPFunctionGetSymbolName
_BNWARPFunctionGetSymbolName.restype = ctypes.POINTER(ctypes.c_byte)
_BNWARPFunctionGetSymbolName.argtypes = [
		ctypes.POINTER(BNWARPFunction),
	]


# noinspection PyPep8Naming
def BNWARPFunctionGetSymbolName(
		function: ctypes.POINTER(BNWARPFunction)
		) -> Optional[Optional[str]]:
	result = _BNWARPFunctionGetSymbolName(function)
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string


# -------------------------------------------------------
# _BNWARPFunctionGetType

_BNWARPFunctionGetType = core.BNWARPFunctionGetType
_BNWARPFunctionGetType.restype = ctypes.POINTER(BNType)
_BNWARPFunctionGetType.argtypes = [
		ctypes.POINTER(BNWARPFunction),
		ctypes.POINTER(BNFunction),
	]


# noinspection PyPep8Naming
def BNWARPFunctionGetType(
		function: ctypes.POINTER(BNWARPFunction), 
		analysisFunction: ctypes.POINTER(BNFunction)
		) -> Optional[ctypes.POINTER(BNType)]:
	result = _BNWARPFunctionGetType(function, analysisFunction)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPFunctionsEqual

_BNWARPFunctionsEqual = core.BNWARPFunctionsEqual
_BNWARPFunctionsEqual.restype = ctypes.c_bool
_BNWARPFunctionsEqual.argtypes = [
		ctypes.POINTER(BNWARPFunction),
		ctypes.POINTER(BNWARPFunction),
	]


# noinspection PyPep8Naming
def BNWARPFunctionsEqual(
		functionA: ctypes.POINTER(BNWARPFunction), 
		functionB: ctypes.POINTER(BNWARPFunction)
		) -> bool:
	return _BNWARPFunctionsEqual(functionA, functionB)


# -------------------------------------------------------
# _BNWARPGetAnalysisFunctionGUID

_BNWARPGetAnalysisFunctionGUID = core.BNWARPGetAnalysisFunctionGUID
_BNWARPGetAnalysisFunctionGUID.restype = ctypes.c_bool
_BNWARPGetAnalysisFunctionGUID.argtypes = [
		ctypes.POINTER(BNFunction),
		ctypes.POINTER(BNWARPFunctionGUID),
	]


# noinspection PyPep8Naming
def BNWARPGetAnalysisFunctionGUID(
		analysisFunction: ctypes.POINTER(BNFunction), 
		result: ctypes.POINTER(BNWARPFunctionGUID)
		) -> bool:
	return _BNWARPGetAnalysisFunctionGUID(analysisFunction, result)


# -------------------------------------------------------
# _BNWARPGetBasicBlockGUID

_BNWARPGetBasicBlockGUID = core.BNWARPGetBasicBlockGUID
_BNWARPGetBasicBlockGUID.restype = ctypes.c_bool
_BNWARPGetBasicBlockGUID.argtypes = [
		ctypes.POINTER(BNBasicBlock),
		ctypes.POINTER(BNWARPBasicBlockGUID),
	]


# noinspection PyPep8Naming
def BNWARPGetBasicBlockGUID(
		basicBlock: ctypes.POINTER(BNBasicBlock), 
		result: ctypes.POINTER(BNWARPBasicBlockGUID)
		) -> bool:
	return _BNWARPGetBasicBlockGUID(basicBlock, result)


# -------------------------------------------------------
# _BNWARPGetContainers

_BNWARPGetContainers = core.BNWARPGetContainers
_BNWARPGetContainers.restype = ctypes.POINTER(ctypes.POINTER(BNWARPContainer))
_BNWARPGetContainers.argtypes = [
		ctypes.POINTER(ctypes.c_ulonglong),
	]


# noinspection PyPep8Naming
def BNWARPGetContainers(
		count: ctypes.POINTER(ctypes.c_ulonglong)
		) -> Optional[ctypes.POINTER(ctypes.POINTER(BNWARPContainer))]:
	result = _BNWARPGetContainers(count)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPGetFunction

_BNWARPGetFunction = core.BNWARPGetFunction
_BNWARPGetFunction.restype = ctypes.POINTER(BNWARPFunction)
_BNWARPGetFunction.argtypes = [
		ctypes.POINTER(BNFunction),
	]


# noinspection PyPep8Naming
def BNWARPGetFunction(
		analysisFunction: ctypes.POINTER(BNFunction)
		) -> Optional[ctypes.POINTER(BNWARPFunction)]:
	result = _BNWARPGetFunction(analysisFunction)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPGetMatchedFunction

_BNWARPGetMatchedFunction = core.BNWARPGetMatchedFunction
_BNWARPGetMatchedFunction.restype = ctypes.POINTER(BNWARPFunction)
_BNWARPGetMatchedFunction.argtypes = [
		ctypes.POINTER(BNFunction),
	]


# noinspection PyPep8Naming
def BNWARPGetMatchedFunction(
		analysisFunction: ctypes.POINTER(BNFunction)
		) -> Optional[ctypes.POINTER(BNWARPFunction)]:
	result = _BNWARPGetMatchedFunction(analysisFunction)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPGetTarget

_BNWARPGetTarget = core.BNWARPGetTarget
_BNWARPGetTarget.restype = ctypes.POINTER(BNWARPTarget)
_BNWARPGetTarget.argtypes = [
		ctypes.POINTER(BNPlatform),
	]


# noinspection PyPep8Naming
def BNWARPGetTarget(
		platform: ctypes.POINTER(BNPlatform)
		) -> Optional[ctypes.POINTER(BNWARPTarget)]:
	result = _BNWARPGetTarget(platform)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPIsLiftedInstructionBlacklisted

_BNWARPIsLiftedInstructionBlacklisted = core.BNWARPIsLiftedInstructionBlacklisted
_BNWARPIsLiftedInstructionBlacklisted.restype = ctypes.c_bool
_BNWARPIsLiftedInstructionBlacklisted.argtypes = [
		ctypes.POINTER(BNLowLevelILFunction),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPIsLiftedInstructionBlacklisted(
		liftedFunction: ctypes.POINTER(BNLowLevelILFunction), 
		idx: int
		) -> bool:
	return _BNWARPIsLiftedInstructionBlacklisted(liftedFunction, idx)


# -------------------------------------------------------
# _BNWARPIsLiftedInstructionVariant

_BNWARPIsLiftedInstructionVariant = core.BNWARPIsLiftedInstructionVariant
_BNWARPIsLiftedInstructionVariant.restype = ctypes.c_bool
_BNWARPIsLiftedInstructionVariant.argtypes = [
		ctypes.POINTER(BNLowLevelILFunction),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPIsLiftedInstructionVariant(
		liftedFunction: ctypes.POINTER(BNLowLevelILFunction), 
		idx: int
		) -> bool:
	return _BNWARPIsLiftedInstructionVariant(liftedFunction, idx)


# -------------------------------------------------------
# _BNWARPIsLowLevelInstructionComputedVariant

_BNWARPIsLowLevelInstructionComputedVariant = core.BNWARPIsLowLevelInstructionComputedVariant
_BNWARPIsLowLevelInstructionComputedVariant.restype = ctypes.c_bool
_BNWARPIsLowLevelInstructionComputedVariant.argtypes = [
		ctypes.POINTER(BNLowLevelILFunction),
		ctypes.c_ulonglong,
	]


# noinspection PyPep8Naming
def BNWARPIsLowLevelInstructionComputedVariant(
		llilFunction: ctypes.POINTER(BNLowLevelILFunction), 
		idx: int
		) -> bool:
	return _BNWARPIsLowLevelInstructionComputedVariant(llilFunction, idx)


# -------------------------------------------------------
# _BNWARPNewContainerReference

_BNWARPNewContainerReference = core.BNWARPNewContainerReference
_BNWARPNewContainerReference.restype = ctypes.POINTER(BNWARPContainer)
_BNWARPNewContainerReference.argtypes = [
		ctypes.POINTER(BNWARPContainer),
	]


# noinspection PyPep8Naming
def BNWARPNewContainerReference(
		container: ctypes.POINTER(BNWARPContainer)
		) -> Optional[ctypes.POINTER(BNWARPContainer)]:
	result = _BNWARPNewContainerReference(container)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPNewFunctionReference

_BNWARPNewFunctionReference = core.BNWARPNewFunctionReference
_BNWARPNewFunctionReference.restype = ctypes.POINTER(BNWARPFunction)
_BNWARPNewFunctionReference.argtypes = [
		ctypes.POINTER(BNWARPFunction),
	]


# noinspection PyPep8Naming
def BNWARPNewFunctionReference(
		function: ctypes.POINTER(BNWARPFunction)
		) -> Optional[ctypes.POINTER(BNWARPFunction)]:
	result = _BNWARPNewFunctionReference(function)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPNewTargetReference

_BNWARPNewTargetReference = core.BNWARPNewTargetReference
_BNWARPNewTargetReference.restype = ctypes.POINTER(BNWARPTarget)
_BNWARPNewTargetReference.argtypes = [
		ctypes.POINTER(BNWARPTarget),
	]


# noinspection PyPep8Naming
def BNWARPNewTargetReference(
		target: ctypes.POINTER(BNWARPTarget)
		) -> Optional[ctypes.POINTER(BNWARPTarget)]:
	result = _BNWARPNewTargetReference(target)
	if not result:
		return None
	return result


# -------------------------------------------------------
# _BNWARPRunMatcher

_BNWARPRunMatcher = core.BNWARPRunMatcher
_BNWARPRunMatcher.restype = None
_BNWARPRunMatcher.argtypes = [
		ctypes.POINTER(BNBinaryView),
	]


# noinspection PyPep8Naming
def BNWARPRunMatcher(
		view: ctypes.POINTER(BNBinaryView)
		) -> None:
	return _BNWARPRunMatcher(view)


# -------------------------------------------------------
# _BNWARPUUIDEqual

_BNWARPUUIDEqual = core.BNWARPUUIDEqual
_BNWARPUUIDEqual.restype = ctypes.c_bool
_BNWARPUUIDEqual.argtypes = [
		ctypes.POINTER(BNWARPUUID),
		ctypes.POINTER(BNWARPUUID),
	]


# noinspection PyPep8Naming
def BNWARPUUIDEqual(
		a: ctypes.POINTER(BNWARPUUID), 
		b: ctypes.POINTER(BNWARPUUID)
		) -> bool:
	return _BNWARPUUIDEqual(a, b)


# -------------------------------------------------------
# _BNWARPUUIDGetString

_BNWARPUUIDGetString = core.BNWARPUUIDGetString
_BNWARPUUIDGetString.restype = ctypes.POINTER(ctypes.c_byte)
_BNWARPUUIDGetString.argtypes = [
		ctypes.POINTER(BNWARPUUID),
	]


# noinspection PyPep8Naming
def BNWARPUUIDGetString(
		uuid: ctypes.POINTER(BNWARPUUID)
		) -> Optional[Optional[str]]:
	result = _BNWARPUUIDGetString(uuid)
	if not result:
		return None
	string = str(pyNativeStr(ctypes.cast(result, ctypes.c_char_p).value))
	BNFreeString(result)
	return string



# Helper functions
def handle_of_type(value, handle_type):
	if isinstance(value, ctypes.POINTER(handle_type)) or isinstance(value, ctypes.c_void_p):
		return ctypes.cast(value, ctypes.POINTER(handle_type))
	raise ValueError('expected pointer to %s' % str(handle_type))
