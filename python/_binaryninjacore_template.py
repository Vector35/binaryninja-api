import ctypes, os

from typing import Optional, AnyStr
from .enums import *
# Load core module
import platform
core = None
_base_path = None
core_platform = platform.system()
if core_platform == "Darwin":
	_base_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "MacOS")
	core = ctypes.CDLL(os.path.join(_base_path, "libbinaryninjacore.dylib"))

elif core_platform == "Linux":
	_base_path = os.path.join(os.path.dirname(__file__), "..", "..")
	core = ctypes.CDLL(os.path.join(_base_path, "libbinaryninjacore.so.1"))

elif (core_platform == "Windows") or (core_platform.find("CYGWIN_NT") == 0):
	_base_path = os.path.join(os.path.dirname(__file__), "..", "..")
	core = ctypes.CDLL(os.path.join(_base_path, "binaryninjacore.dll"))
else:
	raise Exception("OS not supported")


def cstr(var: Optional[AnyStr]) -> Optional[bytes]:
	if var is None:
		return None
	if isinstance(var, bytes):
		return var
	return var.encode("utf-8")


def pyNativeStr(arg: Optional[AnyStr]) -> Optional[str]:
	if arg is None or isinstance(arg, str):
		return arg
	else:
		try:
			return arg.decode('utf8')
		except UnicodeDecodeError:
			return arg.decode('charmap')


def free_string(value:ctypes.c_char_p) -> None:
	BNFreeString(ctypes.cast(value, ctypes.POINTER(ctypes.c_byte)))


max_confidence = 255

# @@GENERATED_BINDINGS@@

# Set path for core plugins
BNSetBundledPluginDirectory(os.path.join(_base_path, "plugins"))
