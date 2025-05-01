import binaryninja
import ctypes, os

from typing import Optional
from . import sharedcache_enums
# Load core module
import platform
core = None
core_platform = platform.system()

from binaryninja import Settings
if Settings().get_bool("corePlugins.view.sharedCache"):
    from binaryninja._binaryninjacore import BNGetBundledPluginDirectory
    if core_platform == "Darwin":
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libsharedcache.dylib"))

    elif core_platform == "Linux":
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libsharedcache.so"))

    elif (core_platform == "Windows") or (core_platform.find("CYGWIN_NT") == 0):
        _base_path = BNGetBundledPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "sharedcache.dll"))
    else:
        raise Exception("OS not supported")
else:
    from binaryninja._binaryninjacore import BNGetUserPluginDirectory
    if core_platform == "Darwin":
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libsharedcache.dylib"))

    elif core_platform == "Linux":
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "libsharedcache.so"))

    elif (core_platform == "Windows") or (core_platform.find("CYGWIN_NT") == 0):
        _base_path = BNGetUserPluginDirectory()
        core = ctypes.CDLL(os.path.join(_base_path, "sharedcache.dll"))
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

