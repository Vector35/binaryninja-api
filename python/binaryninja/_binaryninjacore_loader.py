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
import os
import platform
from pathlib import Path
from typing import Iterable


def _core_names() -> tuple[str, ...]:
    core_platform = platform.system()
    if core_platform == "Darwin":
        return ("libbinaryninjacore.dylib",)
    if core_platform == "Linux":
        return ("libbinaryninjacore.so.1", "libbinaryninjacore.so")
    if core_platform == "Windows" or core_platform.startswith("CYGWIN_NT"):
        return ("binaryninjacore.dll",)
    raise ImportError(f"Binary Ninja does not support {core_platform}")


def _core_directories() -> Iterable[Path]:
    core_platform = platform.system()
    install_dir = os.environ.get("BN_INSTALL_DIR")
    if install_dir:
        root = Path(install_dir).expanduser()
        yield root
        if core_platform == "Darwin":
            yield root / "Contents" / "MacOS"

    package_dir = Path(__file__).resolve().parent
    if core_platform == "Darwin":
        # The package bundled with Binary Ninja lives in Contents/Resources/python.
        yield package_dir / ".." / ".." / ".." / "MacOS"
        yield Path("/Applications/Binary Ninja.app/Contents/MacOS")
    elif core_platform in ("Linux", "Windows") or core_platform.startswith("CYGWIN_NT"):
        # Linux and Windows place Resources/python two levels below the core.
        yield package_dir / ".." / ".."
        if core_platform == "Windows":
            for environment_variable in ("ProgramFiles", "LOCALAPPDATA"):
                base = os.environ.get(environment_variable)
                if base:
                    yield Path(base) / "Vector35" / "BinaryNinja"


def load_core() -> tuple[ctypes.CDLL, str]:
    """Load Binary Ninja Core and return it with its containing directory."""
    core_path = os.environ.get("BINARYNINJACORE_PATH")
    if core_path:
        candidate = Path(core_path).expanduser().resolve()
        if not candidate.is_file():
            raise ImportError(f"BINARYNINJACORE_PATH does not name a file: {candidate}")
        try:
            return ctypes.CDLL(str(candidate)), str(candidate.parent)
        except OSError as error:
            raise ImportError(f"Unable to load Binary Ninja Core from {candidate}: {error}") from error

    attempted = []
    errors = []
    seen = set()
    for directory in _core_directories():
        for core_name in _core_names():
            candidate = (directory / core_name).resolve()
            if candidate in seen:
                continue
            seen.add(candidate)
            attempted.append(candidate)
            if not candidate.is_file():
                continue
            try:
                return ctypes.CDLL(str(candidate)), str(candidate.parent)
            except OSError as error:
                errors.append(f"{candidate}: {error}")

    details = "\n".join(f"  - {path}" for path in attempted)
    if errors:
        details += "\nLoad errors:\n" + "\n".join(f"  - {error}" for error in errors)
    raise ImportError(
        "Unable to locate Binary Ninja Core. Set BN_INSTALL_DIR to the Binary Ninja installation "
        "directory or BINARYNINJACORE_PATH to the native core library.\nChecked:\n" + details
    )


def check_core_abi(core: ctypes.CDLL, expected_abi: int) -> None:
    """Verify that generated bindings fall within the core's supported ABI range."""
    try:
        get_current_abi = core.BNGetCurrentCoreABIVersion
        get_minimum_abi = core.BNGetMinimumCoreABIVersion
    except AttributeError as error:
        raise ImportError("Binary Ninja Core does not expose ABI compatibility information") from error

    get_current_abi.restype = ctypes.c_uint32
    get_minimum_abi.restype = ctypes.c_uint32
    current_abi = get_current_abi()
    minimum_abi = get_minimum_abi()
    if not minimum_abi <= expected_abi <= current_abi:
        raise ImportError(
            f"Binary Ninja API/core ABI mismatch: bindings require ABI {expected_abi}, "
            f"but the loaded core supports {minimum_abi} through {current_abi}"
        )
