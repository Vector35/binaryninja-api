import importlib.util
from pathlib import Path
import platform

import pytest


LOADER_PATH = Path(__file__).parent.parent / "binaryninja" / "_binaryninjacore_loader.py"


@pytest.fixture
def loader():
    spec = importlib.util.spec_from_file_location("binaryninjacore_loader_under_test", LOADER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("system", "names"),
    [
        ("Darwin", ("libbinaryninjacore.dylib",)),
        ("Linux", ("libbinaryninjacore.so.1", "libbinaryninjacore.so")),
        ("Windows", ("binaryninjacore.dll",)),
        ("CYGWIN_NT-10.0", ("binaryninjacore.dll",)),
    ],
)
def test_core_names(loader, monkeypatch, system, names):
    monkeypatch.setattr(platform, "system", lambda: system)
    assert loader._core_names() == names


def test_explicit_core_path_takes_precedence(loader, monkeypatch, tmp_path):
    core_path = tmp_path / "custom-core"
    core_path.touch()
    loaded = object()
    monkeypatch.setenv("BINARYNINJACORE_PATH", str(core_path))
    monkeypatch.setenv("BN_INSTALL_DIR", str(tmp_path / "ignored"))
    monkeypatch.setattr(loader.ctypes, "CDLL", lambda path: loaded)

    core, base_path = loader.load_core()

    assert core is loaded
    assert base_path == str(tmp_path)


def test_macos_application_layout(loader, monkeypatch, tmp_path):
    core_path = tmp_path / "Binary Ninja.app" / "Contents" / "MacOS" / "libbinaryninjacore.dylib"
    core_path.parent.mkdir(parents=True)
    core_path.touch()
    monkeypatch.delenv("BINARYNINJACORE_PATH", raising=False)
    monkeypatch.setenv("BN_INSTALL_DIR", str(tmp_path / "Binary Ninja.app"))
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(loader.ctypes, "CDLL", lambda path: path)

    core, base_path = loader.load_core()

    assert core == str(core_path)
    assert base_path == str(core_path.parent)


def test_missing_core_reports_attempted_paths(loader, monkeypatch, tmp_path):
    monkeypatch.delenv("BINARYNINJACORE_PATH", raising=False)
    monkeypatch.setenv("BN_INSTALL_DIR", str(tmp_path))
    monkeypatch.setattr(platform, "system", lambda: "Linux")

    with pytest.raises(ImportError, match="BN_INSTALL_DIR") as error:
        loader.load_core()

    assert "libbinaryninjacore.so.1" in str(error.value)


def test_load_error_is_preserved(loader, monkeypatch, tmp_path):
    core_path = tmp_path / "libbinaryninjacore.so.1"
    core_path.touch()
    monkeypatch.delenv("BINARYNINJACORE_PATH", raising=False)
    monkeypatch.setenv("BN_INSTALL_DIR", str(tmp_path))
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(loader.ctypes, "CDLL", lambda path: (_ for _ in ()).throw(OSError("wrong architecture")))

    with pytest.raises(ImportError, match="wrong architecture"):
        loader.load_core()


def test_unsupported_platform(loader, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Plan9")
    with pytest.raises(ImportError, match="does not support Plan9"):
        loader._core_names()


class _CoreFunction:
    def __init__(self, value):
        self.value = value
        self.restype = None

    def __call__(self):
        return self.value


class _CoreWithAbi:
    def __init__(self, minimum, current):
        self.BNGetMinimumCoreABIVersion = _CoreFunction(minimum)
        self.BNGetCurrentCoreABIVersion = _CoreFunction(current)


def test_compatible_core_abi(loader):
    core = _CoreWithAbi(184, 186)
    loader.check_core_abi(core, 185)
    assert core.BNGetMinimumCoreABIVersion.restype is loader.ctypes.c_uint32
    assert core.BNGetCurrentCoreABIVersion.restype is loader.ctypes.c_uint32


@pytest.mark.parametrize("expected", [183, 187])
def test_incompatible_core_abi(loader, expected):
    with pytest.raises(ImportError, match="ABI mismatch"):
        loader.check_core_abi(_CoreWithAbi(184, 186), expected)


def test_core_without_abi_information(loader):
    with pytest.raises(ImportError, match="does not expose ABI"):
        loader.check_core_abi(object(), 186)
