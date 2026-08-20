import importlib.util
import os
from pathlib import Path

import pytest


INSTALLER_PATH = Path(__file__).parents[2] / "scripts" / "install_api.py"


@pytest.fixture
def installer():
    spec = importlib.util.spec_from_file_location("install_api_under_test", INSTALLER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_installed_python_directory(installer):
    assert installer.installed_python_directory() == INSTALLER_PATH.parent.parent / "python"


def test_explicit_wheel_is_validated(installer, tmp_path):
    wheel = tmp_path / "binaryninja_api-1.0.0-py3-none-any.whl"
    wheel.touch()
    assert installer.find_wheel(wheel, tmp_path) == wheel


def test_missing_explicit_wheel_is_rejected(installer, tmp_path):
    with pytest.raises(FileNotFoundError):
        installer.find_wheel(tmp_path / "missing.whl", tmp_path)


def test_newest_bundled_wheel_is_selected(installer, tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    old = dist / "binaryninja_api-1.0.0-py3-none-any.whl"
    new = dist / "binaryninja_api-2.0.0-py3-none-any.whl"
    old.touch()
    new.touch()
    # Explicit mtimes keep the test deterministic on coarse filesystems.
    os.utime(old, (1, 1))
    os.utime(new, (2, 2))
    assert installer.find_wheel(None, tmp_path) == new
