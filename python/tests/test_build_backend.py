import pytest

import _build_backend


def test_generated_binding_guard_accepts_checkout():
    _build_backend._require_generated_bindings()


def test_generated_binding_guard_rejects_incomplete_source(monkeypatch, tmp_path):
    backend_path = tmp_path / "_build_backend.py"
    package_directory = tmp_path / "binaryninja"
    package_directory.mkdir()
    (package_directory / "enums.py").touch()
    monkeypatch.setattr(_build_backend, "__file__", str(backend_path))

    with pytest.raises(RuntimeError, match="_binaryninjacore.py"):
        _build_backend._require_generated_bindings()
