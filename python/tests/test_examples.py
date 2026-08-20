import ast
import os
from pathlib import Path
import subprocess
import sys

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import pytest


PROJECT_DIRECTORY = Path(__file__).parent.parent
EXAMPLES_DIRECTORY = PROJECT_DIRECTORY / "examples"


def _manifest():
    with (EXAMPLES_DIRECTORY / "manifest.toml").open("rb") as manifest_file:
        return tomllib.load(manifest_file)


def _python_examples():
    return {path.relative_to(EXAMPLES_DIRECTORY).as_posix() for path in EXAMPLES_DIRECTORY.rglob("*.py")}


def test_all_examples_are_classified_once():
    manifest = _manifest()
    groups = [manifest[mode] for mode in ("standalone", "core_plugins", "ui_plugins")]
    classified = [path for group in groups for path in group]
    assert len(classified) == len(set(classified)), "an example is classified more than once"
    assert set(classified) == _python_examples()


@pytest.mark.parametrize("relative_path", sorted(_python_examples()))
def test_example_parses(relative_path):
    path = EXAMPLES_DIRECTORY / relative_path
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_ui_examples_import_binaryninjaui_before_pyside():
    for relative_path in _manifest()["ui_plugins"]:
        path = EXAMPLES_DIRECTORY / relative_path
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        binaryninjaui_line = None
        pyside_line = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            if any(name == "binaryninjaui" or name.startswith("binaryninjaui.") for name in names):
                binaryninjaui_line = min(binaryninjaui_line or node.lineno, node.lineno)
            if any(name == "PySide6" or name.startswith("PySide6.") for name in names):
                pyside_line = min(pyside_line or node.lineno, node.lineno)
        if pyside_line is not None:
            assert binaryninjaui_line is not None, f"{relative_path} imports PySide6 without binaryninjaui"
            assert binaryninjaui_line < pyside_line, f"{relative_path} must import binaryninjaui before PySide6"


@pytest.mark.skipif("BN_INSTALL_DIR" not in os.environ, reason="requires an installed Binary Ninja core")
@pytest.mark.parametrize(
    "arguments",
    [
        ["cli_dis.py", "x86", "55"],
        ["cli_lift.py", "linux-x86", "55"],
        ["bindiff.py", "--help"],
        ["raw_binary_base_detection.py", "--help"],
    ],
)
def test_headless_example_smoke(arguments):
    environment = os.environ.copy()
    environment.update(
        BN_DISABLE_USER_PLUGINS="1",
        BN_DISABLE_USER_SETTINGS="1",
        BN_DISABLE_REPOSITORY_PLUGINS="1",
    )
    result = subprocess.run(
        [sys.executable, str(EXAMPLES_DIRECTORY / arguments[0]), *arguments[1:]],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
