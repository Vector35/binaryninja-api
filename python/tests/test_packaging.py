from pathlib import Path
import re

import pytest


PROJECT_DIRECTORY = Path(__file__).parent.parent
API_DIRECTORY = PROJECT_DIRECTORY.parent


def test_generated_bindings_are_present():
    for name in ("_binaryninjacore.py", "enums.py"):
        path = PROJECT_DIRECTORY / "binaryninja" / name
        assert path.is_file()
        assert path.stat().st_size > 0


def test_generated_abi_matches_header():
    if not (API_DIRECTORY / "binaryninjacore.h").is_file():
        pytest.skip("requires a full binaryninja-api checkout")
    header = (API_DIRECTORY / "binaryninjacore.h").read_text(encoding="utf-8")
    bindings = (PROJECT_DIRECTORY / "binaryninja" / "_binaryninjacore.py").read_text(encoding="utf-8")
    header_abi = re.search(r"#define BN_CURRENT_CORE_ABI_VERSION (\d+)", header)
    bindings_abi = re.search(r"BN_EXPECTED_CORE_ABI_VERSION = (\d+)", bindings)
    assert header_abi is not None
    assert bindings_abi is not None
    assert bindings_abi.group(1) == header_abi.group(1)
