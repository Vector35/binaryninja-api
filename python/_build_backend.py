"""PEP 517 guard around uv_build for the generated Binary Ninja bindings."""

from pathlib import Path

import uv_build


_GENERATED_FILES = ("_binaryninjacore.py", "enums.py")


def _require_generated_bindings() -> None:
    package_directory = Path(__file__).parent / "binaryninja"
    missing = [name for name in _GENERATED_FILES if not (package_directory / name).is_file()]
    if missing:
        raise RuntimeError(
            "The generated Binary Ninja bindings are missing: "
            + ", ".join(missing)
            + ". Run the CMake generator_copy target before building or installing the package."
        )


def build_sdist(sdist_directory, config_settings=None):
    _require_generated_bindings()
    return uv_build.build_sdist(sdist_directory, config_settings)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _require_generated_bindings()
    return uv_build.build_wheel(wheel_directory, config_settings, metadata_directory)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    _require_generated_bindings()
    return uv_build.build_editable(wheel_directory, config_settings, metadata_directory)


get_requires_for_build_sdist = uv_build.get_requires_for_build_sdist
get_requires_for_build_wheel = uv_build.get_requires_for_build_wheel
get_requires_for_build_editable = uv_build.get_requires_for_build_editable
prepare_metadata_for_build_wheel = uv_build.prepare_metadata_for_build_wheel
prepare_metadata_for_build_editable = uv_build.prepare_metadata_for_build_editable
