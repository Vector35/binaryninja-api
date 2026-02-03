#!/usr/bin/env python3
"""
Generate a static crate from an original crate.

This script transforms a Cargo.toml for static builds:
- Adds -static suffix to package name
- Changes crate-type from cdylib to rlib
- Adds path to lib.rs pointing to original source
- References original build.rs via absolute path
- Converts workspace dependencies to path dependencies
- Converts relative path dependencies to absolute paths
- Adds specified feature to binaryninja dependency
- Ensures specified feature exists in [features] section
"""

import argparse
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import pip._vendor.tomli as tomllib

# Workspace dependencies and their paths relative to api_path
WORKSPACE_DEPS = {
    'binaryninja': 'rust',
    'binaryninjacore-sys': 'rust/binaryninjacore-sys',
}

# Sections emitted in this order; anything else follows after.
_SECTION_ORDER = [
    "package", "lib", "features",
    "dependencies", "build-dependencies", "dev-dependencies",
]

# Top-level keys whose dict values represent sub-sections ([key.subkey])
# rather than inline tables.
_SUBSECTION_KEYS = {"profile"}


def parse_toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def _format_value(value):
    """Format a single TOML value for inline use."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(value)
    if isinstance(value, str):
        return f'"{value}"'
    if isinstance(value, list):
        items = ", ".join(_format_value(v) for v in value)
        return f"[{items}]"
    if isinstance(value, dict):
        items = ", ".join(f"{k} = {_format_value(v)}" for k, v in value.items())
        return f"{{ {items} }}"
    raise ValueError(f"Unsupported TOML value type: {type(value)}")


def _write_table(lines, header, data):
    """Append a [header] section with key = value lines."""
    if lines and lines[-1] != "":
        lines.append("")
    lines.append(f"[{header}]")
    for key, value in data.items():
        lines.append(f"{key} = {_format_value(value)}")


def serialize_toml(data):
    """Serialize a dict to TOML (Cargo.toml subset)."""
    lines = []

    ordered_keys = [k for k in _SECTION_ORDER if k in data]
    ordered_keys += [k for k in data if k not in ordered_keys]

    for key in ordered_keys:
        value = data[key]

        # Array of tables: [[key]]
        if isinstance(value, list) and value and isinstance(value[0], dict):
            for item in value:
                if lines and lines[-1] != "":
                    lines.append("")
                lines.append(f"[[{key}]]")
                for k, v in item.items():
                    lines.append(f"{k} = {_format_value(v)}")
            continue

        if not isinstance(value, dict):
            continue

        # Sub-sections: [key.subkey]
        if key in _SUBSECTION_KEYS:
            for subkey, subvalue in value.items():
                if isinstance(subvalue, dict):
                    _write_table(lines, f"{key}.{subkey}", subvalue)
        else:
            _write_table(lines, key, value)

    return "\n".join(lines) + "\n"


def _transform_deps(deps, source_dir, api_path, bn_feature):
    """Transform a dependencies section: resolve workspace / relative paths."""
    result = {}
    for name, spec in deps.items():
        # Simple version string – keep as-is
        if isinstance(spec, str):
            result[name] = spec
            continue

        spec = dict(spec)

        # Resolve workspace dependencies to absolute path dependencies
        if spec.pop("workspace", None):
            if name in WORKSPACE_DEPS:
                spec["path"] = (api_path / WORKSPACE_DEPS[name]).resolve().as_posix()

        # Make relative paths absolute (resolve relative to crate directory)
        if "path" in spec:
            p = Path(spec["path"])
            if not p.is_absolute():
                spec["path"] = (source_dir / p).resolve().as_posix()

        # Add feature to binaryninja dependency
        if name == "binaryninja" and bn_feature:
            features = list(spec.get("features", []))
            if bn_feature not in features:
                features.append(bn_feature)
            spec["features"] = features

        result[name] = spec
    return result


def transform_cargo_data(data, source_dir, api_path, bn_feature, crate_feature):
    """Return a new dict representing the static variant of *data*."""
    result = {}

    # Package – rename with -static suffix and point to original build.rs
    package = dict(data.get("package", {}))
    package["name"] = package["name"] + "-static"
    build_rs_path = source_dir / "build.rs"
    if build_rs_path.exists():
        package["build"] = build_rs_path.resolve().as_posix()
    result["package"] = package

    # Lib – switch to rlib and point at the original source tree
    lib = dict(data.get("lib", {}))
    lib["crate-type"] = ["rlib"]
    lib["path"] = (source_dir / "src" / "lib.rs").resolve().as_posix()
    result["lib"] = lib

    # Features – ensure the requested crate feature exists
    features = dict(data.get("features", {}))
    if crate_feature and crate_feature not in features:
        features[crate_feature] = []
    if features:
        result["features"] = features

    # Dependencies
    if "dependencies" in data:
        result["dependencies"] = _transform_deps(
            data["dependencies"], source_dir, api_path, bn_feature
        )

    # Build-dependencies (no bn_feature injection here)
    if "build-dependencies" in data:
        result["build-dependencies"] = _transform_deps(
            data["build-dependencies"], source_dir, api_path, None
        )

    # Dev-dependencies (no bn_feature injection here)
    if "dev-dependencies" in data:
        result["dev-dependencies"] = _transform_deps(
            data["dev-dependencies"], source_dir, api_path, None
        )

    # Carry over remaining sections (profiles, etc.)
    for key in data:
        if key not in result:
            result[key] = data[key]

    return result


def main():
    parser = argparse.ArgumentParser(description='Generate static Cargo.toml')
    parser.add_argument('--source', required=True, help='Path to original Cargo.toml')
    parser.add_argument('--output-dir', required=True, help='Output directory for generated crate')
    parser.add_argument('--crate-name', required=True, help='Name for the generated crate')
    parser.add_argument('--api-path', required=True, help='Path to the api directory')
    parser.add_argument('--bn-feature', default='demo', help='Feature to add to binaryninja (default: demo)')
    parser.add_argument('--crate-feature', default='demo', help='Feature to add to crate (default: demo)')
    args = parser.parse_args()

    source_path = Path(args.source)
    output_dir = Path(args.output_dir)
    api_path = Path(args.api_path)
    source_dir = source_path.parent

    data = parse_toml(source_path)

    new_data = transform_cargo_data(
        data, source_dir, api_path,
        bn_feature=args.bn_feature,
        crate_feature=args.crate_feature,
    )

    new_content = serialize_toml(new_data)

    crate_dir = output_dir / args.crate_name
    crate_dir.mkdir(parents=True, exist_ok=True)

    (crate_dir / 'Cargo.toml').write_text(new_content)

    # Write source directory for build.rs to read at compile time
    (crate_dir / 'source_dir.txt').write_text(source_dir.resolve().as_posix())

    print(crate_dir)


if __name__ == '__main__':
    main()
