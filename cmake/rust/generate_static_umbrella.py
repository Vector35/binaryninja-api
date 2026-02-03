#!/usr/bin/env python3
"""
Generate a static umbrella crate that combines multiple static crates into one staticlib.

This avoids duplicate symbol errors from Rust standard library symbols when linking
multiple Rust staticlibs into a single binary.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_crate_arg(value: str) -> tuple[str, str, str | None]:
    """Parse a 'name=path' or 'name=path:feature' crate argument."""
    name, _, rest = value.partition('=')
    if not rest:
        raise argparse.ArgumentTypeError(f"Expected name=path, got: {value}")
    # Split on the *last* colon to avoid matching the Windows drive letter (C:\...).
    left, sep, right = rest.rpartition(':')
    if sep and len(left) > 1:
        path, feature = left, right
    else:
        path, feature = rest, None
    return name, path, feature or None


def generate_cargo_toml(name: str, crates: list[tuple[str, str, str | None]]) -> str:
    """Generate Cargo.toml content for the umbrella crate."""
    lines = [
        '[package]',
        f'name = "{name}"',
        'version = "0.1.0"',
        'edition = "2021"',
        '',
        '[lib]',
        'crate-type = ["staticlib"]',
        '',
        '[dependencies]',
    ]

    for crate_name, crate_path, feature in crates:
        # Normalize to forward slashes for TOML basic strings (backslash is escape)
        crate_path = crate_path.replace('\\', '/')
        if feature:
            lines.append(f'{crate_name} = {{ path = "{crate_path}", features = ["{feature}"] }}')
        else:
            lines.append(f'{crate_name} = {{ path = "{crate_path}" }}')

    lines.extend([
        '',
        '[profile.release]',
        'panic = "abort"',
        'lto = false',
        'debug = 1',
        '',
        '[profile.release-demo]',
        'inherits = "release"',
        'lto = false',
        '',
        '[profile.dev-demo]',
        'inherits = "dev"',
    ])

    return '\n'.join(lines) + '\n'


def generate_lib_rs(crates: list[tuple[str, str, str | None]]) -> str:
    """Generate lib.rs content for the umbrella crate."""
    lines = [
        '// Generated umbrella crate - do not edit',
        '// Combines multiple static Rust crates into a single staticlib',
        '',
    ]

    for crate_name, _, _ in crates:
        crate_ident = crate_name.replace('-', '_')
        lines.append(f'pub use {crate_ident};')

    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='Generate static umbrella crate')
    parser.add_argument('--name', required=True, help='Name of the umbrella crate')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    parser.add_argument('--crate', action='append', required=True,
                        type=parse_crate_arg, metavar='NAME=PATH',
                        help='Crate to include (may be repeated)')
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    crates = args.crate

    umbrella_dir = output_dir / args.name
    src_dir = umbrella_dir / 'src'
    src_dir.mkdir(parents=True, exist_ok=True)

    (umbrella_dir / 'Cargo.toml').write_text(generate_cargo_toml(args.name, crates))
    (src_dir / 'lib.rs').write_text(generate_lib_rs(crates))

    print(umbrella_dir)


if __name__ == '__main__':
    main()
