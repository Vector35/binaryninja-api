#!/usr/bin/env python3
"""Install the Binary Ninja Python API into the selected Python environment.

Wheel installation is preferred. A .pth compatibility installation remains available
for product layouts that do not yet bundle a wheel and for the product UI bindings.
"""

import argparse
import importlib.metadata
import importlib.util
import os
from pathlib import Path
import shutil
from site import check_enableusersite, getusersitepackages
import subprocess
import sys
from typing import Optional


DISTRIBUTION_NAME = "binaryninja-api"
PTH_FILENAME = "binaryninja.pth"

try:
    from site import getsitepackages
except ImportError:
    getsitepackages = None


def print_error(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def installed_distribution() -> Optional[importlib.metadata.Distribution]:
    try:
        return importlib.metadata.distribution(DISTRIBUTION_NAME)
    except importlib.metadata.PackageNotFoundError:
        return None


def check_virtual_environment() -> bool:
    return sys.prefix != sys.base_prefix


def get_site_packages() -> Path:
    if getsitepackages is not None:
        try:
            return Path(getsitepackages()[0])
        except IndexError:
            pass
    from sysconfig import get_path

    return Path(get_path("purelib"))


def installed_python_directory() -> Path:
    return Path(__file__).resolve().parent.parent / "python"


def validate_api_path(path: Path) -> bool:
    if not (path / "binaryninja" / "__init__.py").is_file():
        return False

    original_path = sys.path[:]
    sys.path.insert(0, str(path))
    try:
        from binaryninja import core_version

        print(f"Found Binary Ninja core version: {core_version()}")
        return True
    except (ImportError, ModuleNotFoundError) as error:
        print_error(f"Unable to import the Binary Ninja API from {path}: {error}")
        return False
    finally:
        sys.path[:] = original_path


def find_wheel(explicit_wheel: Optional[Path], api_path: Path) -> Optional[Path]:
    if explicit_wheel is not None:
        wheel = explicit_wheel.expanduser().resolve()
        if not wheel.is_file():
            raise FileNotFoundError(f"wheel does not exist: {wheel}")
        return wheel

    candidates = []
    for directory in (api_path / "dist", api_path / "wheels", api_path.parent / "wheels"):
        candidates.extend(directory.glob("binaryninja_api-*.whl"))
    return max(candidates, key=lambda path: path.stat().st_mtime) if candidates else None


def install_wheel(wheel: Path, force: bool) -> bool:
    uv = os.environ.get("UV") or shutil.which("uv")
    if uv:
        command = [uv, "pip", "install", "--python", sys.executable]
        if force:
            command.append("--reinstall")
    else:
        command = [sys.executable, "-m", "pip", "install"]
        if force:
            command.append("--force-reinstall")
    command.append(str(wheel))
    print(f"Installing {wheel.name} into {sys.executable}")
    return subprocess.run(command, check=False).returncode == 0


def pth_install_directory(on_root: bool, on_pyenv: bool) -> Optional[Path]:
    if on_root or on_pyenv or check_virtual_environment():
        install_path = get_site_packages()
    else:
        if not check_enableusersite():
            print_error("The Python user site is disabled; use a virtual environment or --install-on-root.")
            return None
        install_path = Path(getusersitepackages())

    try:
        install_path.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        print_error(f"Unable to create site-packages directory {install_path}: {error}")
        return None
    if not os.access(install_path, os.W_OK):
        print_error(f"Site-packages directory is not writable: {install_path}")
        return None
    return install_path


def install_pth(api_path: Path, on_root: bool, on_pyenv: bool) -> bool:
    install_path = pth_install_directory(on_root, on_pyenv)
    if install_path is None:
        return False

    pth_path = install_path / PTH_FILENAME
    pth_path.write_text(f"{api_path}\n{api_path}{sys.version_info.major}\n", encoding="utf-8")
    print(f"Installed compatibility path file: {pth_path}")
    print("This is a product-path compatibility installation, not an installed binaryninja-api wheel.")
    return True


def install(
    *,
    method: str = "auto",
    wheel: Optional[Path] = None,
    interactive: bool = False,
    on_root: bool = False,
    on_pyenv: bool = False,
    force: bool = False,
) -> bool:
    distribution = installed_distribution()
    if distribution is not None and not force:
        print_error(f"{DISTRIBUTION_NAME} {distribution.version} is already installed. Use --force to reinstall it.")
        return False

    api_path = installed_python_directory()
    while not validate_api_path(api_path):
        if not interactive:
            return False
        response = input(f"Binary Ninja API path [{api_path}]: ").strip()
        if response:
            candidate = Path(response).expanduser()
            api_path = candidate / "python" if (candidate / "python").is_dir() else candidate

    try:
        selected_wheel = find_wheel(wheel, api_path)
    except FileNotFoundError as error:
        print_error(error)
        return False

    if method == "wheel" and selected_wheel is None:
        print_error("No Binary Ninja API wheel was found; pass --wheel PATH or use --method pth.")
        return False
    if method in ("auto", "wheel") and selected_wheel is not None:
        return install_wheel(selected_wheel, force)

    if module_available("binaryninja") and not force:
        print_error("A binaryninja module is already importable. Use --force to replace its path configuration.")
        return False
    if method == "auto":
        print("No bundled wheel was found; falling back to the .pth compatibility installation.")
    return install_pth(api_path, on_root, on_pyenv)


def uninstall_distribution() -> bool:
    distribution = installed_distribution()
    if distribution is None:
        return True
    uv = os.environ.get("UV") or shutil.which("uv")
    if uv:
        command = [uv, "pip", "uninstall", "--python", sys.executable, DISTRIBUTION_NAME]
    else:
        command = [sys.executable, "-m", "pip", "uninstall", "-y", DISTRIBUTION_NAME]
    print(f"Removing {DISTRIBUTION_NAME} {distribution.version}")
    return subprocess.run(command, check=False).returncode == 0


def uninstall() -> bool:
    success = uninstall_distribution()
    paths = {Path(getusersitepackages()) / PTH_FILENAME, get_site_packages() / PTH_FILENAME}
    for path in paths:
        if path.exists():
            print(f"Removing {path}")
            try:
                path.unlink()
            except OSError as error:
                print_error(f"Unable to remove {path}: {error}")
                success = False
    if installed_distribution() is None and not any(path.exists() for path in paths):
        print("Binary Ninja API installation removed.")
    return success


def print_status() -> None:
    distribution = installed_distribution()
    if distribution is None:
        print(f"{DISTRIBUTION_NAME} distribution: not installed")
    else:
        print(f"{DISTRIBUTION_NAME} distribution: {distribution.version}")
    print(f"binaryninja module: {'available' if module_available('binaryninja') else 'not found'}")
    print(f"binaryninjaui module: {'available' if module_available('binaryninjaui') else 'not found'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-s", "--silent", action="store_true", help="do not prompt for an API path")
    parser.add_argument("-u", "--uninstall", action="store_true")
    parser.add_argument("-f", "--force", action="store_true")
    parser.add_argument("--status", action="store_true", help="show distribution, API, and UI installation status")
    parser.add_argument("--method", choices=("auto", "wheel", "pth"), default="auto")
    parser.add_argument("--wheel", type=Path, help="install this binaryninja-api wheel")
    parser.add_argument("--install-on-root", action="store_true")
    parser.add_argument("--install-on-pyenv", action="store_true")
    args = parser.parse_args()

    if args.status:
        print_status()
        return 0
    if args.uninstall:
        return 0 if uninstall() else 1
    return (
        0
        if install(
            method=args.method,
            wheel=args.wheel,
            interactive=not args.silent,
            on_root=args.install_on_root,
            on_pyenv=args.install_on_pyenv,
            force=args.force,
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
