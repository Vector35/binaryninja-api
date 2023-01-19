#!/usr/bin/env python3

import importlib.util
import os
import sys
from site import check_enableusersite
from typing import Optional

if sys.version_info[0] < 3:
    sys.stderr.print("Python 3 is required.")
    sys.exit(1)

# Handle both normal environments and virtualenvs
try:
    from site import getusersitepackages, getsitepackages
except ImportError:
    from sysconfig import get_path
    getsitepackages = lambda: get_path("purelib")
    getusersitepackages = getsitepackages


def print_error(*args, file=None, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def check_virtual_environment() -> bool:
    if sys.prefix != sys.base_prefix:
        if os.environ.get("VIRTUAL_ENV"):
            return True
    return False


def binaryninja_installed() -> bool:
    try:
        binaryninja = importlib.util.find_spec("binaryninja")
        assert binaryninja is not None
        binaryninjaui = importlib.util.find_spec("binaryninjaui")
        assert binaryninjaui is not None
        return True
    except ModuleNotFoundError:
        return False
    except AssertionError:
        return False


def get_binaryninja_installed_directory() -> Optional[str]:
    dir_name = os.path.dirname(os.path.abspath(__file__))
    api_path = os.path.abspath(os.path.join(dir_name, "..", "python"))
    if os.path.isdir(api_path):
        return api_path


def validate_path(path: str) -> bool:

    try:
        os.stat(path)
    except OSError:
        return False

    old_path = sys.path
    sys.path.append(path)

    try:
        from binaryninja import core_version
        print("Found Binary Ninja core version: {}".format(core_version()))
    except ModuleNotFoundError as e:
        sys.path = old_path
        if e.name == "packaging" and sys.version_info.minor >= 10:
            raise e
        return False
    except ImportError as e:
        sys.path = old_path
        return False

    return True


def install(interactive=False, on_root=False, on_pyenv=False) -> bool:

    if binaryninja_installed():
        print_error("Binary Ninja API already in the path.")
        return False

    api_path = get_binaryninja_installed_directory()
    if not api_path:
        print_error("Failed to find installed python expected at {}".format(api_path))
        return False

    print(f"Found install folder of {api_path}")

    while not validate_path(api_path):
        
        print(f"Binary Ninja not found: {api_path}")
        
        if not interactive:
            print_error("silent mode selected (-s, --silent), failing.")
            return False

        try:
            new_path = input("Please provide the path to Binary Ninja's install directory: \n [{}] : ".format(api_path))
        except KeyboardInterrupt:
            print_error("KeyboardInterrupt detected.")
            return False

        if not new_path:
            print("Invalid path.")
            continue

        if not new_path.endswith("python"):
            os.path.join(new_path, "python")

        api_path = new_path

    if on_root:
        install_path = getsitepackages()[0]
        if not os.access(install_path, os.W_OK):
            print_error(f"Root install specified but cannot write to {install_path}")
            return False
        else:
            print(f"Installing on root site: {install_path}")
    
    elif on_pyenv:
        install_path = getsitepackages()[0]
        print(f"Installing on pyenv site: {install_path}")

    elif check_virtual_environment():
        install_path = getsitepackages()[0]
        print(f"Installing on virtual environment site: {install_path}")

    else:
        if not check_enableusersite():
            print_error("Warning, trying to write to user site packages, but check_enableusersite fails.")
            return False
        else:
            install_path = getusersitepackages()
            if not os.path.exists(install_path):
                os.makedirs(install_path)
            print(f"Installing on user site: {install_path}")

    binaryninja_pth_path = os.path.join(install_path, "binaryninja.pth")
    with open(binaryninja_pth_path, 'wb') as pth_file:
        pth_file.write((api_path + '\n').encode("charmap"))
        pth_file.write((api_path + sys.version[0] + '\n').encode("charmap")) # support for QT bindings

    return True


def uninstall() -> bool:

    if not binaryninja_installed():
        print_error("Uninstall specified, but binaryninja not in the current path.")
        return False

    user_path = os.path.join(getusersitepackages(), "binaryninja.pth")
    site_path = os.path.join(getsitepackages()[0], "binaryninja.pth")

    for path_to_unlink in [user_path, site_path]:

        if not os.path.exists(path_to_unlink):
            print_error(f"{path_to_unlink} not found.")
            continue

        print(f"Removing {path_to_unlink}...")
        try:
            os.unlink(path_to_unlink)
        except OSError as e:
            print_error(f"Unable to unlink, please re-run with appropriate permissions: {str(e)}")
            return False

    return True


if __name__ == '__main__':

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--silent", action='store_true') 
    parser.add_argument("-u", "--uninstall", action='store_true')
    parser.add_argument("--install-on-root", action='store_true')
    parser.add_argument("--install-on-pyenv", action='store_true')
    args = parser.parse_args()

    if args.uninstall:
        uninstall_result = uninstall()
        if not uninstall_result:
            print(f"Binary Ninja API uninstallation failed.")
            sys.exit(-1)
        else:
            print(f"Binary Ninja API uninstallation success.")
    else:
        install_result = install(
            interactive=(not args.silent),
            on_root=args.install_on_root,
            on_pyenv=args.install_on_pyenv
        )
        if not install_result:
            print(f"Binary Ninja API installation failed.")
            sys.exit(-1)
        else:
            print(f"Binary Ninja API installation success.")
