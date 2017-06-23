#!/usr/bin/env python
#
#    Thanks to @withzombies for letting us adapt his script
#

import sys
import os
from site import getsitepackages, getusersitepackages, check_enableusersite

try:
    import binaryninja
    print("Binary Ninja API already Installed")
    sys.exit(1)
except ImportError:
    pass

if sys.platform.startswith("linux"):
    userpath = os.path.expanduser("~/.binaryninja")
    lastrun = os.path.join(userpath, "lastrun")
    if os.path.isfile(lastrun):
        lastrunpath = open(lastrun).read().strip()
        api_path = os.path.join(lastrunpath, "python")
        print("Found install folder of {}".format(api_path))
    else:
        print("Running on linux, but ~/.binaryninja/lastrun does not exist")
        sys.exit(0)
elif sys.platform == "darwin":
    api_path = "/Applications/Binary Ninja.app/Contents/Resources/python"
else:
    # Windows
    api_path = "r'C:\Program Files\Vector35\BinaryNinja\python'"


def validate_path(path):
    try:
        os.stat(path)
    except OSError:
        return False

    old_path = sys.path
    sys.path.append(path)

    try:
        from binaryninja import core_version
        print("Found Binary Ninja core version: {}".format(core_version))
    except ImportError:
        sys.path = old_path
        return False

    return True


while not validate_path(api_path):
    print("\nBinary Ninja not found. Please provide the path to Binary " + \
          "Ninja's install directory: \n [{}] : ".format(api_path))

    new_path = sys.stdin.readline().strip()
    if len(new_path) == 0:
        print("\nInvalid path")
        continue

    if not new_path.endswith('python'):
        new_path = os.path.join(new_path, 'python')

    api_path = new_path

if ( len(sys.argv) > 1 and sys.argv[1].lower() == "root" ):
    #write to root site
    install_path = getsitepackages()[0]
    if not os.access(install_path, os.W_OK):
        print("Root install specified but cannot write to {}".format(install_path))
        sys.exit(1)
else:
    if check_enableusersite():
        install_path = getusersitepackages()
        if not os.path.exists(install_path):
            os.makedirs(install_path)
    else:
        print("Warning, trying to write to user site packages, but check_enableusersite fails.")
        sys.exit(1)

binaryninja_pth_path = os.path.join(install_path, 'binaryninja.pth')
open(binaryninja_pth_path, 'wb').write(api_path)

print("Binary Ninja API installed using {}".format(binaryninja_pth_path))
