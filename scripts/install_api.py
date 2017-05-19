#!/usr/bin/env python
#
#    Thanks to @withzombies for letting us adapt his script
#

import sys
from os import path
from os import stat
from site import getsitepackages

try:
    import binaryninja
    print "Binary Ninja API Installed"
    sys.exit(0)
except ImportError:
    pass

if sys.platform == "linux":
    userpath = path.expanduser("~/.binaryninja")
    lastrun = path.join(userpath, "lastrun")
    if path.isfile(lastrun):
        lastrunpath = open(lastrun).read().strip()
        api_path = path.join(path.dirname(lastrun), "python")
    else:
        print "Running on linux, but ~/.binaryninja/lastrun does not exist"
        sys.exit(0)
elif sys.platform == "darwin":
    api_path = "/Applications/Binary Ninja.app/Contents/Resources/python"
else:
    # Windows
    api_path = "r'C:\Program Files\Vector35\BinaryNinja\python'"


def validate_path(path):
    try:
        stat(path)
    except OSError:
        return False

    old_path = sys.path
    sys.path.append(path)

    try:
        from binaryninja import core_version
    except ImportError:
        sys.path = old_path
        return False

    return True


while not validate_path(api_path):
    print "Binary Ninja not found. Please provide the path to Binary " + \
          "Ninja's install directory"
    sys.stdout.write("[{}] ".format(api_path))

    new_path = sys.stdin.readline().strip()
    if len(new_path) == 0:
        print "Invalid path"
        continue

    if not new_path.endswith('python'):
        new_path = path.join(new_path, 'python')

    api_path = new_path

from binaryninja import core_version
print "Found Binary Ninja core version: {}".format(core_version)

install_path = getsitepackages()[0]
binaryninja_pth_path = path.join(install_path, 'binaryninja.pth')
open(binaryninja_pth_path, 'wb').write(api_path)

print "Binary Ninja API installed using {}".format(binaryninja_pth_path)
