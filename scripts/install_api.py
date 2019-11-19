#!/usr/bin/env python
#
#    Thanks to @withzombies for letting us adapt his script
#

import sys
import os
from site import check_enableusersite

# Handle both normal environments and virtualenvs
try: 
    from site import getusersitepackages, getsitepackages
except ImportError:
    from sysconfig import get_path
    getsitepackages = lambda: get_path('purelib')
    getusersitepackages = getsitepackages

# Hacky command line parsing to accept a silent-install -s flag like linux-setup.sh:
INTERACTIVE = True
if '-s' in sys.argv[1:]:
    INTERACTIVE = False

try:
    import binaryninja
    import binaryninjaui #To better detect if migrating from a version without UI plugin support
    print("Binary Ninja API already in the path")
    sys.exit(1)
except ImportError:
    pass

dir_name = os.path.dirname(os.path.abspath(__file__))
api_path = os.path.abspath(os.path.join(dir_name, "..", "python"))

if (os.path.isdir(api_path)):
    print("Found install folder of {}".format(api_path))
else:
    print("Failed to find installed python expected at {}".format(api_path))
    sys.exit(1)


def validate_path(path):
    try:
        os.stat(path)
    except OSError:
        return False

    old_path = sys.path
    sys.path.append(path)

    try:
        from binaryninja import core_version
        print("Found Binary Ninja core version: {}".format(core_version()))
    except ImportError:
        sys.path = old_path
        return False

    return True


while not validate_path(api_path):
    print("\nBinary Ninja not found.")
    if not INTERACTIVE:
        print("Non-interactive mode selected, failing.")
        sys.exit(-1)

    print("Please provide the path to Binary Ninja's install directory: \n [{}] : ".format(api_path))
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
with open(binaryninja_pth_path, 'wb') as pth_file:
    pth_file.write((api_path+"\n").encode('charmap'))
    if sys.version_info.major < 3 or (sys.version_info.major == 3 and sys.version_info.minor < 8):
        pth_file.write((api_path+sys.version[0]+"\n").encode('charmap')) #support for python2/3 QT bindings

print("Binary Ninja API installed using {}".format(binaryninja_pth_path))
