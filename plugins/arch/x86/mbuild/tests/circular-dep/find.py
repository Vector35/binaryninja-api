#!/usr/bin/env python

# add the right mbuild dir to the sys.path so that we can import mbuild.

import os
import sys

def find_dir(d):
    dir = os.getcwd()
    last = ''
    while dir != last:
        target_dir = os.path.join(dir,d)
        if os.path.exists(target_dir):
            return target_dir
        last = dir
        (dir,tail) = os.path.split(dir)
    return None

# go up an extra level because we are in the mbuild tree.
# otherwise we find the subdir instead of the parent dir.
# normally this last os.path.dirname() would not be required.
mbuild_path = os.path.dirname(find_dir('mbuild'))
sys.path = [ mbuild_path ] + sys.path


