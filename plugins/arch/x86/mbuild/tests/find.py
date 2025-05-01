#!/usr/bin/env python
#BEGIN_LEGAL
#
#Copyright (c) 2016 Intel Corporation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#  
#END_LEGAL

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


