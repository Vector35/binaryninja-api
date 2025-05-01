#!/usr/bin/env python
# -*- python -*-
# Repackage a bunch of static libs as one big static library.
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
from __future__ import print_function
import os
import sys
import shutil
import re

from .base import *
from .util import *

class arar_error(Exception):
    def __init__(self, value):
        self.value = value
    def _str__(self):
        return repr(self.value)

def repack(files, ar='ar', target='liball.a', verbose=False):
    """For linux only. Repackage the list of files using ar as the
    archiver program. The input files list can contain .a or .o
    files. The output library name is supplied by the target keyword
    argument. This will raise an exception arar_error in the event of
    a problem, setting the exception value field with an explanation."""
    import glob
    pid= os.getpid()
    #error=os.system(ar + " --version")
    tdir = 'tmp.arar.%d' % (pid)
    if os.path.exists(tdir):
        raise arar_error('Conflict with existing temporary directory: %s' % \
                         (tdir))
    os.mkdir(tdir)
    # work in a temporary subdirectory
    os.chdir(tdir)
    doto = []
    for arg in files:
        if re.search(r'[.]o$', arg):
            if arg[0] == '/':
                doto.append(arg)
            else:
                doto.append(os.path.join('..',arg))
            continue
        if arg[0] == '/':
            cmd = "%s x %s" % (ar,arg)
        else:
            cmd = "%s x ../%s" % (ar,arg)
        if verbose:
            uprint(u"EXTRACTING %s" % (cmd))
        error= os.system(cmd)
        if error:
            raise arar_error('Extract failed for command %s' % (cmd))
    files = glob.glob('*.o') + doto
    local_target = os.path.basename(target)
    cmd = "%s rcv %s %s" % (ar, local_target, " ".join(files))
    if verbose:
        uprint(u"RECOMBINING %s" % (cmd))
    error=os.system(cmd)
    if error:
        raise arar_error('Recombine failed')

    os.chdir('..')
    os.rename(os.path.join(tdir,local_target), target)
    if verbose:
        uprint(u"CREATED %s" % (target))
    shutil.rmtree(tdir)


