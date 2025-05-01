# -*- python -*-
#BEGIN_LEGAL
#
#Copyright (c) 2017 Intel Corporation
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

"""OS Environment accessors
"""
from __future__ import print_function
import os
import sys
from .base import *

def _get_osenv_sep():
    if on_native_windows():
        return ';'
    return ':'
        
def get_env(v):
    "return the osenv var v as a string"
    if v in os.environ:
        return os.environ[v]
    return ''

def get_env_list(v):
    "return the osenv var v as a list"
    if v in os.environ:
        sep = _get_osenv_sep()
        return os.environ[v].split(sep)
    return []
        
def set_env(v,s):
    """Add v=s to the shell environment"""
    if v in os.environ:
        orig = os.environ[v]
    else:
        orig = ''
        
    # We have had issues on windows were we attempt to make the
    # environment too long. This catches the error and prints a nice
    # error msg.
    try:
        os.environ[v]=s
    except Exception as e:
        sys.stderr.write( str(e) + '\n')
        sys.stderr.write("Env Variable [%s]\n" % (v))
        sys.stderr.write("Original was [%s]\n" % (orig))
        sys.stderr.write("New value was [%s]\n" % (s))
        sys.exit(1)
        
def set_env_list(v,slist):
    """Add list to os env var v"""
    sep = _get_osenv_sep()
    set_env(v,sep.join(slist))

def add_to_front(v,s):
    """Add v=s+old_v to the shell environment"""
    sep = _get_osenv_sep()    
    set_env(v,s + sep + os.environ[v])

def add_to_front_list(v,slist):
    "Add slist to front of env, adding os-specific separator"
    sep = _get_osenv_sep()    
    add_to_front(v,sep.join(slist))
