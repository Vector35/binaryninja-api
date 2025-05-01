#BEGIN_LEGAL
#
#Copyright (c) 2022 Intel Corporation
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
# __init__.py
"""This is mbuild: a simple portable dependence-based build-system
written in python.

mbuild is a python-based build system very similar to scons with some
philosophical features of make.  mbuild exposes the scan and build phases
allowing them to be repeated  as necessary. Multiple DAGs can be
built, one during each scan phase.

Conceptually there are 3 major components to mbuild:
  - The environment L{env_t}
  - The directed acyclic graph  L{dag_t}
  - The work queue L{work_queue_t}

Using the environment L{env_t} you customize your build configuration
and construct names for your source files, object files, executables,
etc.  The environment contains builder methods that create L{plan_t}
objects. There are builders for C, C++, static and dynamic libraries,
assembly files and linking programs. The environment and builders
support string substitution.

The L{plan_t} objects are passed to the L{dag_t} which stores the
dependences that order execution. The L{plan_t} objects describe work
that needs to be done. Plans typically contain a command line strings
(with all substitutions done), but can also be python functions that
will be executed during the build.

Using the L{plan_t} objects, the L{dag_t} creates L{command_t}
objects that are passed to the L{work_queue_t} to ultimately build the
target or targets.

Your build file can have multiple environments, DAGS and work queues.


Using the environment dictionary
================================

You can bind or augmenting environment variables from the command
line. For example, one can say C{build_cpu=ia32} on an x86-64 system
to change the default compilation behavior.  Similarly, one can say
C{CXXFLAGS+=-g} to add the C{-g} flag to the existing C{CXXFLAGS}
variable.

Dynamic substitution is also used. Patterns of the form %(I{string})s
will substitute I{string} dynamically before it is used.  The
expansion can happen directly from the environment and is
recursive. The expansion can also use dictionaries that are variables
in the environment.  A dictionary in the environment is really a tuple
of the key-variable and the dictionary itself.

For example::

    env['opt_flag'] = ( 'opt', {'noopt':'',
                                '0':'%(OPTOPT)s0',
                                '1':'%(OPTOPT)s1',
                                '2':'%(OPTOPT)s2',
                                '3':'%(OPTOPT)s3',
                                '4':'%(OPTOPT)s4'} )

    env['OPTOPT'] = ( 'compiler', { 'gnu':'-O',
                                    'ms':'/O'})


    env['CXXFLAGS'] += ' %(opt_flag)s'

The C{OPTOPT} variable depends on C{env['compiler']}.
If C{env['compiler']='gnu'} then C{env['OPTOPT']} expands to C{-O}.
If C{env['compiler']='ms'} then C{env['OPTOPT']} expands to C{/O}.

If the C{opt} variable is set "C{opt=3}" on the command line, or equivalently
if C{env['opt']='3'} is
set in the script,
then if the C{env['compiler']='gnu'} in the environment at the time of expansion,
then the flag in the
C{CXXFLAGS} will be C{-O3}. If C{env['compiler']='ms'} at the time of expansion,
then the optimiation
flag would be C{/O3}.  If C{opt=noopt} (on the command line) then there will be no
optimization flag in the C{CXXFLAGS}.


Introspection
=============

The L{command_t} that are executed during the build have their output
(stdout/stderr) stored in the L{dag_t}. After a build it is possible
to collect the commands using the L{dag_t.results} function  and analyze the
output. This is very handy for test and validation suites.
""" 

from .base import *
from .dag import *
from .work_queue import *
from .env import *
from .util import *
from .plan import *
from .arar import *
from .doxygen import doxygen_run, doxygen_args, doxygen_env
from .header_tag import *

__all__ = [ 'base',
            'dag',
            'work_queue',
            'env',
            'util',
            'plan',
            'msvs',
            'arar',
            'doxygen',
            'dfs',
            'header_tag' ]


import time
def mbuild_exit():
    """mbuild's exit function"""

import atexit
atexit.register(mbuild_exit)
