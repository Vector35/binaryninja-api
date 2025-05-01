#!/usr/bin/env python
# -*- python -*-
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

"""Environment support"""
from __future__ import print_function
import os
import sys
import re
import platform
import types
import optparse
import time
import copy

from   .base import *
from . import util
from . import build_env
from . import plan
from . import msvs


def _remove_libname(args,env):
    #lib = env.expand('%(LIBNAME)s')
    lib = args[0]
    vmsgb(1, "REMOVING", lib)
    util.remove_file(lib)
    return (0,['REMOVED %s\n' % ( lib )])

# 2014-04-02: Intel has 2 compilers for mac: icc and icl. Intel now
# calls their mac llvm-based comiler "icl". This confuses thing with
# the name of the windows intel compiler which is also called "icl".
# In mbuild, we call the Intel llvm-based compiler "iclang" to
# disambiguate the conflict.

class env_t(object):
    """The is the environment for compilation. The environment
    includes a dictionary for holding everything custom about this
    environment. The default environment includes:

          - command line options. These are also in the environment dictionary.
             - build_dir   defaultE{:} obj
             - src_dir     defaultE{:} . or path to the mfile
             - gen_dir     defaultE{:} None (default path for generated files, if set)
             - shared      defaultE{:} False  (default: no shared libraries)
             - static      defaultE{:} False  (default: not to statically link)
             - opt         defaultE{:} 'noopt' (could be 'noopt, 0,1,2,3)
             - debug       defaultE{:} False
             - separate_pdb_files       defaultE{:} False
             - targets     defaultE{:} []  targets to build
             - verbose     defaultE{:} 1
             - compiler    defaultE{:} 'gnu', 'ms', 'clang', 'icc', 'icl', 'iclang'
             - extra_defines   defaultE{:} '' 
             - extra_flags     defaultE{:} ''  (for both CXXFLAGS & CCFLAGS)
             - extra_cxxflags  defaultE{:} ''
             - extra_ccflags   defaultE{:} ''
             - extra_linkflags defaultE{:} ''
             - extra_libs      defaultE{:} ''
             - use_yasm        defaultE{:} False
          
          - CPPPATH         defaultE{:} [] The list of include paths
          - SYSTEMINCLUDE   defaultE{:} [] The list of system include paths (Not
                            supported by MSVS).
          - DEFINES         defaultE{:} {} The dictionary of defines 

          
          - short names for the primary compiler toolsE{:}
             - CXX_COMPILER   cl or g++
             - CC_COMPILER    cl or gcc
             - ASSEMBLER      ml/ml64 or gcc/gas (gcc is the default for gnu)
             - LINKER         link or g++/gcc (g++ is the default for gnu)
             - ARCHIVER       ar
             - RANLIB_CMD     ranlib
  
          - toolchain      path to the compiler tools (default is ''). If toolchain is
                           set, it should end with a trailing slash.
          - vc_dir         path to the compiler VC directory for MSVS (default is '')n
          - icc_version    7, 8, 9, 10, ...
          - gcc_version    2.96, 3.x.y, 4.x.y, ...
          - msvs_version   6 (VC98), 7 (.NET 2003), 8 (Pro 2005), ...
          
          - primary compilation toolsE{:}
             - CC             cl or gcc          (with toolchain path)
             - CXX            cl or g++          (with toolchain path)
             - AS             ml,ml64 or gcc/gas (with toolchain path)
             - LINK           link or gcc/g++    (with toolchain path)
             - AR             lib  or ar         (with toolchain path)
             - RANLIB         ranlib             (with toolchain path)
          - flags for primary toolsE{:}
             - CCFLAGS
             - CXXFLAGS
             - ASFLAGS
             - ARFLAGS
             - LINKFLAGS
             - LIBS      (libraries for the end of the link statement)
          
          - preprocessor flags
            - DOPT       /D or -D
            - ASDOPT     /D or -D
            - IOPT       /I or -I
            - OPTPOPT    /O or -O
            - DEBUGOPT   /Zi or -g
  
          - options to control compilation outputE{:}
            - COPT       /c or -c
            - COUT       /Fo or -o
            - ASMOUT     /Fo or -o
            - LIBOUT     /outE{:} or -o
            - LINKOUT    /OUTE{:} or -o
            - DLLOPT     -shared
  
          - Override-buildersE{:} set these to a function pointer if you want
            to replace the default builder function.
        
              - ASSEMBLE_BUILDER         if not set default is to use assemble_default()
              - CXX_COMPILE_BUILDER      if not set default is to use cxx_default()
              - CC_COMPILE_BUILDER       if not set default is to use cc_default()
              - LINK_BUILDER             if not set default is to use link_default()
              - STATIC_LIBRARY_BUILDER   if not set default is to use static_lib_default()
              - DYNAMIC_LIBRARY_BUILDER  if not set default is to use dynamic_lib_default()
        
          - default extensionsE{:}
             - OBJEXT     .obj or .o
             - LIBEXT     .lib or .a
             - DLLEXT     .dll, .so, or .dylib 
             - EXEEXT     .exe or ''

          - System valuesE{:}
              - uname        standard python tuple of values from uname.
              - system       standard valuesE{:} 'Linux', 'Windows', 'Darwin', 'Microsoft', 'FreeBSD', 'NetBSD'
              - hostname     
              - build_os     standard valuesE{:} 'lin', 'win', 'mac', 'bsd'
              - host_os      standard valuesE{:} 'lin', 'win', 'mac', 'bsd'
              - build_cpu    standard valuesE{:} 'ia32', 'x86-64', 'ipf'
              - host_cpu     standard valuesE{:} 'ia32', 'x86-64', 'ipf'

        """

    obj_pattern = re.compile(r'.obj$')
    objext_pattern = re.compile(r'[%][(]OBJEXT[)]s$')
    
    mbuild_subs_pattern = re.compile('%[(][^)]+[)]')
    #FIXME: no backslashes in patterns!
    assignment_pattern = re.compile(r'(?P<name>[-A-Za-z0-9_]+)[=](?P<value>.+)')
    supplement_pattern = re.compile(r'(?P<name>[-A-Za-z0-9_]+)[+][=](?P<value>.+)')
    
    def version(self):
        """Emit the version string.
        @rtype: string
        @return: The version string
        """
        # FIXME: could put an Id in each sub-module and look at the
        # doc strings for each one.
        msgb("VERSION", "$Id: mbuild_env.py 44 2007-03-16 15:54:44Z mjcharne $")
    def __setitem__(self,k,value):
        """Write a value to the environment dictionary"""
        if util.is_stringish(value):
            self.env[k] = util.posix_slashes(value)
        else:
            self.env[k] = value
    def __contains__(self,k):
        if k in self.env:
            return True
        return False
    
    def __getitem__(self,k):
        """Read the environment dictionary. Not doing any
        substitutions."""

        try:
            return self.env[k]
        except:
            die("env key not found: %s" % (k))

    def expand(self, command_string, newenv=None):
        """Alias for expand_string()"""
        return self.expand_string(command_string, newenv)
        
    def expand_string(self, command_string, newenv=None):
        """Read the environment dictionary, doing recursive
        substitutions from the environment. If no environment is
        supplied, then the default environment is used.
        
        @type command_string: string or list of strings
        @param command_string: A string with %(...)s variables in it
        @type newenv: L{env_t}
        @param newenv: An environment within which to do the expansion. If
        null, the default environment is used.
        @rtype: string
        """
        if newenv == None:
            newenv = self.env
        if util.is_stringish(command_string):
            return self._iterative_substitute(command_string, newenv)
        if isinstance(command_string, list):
            return [ self._iterative_substitute(x, newenv) for x in command_string ]
        die("expand_string only handles substitution in strings or lists of strings")

    def expand_key(self,k, newenv=None):
        """Read the the value of k from the environment dictionary,
        doing recursive substitutions from the environment. If no
        environment is supplied, then the default environment is used.
        
        @type k: string or list  of strings
        @param k: A string (or strings) containing a single key name(s)
        @type newenv: L{env_t}
        @param newenv: An environment within which to do the expansion. If
        null, the default environment is used.
        @rtype: string
        """
        if newenv == None:
            newenv = self.env
        if  k not in newenv:
            die("Could not find %s in the environment" % k)
            
            
        if isinstance(newenv[k],list):
            # We must process each string in the list and do
            # substitutions on them.  For example, CPPPATH
            return [ self._iterative_substitute(x,newenv) for x in  newenv[k]]
        if util.is_stringish(newenv[k]):
            return self._iterative_substitute("%(" + k + ")s", newenv)
        # non strings (scalars)
        return newenv[k]
    
    def _mysub(self,input, keyname, newval):
        """Replace %(keyname)s in input with newval"""
        # only handling %(...)s replacement. Nothing fancy.
        s = '%('+keyname+')s'
        # simple string replacement, not regexp replacement
        output = input.replace(s,newval) 
        return output


    def _iterative_substitute(self,s,dct1,debug=False):
        """Replace all the %(...)s with values in s from the
        dictionary dct1. Note, the dictionary can contain tuples of
        the form (key, dict). In this case, this code uses the lookup
        result of dct1[key] to query yet the dictionary dict. That
        lookup can result in a string or another such tuple."""
        #error_msg("iterative_substitute", str(s))
        subs_pattern = re.compile('%[(](?P<name>[^)]+)[)]s')
        t = s
        m = subs_pattern.search(t)
        while m:
            name = m.group('name')
            if name not in dct1:
                die("Bad substitution for " + name)
            v = dct1[name]
            # repeatedly expand any tuples that show up.
            while not util.is_stringish(v):
                if isinstance(v,tuple):
                    (key, dct) = v
                    
                    # look up key in the main dictionary to create a
                    # subkey for use in the 2nd level dictionary
                    
                    try:
                        subkey = dct1[key]
                    except:
                        die("nested dictionary lookup error during iterative string " +
                            " expansion. key=%s" % (str(key)))
                        
                    try:
                        v = dct[ subkey ]
                    except:
                        try:
                            v = dct['otherwise']
                        except:
                            die("nested dictionary lookup error during iterative string " +
                                " expansion. key=%s subkey=%s" % (str(key),str(subkey)))
                elif isinstance(v,types.FunctionType):
                    try: 
                        v = v(dct1)
                    except:
                       die("Bad function invokation during iterative string expansion")
                else:
                    die("Bad environment value: " +  str(v) +
                        " when searching: " + s)
            t = self._mysub(t,name,v)
            m = subs_pattern.search(t)
            if debug:
                uprint(t)
        return t
    
    def _dosub_old(self,s,d):
        """Repeatedly substitute values from the dictionary d into the
        string s while '%(...)' substrings remain in the thing we want
        to return.  If the input s is a list, then we recursively
        expand each element of that list"""

        if isinstance(s,list):
            return [ self.dosub(x,d) for x in  s]

        # The common case: Just expanding a simple string.
        t = s
        while env_t.mbuild_subs_pattern.search(t):
            t = t % d
        return t

    def __str__(self):
        """Print out the environment"""
        s = []
        s.append("BUILD_CPU:")
        s.append(self.env['build_cpu'])
        s.append("HOST_CPU:")
        s.append(self.env['host_cpu'])
        s.append("\nBUILD_OS: ")
        s.append(self.env['build_os'])
        s.append("\nHOST_OS: ")
        s.append(self.env['host_os'])
        s.append("\nUNAME: ")
        s.append(str(self.env['uname']))
        s.append("\nHOSTNAME: ")
        s.append(self.env['hostname'])
        s.append("\nSYSTEM: ")
        s.append(self.env['system'])
        s.append("\nDICTIONARY:\n")
        for k,v in iter(self.env.items()):
            s.append("\t")
            s.append(k)
            s.append("->")
            s.append(str(v))
            s.append("\n")
        return ''.join(s)

    def verbose_startup(self):
        if self._emitted_startup_msg:
            return
        self._emitted_startup_msg = True
        if verbose(2):
            msgb("INVOKED", " ".join(sys.argv))
            msgb("START TIME", self.env['start_time_str'])
            msgb("CURRENT DIRECTORY", os.getcwd())

            msgb('UNAME', str(self.env['uname']).replace(':','_'))
            msgb('SYSTEM', self.env['system'])
            msgb('HOSTNAME', self.env['hostname'])
            msgb("BUILD_OS", self.env['build_os'])
            msgb("BUILD_CPU", self.env['build_cpu'])
            msgb("HOST_OS", self.env['host_os'])
            msgb("HOST_CPU", self.env['host_cpu'])

    def _check_registry_environment(self,env_var):
        s = 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment'
        is_py2 = sys.version[0] == '2'
        try:
            if is_py2:
                import _winreg as winreg
            else:
                import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, s)
            (val, typ) = winreg.QueryValueEx(key, env_var)
            return val
        except:
            die(("Could not read windows registry for variable %s.\n" % \
                            (env_var)) + 
                           "Use win32 python and install pywin32")

    def _check_processor_identifier_windows(self):

            return self._check_registry_environment('PROCESSOR_IDENTIFIER')


    def _check_number_of_processors_windows(self):
        return self._check_registry_environment('NUMBER_OF_PROCESSORS')


    def __init__(self, init_verbose=1, default_knobs=True):
        """Build up the environment for compilation.
        """
        set_verbosity(int(init_verbose))
        self.env = {}
        self.parsed_args = False
        self.added_common_knobs=False
        self.added_default_knobs=False
        self.env['python'] = sys.executable
        self.env['CPPPATH'] = []
        self.env['SYSTEMINCLUDE'] = []
        self.env['DEFINES'] = {}
        
        self.env['LINKPATH'] = []
        self.env['LINKDIRS'] = ''
        self.env['LINKFLAGS'] = ' %(LINKDIRS)s '
        
        self.env['targets'] = []

        # defaults for the build dir and src dir
        self.env['build_dir'] = 'obj'
        self.env['src_dir'] = '' # we set this accordingly
        self.env['gen_dir'] = None # location of generated files that do not exist
        self.env['shared'] = False
        self.env['static'] = False
        self.env['debug'] = False
        self.env['separate_pdb_files'] = False
        self.env['opt'] = 'noopt'

        self.env['LIBS'] = '' # default link libraries
        self.env['CXX_COMPILER'] = ''
        self.env['CC_COMPILER'] = ''
        self.env['ASSEMBLER'] = ''
        self.env['LINKER'] = ''


        # windows rc tool for dll resource files.
        self.env['RC'] = ''
        self.env['RC_CMD'] = ''
        self.env['RCFLAGS'] = ''

        # use_compiler_to_link = True if using the compiler to link.
        # use_compiler_to_link = False if using the linker to link
        self.env['use_compiler_to_link'] = False
        self.env['ARCHIVER'] = ''
        self.env['RANLIB_CMD'] = ''

        self.env['CXX'] = ''
        self.env['CC'] = ''
        self.env['LINK'] = ''
        self.env['AR'] = ''
        self.env['AS'] = ''
        self.env['RANLIB'] = ''

        # python3.9 breaks copy.deepcopy() of platform.uname() return
        # values so we make our own.
        self.env['uname'] = ( platform.system(),
                              platform.node(),
                              platform.release(),
                              platform.version(),
                              platform.machine() )
            
        self.env['hostname'] = platform.node()
        self.env['system'] = platform.system() # sort of like build_os
        
        # distro is the empty string on mac and windows
        distro = ''
        distro_ver = ''
        if  not self.on_mac()  and   not self.on_windows():
            if util.check_python_version(3,8):
                # With python 3.8 one needs to install the python "distro"
                # package to obtain the linux distro information. I do not
                # want to require users to install a non-default package
                # so we'll have to live without the distro information.
                # People who require it can "python3 -m pip install distro"
                try:
                    import distro
                    (distro, distro_ver, distro_id) = distro.linux_distribution()
                except:
                    distro = "linux-unknown"
                    distro_ver = "unknown"

            elif util.check_python_version(2,6):
                (distro, distro_ver, distro_id) = platform.linux_distribution()

        self.env['distro'] = distro.strip()
        self.env['distro_version'] = distro_ver


        if 'HOME' in os.environ:
            self.env['home'] = os.environ['HOME']
        elif self.on_windows() and 'USERPROFILE' in os.environ:
            self.env['home'] = os.environ['USERPROFILE']
        else:
            self.env['home'] = 'unknown'

        # the colons in the time string are replaced by underscores.
        # The colons confused xemacs compilation mode error
        # parsing. (emacs was fine)

        self.env['start_time_str'] = re.sub(":","_",util.get_time_str())
        self.start_time = util.get_time()
        
        #Old versions of mbuild used target_cpu erroneously instead of
        #host_cpu. We do a little magic later to try to make those old
        #uses continue to work.
        self.env['target_cpu']=None
        
        if self.env['system'] in [ 'Linux', 'FreeBSD', 'NetBSD']:
            uname = platform.uname() 
            self.env['build_os']  = self._normalize_os_name(uname[0])

            self.env['build_cpu'] = \
                  self._normalize_cpu_name(uname[4])

        elif self.env['system'] in [ 'Darwin']:
            uname = platform.uname() 
            self.env['build_os']  = self._normalize_os_name(uname[0])
            x = uname[4]
            if self._check_mac_64b():
                x = 'x86_64'
            self.env['build_cpu'] = \
                  self._normalize_cpu_name(x)
        elif self.on_windows():
            self.env['build_os']  = self._normalize_os_name(os.environ['OS'])
            if 'PROCESSOR_IDENTIFIER' in os.environ:
                p = os.environ['PROCESSOR_IDENTIFIER']
            else:
                p = self._check_processor_identifier_windows()
            self.env['build_cpu'] = \
                  self._normalize_cpu_name(p)

        else:
            die("Unknown platform")

        # where the compiled thing runs, not where it is built
        # but that is the starting default.
        self.env['host_cpu'] = self.env['build_cpu']
        self.env['host_os']  = self.env['build_os']

        self._add_compilation_support()


        self._emitted_startup_msg = False

        mbuild_env_defaults = dict(
            args = [],
            mbuild_version=False,
            jobs='4',
            build_dir='obj',
            src_dir='',
            gen_dir=None,
            verbose= -1,
            arg_host_cpu=None,
            arg_host_os=None,
            compiler=self.default_compiler(),
            debug=False,
            shared=False,
            static=False,
            opt='noopt',
            silent=False,
            extra_defines=[],
            extra_flags=[],
            extra_cxxflags=[],
            extra_ccflags=[],
            extra_linkflags=[],
            extra_libs=[],
            toolchain='',
            ignorable_files=[], # deprecated, unused 2011-10-20
            required_files=[],
            vc_dir='',
            msvs_version='',
            setup_msvc=False,
            icc_version='',
            gcc_version='',
            cc='',
            cxx='',
            linker='',
            ar='',

            use_yasm=False,
            cygwin_limit_jobs=True
            )
        
        # as is a keyword so must set it separately
        mbuild_env_defaults['as']=''

        # store the default if we ever need them
        self.env_defaults = mbuild_env_defaults
        # put them in the initial environment
        self.update_dict(mbuild_env_defaults)

        self.parser = optparse.OptionParser()
        # set the defaults in the command line option parser
        self.parser.set_defaults(**mbuild_env_defaults)

        if default_knobs:
            self.add_common_knobs()                    
            self.add_default_knobs()            


    def add_common_knobs(self):
        if self.added_common_knobs:
            return
        self.added_common_knobs=True
        self.parser.add_option(
            "-j", "--jobs",
            dest="jobs",
            action="store",
            help="Number of concurrent worker threads to use.")

    def add_default_knobs(self):
        if self.added_default_knobs:
            return
        self.added_default_knobs=True
        self.parser.add_option(
            "--mbuild-version",
            dest="mbuild_version",
            action="store_true",
            help="Emit the version information")
        self.parser.add_option(
            "--build-dir",
            dest="build_dir",
            action="store",
            help="Build directory, default is 'obj'")
        self.parser.add_option(
            "--src-dir",
            action="store",
            dest="src_dir",
            help="The directory where the sources are located.")
        self.parser.add_option(
            "--gen-dir",
            action="store",
            dest="gen_dir",
            help="The directory where generated sources are assumed" + 
            " to be located.")
        self.parser.add_option(
            "-v",
            "--verbose",
            action="store",
            dest="verbose",
            help="Verbosity level. Defaults to value passed to env_t()")
        self.parser.add_option(
            "--compiler",
            dest="compiler",
            action="store",
            help="Compiler (ms,gnu,clang,icc,icl,iclang)." +
                 " Default is gnu on linux and" + 
                 " ms on windows. Default is: %s" % (self.default_compiler()))
        self.parser.add_option(
            "--debug",
            dest="debug",
            action="store_true",
            help="Debug build")
        self.parser.add_option(
            "--shared",
            dest="shared",
            action="store_true",
            help="Shared DLL build")
        self.parser.add_option(
            "--static",
            dest="static",
            action="store_true",
            help="Statically link executables")
        self.parser.add_option(
            "--opt",
            dest="opt",
            action="store",
            help="Optimization level noopt, 0, 1, 2, 3")
        self.parser.add_option(
            "-s",
            "--silent",
            dest="silent",
            action="store_true",
            help="Silence all but the most important messages")
        self.parser.add_option(
            "--extra-defines",
            dest="extra_defines",
            action="append",
            help="Extra preprocessor defines")
        self.parser.add_option(
            "--extra-flags",
            dest="extra_flags",
            action="append",
            help="Extra values for CXXFLAGS and CCFLAGS")
        self.parser.add_option(
            "--extra-cxxflags",
            dest="extra_cxxflags",
            action="append",
            help="Extra values for CXXFLAGS")
        self.parser.add_option(
            "--extra-ccflags",
            dest="extra_ccflags",
            action="append",
            help="Extra values for CCFLAGS")
        self.parser.add_option(
            "--extra-linkflags",
            dest="extra_linkflags",
            action="append",
            help="Extra values for LINKFLAGS")
        self.parser.add_option(
            "--extra-libs",
            dest="extra_libs",
            action="append",
            help="Extra values for LIBS")
        self.parser.add_option(
            "--toolchain",
            dest="toolchain",
            action="store",
            help="Compiler toolchain")
        self.parser.add_option(
            "--vc-dir",
            dest="vc_dir",
            action="store",
            help="MSVS Compiler VC directory. For finding libraries " + 
            " and setting the toolchain")
        self.parser.add_option(
            '--msvs-version',
            '--msvc-version',
            '--msvsversion',
            '--msvcversion',
            dest='msvs_version',
            action='store',
            help="MSVS version 6=VC98, 7=VS .Net 2003, 8=VS 2005, " + 
            "9=VS2008, 10=VS 2010/DEV10, 11=VS2012/DEV11, 12=VS2013, " +
            "14=VS2015, 15=VS2017, 16=VS2019, 17=VS2022. " +
            "This sets certain flags and idioms for quirks in some compilers.")
        self.parser.add_option(
            '--setup-msvc',
            '--setup-msvs',
            '--msvs-setup',
            '--msvc-setup',
            dest='setup_msvc',
            action='store_true',
            help="Use the value of the --msvc-version to initialize" +
            " the MSVC configuration.")
        self.parser.add_option(
            '--icc-version',
            '--iccver',
            '--icc-ver',
            dest='icc_version',
            action='store',
            help="ICC/ICL version 7, 8, 9, 10, 11")
        self.parser.add_option(
            '--gcc-version',
            '--gccversion',
            '--gcc-ver',
            dest='gcc_version',
            action='store',
            help="GCC version, with dots as in 2.96, 3.4.3, 4.2.0, etc. ")

        self.parser.add_option(
            "--cc",
            dest="cc",
            action="store",
            help="full path to C compiler")
        self.parser.add_option(
            "--cxx",
            dest="cxx",
            action="store",
            help="full path to C++ compiler")
        self.parser.add_option(
            "--linker",
            dest="linker",
            action="store",
            help="full path to linker")
        self.parser.add_option(
            "--ar",
            dest="ar",
            action="store",
            help="full path to archiver (lib/ar)")
        self.parser.add_option(
            "--as",
            dest="as",
            action="store",
            help="full path to assembler (gas/as/ml/ml64)")

        self.parser.add_option(
            "--yasm",
            dest="use_yasm",
            action="store_true",
            help="Use yasm")
        self.parser.add_option(
            "--no-cygwin-limit",
            dest="cygwin_limit_jobs",
            action="store_false",
            help="Do not limit cygwin to one job at a time. " +
            " Default is to limit cygwin to one job.")

        self.parser.add_option(
            "--host-cpu",
            dest="arg_host_cpu",
            action="store",
            help="Host CPU, typically ia32, intel64 or x86-64")

        self.parser.add_option(
            "--host-os",
            dest="arg_host_os",
            action="store",
            help="Host OS (where the binary runs)")

    def _implied_compiler(self,dct):
        """If one of the icc_version, gcc_version_ or msvs_version
        variables are set, deduce the compiler variable setting."""

        # windows default is ms so no need to set that.
        if dct['icc_version'] != '':
            if self.on_windows():
                dct['compiler'] = 'icl'
            else:
                dct['compiler'] = 'icc'
        if dct['gcc_version'] != '':
            dct['compiler'] = 'gnu'

    def _check_mac_ncpu(self):
        """How many CPUs on a mac"""
        
        cmd = "/usr/sbin/sysctl hw.ncpu"
        (retval,output, error_output) = util.run_command(cmd)
        if retval == 0 and len(output)>0:
            if re.match('hw.ncpu', output[0]):
                n = int(re.sub('hw.ncpu: ','',output[0]))
                return n
        return 0
    
    def number_of_cpus(self):
        """Return the number of CPUs or 0 if we don't know anything for sure"""
        n = 0 
        if self.on_mac():
            n = self._check_mac_ncpu()
        elif self.on_windows():
            ns = "NUMBER_OF_PROCESSORS"
            if ns in os.environ:
                nsv = os.environ[ns]
            else:
                nsv = self._check_number_of_processors_windows()
            n = int(nsv)
        elif self.on_freebsd():
            getconf = "/usr/bin/getconf"
            if os.path.exists(getconf):
                cmd = "%s NPROCESSORS_ONLN" % (getconf)  # or NPROCESSORS_CONF
                (retval, output, error_output) = util.run_command(cmd)
                if retval == 0 and len(output)>0:
                    n = int(output[0])
        elif self.on_netbsd():
            sysctl = "/sbin/sysctl"
            if os.path.exists(sysctl):
                cmd = "%s -n hw.ncpuonline" % (sysctl)
                (retval, output, error_output) = util.run_command(cmd)
                if retval == 0 and len(output)>0:
                    n = int(output[0])
        else:
            f = '/proc/cpuinfo'
            proc_pat= re.compile(r'proces')
            if os.path.exists(f):
                for line in open(f,'r'):
                    if proc_pat.search(line):
                        n += 1
        return n

    def update_dict(self, dct):
        """Update the environment dictionary with another dictionary."""
        self.env.update(dct)

    def copy_settings(self, incoming_env, kwds, replace=False):
        
        """Update the environment dictionary with elements of kwds
        from the dictionary in the incoming_env. Lists are extended with the
        incoming elements and other types of elements are assigned directly.

        @type incoming_env: env_t
        @param incoming_env: the source environment

        @type kwds: list of strings
        @param kwds: elements to copy from the source enviornment

        @type replace: bool
        @param replace: if True, replace lists in the source environment
        """
        for k in kwds:
            if k in incoming_env:
                t = incoming_env[k]
                if  isinstance(t,list) and replace==False:
                    self.env[k].extend(t)
                else:
                    self.env[k] = t
            else:
                die("copy_settings() could not read key %s from incoming environment" % k)
        
    def update(self, targets=None):
        """Post process the current environment, setting targets and bindings"""

        # if the dct['args'] exists, supplement the targets list with
        # that. This is how non-command-line invocations of mbuild
        # pass the "other stuff"
        if targets == None:
            targets = []
            
        if not isinstance(targets,list):
            die("The 'targets' environment option must be a list")

        if 'args' in self.env:
            args = self.env['args']
            if isinstance(args,list):
                targets.extend(args)
            else:
                die("The 'args' environment option must be a list")
            
        # split up the targets list so we can extract the command line
        # variable bindings
        just_targets = []
        bindings = []
        for t in targets:
            ap = env_t.assignment_pattern.match(t)
            if ap:
                msgb("BINDING", "%s --> [%s]" % 
                     (ap.group('name'), ap.group('value')))
                bindings.append( (ap.group('name'), 
                                  ap.group('value'), 'equals' ))
                continue
            sp = env_t.supplement_pattern.match(t)
            if ap:
                msgb("BINDING", "%s --> [%s]" % 
                     (ap.group('name'), ap.group('value')))
                bindings.append( (ap.group('name'), 
                                  ap.group('value'), 'plusequals') )
                continue
            just_targets.append(t)

        # add command line variable bindings to the environment
        for (var,value, how) in bindings:
            if how == 'equals':
                self.env[var] = value
                
                # early versions of mbuild used target_cpu instead of
                # host_cpu. This next override compensates for that,
                # compatibility with older clients.
                if var == 'target_cpu':
                    self.env['host_cpu'] = value
                    
            elif how == 'plusequals':
                self.add_to_var(var,value)
        
        # give precidence to the knob for --host-cpu and --host-os
        # over the default binding.
        if self.env['arg_host_cpu']:
            self.env['host_cpu'] = self.env['arg_host_cpu']
        if self.env['arg_host_os']:
            self.env['host_os'] = self.env['arg_host_os']
            
        # make sure we understand what host cpu we are dealing
        # with. If someone puts in an Intel64 it'll come out as
        # x86-64.

        self.env['host_cpu'] = self._normalize_cpu_name(self.env['host_cpu'])
        self.env['host_os'] = self._normalize_os_name(self.env['host_os'])
        self.add_to_var('targets',just_targets)

        # old versions of mbuild used target_cpu. To allow them to
        # continue to work, we copy target_cpu to host_cpu if
        # target_cpu is non null and differs from the setting for the
        # host_cpu and the host_cpu is the same as the build_cpu. If
        # the host_cpu and build_cpu differ, someone must have set
        # host_cpu so leave it alone in that case.
        
        if self.env['target_cpu']:
            if self.env['target_cpu'] != self.env['host_cpu']:
                # build_cpu and host_cpu start out the same, so only
                # change host_cpu if it has the original value.
                if self.env['build_cpu'] == self.env['host_cpu']:
                    self.env['host_cpu'] = self.env['target_cpu']


    def process_user_settings(self):
        """Set the initial derived environment settings"""

        self.update()
        
        if self.env['mbuild_version']:
            self.version()
            sys.exit(0)

        self._implied_compiler(self.env)

        if self.env['silent']:
            set_verbosity(0)
        else:
            arg_verbosity = int(self.env['verbose'])
            if arg_verbosity >= 0:
                set_verbosity( arg_verbosity ) 
        self.verbose_startup()

        # convert several of the lists to strings
        for f in ['extra_cxxflags', 'extra_ccflags', 'extra_linkflags',
                  'extra_libs', 'extra_flags']:
            self._flatten_list_to_string(f,self.env)
        # distribute the "extra" flags.
        if self.env['extra_flags']:
            self.env['extra_cxxflags'] += ' ' + self.env['extra_flags']
            self.env['extra_ccflags']  += ' ' + self.env['extra_flags']

        # This starts the compilation environment off CLEAN
        self.set_compiler_env()

        # if the user did not use --src-dir, then we check the path to
        # the mbuild script. If it there is no path, we assume we are
        # in the right directory. If there is a path, we assume that
        # is where the sources are, and change the option before anyone
        # can see it.
        if self.env['src_dir'] == '':
            (path_to_src, this_file) = os.path.split(sys.argv[0])
            if path_to_src == '':
                path_to_src = '.'
            self.env['src_dir'] = util.posix_slashes(path_to_src)

        # This works around a longstanding python-specific bug in
        # cygwin with running multiple threads.
        if self.on_windows():
            try:
                import win32api # we don't use it. We just test for it.
            except:
                if self.env['cygwin_limit_jobs'] and self.on_cygwin():
                    msgb('NOTE', 
                         'Using just one worker thread to avoid' + \
                         ' a cygwin threading problem.')
                    self.env['jobs'] = "1"

        # if 0 jobs were specified, try to use 2x the number of cpus.
        if self.env['jobs'] == '0':
            n = self.number_of_cpus()
            if n:
                self.env['jobs'] = str(2*n)
                msgb('NOTE', 
                     'Setting jobs to %d, 2x the detected number of CPUs (%d)' %
                     (2*n,n))
            else:
                self.env['jobs'] = "1"
                msgb('NOTE', 
                     'Setting jobs to 1 because we could not detect' + 
                     ' the number of CPUs')
                
        if verbose(2):
            # print host_cpu here because it may be overridden for
            # cross compilations
            msgb("HOST_CPU", self.env['host_cpu'])
            


        
    def _flatten_list_to_string(self, field, dct):
        """See if options has a field named field. If it does and its
        value is a list, flatten the list, joining the substrings with
        spaces."""
        if field in dct:
            v = dct[field]
            if isinstance(v,list):
                vflat = ' '.join(v)
                dct[field]= vflat

    def set_defaults(self, dct):

        """Take the dictionary of defaults and apply to the
        environment. Any extra bindings and targets should be listed
        in the 'args' list option of the dictionary"""

        self.parser.set_defaults(**dct)
        self.update_dict(dct)


        
    def parse_args(self, user_default_options=None):
        """Call this to re-initialize the environment from the command
        line arguments. This calls update() with the results of
        command line processing.
        @type  user_default_options: dict
        @param user_default_options: dictionary of default options
        """
        
        # make parse_args() runnable only once per environment.
        # ("append"-mode arguments get messed up if args parsed
        # more than once.)
        if self.parsed_args:
            return
        self.parsed_args=True

        if user_default_options:
            # pass a dictionary where keyword args are expected using
            # "**" SEE:
            # http://docs.python.org/tut/node6.html#SECTION006740000000000000000
            self.parser.set_defaults(**user_default_options)

        (options, args) =  self.parser.parse_args()
        dct = vars(options)
        dct['args'].extend(args)
        self.update_dict(dct)

        self.process_user_settings()
        

    def on_ipf(self):
        """@rtype: bool
           @return:  True iff on IA64"""
        if self.env['build_cpu'] == 'ipf':
            return True
        return False
        
    def on_ia32(self):
        """@rtype: bool
           @return:  True iff on IA32"""
        if self.env['build_cpu'] == 'ia32':
            return True
        return False

    def on_intel64(self):
        """@rtype: bool
           @return:  True iff on Intel64"""
        if self.env['build_cpu'] == 'x86-64':
            return True
        return False

    def on_mac(self):
        """@rtype: bool
           @return:  True iff on Mac OSX Darwin"""
        if self.env['system'] == 'Darwin':
            return True
        return False

    def mac_ver(self):
        val = [0]*3
        if self.on_mac():
           version_string = platform.mac_ver()[0]
           chunks = version_string.split('.')
           for i,c in enumerate(chunks):
               val[i]=int(c)
        return tuple(val)

    def check_mac_ver(self, x,y,z):
        """@rtype: bool
           @return:  True iff on a mac and the version is later than x.y.z"""
        if self.on_mac():
            (maj,min,rev) = self.mac_ver()
            if x > maj:
                return False
            if x == maj and y > min:
                return False
            if x == maj and y == min and z > rev:
                return False
            return True
        return False

    def on_tiger(self):
        """@rtype: bool
           @return:  True iff on Mac running OS X Tiger 10.4.x"""
        if self.check_mac_ver(10,4,0):
            return True
        return False
    def on_leopard(self):
        """@rtype: bool
           @return:  True iff on Mac running OS X Leopard 10.5.x"""
        if self.check_mac_ver(10,5,0):
            return True
        return False

    def on_freebsd(self):
        """@rtype: bool
           @return:  True iff on freebsd"""
        if self.env['system'] == 'FreeBSD':
            return True
        return False

    def on_netbsd(self):
        """@rtype: bool
           @return:  True iff on netbsd"""
        if self.env['system'] == 'NetBSD':
            return True
        return False

    def on_linux(self):
        """@rtype: bool
           @return:  True iff on linux"""
        if self.env['system'] == 'Linux':
            return True
        return False

    def on_cygwin(self):
        """@rtype: bool
           @return:  True iff on cygwin"""
        if len(self.env['system']) >= 6 and self.env['system'][0:6] == 'CYGWIN':
            return True
        return False

    def windows_native(self):
        """@rtype: bool
           @return:  True iff on windows native -- not using cygwin"""
        if self.env['system'] == 'Windows' or self.env['system'] == 'Microsoft':
            return True
        return False

    def on_windows(self):
        """@rtype: bool
           @return:  True iff on windows"""
        if self.windows_native():
            return True
        return self.on_cygwin()

    def supports_avx(self):
        """Return True if system supports AVX1. Does not work
        on windows"""
        if self.on_linux():
            with open('/proc/cpuinfo','r') as fp:
                for l in fp:
                    if 'avx' in l:
                        return True
        elif self.on_mac():
            cmd = "/usr/sbin/sysctl hw.optional.avx1_0"
            (retval, output, error_output) = util.run_command(cmd)
            if retval == 0 and len(output)>0:
                if re.match('hw.optional.avx1_0: 1', output[0]):
                    return True

        # FIXME: find some way of doing this on windows
        return False

    def _check_mac_64b(self):
        """Check to see if a mac is 64b"""
        
        cmd = "/usr/sbin/sysctl hw.optional.x86_64"
        (retval,output, error_output) = util.run_command(cmd)
        if retval == 0 and len(output)>0:
            if re.match('hw.optional.x86_64: 1', ensure_string(output[0])):
                return True
        return False
    
    def _normalize_cpu_name(self, name):
        """Internal function. Standardize various CPU identifiers"""
        if name in ['ia32', 'i386', 'i686','x86']:
            return 'ia32'
        elif name in ['ia32e', 'x86_64', 'amd64',
                      'x86-64', 'Intel64','intel64']:
            return 'x86-64'
        elif name == 'ia64':
            return 'ipf'
        elif name[0:5] == 'EM64T':
            return 'x86-64'
        elif name[0:7] == 'Intel64':
            return 'x86-64'
        elif name == 'intel64':
            return 'x86-64'
        elif name[0:5] == 'AMD64':
            return 'x86-64'
        elif name[0:3] == 'x86':
            return 'ia32'
        elif name in ['aarch64', 'arm64']:
            return 'aarch64'
        else:
            die("Unknown cpu " + name)

    def _normalize_os_name(self,name):
        """Internal function. Standardize various O/S identifiers"""
        if name in  ['android']:
            return 'android'
        elif name in ['lin', 'Linux']:
            return 'lin'
        elif name in ['mac', 'Darwin']:
            return 'mac'
        elif name in ['bsd', 'FreeBSD', 'NetBSD']:
            return 'bsd'
        elif name[0:6] == 'CYGWIN':
            return 'win'
        elif name in ['win', 'Windows_NT']:
            return 'win'
        else:
            die("Unknown os " + name)

    def default_compiler(self):
        """Default to ms on windows and gnu everywhere else.
        @rtype: string
        @returns: "ms" on windows, "clang" on mac, otherwise "gnu"
        """
        if self.on_windows():
            return "ms"
        if self.on_mac():
            return "clang"
        return "gnu"

    def set_compiler_env(self, compiler_family=None):
        """Initialize the build environment based on the compiler
        environment variable setting. 

        Adds in the "extra" flags from the environment.

        @type compiler_family: string
        @param compiler_family: an override for the default 
                       compiler family (gnu, ms, clang, icl, icc, iclang)
        """


        # copy the command line version of the tool overrides to the
        # real ones that we use.

        if self.env['cxx'] != '':
            self.env['CXX'] = self.env['cxx']
        if self.env['cc'] != '':
            self.env['CC'] = self.env['cc']
        if self.env['linker'] != '':
            self.env['LINK'] = self.env['linker']
        if self.env['ar'] != '':
            self.env['AR'] = self.env['ar']
        if self.env['as'] != '':
            self.env['AS'] = self.env['as']
            
        if compiler_family == None:
            if 'compiler' in self.env:
                self.env['compiler'] = self.env['compiler'].lower()
                compiler_family = self.env['compiler']
            else:
                die("Compiler family not specified in the environment or as an argument")

        if compiler_family == 'gnu':
            build_env.set_env_gnu(self)
        elif compiler_family == 'clang':
            build_env.set_env_clang(self)
        elif compiler_family == 'ms':
            build_env.set_env_ms(self)
        elif compiler_family == 'icc':
            build_env.set_env_icc(self)
        elif compiler_family == 'iclang':
            build_env.set_env_iclang(self)
        elif compiler_family == 'icl':
            build_env.set_env_icl(self)
        else:
            die("Compiler family not recognized. Need gnu or ms")

        if self.env['use_yasm']:
            if verbose(2):
                msgb("USE YASM")
            build_env.yasm_support(self)

        self.add_to_var('CXXFLAGS',  self.env['extra_cxxflags'])
        self.add_to_var('CCFLAGS', self.env['extra_ccflags']  )
        self.add_to_var('LINKFLAGS',  self.env['extra_linkflags'] )
        self.add_to_var('LIBS',  self.env['extra_libs'] )
        for d in self.env['extra_defines']:
            self.add_define(d)
            
    def resuffix(self, fn, newext):
        """Replace the suffix of single fn (or list of files) with
        newext. newext should supply its own dot if you want one.
        @type  fn: string (or list of strings)
        @param fn: a filename
        @type  newext: string
        @param newext: a new extension starting with a '.'
        @rtype: string
        @return: fn with a new suffix specified by newext
        """
        if isinstance(fn,list):
            return [self.resuffix(x,newext) for x in fn]
        else:
            (root,ext) = os.path.splitext(fn)
            return root + newext

    def osenv_add_to_front(self,evar,newstring,osenv=None):
        """Add newstring to front of the environment variable osenv if given
           if not given add to os.environ """
        environ = os.environ
        if osenv:
            environ = osenv 
        
        if self.on_windows():
            sep  = ';' 
        else:
            sep  = ':' 
        if evar in environ:
            # The environment variable already exists
           environ[evar]= newstring + sep + environ[evar]
        else:
            # Support creation of a new environment variable
            environ[evar]= newstring

    def path_search(self,exe):
        path = os.environ['PATH']
        if self.on_freebsd() or self.on_linux() or self.on_cygwin() or self.on_netbsd():
            sep = ':'
        else:
            sep = ';'
        for p in path.split(sep):
            t = util.prefix_files(p,exe)
            if os.path.exists(t):
                return t
        return None

        
    def make_obj(self,flist):
        """Take file or list of files and return a file or list of
        files with the OBJEXT extension from the environment.
        @type  flist: string or list of strings
        @param flist: a filename (or list of filenames)
        @rtype: string
        @return: fn with a suffix specified %(OBJEXT)s
        """
        return self.resuffix(flist,"%(OBJEXT)s")


    def build_dir_join(self,files):
        """Make the file (or list of files) with the build
        directory name.
        
        @type files: string or list of strings
        @param files: filename(s)

        @rtype: string or list of strings
        @return: filenames prepended with the current build_dir
        """

        # FIXME: could do this lazily... and just prepend %(build_dir)s
        try:
            objdir = self.env['build_dir']
        except:
            die("build_dir not defined in build_dir_join")
        if objdir == '':
            return files
        return util.prefix_files(objdir, files)

    def src_dir_join(self,files):
        """Prefix file (or list of files) with the src directory name.
        @type files: string or list of strings
        @param files:  filename(s)

        @rtype: string or list of strings
        @return: filenames prepended with the current src_dir
        """
        # FIXME: could do this lazily... and just prepend %(src_dir)s
        try:
            srcdir = self.env['src_dir']
        except:
            die("src_dir not defined in src_dir_join")
        if srcdir == '':
            return files
        return util.prefix_files(srcdir, files)

    def add_define(self,newdef):
        """Add a define or list defines to the CXXFLAGS and CCFLAGS 
        @type newdef: string or list of strings
        @param newdef: string to add to the CXXFLAGS and CCFLAGS 
                       environment variables.
        """
        self.add_cc_define(newdef)
        self.add_cxx_define(newdef)
        self.add_as_define(newdef)

    def _collect_defines(self, dlist):
        for d in dlist:
            if d not in self.env['DEFINES']:
                self.env['DEFINES'][d]=True

    def add_as_define(self,newdef):
        """Add a define or list defines to the ASFLAGS 
        @type newdef: string or list of strings
        @param newdef: string to add to the ASFLAGS 
                       environment variable.
        """
        if isinstance(newdef,list):
            deflist = newdef
        else:
            deflist = [ newdef ]
        self._collect_defines(deflist)
        for d in deflist:
            self.add_to_var('ASFLAGS', "%(ASDOPT)s" + d  )

    def add_cc_define(self,newdef):
        """Add a define or list defines to the CCFLAGS 
        @type newdef: string or list of strings
        @param newdef: string to add to the CCFLAGS 
                       environment variable.
        """
        if isinstance(newdef,list):
            deflist = newdef
        else:
            deflist = [ newdef ]
        self._collect_defines(deflist)

        for d in deflist:
            self.add_to_var('CCFLAGS', "%(DOPT)s" + d )

    def add_cxx_define(self,newdef):
        """Add a define or list defines to the CXXFLAGS 
        @type newdef: string or list of strings
        @param newdef: string to add to the CXXFLAGS 
                       environment variable.
        """
        if isinstance(newdef,list):
            deflist = newdef
        else:
            deflist = [ newdef ]
        self._collect_defines(deflist)
        for d in deflist:
            self.add_to_var('CXXFLAGS', "%(DOPT)s" + d  )

        
    def add_include_dir(self,include_dir):
        """Add a directory or list of directories to the CPPPATH. Just
        a short cut for adding things to the list of files in the
        env['CPPPATH']
        @type include_dir: string or list of strings
        @param include_dir: string to add to the CPPPATH environment variable
        """
        if isinstance(include_dir,list):
            lst = include_dir
        else:
            lst = [ include_dir ]
        for d in lst:
            p = util.posix_slashes(d)
            if p not in self.env['CPPPATH']:
                self.env['CPPPATH'].append(p)

    def add_system_include_dir(self,sys_include_dir):
        """Add a directory or list of directories to the SYSTEMINCLUDE. Just
        a short cut for adding things to the list of files in the
        env['SYSTEMINCLUDE']
        @type sys_include_dir: string or list of strings
        @param sys_include_dir: string to add to the SYSTEMINCLUDE environment variable
        """
        if isinstance(sys_include_dir,list):
            lst = sys_include_dir
        else:
            lst = [ sys_include_dir ]
        for d in lst:
            p = util.posix_slashes(d)
            if p not in self.env['SYSTEMINCLUDE']:
                self.env['SYSTEMINCLUDE'].append(p)

    def add_link_dir(self,link_dir):
        """Add a directory or list of directories to the LINKPATH. These
        get included in the LINKFLAGS

        @type link_dir: string or list of strings
        @param link_dir: string to add to the LINKPATH variable
        """
        if isinstance(link_dir,list):
            for d in link_dir:
                self.env['LINKPATH'].append(util.posix_slashes(d))
        else:
            self.env['LINKPATH'].append(util.posix_slashes(link_dir))


    def remove_from_var(self, var, value):
        """Remove a substring (or list entry) from env[var]. Opposite
        of add_to_var().

        @type var: string
        @param var: name of a dictionary key
        @type value: string 
        @param value: the value to remove
        """
        if var in self.env:
            if isinstance(self.env[var], list):
                try:
                    self.env[var].remove(value)
                except:
                    pass
            else:
                self.env[var] = re.sub(value,'',self.env[var])
            

    def add_to_var(self, var, value):
        """Add or append value to the environment variable var. If the
        variable is not in the environment, then it is added as
        is. Otherwise if the variable is in the environment and is a
        list then value is appended. Otherwise, the value is appended
        as a string with a leading space. This will *NOT* do variable
        substitution when adding to a variable.

        @type var: string
        @param var: name of a dictionary key
        @type value: string 
        @param value: the value to add or append

        """
        if var not in self.env:
            self.env[var]  = value
        elif isinstance(self.env[var],list):
            if isinstance(value, list):
                self.env[var].extend(value)
            else:
                self.env[var].append(value)
        else:
            self.env[var] += ' ' + value # This would do variable expansion when calling __getitem__
            
    # These strings should be % env expanded.

    # COUT should be  "-o " on linux. Note the trailing space
    # COPT should be "-c" on linux
    # OBJNAME and SRCNAME should be fully qualified suffix-wise
    # OBJNAMES is used for the link and lib statements
    # EXENAME is used for link statements
    # LIBNAME is used for lib statements
    # SOLIBNAME is used for shared objects "soname"  embedded names
    # LIBOUT, LINKOUT should be set appropriately. Trailing spaces needed on linux
    # DLLOPT is needed for dynamic libraries

    # Example:
    # a = '%(lang)s has %(c)03d quote types.' % dict(lang='Python', c=2)

    def _add_c_compile(self):
        s = "%(CC)s %(CPPINCLUDES)s %(SYSINCLUDES)s %(CCFLAGS)s %(COPT)s %(COUT)s%(OBJNAME)s %(SRCNAME)s"
        return s

    def _add_assemble(self):
        s = "%(AS)s %(CPPINCLUDES)s %(SYSINCLUDES)s %(ASFLAGS)s %(ASMOUT)s%(OBJNAME)s %(SRCNAME)s"
        return s

    def _add_cxx_compile(self):
        s = "%(CXX)s %(CPPINCLUDES)s %(SYSINCLUDES)s %(CXXFLAGS)s %(COPT)s %(COUT)s%(OBJNAME)s %(SRCNAME)s"
        return s

    def _add_link(self):
        s = "%(LINK)s %(LINKFLAGS)s %(LINKOUT)s%(EXENAME)s %(OBJNAMES)s %(LIBS)s"
        return s

    def _add_static_lib(self):
        s = [ _remove_libname,
              "%(AR)s %(ARFLAGS)s  %(LIBOUT)s%(LIBNAME)s %(OBJNAMES)s" ]
        return s

    def _add_dynamic_lib(self):
        s = "%(LINK)s %(LINKFLAGS)s %(DLLOPT)s  %(LIBOUT)s%(LIBNAME)s %(OBJNAMES)s %(LIBS)s"
        return s
    
    def _add_cxx_shared_lib(self):
        s = "%(CXX)s %(LINKFLAGS)s %(DLLOPT)s   %(COUT)s%(LIBNAME)s %(OBJNAMES)s %(LIBS)s"
        return s

    def _add_res_file_cmd(self):
        s = "%(RC)s %(RCFLAGS)s /fo%(RESNAME)s %(RCNAME)s"
        return s

    def _add_default_builders(self):
        """Private. Part of initialization for the environment. Sets
        the default builders"""

        # Instead use default function if these are not set.
        self.env['ASSEMBLE_BUILDER'] = None
        self.env['CXX_COMPILE_BUILDER'] = None
        self.env['CC_COMPILE_BUILDER'] = None
        self.env['LINK_BUILDER'] = None
        self.env['STATIC_LIBRARY_BUILDER'] = None
        self.env['DYNAMIC_LIBRARY_BUILDER'] = None
        self.env['RES_FILE_BUILDER'] = None
        
    def _add_default_builder_templates(self):
        """Private. Part of initialization for the environment. Sets
        the default templates used by the default builders"""
        self.env['CC_COMPILE_COMMAND'] = self._add_c_compile()
        self.env['CXX_COMPILE_COMMAND'] = self._add_cxx_compile()
        self.env['ASSEMBLE_COMMAND'] = self._add_assemble()
        self.env['LINK_COMMAND'] = self._add_link()
        self.env['STATIC_LIB_COMMAND'] = self._add_static_lib()
        self.env['DYNAMIC_LIB_COMMAND'] = self._add_dynamic_lib()
        self.env['CXX_SHARED_LIB_COMMAND'] = self._add_cxx_shared_lib()
        self.env['RES_FILE_COMMAND'] = self._add_res_file_cmd()

    def _add_compilation_support(self):
        """Private. Part of initialization for the environment. Sets
        the default builders and templates."""
        self._add_default_builders()
        self._add_default_builder_templates()

    def escape_string(self,s): 
        return util.escape_string(s)
    
    def _escape_list_of_strings(self,sl):
        n = []
        for s in sl:
            n.append(self.escape_string(s))
        return n

    def _make_cpp_include(self):
        s = []
        
        iopt = self.env['IOPT']
            
        for p in self.env['CPPPATH']:
            s.extend([iopt, self.escape_string(p), ' '])
        return ''.join(s)

    def _make_system_include(self):
        s = []
        iopt = self.env['ISYSOPT']
        for p in self.env['SYSTEMINCLUDE']:
            s.extend([iopt, self.escape_string(p), ' '])
        return ''.join(s)

    def _make_link_dirs(self):
        s = []
        lopt = self.env['LOPT']
        for p in self.env['LINKPATH']:
            s.extend([lopt, self.escape_string(p), ' '])
        return ''.join(s)

    def _make_cpp_flags(self):
        self.env['CPPINCLUDES'] = self._make_cpp_include()
    def _make_sys_include_flags(self):
        self.env['SYSINCLUDES'] = self._make_system_include()
    def _make_link_flags(self):
        self.env['LINKDIRS'] = self._make_link_dirs()

    def make_derived_flags(self):
        """Put together any derived flags. This is required to be
        called by builder functions before they do their expansion.
        """
        
        self._make_cpp_flags()
        self._make_sys_include_flags()
        self._make_link_flags()


        
    def assemble(self, source, obj=None):
        """Indirection function. Reads builder function from the
        environment variable ASSEMBLER_BUILDER. Assemble a source file
        to the obj file. If no obj file name is given one will be
        created in the build directory.
        @type source: string
        @param source: filename to assemble
        
        @type obj: string
        @param obj: output filename.

        @rtype: L{plan_t}
        @return: an input for the DAG
        """
        # FIXME abspath breaks windows compilation under cygwin python
        new_source = os.path.abspath(source)

        f= self.env['ASSEMBLE_BUILDER']
        if f:
            return f(new_source,obj)
        return self._assemble_default(new_source,obj)

    def cxx_compile(self, source, obj=None):
        """Indirection function. Reads builder function from the
        environment variable CXX_COMPILE_BUILDER. C++-compile a source
        file to a file called obj. If no obj file name is given one
        will be created in the build directory.
        @type source: string
        @param source: filename to compile
        
        @type obj: string
        @param obj: output filename.

        @rtype: L{plan_t}
        @return: an input for the DAG
        """
        # FIXME abspath breaks windows compilation under cygwin python
        new_source = os.path.abspath(source)

        f = self.env['CXX_COMPILE_BUILDER']
        if f:
            return f(new_source,obj)
        return self._cxx_compile_default(new_source,obj)
    
    def cc_compile(self, source, obj=None):
        """Indirection function. Reads builder function from the
        environment variable CC_COMPILE_BUILDER. C-compile a source
        file to a file named obj. If no obj file name is given one
        will be created in the build directory.
        @type source: string
        @param source: filename to compile
        
        @type obj: string
        @param obj: output filename.

        @rtype: L{plan_t}
        @return: an input for the DAG
        """

        # FIXME abspath breaks windows compilation under cygwin python
        new_source = os.path.abspath(source)

        f = self.env['CC_COMPILE_BUILDER']
        if f:
            return f(new_source,obj)
        return self._cc_compile_default(new_source,obj)
    
    def link(self, objs, exename, relocate=False):
        """Indirection function. Reads builder function from the
        environment variable LINK_BUILDER. Link an executable from
        objs. If relocate is True, then prefix exename with the build
        directory name.
        @type objs: list of strings
        @param objs: filenames to link
        
        @type exename: string
        @param exename: output filename.

        @type relocate: bool
        @param relocate: If true, relocate the exename to the build directory.

        @rtype: L{plan_t}
        @return: an input for the DAG

        """
        f = self.env['LINK_BUILDER']
        if f:
            return f(objs,exename, relocate)
        return self._link_default(objs,exename,relocate)

    def static_lib(self, objs, libname, relocate=False):
        """Indirection function. Reads builder function from the
        environment variable STATIC_LIBRARY_BUILDER. Make a static
        library libname from objs. If relocate is True, then prefix
        libname with the build directory name

        @type objs: list of strings
        @param objs: filenames to link
        
        @type libname: string
        @param libname: output filename.

        @type relocate: bool
        @param relocate: If true, relocate the library to the build directory.

        @rtype: L{plan_t}
        @return: an input for the DAG


        """
        f = self.env['STATIC_LIBRARY_BUILDER']
        if f:
            return f(objs,libname, relocate)
        return self._static_lib_default(objs,libname,relocate)

    def compile_and_static_lib(self, dag, sources, libname):
        """Build all the sources by adding them to the dag. Use the
        suffixes to figure out how to handle the files. The dag can be
        passed to a work queue. See the build function. """

        # Compile
        objs = self.compile(dag, sources)
    
        # Link the lib
        dag.add(self, self.static_lib(objs, libname, relocate=True))

    def dynamic_lib_name(self, base):
        return self.shared_lib_name(base)

    def shared_lib_name(self, base):
        if self.on_windows():
            s = '{}%(DLLEXT)s'.format(base)
        else:
            s = 'lib{}%(DLLEXT)s'.format(base)
        return s
    def static_lib_name(self, base):
        if self.on_windows():
            s = '{}%(LIBEXT)s'.format(base)
        else:
            s = 'lib{}%(LIBEXT)s'.format(base)
        return s

    def dynamic_lib(self, objs, libname, relocate=False):
        """Indirection function. Reads builder function from the
        environment variable DYNAMIC_LIBRARY_BUILDER. Make a dynamic
        library libname from objs. If relocate is True, then prefix
        libname with the build directory name
        
        @type objs: list of strings
        @param objs: filenames to link
        
        @type libname: string
        @param libname: output filename.

        @type relocate: bool
        @param relocate: If true, relocate the library to the build directory.

        @rtype: L{plan_t}
        @return: an input for the DAG

        """
        f = self.env['DYNAMIC_LIBRARY_BUILDER']
        if f:
            return f(objs,libname, relocate)
        return self._dynamic_lib_default(objs,libname,relocate)


    def rc_file(self, rc_file, res_file=None):
        """Indirection function. For making RES files 
        from RC files on windows.
        
        @type rc_file: string
        @param rc_file: filename for RC file
        
        @type res_file: string
        @param res_file: filename for RES file

        """
        f = self.env['RES_FILE_BUILDER']
        if f:
            return f(rc_file, res_file)
        return self._res_file_builder_default(rc_file, res_file)

    def _escape_dict(self, d):
        file_name_keys = ['SRCNAME','OBJNAME', 'LIBNAME', 
                          'SOLIBNAME', 'EXENAME', 
                          'RCNAME', 'RESNAME' ]
        for k in file_name_keys:
            if k in d:
                d[k] = self.escape_string(d[k])
                
    def _assemble_default(self, source, obj=None):
        """Assemble a source file to the obj file. If no obj file name
        is given one will be created in the build directory."""
        cmd = self.env['ASSEMBLE_COMMAND']
        d = copy.copy(self)
        self.make_derived_flags() 
        d['SRCNAME'] = source
        if obj == None:
            (filepath,fullfilename) = os.path.split(source)
            (filename,ext) = os.path.splitext(fullfilename)
            obj = filename + self.env['OBJEXT']
            obj = self.build_dir_join(obj)
        d['OBJNAME'] = obj
        self._escape_dict(d)
        s = self.expand_string(cmd, d)
        return  plan.plan_t(command=s, output=obj, input=source)

    def _make_pdb_file(self,obj):
        """If obj obj file ends in '.obj$' or '%(OBJEXT)s' replace it
        so it looks like: '%(PDBEXT)s'"""
        
        if env_t.obj_pattern.search(obj):
            pdbfile = env_t.obj_pattern.sub('%(PDBEXT)s',obj)
        elif  env_t.objext_pattern.search(obj):
            pdbfile = env_t.objext_pattern.sub('%(PDBEXT)s',obj)
        else:
            die("Could not make PDB file from OBJ file: %s" % obj)
        return pdbfile

    def _cxx_compile_default(self, source, obj=None):
        """C++-compile a source file to a file called obj. If no obj file
        name is given one will be created in the build directory."""
        cmd = self.env['CXX_COMPILE_COMMAND']
        d = copy.copy(self)
        self.make_derived_flags()
        d['SRCNAME'] = source
        if obj == None:
            (filepath,fullfilename) = os.path.split(source)
            (filename,ext) = os.path.splitext(fullfilename)
            obj = filename + self.env['OBJEXT']
            obj = self.build_dir_join(obj)
        if d['separate_pdb_files']  and d['compiler'] == 'ms' and d['debug'] == 1:
            pdbfile = self._make_pdb_file(obj)
            d['CXXFLAGS'] += ' /Fd%s ' % pdbfile

        d['OBJNAME'] = obj
        self._escape_dict(d)
        s = self.expand_string(cmd, d)
        return plan.plan_t(command=s, output=obj, input=source)


    def _cc_compile_default(self, source, obj=None):
        """C-compile a source file to a file named obj. If no obj file
        name is given one will be created in the build directory."""

        cmd = self.env['CC_COMPILE_COMMAND']
        d = copy.copy(self)
        self.make_derived_flags()
        d['SRCNAME'] = source
        if obj == None:
            (filepath,fullfilename) = os.path.split(source)
            (filename,ext) = os.path.splitext(fullfilename)
            obj = filename + self.env['OBJEXT']
            obj = self.build_dir_join(obj)
        if d['separate_pdb_files'] and d['compiler'] == 'ms' and d['debug'] == 1:
            pdbfile = self._make_pdb_file(obj)
            d['CCFLAGS'] += ' /Fd%s ' % pdbfile

        d['OBJNAME'] = obj
        self._escape_dict(d)
        s = self.expand_string(cmd, d)
        return plan.plan_t(command=s, output=obj, input=source)

    def _find_libs(self):
        libs = []
        for lib in self.expand_string('%(LIBS)s').split():
            if lib:
                # ignore libraries that start with "-" as in -lc -lm. I
                # would not know what suffix to put on them anyway
                # (LIBEXT,DLLEXT) without trying them all.
                if lib[0]=='-':
                    continue 
                if os.path.exists(lib):
                    #msgb("ADDING DEPENDENCE ON LIBRARY", lib)
                    libs.append(lib)
                else:
                    for dir in self.env['LINKPATH']:
                        t = util.join(dir,lib)
                        if os.path.exists(t):
                            #msgb("ADDING DERIVED DEPENDENCE ON LIBRARY", t)
                            libs.append(t)
        return libs
                        

    def _link_default(self, objs, exename, relocate=False):
        """Link an executable from objs. If relocate is True,
        then prefix exename  with the build directory name."""
        cmd = self.env['LINK_COMMAND']
        d = copy.copy(self)
        self.make_derived_flags()        
        if relocate:
            exename = self.build_dir_join(exename)
        d['EXENAME'] = exename

        if not isinstance(objs, list):
            objs = [ objs ]
        objs = self._escape_list_of_strings(objs)
        obj = " ".join(objs)
        d['OBJNAMES'] = obj
        self._escape_dict(d)
        s = self.expand_string(cmd, d)
        return plan.plan_t(command=s, output=exename, input=objs + self._find_libs())


    def _static_lib_default(self,  objs, libname, relocate=False):
        """Make a static library libname from objs. If relocate is True,
        then prefix libname with the build directory name"""
        d = copy.copy(self)
        self.make_derived_flags()        
        if relocate:
            libname = self.build_dir_join(libname)
        d['LIBNAME'] = libname
        if not isinstance(objs,list):
            objs = [ objs ]
        objs = self._escape_list_of_strings(objs)
        obj = " ".join(objs)

        d['OBJNAMES'] = obj
        self._escape_dict(d)
        n = []
        scmd = self.env['STATIC_LIB_COMMAND']
        if not isinstance(scmd,list):
            scmd = [ scmd ]
        for cmd in scmd:
            if util.is_stringish(cmd):
                n.append(self.expand_string(cmd, d))
            else:
                n.append(cmd)
        # we pass args to the python scripts... Must expand now or
        # else suffer concurrency bugs at build time.
        args = [ self.expand_string('%(LIBNAME)s') ]
        return plan.plan_t(command=n, output=libname, 
                           args=args,
                           input=objs, env=self)


    def _dynamic_lib_default(self, objs, libname, relocate=False):
        """Make a dynamic library libname from objs. If relocate is True,
        then prefix libname with the build directory name"""
        if self.env['compiler'] in [ 'gnu','icc','clang','iclang']:
            cmd = self.env['CXX_SHARED_LIB_COMMAND']
        else:
            cmd = self.env['DYNAMIC_LIB_COMMAND']
        d = copy.copy(self)
        self.make_derived_flags()        
        if relocate:
            libname = self.build_dir_join(libname)
        d['LIBNAME'] = libname
        d['SOLIBNAME'] = os.path.basename(libname)
        if not isinstance(objs,list):
            objs = [ objs ]
        objs = self._escape_list_of_strings(objs)            
        obj = " ".join(objs)
        d['OBJNAMES'] = obj
        self._escape_dict(d)
        s = self.expand_string(cmd, d)
        return plan.plan_t(command=s, output=libname, 
                           input=objs + self._find_libs())



    def _res_file_builder_default(self, rc_file,res_file=None):
        """Make a res file from an rc file. Windows only."""
        cmd = self.env['RES_FILE_COMMAND']
        d = copy.copy(self)
        if not res_file:
            res_file = self.build_dir_join(self.resuffix(rc_file,'%(RESEXT)s'))
        d['RESNAME'] = res_file
        d['RCNAME'] = rc_file
        self._escape_dict(d)
        s = self.expand_string(cmd, d)
        return plan.plan_t(command=s, 
                           output=res_file, 
                           input=rc_file)

    def compile(self, dag, sources):
        """Build all the sources by adding them to the dag. Use the
        suffixes to figure out how to handle the files. The dag can be
        passed to a work queue. See the build function. """

        objs = []
        for s in sources:
            b = os.path.basename(s) # filename component of path/filename
            (base,ext) = os.path.splitext(b)
            if ext in ['.rc' ]:
                obj = self.build_dir_join(self.resuffix(b,'%(RESEXT)s'))
            else:
                obj = self.build_dir_join(self.make_obj(b))

            if ext in ['.asm', '.s' ]:
                c = self.assemble( s, obj )
            elif ext in ['.c']:
                c = self.cc_compile( s, obj )
            elif ext in ['.cpp', '.C' ]:
                c = self.cxx_compile( s, obj )
            elif ext in ['.rc' ]:
                c = self.rc_file( s, obj ) # obj is a res file in this case
            else:
                die("Unsupported file type %s" % (s))
            cmd = dag.add(self,c)
            objs.append(self.expand_string(obj))
        return objs
            

    def compile_and_link(self, dag, sources, exe, shared_object=False, libs=[]):
        """Build all the sources by adding them to the dag. Use the
        suffixes to figure out how to handle the files. The dag can be
        passed to a work queue. See the build function. """

        objs = self.compile(dag, sources)
        
        if shared_object:
            cmd2 = dag.add(self, 
                           self.dynamic_lib(objs + libs, exe, relocate=True))
        else:
            cmd2 = dag.add(self, 
                           self.link(objs + libs , exe,relocate=True))
        return cmd2


    def build(self, work_queue, dag, phase='BUILD',terminate_on_errors=False):
        """Build everything in the work queue"""
        okay = work_queue.build(dag=dag, die_on_errors=False)
        if not okay:
            if terminate_on_errors:
                die("[%s] failed." % phase)
            else:
                msgb(phase,"failed.")
                return False
        msgb(phase, "succeeded")
        return True
