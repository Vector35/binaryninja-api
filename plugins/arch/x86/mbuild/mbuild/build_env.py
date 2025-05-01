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

"""Setup functions for the ms/gnu compiler environment"""

import os
import sys
import platform
from .base import *
from .util import *
from .env import *
from . import msvs


def set_compiler_env_common(env):
    """Set up some common stuff that depends heavily on the compiler setting"""
    
    # This whole section was really an experiment in how dynamically I
    # could do substitutions.
    
    env['debug_flag'] = ( 'debug', { True: '%(DEBUGFLAG)s',
                                     False:''})
    env['debug_flag_link'] = ( 'debug', { True: '%(DEBUGFLAG_LINK)s',
                                          False:''})

    win_shared_compile_dict = ( 'compiler', { 'ms': ( 'debug', { True: '/MDd', False: '/MD' }),
                                              'icl': ( 'debug', { True: '/MDd', False: '/MD' }), 
                                              'otherwise': '',
                                              })

    shared_compile_dict = ( 'host_os', { 'android': '-fPIC',
                                          'lin': '-fPIC',
                                          'win': win_shared_compile_dict,
                                          'bsd': '-fPIC',
                                          'otherwise': '',
                                          })
    
    win_static_compile_dict = ( 'compiler', { 'ms': ( 'debug', { True: '/MTd', False: '/MT' }),
                                              'icl': ( 'debug', { True: '/MTd', False: '/MT' }), 
                                              'otherwise': '',
                                              })

    static_compile_dict = ( 'host_os', { 'android': '',
                                          'lin': '',
                                          'win': win_static_compile_dict,
                                          'bsd': '',
                                          'otherwise': '',
                                          })
    
    env['shared_compile_flag'] =  ( 'shared', { True: shared_compile_dict,
                                                False: static_compile_dict
												})
    
    shared_link_dict =  ('compiler', { 'ms':'/dll',
                                       'icl':'/dll',
                                       'icc':'-shared',
                                       'gnu':'-shared'})
    
    env['shared_link'] = ( 'shared', { True:  shared_link_dict,
                                       False:''})
    
    env['OPTOPT'] = ( 'compiler', { 'gnu':'-O',
                                    'clang':'-O',
                                    'iclang':'-O',
                                    'icc':'-O',
                                    'icl':'/O',
                                    'ms':'/O'})

    env['nologo'] = ( 'compiler', { 'gnu':'',
                                    'clang':'',
                                    'iclang':'',
                                    'icc':'',
                                    'icl':'/nologo',
                                    'ms':'/nologo'})
    flags = ''
    flags += ' %(debug_flag)s'
    flags += ' %(nologo)s'
    flags += ' %(opt_flag)s'
    flags += ' %(shared_compile_flag)s'
    env['CCFLAGS'] = flags 
    env['CXXFLAGS'] = flags 
    env['LINKFLAGS'] += ' %(debug_flag_link)s'

def add_gnu_arch_flags(d):
    """Accept a dictionary, return a string"""
    if d['compiler'] in ['gnu','clang'] and d['gcc_version'] != '2.96': # FIXME: iclang?
        if d['host_cpu'] == 'x86-64':
            return '-m64'
        elif d['host_cpu'] == 'ia32':
            return '-m32'
    return ''
    

def set_env_gnu(env):
    """Example of setting up the GNU GCC environment for compilation"""
    set_compiler_env_common(env)

    env['opt_flag'] = ( 'opt', {'noopt':'',
                                's':'%(OPTOPT)ss',
                                '0':'%(OPTOPT)s0',
                                '1':'%(OPTOPT)s1',
                                '2':'%(OPTOPT)s2',
                                '3':'%(OPTOPT)s3',
                                '4':'%(OPTOPT)s4'} )

    # lazy toolchain and other env var (f)  expansion
    mktool = lambda f: "%(toolchain)s%(" + f + ")s" 

    if env['CXX_COMPILER'] == '':
        env['CXX_COMPILER'] = ( 'compiler', { 'gnu':'g++',
                                              'icc':'icpc',
                                              'iclang':'icl++',
                                              'clang':'clang++'})
    if env['CC_COMPILER'] == '':
        env['CC_COMPILER'] =  ( 'compiler', { 'gnu':'gcc',
                                              'icc':'icc',
                                              'iclang':'icl',
                                              'clang':'clang' })
    if env['ASSEMBLER'] == '':
        env['ASSEMBLER'] =  ( 'compiler', { 'gnu':'gcc',
                                            'icc':'icc',
                                            'iclang':'icl',
                                            'clang':'yasm' })

    if env['LINKER'] == '':
        env['LINKER'] = '%(CXX_COMPILER)s' # FIXME C++ or C?  
    if env['ARCHIVER'] == '':
        env['ARCHIVER'] = ( 'compiler', { 'gnu': 'ar',    # or GAR??
                                          'icc' : 'xiar',
                                          'iclang' : 'xiar',
                                          'clang':'llvm-ar' })
    if env['RANLIB_CMD'] == '':
        env['RANLIB_CMD'] = 'ranlib'

    if env['CC'] == '':
        env['CC'] = mktool('CC_COMPILER')
    if env['CXX'] == '':
        env['CXX'] =  mktool('CXX_COMPILER')
    if env['AS'] == '':
        env['AS'] =  mktool('ASSEMBLER')
    if env['LINK'] == '':
        env['LINK'] = mktool('LINKER')
    if env['AR'] == '':
        env['AR'] = mktool('ARCHIVER')
    if env['RANLIB'] == '':
        env['RANLIB'] = mktool('RANLIB_CMD')

    # if using gcc to compile include -c. If using gas, omit the -c
    env['ASFLAGS'] = ' -c'

    env['ARFLAGS'] = "rcv"
    env['STATIC'] = (  'static', { True :  "-static", 
                                   False : "" } )
    env['LINKFLAGS'] += " %(STATIC)s"

    env['GNU64'] = add_gnu_arch_flags # dynamically called function during variable expansion!
    s = ' %(GNU64)s'
    env['CCFLAGS']  += s
    env['CXXFLAGS']  += s
    env['LINKFLAGS'] += s
    # if using gcc to compile use -m64, otherwise if gas is used, omit the -m64.
    env['ASFLAGS'] += s
    
    env['DEBUGFLAG'] = '-g' 
    env['DEBUGFLAG_LINK'] = '-g' 
    env['COPT'] = '-c'
    env['DOPT'] = '-D'
    env['ASDOPT'] = '-D'
    env['IOPT'] = '-I'
    env['ISYSOPT'] = '-isystem ' # trailing space required
    env['LOPT'] = '-L'
 
    env['COUT'] = '-o '
    env['ASMOUT'] = '-o '
    env['LIBOUT'] = ' ' # nothing when using gar/ar
    env['LINKOUT'] = '-o '
    env['EXEOUT'] = '-o '
    if env.on_mac():
        env['DLLOPT'] = '-shared' # '-dynamiclib'
    else:
        env['DLLOPT'] = '-shared -Wl,-soname,%(SOLIBNAME)s'

    env['OBJEXT'] = '.o'
    if env.on_windows():
        env['EXEEXT'] = '.exe'
        env['DLLEXT'] = '.dll'
        env['LIBEXT'] = '.lib'
        env['PDBEXT'] = '.pdb'
    elif env.on_mac():
        env['EXEEXT'] = ''
        env['DLLEXT'] = '.dylib'
        env['LIBEXT'] = '.a'
        env['PDBEXT'] = ''
    else:
        env['EXEEXT'] = ''
        env['DLLEXT'] = '.so'
        env['LIBEXT'] = '.a'
        env['PDBEXT'] = ''

def find_ms_toolchain(env):
    if env['msvs_version']:
        env['setup_msvc']=True

    if env['vc_dir'] == '' and not env['setup_msvc']:
        if 'MSVCDir' in os.environ:
            vs_dir = os.environ['MSVCDir']
            if os.path.exists(vs_dir):
                env['vc_dir'] = vs_dir
        elif 'VCINSTALLDIR' in os.environ: 
            vc_dir = os.environ['VCINSTALLDIR']
            if os.path.exists(vc_dir):
                env['vc_dir'] = vc_dir
                msvs7 = os.path.join(env['vc_dir'],"Vc7") 
                if os.path.exists(msvs7):
                    env['vc_dir'] = msvs7
        elif 'VSINSTALLDIR' in os.environ: 
            vs_dir = os.environ['VSINSTALLDIR']
            if os.path.exists(vs_dir):
                env['vc_dir'] = os.path.join(vs_dir, 'VC')
        elif 'MSVCDIR' in os.environ:
            vs_dir = os.environ['MSVCDIR']
            if os.path.exists(vs_dir):
                env['vc_dir'] = vs_dir

    # Before DEV15, the VCINSTALLDIR was sufficient to find the
    # compiler. But with DEV15, they locate the compiler more deeply
    # in to the file system and we need more information including the
    # build number. The DEV15 installation sets the env var
    # VCToolsInstallDir with that information.  The headers and
    # libraries change location too so relying on VCINTALLDIR is
    # insufficient.  So if people run with (1) mbuild's setup of DEV15
    # or (2) the MSVS command prompt, they should be fine. But
    # anything else is probably questionable.

    incoming_setup = True # presume system setup by user
    if env['vc_dir'] == '' or env['setup_msvc']:
        incoming_setup = False
        env['vc_dir'] = msvs.set_msvs_env(env)

    # toolchain is the bin directory of the compiler with a trailing slash
    if env['toolchain'] == '':
        if incoming_setup: 
            # relying on user-setup env (say MSVS cmd.exe or vcvars-equiv bat file)
            if os.environ['VisualStudioVersion']  in ['15.0','16.0','17.0']:
                env['msvs_version'] = str(int(float(os.environ['VisualStudioVersion'])))
                msvs.set_msvc_compilers(env, os.environ['VCToolsInstallDir'])
        if env['compiler']=='ms':
            env['toolchain'] = msvs.pick_compiler(env)
    

        
def _check_set_rc(env, sdk):
    def _path_check_rc_cmd(env):
        if  os.path.exists(env.expand('%(RC_CMD)s')):
            return True
        return False

    if env['host_cpu'] == 'x86-64':
        env['RC_CMD'] = os.path.join(sdk,'x64','rc.exe')
    else:
        env['RC_CMD'] = os.path.join(sdk,'x86','rc.exe')
    if not _path_check_rc_cmd(env):
        env['RC_CMD'] = os.path.join(sdk,'rc.exe')
    return _path_check_rc_cmd(env)


def _find_rc_cmd(env):
    """Finding the rc executable is a bit of a nightmare.
    
     In MSVS2005(VC8):
         C:/Program Files (x86)/Microsoft Visual Studio 8/VC
             bin/rc.exe  
           or
             PlatformSDK/Bin/win64/AMD64/rc.exe
       which is $VCINSTALLDIR/bin or 
                $VCINSTALLDIR/PlatformSDK/bin/win64/AMD64
       We do not bother attempting to find that version of rc.
       Put it on your path or set env['RC_CMD'] if you need it.
    
     In MSVS2008(VC9), MSVS2010 (VC10) and MSVS2012 (VC11):
       have rc.exe in the SDK directory, though the location varies
       a little for the 32b version.

     With winsdk10 (used by MSVS2017/DEV15), rc.exe moved around from
     version to version of the sdk. In the early versions of the SDK,
     the rc.exe is located in:

          C:\Program Files (x86)\Windows Kits\10\bin\{x86,x64}

     However, in later versions (starting with 10.0.16299.0), they
     placed the rc.exe in the numbered subdirectory:

          C:\Program Files (x86)\Windows Kits\10\bin\10.0.16299.0\{x86,x64}
    """
    sdks = [] # list of directories to search

    def _add_bin(s):
        return os.path.join(s,'bin')
    
    if 'rc_winkit_number' in env: # set up by msvs.py for dev14, dev15
        p = "{}/bin/{}".format( env['rc_winkit'],        
                                env['rc_winkit_number'])
        sdks.append(p)
        
    if 'rc_winkit' in env: # set up by msvs.py for dev14, dev15
        sdks.append(_add_bin(env['rc_winkit']))
        pass
    
    if 'WindowsSdkDir' in env:
        sdks.append( _add_bin(env['WindowsSdkDir']))
    elif 'WindowsSdkDir' in os.environ:
        sdks.append( _add_bin(os.environ['WindowsSdkDir']))

    for k in sdks:
        if _check_set_rc(env,k):
            # found a good one...work with that.
            return

    if env['host_cpu'] == 'x86-64':
        warn("Could not find 64b RC command in SDK directory; assuming on PATH")
    else:
        warn("Could not find 32b RC command in SDK directory; assuming on PATH")
    # hope the user puts the location of RC on their PATH
    env['RC_CMD'] = 'rc' 



def set_env_ms(env):
    """Example of setting up the MSVS environment for compilation"""
    set_compiler_env_common(env)

    # FIXME: allow combinations of options
    env['opt_flag'] = ( 'opt', {'noopt':'',
                                '0':'%(OPTOPT)sd',
                                '1':'%(OPTOPT)s1',
                                '2':'%(OPTOPT)s2',
                                '3':'%(OPTOPT)s2', # map O3 and O4 to O2
                                '4':'%(OPTOPT)s2', # map O3 and O4 to O2
                                'b':'%(OPTOPT)sb',
                                'i':'%(OPTOPT)si',
                                's':'%(OPTOPT)ss',
                                'x':'%(OPTOPT)sx',
                                'd':'%(OPTOPT)sd',
                                'g':'%(OPTOPT)sg'} )

    env['ASFLAGS'] = '/c /nologo '
    env['LINKFLAGS']  += ' /nologo'
    env['ARFLAGS']     = '/nologo'

    env['link_prefix'] = ('use_compiler_to_link', { True:'/link', 
                                                    False:'' })
    if env['host_cpu'] == 'ia32':
        env['LINKFLAGS'] += ' %(link_prefix)s /MACHINE:X86'
        env['ARFLAGS']   += ' /MACHINE:X86'
    elif env['host_cpu'] == 'x86-64':
        env['LINKFLAGS'] += ' %(link_prefix)s /MACHINE:X64'
        env['ARFLAGS']   += ' /MACHINE:X64'

        env['favor'] = ( 'compiler', { 'ms'        : ' /favor:EM64T', 
                                       'otherwise' : '' })
        env['CXXFLAGS'] += ' %(favor)s'
        env['CCFLAGS']  += ' %(favor)s'
                          
    elif env['host_cpu'] == 'ipf':
        env['LINKFLAGS'] += ' %(link_prefix)s /MACHINE:IA64'
        env['ARFLAGS']   += ' /MACHINE:IA64'

    env['COPT'] = '/c'
    env['DOPT'] = '/D'
    env['ASDOPT'] = '/D'
    
    # I use '-I' instead of '/I' because it simplifies use of YASM
    # which requires -I for includes.
    env['IOPT'] = '-I' # -I or /I works with MSVS8.
    env['ISYSOPT'] = '-I' # MSVS has not -isystem so we use -I
    env['LOPT'] = '%(link_prefix)s /LIBPATH:'

    
    # Some options differ when using the compiler to link programs.
    # Note: /Zi has parallel-build synchronization bugs
    env['DEBUGFLAG'] = '/Z7'
    env['DEBUGFLAG_LINK'] = ('use_compiler_to_link', { True:'/Z7', # of /Zi
                                                       False:'/debug'})
    env['COUT'] = '/Fo'
    env['ASMOUT'] = '/Fo'
    env['LIBOUT'] = '/out:'
    env['EXEOUT'] = '/Fe'
    env['LINKOUT'] = ('use_compiler_to_link',{ True:'/Fo',
                                               False:'/OUT:'})
    env['DLLOPT'] = '/dll'
    env['OBJEXT'] = '.obj'
    env['LIBEXT'] = '.lib'
    env['DLLEXT'] = '.dll'
    env['EXEEXT'] = '.exe'
    env['PDBEXT'] = '.pdb'
    env['PDBEXT'] = '.pdb'
    env['RCEXT']  = '.rc'
    env['RESEXT'] = '.res'

    find_ms_toolchain(env)
    
    if env['ASSEMBLER'] == '':
        if env['host_cpu'] == 'ia32':
            env['ASSEMBLER'] = 'ml.exe'
        elif env['host_cpu'] == 'x86-64':
            env['ASSEMBLER'] = 'ml64.exe'

    if env['CXX_COMPILER'] == '':
        env['CXX_COMPILER'] = ( 'compiler', { 'ms':'cl.exe',
                                              'icl':'icl.exe' })
    if env['CC_COMPILER'] == '':
        env['CC_COMPILER'] = ( 'compiler', { 'ms':'cl.exe',
                                             'icl':'icl.exe' })
    if env['LINKER'] == '':
        env['LINKER'] = ( 'compiler', { 'ms': 'link.exe',
                                        'icl' : 'xilink.exe'})

    # old versions of RC do not accept the /nologo switch
    env['rcnologo'] = ( 'msvs_version', { 'otherwise':' /nologo',
                                          '6':'',
                                          '7':'',
                                          '8':'',
                                          '9':'' })
    env['RCFLAGS'] = " %(rcnologo)s"


    if env['RC_CMD'] == '':
        _find_rc_cmd(env)

    if env['RC'] == '':
        env['RC']  = quote('%(RC_CMD)s')

    if env['ARCHIVER'] == '':
        env['ARCHIVER'] =( 'compiler', { 'ms': 'lib.exe',
                                         'icl' : 'xilib.exe'})
    # lazy toolchain and other env var (f)  expansion
    mktool = lambda f: "%(toolchain)s%(" + f + ")s" 

    if env['CXX'] == '':
        env['CXX']  = quote(mktool('CXX_COMPILER'))
    if env['CC'] == '':
        env['CC']   = quote(mktool('CC_COMPILER'))
    if env['AS'] == '':
        env['AS']   = quote(mktool('ASSEMBLER'))
    if env['LINK'] == '':
        env['LINK'] = quote(mktool('LINKER'))
    if env['AR'] == '':
        env['AR']   = quote(mktool('ARCHIVER'))

        

def yasm_support(env):
    """Initialize the YASM support based on the env's host_os and host_cpu"""
    # FIXME: android???
    yasm_formats={}
    yasm_formats['win'] = { 'ia32': 'win32', 'x86-64': 'win64'}
    yasm_formats['lin'] = { 'ia32': 'elf32', 'x86-64': 'elf64'}
    yasm_formats['bsd'] = { 'ia32': 'elf32', 'x86-64': 'elf64'}
    yasm_formats['mac'] = { 'ia32': 'macho32', 'x86-64': 'macho64'}
    env['ASDOPT']='-D'
    try:
        env['ASFLAGS'] = ' -f' + yasm_formats[env['host_os']][env['host_cpu']]
        env['ASMOUT'] = '-o '
        env['AS'] = 'yasm'
    except:
        die("YASM does not know what format to use for build O/S: %s and target CPU: %s" %
            (env['host_os'], env['host_cpu']))
            


def set_env_clang(env):
    set_env_gnu(env)


def set_env_icc(env):
    """Example of setting up the Intel ICC  environment for compilation"""
    set_env_gnu(env)

def set_env_iclang(env):
    """Example of setting up the Intel iclang (aka mac icl) environment for compilation"""
    set_env_gnu(env)
    
def set_env_icl(env):
    """Example of setting up the Intel ICL (windows) environment for compilation"""
    set_env_ms(env)
