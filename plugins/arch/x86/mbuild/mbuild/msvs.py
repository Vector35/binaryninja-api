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

# TESTING MATRIX
# ('e' is for express)
#
#       32   32/64 64
#  6    ok    ?    N/A
#  7    ok    ok   N/A
#  8    ?     ok   ok
#  8e   ?     ?    ?
#  9    ?     ok   ok
#  9e   ok    ?    ?
# 10    ?     ?    ?
#

"""Environment setup for Microsoft Visual Studio.  Set INCLUDE,
LIBPATH, LIB, PATH, VCINSTALLDIR, VS80COMNTOOLS, VSINSTALLDIR, etc.
"""
from __future__ import print_function
import os
import sys
import platform
from .base import *
from .util import *
from .env import *
from .osenv import *

########################################################################
def add_env(v,s):
    """Add v=v;old_vs to the shell environment. Inserts at front"""
    if 0:
        if os.path.exists(s):
            tag = u"GOOD"
        else:
            tag = u"BAD"
        uprint(u"{} {}".format(tag,s))
    v.insert(0,s)
########################################################################

def _find_dir_list(lst):
    for dir in lst:
        if os.path.exists(dir):
            return dir
    return None


def _set_msvs_dev6(env, x64_host, x64_target):   # VC 98
    vc_prefixes = [ "C:/VC98",
                    "C:/Program Files (x86)/Microsoft Visual Studio",
                    "C:/Program Files/Microsoft Visual Studio" ]

    msdev_prefixes = [
        "C:/Program Files/Microsoft Visual Studio/Common" ]
    vc_prefix = _find_dir_list(vc_prefixes)
    msdev_prefix = _find_dir_list(msdev_prefixes)
    if not vc_prefix:
        die("Could not find VC98")
    if not msdev_prefix:
        die("Could not find VC98 MSDEV")

    i = []
    add_env(i, vc_prefix + "/VC98/ATL/INCLUDE")
    add_env(i, vc_prefix + "/VC98/INCLUDE")
    add_env(i, vc_prefix + "/VC98/MFC/INCUDE")
    set_env_list("INCLUDE",i)

    lib = []
    add_env(lib, vc_prefix + "/VC98/LIB")
    add_env(lib, vc_prefix + "/VC98/MFC/LIB")
    set_env_list("LIB",lib)

    path=[]
    add_env(path, msdev_prefix + "/msdev98/Bin")
    add_env(path,    vc_prefix + "/VC98/Bin")
    add_env(path, msdev_prefix + "/TOOLS/WINNT")
    add_env(path, msdev_prefix + "/TOOLS")
    add_to_front_list('PATH', path)

    set_env("MSDevDir", msdev_prefix + "/msdev98")
    set_env("MSVCDir",     vc_prefix + "/VC98")

    return    vc_prefix + "/VC98"

def _set_msvs_dev7(env, x64_host, x64_target): # .NET 2003

    prefixes = [ "c:/Program Files/Microsoft Visual Studio .NET 2003",
                 "c:/Program Files (x86)/Microsoft Visual Studio .NET 2003"]
    prefix = _find_dir_list(prefixes)
    if not prefix:
        die("Could not find MSVS7 .NET 2003")

    inc = []
    add_env(inc, prefix + '/VC7/ATLMFC/INCLUDE')
    add_env(inc, prefix + '/VC7/include')
    add_env(inc, prefix + '/VC7/PlatformSDK/include/prerelease')
    add_env(inc, prefix + '/VC7/PlatformSDK/include')
    add_env(inc, prefix + '/SDK/v1.1/include')
    add_env(inc, prefix + '/SDK/v1.1/include/')
    set_env_list("INCLUDE",inc)

    lib = []
    add_env(lib, prefix + '/VC7/ATLMFC/LIB')
    add_env(lib, prefix + '/VC7/LIB')
    add_env(lib, prefix + '/VC7/PlatformSDK/lib/prerelease')
    add_env(lib, prefix + '/VC7/PlatformSDK/lib')
    add_env(lib, prefix + '/SDK/v1.1/lib')
    add_env(lib, prefix + '/SDK/v1.1/Lib/')
    set_env_list("LIB",lib)
    
    path = []
    add_env(path, prefix + "/Common7/IDE")
    add_env(path, prefix + "/VC7/bin")
    add_env(path, prefix + "/Common7/Tools")
    add_env(path, prefix + "/Common7/Tools/bin/prerelease")
    add_env(path, prefix + "/Common7/Tools/bin")
    add_env(path, prefix + "/SDK/v1.1/bin")
    add_to_front_list('PATH', path)
   
    set_env("VCINSTALLDIR",  prefix)
    set_env("VC71COMNTOOLS", prefix + "/Common7/Tools/")
    set_env("VSINSTALLDIR",  prefix + '/Common7/IDE')
    set_env("MSVCDir",  prefix + '/VC7')
    set_env("FrameworkVersion","v1.1.4322")
    set_env("FrameworkSDKDir", prefix + "/SDK/v1.1")
    set_env("FrameworkDir", "C:/WINDOWS/Microsoft.NET/Framework")
    # DevEnvDir has a trailing slash
    set_env("DevEnvDir",  prefix + "/Common7/IDE/")

    return    prefix + "/VC7"
def _set_msvs_dev8(env, x64_host, x64_target, regv=None): # VS 2005
    if regv:
        prefix = regv
    else:
        prefixes = ["c:/Program Files (x86)/Microsoft Visual Studio 8",
                    "c:/Program Files/Microsoft Visual Studio 8"]
    prefix = _find_dir_list(prefixes)
    if not os.path.exists(prefix):
        die("Could not find MSVC8 (2005)")

    set_env('VCINSTALLDIR',  prefix + '/VC')
    set_env('VS80COMNTOOLS', prefix + "/Common7/Tools")
    set_env('VSINSTALLDIR',  prefix)

    i =[] 
    add_env(i, prefix + "/VC/ATLMFC/INCLUDE")
    add_env(i, prefix + "/VC/INCLUDE")
    add_env(i, prefix + "/VC/PlatformSDK/include")
    add_env(i, prefix + "/SDK/v2.0/include")
    set_env_list('INCLUDE', i)

    set_env('FrameworkDir','C:/WINDOWS/Microsoft.NET/Framework')
    set_env('FrameworkVersion', 'v2.0.50727')
    set_env('FrameworkSDKDir', prefix  +'/SDK/v2.0')

    # DevEnvDir has a trailing slash
    set_env("DevEnvDir", prefix  +'/Common7/IDE/')

    lp = []
    path=[]
    lib=[]
    if x64_host and x64_target:
        add_env(lp, prefix + '/VC/ATLMFC/LIB/amd64')
        
        add_env(lib, prefix  + "/VC/ATLMFC/LIB/amd64")
        add_env(lib, prefix  + "/VC/LIB/amd64")
        add_env(lib, prefix  + "/VC/PlatformSDK/lib/amd64")
        add_env(lib, prefix  + "/SDK/v2.0/LIBAMD64")

        add_env(path, prefix + "/VC/bin/amd64")                    
        add_env(path, prefix + "/VC/PlatformSDK/bin/win64/amd64")  
        add_env(path, prefix + "/VC/PlatformSDK/bin")              
        add_env(path, prefix + "/VC/VCPackages")                   
        add_env(path, prefix + "/Common7/IDE")                     
        add_env(path, prefix + "/Common7/Tools")                   
        add_env(path, prefix + "/Common7/Tools/bin")               
        add_env(path, prefix + "/SDK/v2.0/bin")                    
        add_env(path, prefix + "C:/WINDOWS/Microsoft.NET/Framework64/v2.0.50727")

    elif not x64_target:

        add_env(path, prefix + '/Common7/IDE')
        add_env(path, prefix + '/VC/BIN')
        add_env(path, prefix + '/Common7/Tools')
        add_env(path, prefix + '/Common7/Tools/bin')
        add_env(path, prefix + '/VC/PlatformSDK/bin')
        add_env(path, prefix + '/SDK/v2.0/bin')
        add_env(path, prefix + '/VC/VCPackages')
        add_env(path, 'C:/WINDOWS/Microsoft.NET/Framework/v2.0.50727')

        add_env(lib, prefix +  '/VC/ATLMFC/LIB')
        add_env(lib, prefix +  '/VC/LIB')
        add_env(lib, prefix +  '/VC/PlatformSDK/lib')
        add_env(lib, prefix +  '/SDK/v2.0/lib')

        add_env(lp, prefix + '/VC/ATLMFC/LIB')
        add_env(lp, 'C:/WINDOWS/Microsoft.NET/Framework/v2.0.50727')

    add_to_front_list('PATH', path)
    set_env_list('LIB',lib)
    set_env_list('LIBPATH', lp)

    return    prefix + "/VC"

def _set_msvs_dev9(env, x64_host, x64_target, regv=None): # VS 2008
    if regv:
        prefix = regv
    else:
        prefixes = ['C:/Program Files (x86)/Microsoft Visual Studio 9.0',
                    'C:/Program Files/Microsoft Visual Studio 9.0']
    prefix = _find_dir_list(prefixes)

    set_env('VSINSTALLDIR', prefix)
    set_env('VS90COMNTOOLS', prefix + '/Common7/Tools')
    set_env('VCINSTALLDIR', prefix  +'/VC')
    set_env('FrameworkDir', 'C:/WINDOWS/Microsoft.NET/Framework')
    set_env('Framework35Version','v3.5')
    set_env('FrameworkVersion','v2.0.50727')
    set_env('FrameworkSDKDir', prefix  +'/SDK/v3.5')
    set_env('WindowsSdkDir','C:/Program Files/Microsoft SDKs/Windows/v6.0A')

    # DevEnvDir has a trailing slash
    set_env('DevEnvDir', prefix  + '/Common7/IDE/')
    inc = []
    add_env(inc,  prefix + 'VC/ATLMFC/INCLUDE')
    add_env(inc,  prefix + '/VC/INCLUDE')
    add_env(inc,  'C:/Program Files/Microsoft SDKs/Windows/v6.0A/include')
    set_env_list('INCLUDE',inc)

    path = []
    lib = []
    libpath = []

    if x64_target: # FIXME! 64b!!!!
        add_env(path, prefix + '/Common7/IDE')
        add_env(path, prefix + '/VC/BIN')
        add_env(path, prefix + '/Common7/Tools')
        add_env(path, prefix + '/VC/VCPackages')
        add_env(path, 'C:/Program Files/Microsoft SDKs/Windows/v6.0A/bin')
        add_env(path, 'C:/WINDOWS/Microsoft.NET/Framework/v3.5')
        add_env(path, 'C:/WINDOWS/Microsoft.NET/Framework/v2.0.50727')

        add_env(lib,  prefix +'/VC/ATLMFC/LIB/amdt64')
        add_env(lib,  prefix +'/VC/LIB/amd64')
        add_env(lib,  'C:/Program Files/Microsoft SDKs/Windows/v6.0A/lib/x64')

        add_env(libpath, 'C:/WINDOWS/Microsoft.NET/Framework64/v2.0.50727')
        add_env(libpath, 'C:/WINDOWS/Microsoft.NET/Framework64/v3.5')
        add_env(libpath, 'C:/WINDOWS/Microsoft.NET/Framework64/v2.0.50727')
        add_env(libpath, 'C:/WINDOWS/Microsoft.NET/Framework64/v2.0.50727')
        add_env(libpath, prefix + '/VC/ATLMFC/LIB/amd64')
        add_env(libpath, prefix + '/VC/LIB/amd64')
    else:
        add_env(path, prefix + '/Common7/IDE')
        add_env(path, prefix + '/VC/BIN')
        add_env(path, prefix + '/Common7/Tools')
        add_env(path, prefix + '/VC/VCPackages')
        add_env(path, 'C:/Program Files/Microsoft SDKs/Windows/v6.0A/bin')
        add_env(path, 'C:/WINDOWS/Microsoft.NET/Framework/v3.5')
        add_env(path, 'C:/WINDOWS/Microsoft.NET/Framework/v2.0.50727')

        add_env(lib,  prefix +'/VC/LIB')
        add_env(lib,  prefix +'/VC/ATLMFC/LIB')
        add_env(lib,  'C:/Program Files/Microsoft SDKs/Windows/v6.0A/lib')

        add_env(libpath, 'C:/WINDOWS/Microsoft.NET/Framework/v3.5')
        add_env(libpath, 'C:/WINDOWS/Microsoft.NET/Framework/v2.0.50727')
        add_env(libpath, prefix + '/VC/ATLMFC/LIB')
        add_env(libpath, prefix + '/VC/LIB')

    set_env_list('LIBPATH',libpath)
    set_env_list('LIB',lib)
    add_to_front_list('PATH',path)

    return    prefix + "/VC"


def _set_msvs_dev10(env, x64_host, x64_target, regv=None): # VS 2010
    if regv:
        prefix = regv
    else:
        prefix = 'C:/Program Files (x86)/Microsoft Visual Studio 10.0'

    path = []
    lib = []
    libpath = []

    inc  = []
    add_env(inc, prefix + '/VC/INCLUDE')
    add_env(inc, prefix + '/VC/ATLMFC/INCLUDE')
    add_env(inc, 'c:/Program Files (x86)/Microsoft SDKs/Windows/v7.0A/include')
    set_env_list('INCLUDE',inc)

    set_env('Framework35Version','v3.5')
    set_env('FrameworkVersion',   'v4.0.20728')
    set_env('FrameworkVersion32', 'v4.0.20728')

    set_env('VCINSTALLDIR', prefix + '/VC')
    set_env('VS100COMNTOOLS', prefix + '/Common7/Tools')
    set_env('VSINSTALLDIR' , prefix)
    set_env('WindowsSdkDir', 'c:/Program Files (x86)/Microsoft SDKs/Windows/v7.0A')

    # DevEnvDir has a trailing slash
    set_env('DevEnvDir', prefix  + '/Common7/IDE/')

    if x64_target:
        set_env('FrameworkDir','c:/WINDOWS/Microsoft.NET/Framework64')
        set_env('FrameworkDIR64','c:/WINDOWS/Microsoft.NET/Framework64')
        set_env('FrameworkVersion64', 'v4.0.20728')

        set_env('Platform','X64')
        add_env(lib, prefix  + '/VC/LIB/amd64')
        add_env(lib, prefix  + '/VC/ATLMFC/LIB/amd64')
        add_env(lib, 'c:/Program Files (x86)/Microsoft SDKs/Windows/v7.0A/lib/x64')
        
        add_env(libpath, 'c:/WINDOWS/Microsoft.NET/Framework64/v4.0.20728')
        add_env(libpath, 'c:/WINDOWS/Microsoft.NET/Framework64/v3.5')
        add_env(libpath, prefix + '/VC/LIB/amd64')
        add_env(libpath, prefix + '/VC/ATLMFC/LIB/amd64')

        add_env(path,  prefix + '/VC/BIN/amd64')
        add_env(path,  'c:/WINDOWS/Microsoft.NET/Framework64/v4.0.20728')
        add_env(path,  'C:/WINDOWS/Microsoft.NET/Framework64/v3.5')
        add_env(path,  prefix + '/VC/VCPackages')
        add_env(path,  prefix + '/Common7/IDE')
        add_env(path,  prefix + '/Common7/Tools')
        add_env(path,  'C:/Program Files (x86)/HTML Help Workshop')
        add_env(path,  'C:/Program Files (x86)/Microsoft SDKs/Windows/v7.0A/' +
                'bin/NETFX 4.0 Tools/x64')
        add_env(path,  'C:/Program Files (x86)/Microsoft SDKs/Windows/v7.0A/bin/x64')
        add_env(path,  'C:/Program Files (x86)/Microsoft SDKs/Windows/v7.0A/bin')
    else:
        set_env('FrameworkDir', 'c:/WINDOWS/Microsoft.NET/Framework')
        set_env('FrameworkDIR32', 'c:/WINDOWS/Microsoft.NET/Framework')
        
        add_env(lib,  prefix  + '/VC/LIB')
        add_env(lib,  prefix  + '/VC/ATLMFC/LIB')
        add_env(lib,  'c:/Program Files (x86)/Microsoft SDKs/Windows/v7.0A/lib')
        
        add_env(libpath,  'c:/WINDOWS/Microsoft.NET/Framework/v4.0.20728')
        add_env(libpath,  'c:/WINDOWS/Microsoft.NET/Framework/v3.5')
        add_env(libpath,  prefix  + '/VC/LIB')
        add_env(libpath,  prefix  + '/VC/ATLMFC/LIB')
        
        add_env(path,  prefix + '/Common7/IDE/')
        add_env(path,  prefix + '/VC/BIN')
        add_env(path,  prefix +'/Common7/Tools')
        add_env(path,  'C:/WINDOWS/Microsoft.NET/Framework/v4.0.20728')
        add_env(path,  'C:/WINDOWS/Microsoft.NET/Framework/v3.5')
        add_env(path,  prefix + '/VC/VCPackages')
        add_env(path,  'C:/Program Files (x86)/HTML Help Workshop')
        add_env(path,  prefix + '/Team Tools/Performance Tools')
        add_env(path,  'C;/Program Files (x86)/Microsoft SDKs/Windows/v7.0A/' +
                'bin/NETFX 4.0 Tools')
        add_env(path,  'C:/Program Files (x86)/Microsoft SDKs/Windows/v7.0A/bin')

    set_env_list('LIBPATH',libpath)
    set_env_list('LIB',lib)
    add_to_front_list('PATH',path)

    return    prefix + "/VC"


def _set_msvs_dev11(env, x64_host, x64_target, regv=None): # msvs2012
    progfi = 'C:/Program Files (x86)'
    if regv:
        prefix = regv
    else:
        prefix = progfi + '/Microsoft Visual Studio 11.0'

    sdkdir = progfi + '/Microsoft SDKs/Windows/v8.0'
    sdk8   = progfi + '/Microsoft SDKs/Windows/v8.0A'
    sdk7   = progfi + '/Microsoft SDKs/Windows/v7.0A'
    winkit = progfi + '/Windows Kits/8.0'

    path = []
    lib = []
    libpath = []

    inc  = []
    add_env(inc, prefix + '/VC/INCLUDE')
    add_env(inc, prefix + '/VC/ATLMFC/INCLUDE')
    add_env(inc, winkit + '/include')
    add_env(inc, winkit + '/include/um')
    add_env(inc, winkit + '/include/shared')
    add_env(inc, winkit + '/include/winrt')
    set_env_list('INCLUDE',inc)

    set_env('Framework35Version','v3.5')
    set_env('FrameworkVersion',   'v4.0.30319')
    set_env('FrameworkVersion32', 'v4.0.30319')

    set_env('VCINSTALLDIR', prefix + '/VC/')
    set_env('VS110COMNTOOLS', prefix + '/Common7/Tools')
    set_env('VSINSTALLDIR' , prefix)
    set_env('WindowsSdkDir', winkit)


    if x64_target:
        set_env('FrameworkDir','c:/WINDOWS/Microsoft.NET/Framework64')
        set_env('FrameworkDIR64','c:/WINDOWS/Microsoft.NET/Framework64')
        set_env('FrameworkVersion64', 'v4.0.30319')

        set_env('Platform','X64')

        add_env(lib, prefix  + '/VC/LIB/amd64')
        add_env(lib, prefix  + '/VC/ATLMFC/LIB/amd64')
        add_env(lib, winkit + '/lib/win8/um/x64')


        add_env(libpath, 'c:/WINDOWS/Microsoft.NET/Framework64/v4.0.30319')
        add_env(libpath, 'c:/WINDOWS/Microsoft.NET/Framework64/v3.5')
        add_env(libpath, prefix + '/VC/LIB/amd64')
        add_env(libpath, prefix + '/VC/ATLMFC/LIB/amd64')
        add_env(libpath, winkit + '/References/CommonConfiguration/Neutral')
        add_env(libpath, sdkdir + 'ExtensionSDKs/Microsoft.VCLibs/11.0/' + 
                'References/CommonConfiguration/neutral')

        add_env(path,  prefix + '/VC/BIN/amd64')
        add_env(path,  'c:/WINDOWS/Microsoft.NET/Framework64/v4.0.30319')
        add_env(path,  'C:/WINDOWS/Microsoft.NET/Framework64/v3.5')

        add_env(path, prefix + '/Common7/IDE/CommonExtensions/Microsoft/TestWindow')
        add_env(path, prefix + '/VC/VCPackages')
        add_env(path, prefix + '/Common7/IDE')
        add_env(path, prefix + '/Common7/Tools')
        add_env(path, 'C:/Program Files (x86)/HTML Help Workshop')
        add_env(path, prefix + '/Team Tools/Performance Tools/x64')
        add_env(path, prefix + '/Team Tools/Performance Tools')
        add_env(path, winkit  + '/8.0/bin/x64')
        add_env(path, sdk8 + '/bin/NETFX 4.0 Tools/x64')
        add_env(path, sdk7 + '/Bin/x64')
        add_env(path, sdk8 + '/bin/NETFX 4.0 Tools')
        add_env(path, sdk7 + '/Bin')
        add_env(path, winkit + '/Windows Performance Toolkit')
        add_env(path, 'C:/Program Files/Microsoft SQL Server/110/Tools/Binn')

    else:
        set_env('FrameworkDir', 'c:/WINDOWS/Microsoft.NET/Framework')
        set_env('FrameworkDIR32', 'c:/WINDOWS/Microsoft.NET/Framework')

        add_env(lib,  prefix + '/VC/LIB')
        add_env(lib,  prefix + '/VC/ATLMFC/LIB')
        add_env(lib,  winkit + '/lib/win8/um/x86')

        
        add_env(libpath,  'c:/WINDOWS/Microsoft.NET/Framework/v4.0.30319')
        add_env(libpath,  'c:/WINDOWS/Microsoft.NET/Framework/v3.5')
        add_env(libpath,  prefix  + '/VC/LIB')
        add_env(libpath,  prefix  + '/VC/ATLMFC/LIB')
        add_env(libpath,  winkit  + '/References/CommonConfiguration/Neutral')
        add_env(libpath,  sdkdir  + '/ExtensionSDKs/Microsoft.VCLibs/11.0/' +
                'References/CommonConfiguration/neutral')


        add_env(path, prefix + '/Common7/IDE/CommonExtensions/Microsoft/TestWindow')
        add_env(path, 'C:/Program Files (x86)/Microsoft SDKs/F#/3.0/Framework/v4.0')
        add_env(path, prefix + '/Common7/IDE')
        add_env(path, prefix + '/VC/BIN')
        add_env(path, prefix + '/Common7/Tools')
        add_env(path, 'C:/Windows/Microsoft.NET/Framework/v4.0.30319')
        add_env(path, 'C:/Windows/Microsoft.NET/Framework/v3.5')
        add_env(path, prefix + '/VC/VCPackages')
        add_env(path, 'C:/Program Files (x86)/HTML Help Workshop')
        add_env(path, prefix + '/Team Tools/Performance Tools')
        add_env(path, winkit + '/bin/x86')
        add_env(path, sdk8 + '/bin/NETFX 4.0 Tools')
        add_env(path, sdk7 + '/Bin')
        add_env(path, winkit + '/Windows Performance Toolkit')
        add_env(path, 'C:/Program Files/Microsoft SQL Server/110/Tools/Binn')



    set_env_list('LIBPATH',libpath)
    set_env_list('LIB',lib)
    add_to_front_list('PATH',path)

    return    prefix + "/VC"



def _set_msvs_dev12(env, x64_host, x64_target, regv=None): # msvs2013
    progfi = 'C:/Program Files (x86)'
    if regv:
        prefix = regv
    else:
        prefix = progfi + '/Microsoft Visual Studio 12.0'

    sdk81a = progfi + '/Microsoft SDKs/Windows/v8.1A'
    sdk81  = progfi + '/Microsoft SDKs/Windows/v8.1'
    winkit = progfi + '/Windows Kits/8.1'


    path = []
    lib = []
    libpath = []

    inc  = []
    add_env(inc, prefix + '/VC/INCLUDE')
    add_env(inc, prefix + '/VC/ATLMFC/INCLUDE')
    add_env(inc, winkit + '/include') # not used in msvs12
    add_env(inc, winkit + '/include/um')
    add_env(inc, winkit + '/include/shared')
    add_env(inc, winkit + '/include/winrt')
    set_env_list('INCLUDE',inc)

    set_env('Framework40Version','v4.0')
    set_env('FrameworkVersion',   'v4.0.30319')
    set_env('ExtensionSdkDir', 
                   sdk81  + '/ExtensionSDKs')

    set_env('VCINSTALLDIR', prefix + '/VC/')
    set_env('VS120COMNTOOLS', prefix + '/Common7/Tools')
    set_env('VSINSTALLDIR' , prefix)
    set_env('WindowsSdkDir', winkit)
    set_env('VisualStudioVersion','12.0')

    set_env('WindowsSDK_ExecutablePath_x86',
            sdk81a + '/bin/NETFX 4.5.1 Tools/')

    if x64_target:
        set_env('WindowsSDK_ExecutablePath_x64',
                sdk81a +'/bin/NETFX 4.5.1 Tools/x64/')

        set_env('FrameworkDir','c:/WINDOWS/Microsoft.NET/Framework64')
        set_env('FrameworkDIR64','c:/WINDOWS/Microsoft.NET/Framework64')
        set_env('FrameworkVersion64', 'v4.0.30319')

        set_env('Platform','X64')

        add_env(lib, prefix  + '/VC/LIB/amd64')
        add_env(lib, prefix  + '/VC/ATLMFC/LIB/amd64')
        add_env(lib, winkit + '/lib/winv6.3/um/x64')

        add_env(libpath, 'c:/WINDOWS/Microsoft.NET/Framework64/v4.0.30319')
        add_env(libpath, prefix + '/VC/LIB/amd64')
        add_env(libpath, prefix + '/VC/ATLMFC/LIB/amd64')
        add_env(libpath, winkit + '/References/CommonConfiguration/Neutral')
        add_env(libpath, sdk81 + '/ExtensionSDKs/Microsoft.VCLibs/12.0/' + 
                'References/CommonConfiguration/neutral')

        add_env(path, prefix + '/Common7/IDE/CommonExtensions/Microsoft/TestWindow')
        add_env(path,  prefix + '/VC/BIN/amd64')
        add_env(path,  'c:/WINDOWS/Microsoft.NET/Framework64/v4.0.30319')

        add_env(path, prefix + '/VC/VCPackages')
        add_env(path, prefix + '/Common7/IDE')
        add_env(path, prefix + '/Common7/Tools')
        add_env(path, 'C:/Program Files (x86)/HTML Help Workshop')
        add_env(path, prefix + '/Team Tools/Performance Tools/x64')
        add_env(path, prefix + '/Team Tools/Performance Tools')
        add_env(path, winkit  + '/8.1/bin/x64')
        add_env(path, winkit  + '/8.1/bin/x86')
        add_env(path, sdk81a + '/bin/NETFX 4.5.1 Tools/x64')
        add_env(path, winkit + '/Windows Performance Toolkit')


    else:
        set_env('FrameworkDir', 'c:/WINDOWS/Microsoft.NET/Framework')
        set_env('FrameworkDIR32', 'c:/WINDOWS/Microsoft.NET/Framework')
        set_env('FrameworkVersion32','v4.0.30319')

        add_env(lib,  prefix + '/VC/LIB')
        add_env(lib,  prefix + '/VC/ATLMFC/LIB')
        add_env(lib,  winkit + '/lib/winv6.3/um/x86')
        
        add_env(libpath,  'c:/WINDOWS/Microsoft.NET/Framework/v4.0.30319')
        add_env(libpath,  prefix  + '/VC/LIB')
        add_env(libpath,  prefix  + '/VC/ATLMFC/LIB')
        add_env(libpath,  winkit  + '/References/CommonConfiguration/Neutral')
        add_env(libpath,  sdk81  + '/ExtensionSDKs/Microsoft.VCLibs/12.0/' + 
                'References/CommonConfiguration/neutral')


        add_env(path, prefix + '/Common7/IDE/CommonExtensions/Microsoft/TestWindow')
        add_env(path, progfi + '/Microsoft SDKs/F#/3.1/Framework/v4.0')
        add_env(path, progfi  + '/MSBuild/12.0/bin')
        add_env(path, prefix + '/Common7/IDE')
        add_env(path, prefix + '/VC/BIN')
        add_env(path, prefix + '/Common7/Tools')
        add_env(path, 'C:/Windows/Microsoft.NET/Framework/v4.0.30319')
        add_env(path, prefix + '/VC/VCPackages')
        add_env(path, progfi + '/HTML Help Workshop')
        add_env(path, prefix + '/Team Tools/Performance Tools')
        add_env(path, winkit + '/bin/x86')
        add_env(path, sdk81a + '/bin/NETFX 4.5.1 Tools')
        add_env(path, winkit + '/Windows Performance Toolkit')


    set_env_list('LIBPATH',libpath)
    set_env_list('LIB',lib)
    add_to_front_list('PATH',path)

    return    prefix + "/VC"


def _get_winkit10_version(env, winkit10):
    # Find the UCRT Version. Could not locate a registry entry with
    # the information. Preview version of msvs2015/dev14 did not set
    # the env var. Poke around in the directory system as a last
    # resort. Could make this configrable
    winkit10version = None
    if 'UCRTVersion' in os.environ:
        winkit10version = os.environ['UCRTVersion']

    # Early versions of winkit10 that ship with MSVS2015(dev14) do not
    # have the the required stuff so people had to rely on SDK
    # 8.1. The early versions only have a ucrt subdirectory and not a
    # "shared", "um" or "winrt" directories. We use the "shared"
    # directory as our guide.

    if winkit10 and not winkit10version:
        # use glob and find youngest named directory. This code had
        # used os.path.getctime() but that gave the wrong result if an
        # older SDK was installed after a younger SDK was installed.
        dlist = glob(winkit10 + '/include/*')
        dlist.sort(reverse=True)
        for g in dlist:
            if (os.path.exists('{}/shared'.format(g)) and
                os.path.exists('{}/ucrt'.format(g))     ):
                    winkit10version = os.path.basename(g)

    if winkit10version:
        complete = True
        msgb("UCRT Version", winkit10version)
    else:
        complete = False
        warn("Did not find winkit 10 version. RC tool may not be available")

    return (winkit10version,complete)

def _find_msvc_version_directory(root):
    ctime = 0
    msvc_ver = None
    for g in glob(root + '/*'):
        gtime = os.path.getctime(g)
        if gtime > ctime:
            msvc_ver = os.path.basename(g)
            ctime = gtime
    if not msvc_ver:
        die("Could not find MSVC version directory.")
    return msvc_ver

def _find_latest_subdir(d):
    ctime = 0
    for g in glob(d + '*'):
        gtime = os.path.getctime(g)
        if gtime > ctime:
            ctime = gtime
            subdir = g
    return subdir
def _ijoin(x,y):
    return '{}/{}'.format(x,y)

def msvc_dir_from_vc_dir(vc_dir):
    msvc_tools_root = vc_dir + '/Tools/MSVC'
    msvc_ver = _find_msvc_version_directory(msvc_tools_root)
    msvc_tools_root = _ijoin(msvc_tools_root,msvc_ver)
    #msgb('MSVC version', msvc_tools_root)
    return msvc_tools_root, msvc_ver

def set_msvc_compilers(env,msvc_tools_root):
    """set host/target paths for MSVS2017/DEV15. Also called from
    build_env.py when using an externally configured shell."""
    x64_to_x64 = '{}/bin/Host{}/{}/'.format(msvc_tools_root,'x64','x64')
    x64_to_x86 = '{}/bin/Host{}/{}/'.format(msvc_tools_root,'x64','x86')
    x86_to_x64 = '{}/bin/Host{}/{}/'.format(msvc_tools_root,'x86','x64')
    x86_to_x86 = '{}/bin/Host{}/{}/'.format(msvc_tools_root,'x86','x86')
    env['msvc_compilers'] = {}
    env['msvc_compilers']['ia32'] = {}
    env['msvc_compilers']['x86-64'] = {}
    env['msvc_compilers']['ia32']['ia32'] =  x86_to_x64
    env['msvc_compilers']['ia32']['x86-64'] = x86_to_x86
    env['msvc_compilers']['x86-64']['ia32'] = x64_to_x86
    env['msvc_compilers']['x86-64']['x86-64'] = x64_to_x64

def _set_msvs_dev17(env, x64_host, x64_target, regv=None): # msvs 2022
    versions = ['Enterprise', 'Professional', 'Community']
    
    progfi = 'C:/Program Files (x86)'
    if regv:
        prefix = regv
    else:
        prefix = 'C:/Program Files/Microsoft Visual Studio/2022'

    if x64_target:
        tgt = 'x64'
    else:
        tgt = 'x86'

    found = False
    for v in versions:
        p = _ijoin(prefix,v)
        if os.path.exists(p):
            found = True
            break
    if not found:
        die('Could not find MSVS 2022 directory')
    vprefix = p
    winkit10 = progfi + '/Windows Kits/10'    
    winkit10version, winkit10complete = _get_winkit10_version(env,winkit10)
    #msgb('WINKIT10 VERSION', winkit10version)
    if winkit10complete == False:
        die('need a complete winkit10 for MSVS 2022 (dev 17)')
    env['rc_winkit'] = winkit10
    env['rc_winkit_number'] = winkit10version

    msvc_tools_root, msvc_ver = msvc_dir_from_vc_dir(vprefix + '/VC')
    
    netfx_sdk = progfi + '/Windows Kits/NETFXSDK/4.8/'
    
    path = []
    lib = []
    libpath = []
    inc  = []
    
    add_env(inc, prefix + '/ATLMFC/include')
    add_env(inc, msvc_tools_root + '/include')
    add_env(inc, netfx_sdk + 'include/um')
    wki = '{}/include/{}'.format(winkit10, winkit10version)
    add_env(inc, wki + '/ucrt')
    add_env(inc, wki + '/shared')
    add_env(inc, wki + '/um')
    add_env(inc, wki + '/winrt')
    add_env(inc, wki + '/cppwinrt')

    # LIB
    wkl = '{}/lib/{}'.format(winkit10, winkit10version)
    lib1 = '{}/ATLMFC/lib/{}'.format(msvc_tools_root,tgt)
    lib2 = '{}/lib/{}'.format(msvc_tools_root,tgt)
    add_env(lib, lib1)
    add_env(lib, lib2)
    add_env(lib, '{}lib/um/{}'.format(netfx_sdk,tgt))
    add_env(lib, '{}/ucrt/{}'.format(wkl,tgt))
    add_env(lib, '{}/um/{}'.format(wkl,tgt))

    # LIBPATH
    add_env(libpath, lib1)
    add_env(libpath, lib2)
    add_env(libpath, winkit10 + '/UnionMetadata')
    add_env(libpath, winkit10 + '/References')
    s = ''
    if tgt == 'x64':
        s = '64'
    fwr = 'C:/windows/Microsoft.NET/Framework{}'.format(s)
    fwr64 = 'C:/windows/Microsoft.NET/Framework64'
    fwv = 'v4.0.30319'
    fwp = '{}/{}'.format(fwr,fwv)
    add_env(libpath, fwp)

    # PATH

    # locations for cross compilers changed in this version
    set_msvc_compilers(env, msvc_tools_root)
    x86_to_x64 = env['msvc_compilers']['ia32']['ia32'] 
    x86_to_x86 = env['msvc_compilers']['ia32']['x86-64']
    x64_to_x86 = env['msvc_compilers']['x86-64']['ia32'] 
    x64_to_x64 = env['msvc_compilers']['x86-64']['x86-64'] 
    
    cross = False
    if x64_host:
        if x64_target:
            cl_tgt_bin_dir = x64_to_x64
        else:
            cross = True
            cl_tgt_bin_dir = x64_to_x86
            cl_host_bin_dir = x64_to_x64
    else: 
        if x64_target:
            cross = True
            cl_tgt_bin_dir = x86_to_x64
            cl_host_bin_dir = x64_to_x86
        else:
            cl_tgt_bin_dir = x86_to_x86
    
    add_env(path, cl_tgt_bin_dir)
    # CL TARGET compiler gets DLLs from the HOST bin dir
    if cross:
        add_env(path, cl_host_bin_dir)
        
    add_env(path, '{}/Common7/IDE/VC/VCPackages'.format(msvc_tools_root))
    add_env(path, '{}/Common7/IDE/CommonExtensions/Microsoft/TestWindow'.format(msvc_tools_root))
    add_env(path, '{}/Common7/IDE/CommonExtensions/Microsoft/TeamFoundation/Team Explorer'.format(msvc_tools_root))
    add_env(path, '{}/MsBuild/Current/Bin/Roslyn'.format(msvc_tools_root))
    add_env(path, '{}/Team Tools/Performance Tools'.format(msvc_tools_root))
    
    add_env(path, progfi + '/Microsoft Visual Studio/Shared/Common/VSPerfCollectionTools/vs2022')
    netfx_tools = progfi + '/Microsoft SDKs/Windows/v10.0A/bin/NETFX 4.8 Tools'
    add_env(path, netfx_tools)

    add_env(path, '{}/bin/{}'.format(winkit10,tgt))
    add_env(path, '{}/bin/{}/{}'.format(winkit10,winkit10version,tgt))
    add_env(path, '{}/MSBuild/Current/Bin'.format(vprefix))
    add_env(path, fwp)
    add_env(path, '{}/Common7/IDE'.format(vprefix))
    add_env(path, '{}/Common7/Tools'.format(vprefix))

    set_env_list('INCLUDE',inc)
    set_env_list('LIB',lib)
    set_env_list('LIBPATH',libpath)
    add_to_front_list('PATH',path)
    if 0:
        msgb("INCLUDE", "\n\t".join(inc))
        msgb("LIB", "\n\t".join(lib))
        msgb("LIBPATH", "\n\t".join(libpath))
        msgb("PATH", "\n\t".join(path))

    # Misc env variables. Not sure which are needed, if any
    set_env('NETFXSDKDir',netfx_sdk)
    set_env('DevEnvDir', vprefix + '/Common7/IDE/')
    set_env('ExtensionSdkDir', progfi + '/Microsoft SDKs/Windows Kits/10/ExtensionSDKs')
    set_env('Framework40Version','v4.0')
    set_env('FrameworkVersion',fwv)
    if x64_host:
        set_env('VSCMD_ARG_HOST_ARCH','x64')
    else:
        set_env('VSCMD_ARG_HOST_ARCH','x86')
        
    set_env('Platform',tgt)
    set_env('VSCMD_ARG_TGT_ARCH',tgt)
        
    if x64_target:
        set_env('FrameworkDir', fwr)
        set_env('FrameworkDIR64',fwr)
        set_env('FrameworkVersion64',fwv)
    else: 
        set_env('FrameworkDIR32',fwr)
        set_env('FrameworkVersion32',fwv)
        if x64_host:
            set_env('FrameworkDir', fwr64)
            set_env('FrameworkDIR64',fwr64)
            set_env('FrameworkVersion64',fwv)
        else:
            set_env('FrameworkDir', fwr)
        
    set_env('UCRTVersion',          winkit10version)
    set_env('WindowsSDKLibVersion', winkit10version + '/')
    set_env('WindowsSDKVersion',    winkit10version + '/')
    set_env('WindowsSdkVerBinPath', '{}/bin/{}/'.format(winkit10,winkit10version))
    set_env('WindowsSdkBinPath', winkit10 + '/bin/')
    set_env('WindowsSdkDir',     winkit10 + '/')
    set_env('UniversalCRTSdkDir',winkit10 + '/')
    set_env('WindowsLibPath',    winkit10 + '/UnionMetadata;' + winkit10 + '/References')
    
    set_env('VCIDEInstallDir',   vprefix + '/Common7/IDE/VC/')
    set_env('VCINSTALLDIR',      vprefix + '/VC/')
    set_env('VCToolsInstallDir', vprefix + '/VC/Tools/MSVC/' + msvc_ver + '/')
    set_env('VCToolsRedistDir',  vprefix + '/VC/Redist/MSVC/' + msvc_ver + '/')
    set_env('VS150COMNTOOLS',    vprefix + '/Common7/Tools/')
    set_env('VSINSTALLDIR',      vprefix + '/')
    set_env('VisualStudioVersion', '17.0')
        
    set_env('WindowsSDK_ExecutablePath_x64', netfx_tools + '/x64/')
    set_env('WindowsSDK_ExecutablePath_x86', netfx_tools + '/')
    
    return vprefix + '/VC'

def _set_msvs_dev16(env, x64_host, x64_target, regv=None): # msvs 2019
    versions = ['Enterprise', 'Professional', 'Community']
    
    progfi = 'C:/Program Files (x86)'
    if regv:
        prefix = regv
    else:
        prefix = progfi + '/Microsoft Visual Studio/2019'

    if x64_target:
        tgt = 'x64'
    else:
        tgt = 'x86'

    found = False
    for v in versions:
        p = _ijoin(prefix,v)
        if os.path.exists(p):
            found = True
            break
    if not found:
        die('Could not find MSVS 2019 directory')
    vprefix = p
    winkit10 = progfi + '/Windows Kits/10'    
    winkit10version, winkit10complete = _get_winkit10_version(env,winkit10)
    #msgb('WINKIT10 VERSION', winkit10version)
    if winkit10complete == False:
        die('need a complete winkit10 for MSVS 2019 (dev 16)')
    env['rc_winkit'] = winkit10
    env['rc_winkit_number'] = winkit10version

    msvc_tools_root, msvc_ver = msvc_dir_from_vc_dir(vprefix + '/VC')
    
    netfx_sdk = progfi + '/Windows Kits/NETFXSDK/4.6.1/'
    
    path = []
    lib = []
    libpath = []
    inc  = []
    
    add_env(inc, prefix + '/ATLMFC/include')
    add_env(inc, msvc_tools_root + '/include')
    add_env(inc, netfx_sdk + 'include/um')
    wki = '{}/include/{}'.format(winkit10, winkit10version)
    add_env(inc, wki + '/ucrt')
    add_env(inc, wki + '/shared')
    add_env(inc, wki + '/um')
    add_env(inc, wki + '/winrt')
    add_env(inc, wki + '/cppwinrt')

    # LIB
    wkl = '{}/lib/{}'.format(winkit10, winkit10version)
    lib1 = '{}/ATLMFC/lib/{}'.format(msvc_tools_root,tgt)
    lib2 = '{}/lib/{}'.format(msvc_tools_root,tgt)
    add_env(lib, lib1)
    add_env(lib, lib2)
    add_env(lib, '{}lib/um/{}'.format(netfx_sdk,tgt))
    add_env(lib, '{}/ucrt/{}'.format(wkl,tgt))
    add_env(lib, '{}/um/{}'.format(wkl,tgt))

    # LIBPATH
    add_env(libpath, lib1)
    add_env(libpath, lib2)
    add_env(libpath, winkit10 + '/UnionMetadata')
    add_env(libpath, winkit10 + '/References')
    s = ''
    if tgt == 'x64':
        s = '64'
    fwr = 'C:/windows/Microsoft.NET/Framework{}'.format(s)
    fwr64 = 'C:/windows/Microsoft.NET/Framework64'
    fwv = 'v4.0.30319'
    fwp = '{}/{}'.format(fwr,fwv)
    add_env(libpath, fwp)

    # PATH

    # locations for cross compilers changed in this version
    set_msvc_compilers(env, msvc_tools_root)
    x86_to_x64 = env['msvc_compilers']['ia32']['ia32'] 
    x86_to_x86 = env['msvc_compilers']['ia32']['x86-64']
    x64_to_x86 = env['msvc_compilers']['x86-64']['ia32'] 
    x64_to_x64 = env['msvc_compilers']['x86-64']['x86-64'] 
    
    cross = False
    if x64_host:
        if x64_target:
            cl_tgt_bin_dir = x64_to_x64
        else:
            cross = True
            cl_tgt_bin_dir = x64_to_x86
            cl_host_bin_dir = x64_to_x64
    else: 
        if x64_target:
            cross = True
            cl_tgt_bin_dir = x86_to_x64
            cl_host_bin_dir = x64_to_x86
        else:
            cl_tgt_bin_dir = x86_to_x86
    
    add_env(path, cl_tgt_bin_dir)
    # CL TARGET compiler gets DLLs from the HOST bin dir
    if cross:
        add_env(path, cl_host_bin_dir)
        
    add_env(path, '{}/Common7/IDE/VC/VCPackages'.format(msvc_tools_root))
    add_env(path, '{}/Common7/IDE/CommonExtensions/Microsoft/TestWindow'.format(msvc_tools_root))
    add_env(path, '{}/Common7/IDE/CommonExtensions/Microsoft/TeamFoundation/Team Explorer'.format(msvc_tools_root))
    add_env(path, '{}/MSBuild/15.0/bin/Roslyn'.format(msvc_tools_root))
    add_env(path, '{}/Team Tools/Performance Tools'.format(msvc_tools_root))
    
    add_env(path, progfi + '/Microsoft Visual Studio/Shared/Common/VSPerfCollectionTools')
    netfx_tools = progfi + '/Microsoft SDKs/Windows/v10.0A/bin/NETFX 4.6.1 Tools'
    add_env(path, netfx_tools)

    add_env(path, '{}/bin/{}'.format(winkit10,tgt))
    add_env(path, '{}/bin/{}/{}'.format(winkit10,winkit10version,tgt))
    add_env(path, '{}/MSBuild/15.0/bin'.format(vprefix))
    add_env(path, fwp)
    add_env(path, '{}/Common7/IDE'.format(vprefix))
    add_env(path, '{}/Common7/Tools'.format(vprefix))

    set_env_list('INCLUDE',inc)
    set_env_list('LIB',lib)
    set_env_list('LIBPATH',libpath)
    add_to_front_list('PATH',path)
    if 0:
        msgb("INCLUDE", "\n\t".join(inc))
        msgb("LIB", "\n\t".join(lib))
        msgb("LIBPATH", "\n\t".join(libpath))
        msgb("PATH", "\n\t".join(path))

    # Misc env variables. Not sure which are needed, if any
    set_env('NETFXSDKDir',netfx_sdk)
    set_env('DevEnvDir', vprefix + '/Common7/IDE/')
    set_env('ExtensionSdkDir', progfi + '/Microsoft SDKs/Windows Kits/10/ExtensionSDKs')
    set_env('Framework40Version','v4.0')
    set_env('FrameworkVersion',fwv)
    if x64_host:
        set_env('VSCMD_ARG_HOST_ARCH','x64')
    else:
        set_env('VSCMD_ARG_HOST_ARCH','x86')
        
    set_env('Platform',tgt)
    set_env('VSCMD_ARG_TGT_ARCH',tgt)
        
    if x64_target:
        set_env('FrameworkDir', fwr)
        set_env('FrameworkDIR64',fwr)
        set_env('FrameworkVersion64',fwv)
    else: 
        set_env('FrameworkDIR32',fwr)
        set_env('FrameworkVersion32',fwv)
        if x64_host:
            set_env('FrameworkDir', fwr64)
            set_env('FrameworkDIR64',fwr64)
            set_env('FrameworkVersion64',fwv)
        else:
            set_env('FrameworkDir', fwr)
        
    set_env('UCRTVersion',          winkit10version)
    set_env('WindowsSDKLibVersion', winkit10version + '/')
    set_env('WindowsSDKVersion',    winkit10version + '/')
    set_env('WindowsSdkVerBinPath', '{}/bin/{}/'.format(winkit10,winkit10version))
    set_env('WindowsSdkBinPath', winkit10 + '/bin/')
    set_env('WindowsSdkDir',     winkit10 + '/')
    set_env('UniversalCRTSdkDir',winkit10 + '/')
    set_env('WindowsLibPath',    winkit10 + '/UnionMetadata;' + winkit10 + '/References')
    
    set_env('VCIDEInstallDir',   vprefix + '/Common7/IDE/VC/')
    set_env('VCINSTALLDIR',      vprefix + '/VC/')
    set_env('VCToolsInstallDir', vprefix + '/VC/Tools/MSVC/' + msvc_ver + '/')
    set_env('VCToolsRedistDir',  vprefix + '/VC/Redist/MSVC/' + msvc_ver + '/')
    set_env('VS150COMNTOOLS',    vprefix + '/Common7/Tools/')
    set_env('VSINSTALLDIR',      vprefix + '/')
    set_env('VisualStudioVersion', '15.0')
        
    set_env('WindowsSDK_ExecutablePath_x64', netfx_tools + '/x64/')
    set_env('WindowsSDK_ExecutablePath_x86', netfx_tools + '/')
    
    return vprefix + '/VC'
    
    
def _set_msvs_dev15(env, x64_host, x64_target, regv=None): # msvs 2017
    versions = ['Enterprise', 'Professional', 'Community']
    
    progfi = 'C:/Program Files (x86)'
    if regv:
        prefix = regv
    else:
        prefix = progfi + '/Microsoft Visual Studio/2017'

    if x64_target:
        tgt = 'x64'
    else:
        tgt = 'x86'

    found = False
    for v in versions:
        p = _ijoin(prefix,v)
        if os.path.exists(p):
            found = True
            break
    if not found:
        die('Could not find MSVS 2017 directory')
    vprefix = p
    #msgb('VPREFIX', vprefix)
    winkit10 = progfi + '/Windows Kits/10'    
    winkit10version, winkit10complete = _get_winkit10_version(env,winkit10)
    #msgb('WINKIT10 VERSION', winkit10version)
    if winkit10complete == False:
        die('need a complete winkit10 for MSVS 2017 (dev 15)')
    env['rc_winkit'] = winkit10
    env['rc_winkit_number'] = winkit10version

    msvc_tools_root, msvc_ver = msvc_dir_from_vc_dir(vprefix + '/VC')
    
    netfx_sdk = progfi + '/Windows Kits/NETFXSDK/4.6.1/'
    
    path = []
    lib = []
    libpath = []
    inc  = []
    
    add_env(inc, prefix + '/ATLMFC/include')
    add_env(inc, msvc_tools_root + '/include')
    add_env(inc, netfx_sdk + 'include/um')
    wki = '{}/include/{}'.format(winkit10, winkit10version)
    add_env(inc, wki + '/ucrt')
    add_env(inc, wki + '/shared')
    add_env(inc, wki + '/um')
    add_env(inc, wki + '/winrt')

    # LIB
    wkl = '{}/lib/{}'.format(winkit10, winkit10version)
    lib1 = '{}/ATLMFC/lib/{}'.format(msvc_tools_root,tgt)
    lib2 = '{}/lib/{}'.format(msvc_tools_root,tgt)
    add_env(lib, lib1)
    add_env(lib, lib2)
    add_env(lib, '{}lib/um/{}'.format(netfx_sdk,tgt))
    add_env(lib, '{}/ucrt/{}'.format(wkl,tgt))
    add_env(lib, '{}/um/{}'.format(wkl,tgt))

    # LIBPATH
    add_env(libpath, lib1)
    add_env(libpath, lib2)
    add_env(libpath, winkit10 + '/UnionMetadata')
    add_env(libpath, winkit10 + '/References')
    s = ''
    if tgt == 'x64':
        s = '64'
    fwr = 'C:/windows/Microsoft.NET/Framework{}'.format(s)
    fwr64 = 'C:/windows/Microsoft.NET/Framework64'
    fwv = 'v4.0.30319'
    fwp = '{}/{}'.format(fwr,fwv)
    add_env(libpath, fwp)

    # PATH

    # locations for cross compilers changed in this version
    set_msvc_compilers(env, msvc_tools_root)
    x86_to_x64 = env['msvc_compilers']['ia32']['ia32'] 
    x86_to_x86 = env['msvc_compilers']['ia32']['x86-64']
    x64_to_x86 = env['msvc_compilers']['x86-64']['ia32'] 
    x64_to_x64 = env['msvc_compilers']['x86-64']['x86-64'] 
    
    cross = False
    if x64_host:
        if x64_target:
            cl_tgt_bin_dir = x64_to_x64
        else:
            cross = True
            cl_tgt_bin_dir = x64_to_x86
            cl_host_bin_dir = x64_to_x64
    else: 
        if x64_target:
            cross = True
            cl_tgt_bin_dir = x86_to_x64
            cl_host_bin_dir = x64_to_x86
        else:
            cl_tgt_bin_dir = x86_to_x86
    
    add_env(path, cl_tgt_bin_dir)
    # CL TARGET compiler gets DLLs from the HOST bin dir
    if cross:
        add_env(path, cl_host_bin_dir)
        
    add_env(path, '{}/Common7/IDE/VC/VCPackages'.format(msvc_tools_root))
    add_env(path, '{}/Common7/IDE/CommonExtensions/Microsoft/TestWindow'.format(msvc_tools_root))
    add_env(path, '{}/Common7/IDE/CommonExtensions/Microsoft/TeamFoundation/Team Explorer'.format(msvc_tools_root))
    add_env(path, '{}/MSBuild/15.0/bin/Roslyn'.format(msvc_tools_root))
    add_env(path, '{}/Team Tools/Performance Tools'.format(msvc_tools_root))
    
    add_env(path, progfi + '/Microsoft Visual Studio/Shared/Common/VSPerfCollectionTools')
    netfx_tools = progfi + '/Microsoft SDKs/Windows/v10.0A/bin/NETFX 4.6.1 Tools'
    add_env(path, netfx_tools)

    add_env(path, '{}/bin/{}'.format(winkit10,tgt))
    add_env(path, '{}/bin/{}/{}'.format(winkit10,winkit10version,tgt))
    add_env(path, '{}/MSBuild/15.0/bin'.format(vprefix))
    add_env(path, fwp)
    add_env(path, '{}/Common7/IDE'.format(vprefix))
    add_env(path, '{}/Common7/Tools'.format(vprefix))

    set_env_list('INCLUDE',inc)
    set_env_list('LIB',lib)
    set_env_list('LIBPATH',libpath)
    add_to_front_list('PATH',path)
    if 0:
        msgb("INCLUDE", "\n\t".join(inc))
        msgb("LIB", "\n\t".join(lib))
        msgb("LIBPATH", "\n\t".join(libpath))
        msgb("PATH", "\n\t".join(path))

    # Misc env variables. Not sure which are needed, if any
    set_env('NETFXSDKDir',netfx_sdk)
    set_env('DevEnvDir', vprefix + '/Common7/IDE/')
    set_env('ExtensionSdkDir', progfi + '/Microsoft SDKs/Windows Kits/10/ExtensionSDKs')
    set_env('Framework40Version','v4.0')
    set_env('FrameworkVersion',fwv)
    if x64_host:
        set_env('VSCMD_ARG_HOST_ARCH','x64')
    else:
        set_env('VSCMD_ARG_HOST_ARCH','x86')
        
    set_env('Platform',tgt)
    set_env('VSCMD_ARG_TGT_ARCH',tgt)
        
    if x64_target:
        set_env('FrameworkDir', fwr)
        set_env('FrameworkDIR64',fwr)
        set_env('FrameworkVersion64',fwv)
    else: 
        set_env('FrameworkDIR32',fwr)
        set_env('FrameworkVersion32',fwv)
        if x64_host:
            set_env('FrameworkDir', fwr64)
            set_env('FrameworkDIR64',fwr64)
            set_env('FrameworkVersion64',fwv)
        else:
            set_env('FrameworkDir', fwr)
        
    set_env('UCRTVersion',          winkit10version)
    set_env('WindowsSDKLibVersion', winkit10version + '/')
    set_env('WindowsSDKVersion',    winkit10version + '/')
    set_env('WindowsSdkVerBinPath', '{}/bin/{}/'.format(winkit10,winkit10version))
    set_env('WindowsSdkBinPath', winkit10 + '/bin/')
    set_env('WindowsSdkDir',     winkit10 + '/')
    set_env('UniversalCRTSdkDir',winkit10 + '/')
    set_env('WindowsLibPath',    winkit10 + '/UnionMetadata;' + winkit10 + '/References')
    
    set_env('VCIDEInstallDir',   vprefix + '/Common7/IDE/VC/')
    set_env('VCINSTALLDIR',      vprefix + '/VC/')
    set_env('VCToolsInstallDir', vprefix + '/VC/Tools/MSVC/' + msvc_ver + '/')
    set_env('VCToolsRedistDir',  vprefix + '/VC/Redist/MSVC/' + msvc_ver + '/')
    set_env('VS150COMNTOOLS',    vprefix + '/Common7/Tools/')
    set_env('VSINSTALLDIR',      vprefix + '/')
    set_env('VisualStudioVersion', '15.0')
        
    set_env('WindowsSDK_ExecutablePath_x64', netfx_tools + '/x64/')
    set_env('WindowsSDK_ExecutablePath_x86', netfx_tools + '/')
    
    return vprefix + '/VC'

def _set_msvs_dev14(env, x64_host, x64_target, regv=None): # msvs 2015
    progfi = 'C:/Program Files (x86)'
    if regv:
        prefix = regv
    else:
        prefix = progfi + '/Microsoft Visual Studio 14.0'
        
    sdk81a = progfi + '/Microsoft SDKs/Windows/v8.1A'
    sdk81  = progfi + '/Microsoft SDKs/Windows/v8.1'
    sdk10a = progfi + '/Microsoft SDKs/Windows/v10.0A'
    if os.path.exists(sdk10a):
        sdk81a = None
        sdk81 = None
    else:
        sdk10a = None
        
    winkit8 = progfi + '/Windows Kits/8.1'
    winkit10 = progfi + '/Windows Kits/10'

    if os.path.exists(winkit10):
        winkit = winkit10
        sdk81 = None
        sdk81a = None
    else:
        winkit = winkit8
        winkit10 = None

    winkit10version, winkit10complete = _get_winkit10_version(env,winkit10)
    # if winkit10complete is False, we need to fall back on 
    # winkit8 for some stuff

    if winkit10complete:
        env['rc_winkit'] = winkit10
        env['rc_winkit_number'] = winkit10version
    else:
        env['rc_winkit'] = winkit8

    path = []
    lib = []
    libpath = []

    inc  = []
    add_env(inc, prefix + '/VC/INCLUDE')
    add_env(inc, prefix + '/VC/ATLMFC/INCLUDE')

    if winkit10version:
        t = '{}/include/{}'.format(winkit10,winkit10version)
        add_env(inc, t + '/ucrt')

    if winkit10version and winkit10complete:
        add_env(inc, t + '/shared')
        add_env(inc, t + '/um')
        add_env(inc, t + '/winrt')
    else:
        add_env(inc, winkit8 + '/include') # not used in msvs12
        add_env(inc, winkit8 + '/include/shared')
        add_env(inc, winkit8 + '/include/um')
        add_env(inc, winkit8 + '/include/winrt')

    set_env_list('INCLUDE',inc)

    set_env('Framework40Version', 'v4.0')
    set_env('FrameworkVersion',  'v4.0.30319')
    #set_env('ExtensionSdkDir', sdk81  + '/ExtensionSDKs')

    set_env('VCINSTALLDIR', prefix + '/VC/')
    set_env('VS140COMNTOOLS', prefix + '/Common7/Tools')
    set_env('VSINSTALLDIR' , prefix)
    set_env('WindowsSdkDir', winkit  + '/')
    set_env('VisualStudioVersion','14.0')

    if sdk10a:
        set_env('WindowsSDK_ExecutablePath_x86',
                sdk10a + '/bin/NETFX 4.6.1 Tools/')
    elif sdk81a:
        set_env('WindowsSDK_ExecutablePath_x86',
                sdk81a + '/bin/NETFX 4.5.1 Tools/')
        
    if x64_target:
        if sdk10a:
            set_env('WindowsSDK_ExecutablePath_x64',
                    sdk10a +'/bin/NETFX 4.6.1 Tools/x64/')
        elif sdk81a:
            set_env('WindowsSDK_ExecutablePath_x64',
                    sdk81a +'/bin/NETFX 4.5.1 Tools/x64/')

        set_env('FrameworkDir','c:/WINDOWS/Microsoft.NET/Framework64')
        set_env('FrameworkDIR64','c:/WINDOWS/Microsoft.NET/Framework64')
        set_env('FrameworkVersion64', 'v4.0.30319')

        set_env('Platform','X64')

        add_env(lib, prefix  + '/VC/LIB/amd64')
        add_env(lib, prefix  + '/VC/ATLMFC/LIB/amd64')
        if winkit10version:
            add_env(lib,  winkit10 + '/lib/{}/ucrt/x64'.format(winkit10version))
        if winkit10version and winkit10complete:
            add_env(lib,  winkit10 + '/lib/{}/um/x64'.format(winkit10version))
        else:
            add_env(lib, winkit8 + '/lib/winv6.3/um/x64')

        add_env(libpath, 'c:/WINDOWS/Microsoft.NET/Framework64/v4.0.30319')
        add_env(libpath, prefix + '/VC/LIB/amd64')
        add_env(libpath, prefix + '/VC/ATLMFC/LIB/amd64')
        if not winkit10:
            add_env(libpath, winkit + '/References/CommonConfiguration/Neutral')
        # next one is usually not present and I am unclear of value/need
        #if sdk81:
        #    add_env(libpath, sdk81 + '/ExtensionSDKs/Microsoft.VCLibs/14.0/' + 
        #            'References/CommonConfiguration/neutral')

        add_env(path, prefix + '/Common7/IDE/CommonExtensions/Microsoft/TestWindow')
        add_env(path,  prefix + '/VC/BIN/amd64')
        add_env(path,  'c:/WINDOWS/Microsoft.NET/Framework64/v4.0.30319')

        add_env(path, prefix + '/VC/VCPackages')
        add_env(path, prefix + '/Common7/IDE')
        add_env(path, prefix + '/Common7/Tools')
        add_env(path, 'C:/Program Files (x86)/HTML Help Workshop')
        add_env(path, prefix + '/Team Tools/Performance Tools/x64')
        add_env(path, prefix + '/Team Tools/Performance Tools')
        
        if winkit10complete:
            t = winkit10
        else:
            t = winkit8
        add_env(path, t  + '/bin/x64')
        add_env(path, t  + '/bin/x86')
            
        if sdk10a:
            b = _find_latest_subdir(sdk10a + '/bin/')
            add_env(path, b + '/x64')
        elif sdk81a:
            add_env(path, sdk81a + '/bin/NETFX 4.5.1 Tools/x64')

    else: # 32b
        set_env('FrameworkDir', 'c:/WINDOWS/Microsoft.NET/Framework')
        set_env('FrameworkDIR32', 'c:/WINDOWS/Microsoft.NET/Framework')
        set_env('FrameworkVersion32','v4.0.30319')

        add_env(lib,  prefix + '/VC/LIB')
        add_env(lib,  prefix + '/VC/ATLMFC/LIB')
        if winkit10version:
            add_env(lib,  winkit10 + '/lib/{}/ucrt/x86'.format(winkit10version))
        if winkit10version and winkit10complete:
            add_env(lib,  winkit10 + '/lib/{}/um/x86'.format(winkit10version))
        else:
            add_env(lib,  winkit8 + '/lib/winv6.3/um/x86')
        
        add_env(libpath,  'c:/WINDOWS/Microsoft.NET/Framework/v4.0.30319')
        add_env(libpath,  prefix  + '/VC/LIB')
        add_env(libpath,  prefix  + '/VC/ATLMFC/LIB')
        if not winkit10complete:
            add_env(libpath,  winkit8  + '/References/CommonConfiguration/Neutral')
        # next one is usually not present and I am unclear of value/need
        #if sdk81:
        #    add_env(libpath,  sdk81  + '/ExtensionSDKs/Microsoft.VCLibs/14.0/' + 
        #            'References/CommonConfiguration/neutral')

        add_env(path, prefix + '/Common7/IDE/CommonExtensions/Microsoft/TestWindow')
        add_env(path, progfi + '/Microsoft SDKs/F#/3.1/Framework/v4.0')
        add_env(path, progfi  + '/MSBuild/14.0/bin')
        add_env(path, prefix + '/Common7/IDE')
        add_env(path, prefix + '/VC/BIN')
        add_env(path, prefix + '/Common7/Tools')
        add_env(path, 'C:/Windows/Microsoft.NET/Framework/v4.0.30319')
        add_env(path, prefix + '/VC/VCPackages')
        add_env(path, progfi + '/HTML Help Workshop')
        add_env(path, prefix + '/Team Tools/Performance Tools')

        if winkit10complete:
            t = winkit10
        else:
            t = winkit8
        add_env(path, t  + '/bin/x86')

        if sdk10a:
            b = _find_latest_subdir(sdk10a + '/bin/')
            add_env(path, b + '/x64')
        elif sdk81a:
            add_env(path, sdk81a + '/bin/NETFX 4.5.1 Tools')


    set_env_list('LIBPATH',libpath)
    set_env_list('LIB',lib)
    add_to_front_list('PATH',path)

    return    prefix + "/VC"


def _figure_out_msvs_version_filesystem(env, specific_version=0):
    """If specific_version is set to one of the listed versions, this will
    only return success if that version is found. Otherwise it returns
    the latest install. """
    
    prefixes = [
        (17,'C:/Program Files/Microsoft Visual Studio/2022'),
        (16,'C:/Program Files (x86)/Microsoft Visual Studio/2019'),
        
        # starting with DEV15, everything is in the "Program Files
        # (x86)" directory.
        (15,'C:/Program Files (x86)/Microsoft Visual Studio/2017'),
        
        (14,'C:/Program Files (x86)/Microsoft Visual Studio 14.0'),
        (14,'C:/Program Files/Microsoft Visual Studio 14.0'),
        
        (12,'C:/Program Files (x86)/Microsoft Visual Studio 12.0'),
        (12,'C:/Program Files/Microsoft Visual Studio 12.0'),

        (11,'C:/Program Files (x86)/Microsoft Visual Studio 11.0'),
        (11,'C:/Program Files/Microsoft Visual Studio 11.0'),
        
        (10,'C:/Program Files (x86)/Microsoft Visual Studio 10.0'),
        (10,'C:/Program Files/Microsoft Visual Studio 10.0'),
        
        (9,'C:/Program Files (x86)/Microsoft Visual Studio 9.0'),
        (9,'C:/Program Files/Microsoft Visual Studio 9.0'),
        
        (8, "c:/Program Files (x86)/Microsoft Visual Studio 8"),
        (8,"c:/Program Files/Microsoft Visual Studio 8"),
        
        (7, "c:/Program Files/Microsoft Visual Studio .NET 2003"),
        (7,"c:/Program Files (x86)/Microsoft Visual Studio .NET 2003")
    ]
    for v,dir in prefixes:
        if os.path.exists(dir):
            if specific_version:
                if specific_version == v:
                    return str(v)
            else:
                return str(v)
    return None # we don't know

_is_py2 = sys.version[0] == '2'

def _read_registry(root,key,value):
    if _is_py2:
        import _winreg as winreg
    else:
        import winreg
    try:
        hkey = winreg.OpenKey(root, key)
    except:
        return None
    try:
        (val, typ) = winreg.QueryValueEx(hkey, value)
    except:
        winreg.CloseKey(hkey)
        return None
    winreg.CloseKey(hkey)
    return val

def pick_compiler(env):
    if env['msvs_version']:
        if int(env['msvs_version']) >= 15:
            compilers_dict = env['msvc_compilers']
            return compilers_dict[env['build_cpu']][env['host_cpu']]
    return _pick_compiler_until_dev14(env)
    
def _pick_compiler_until_dev14(env):
    if env['build_cpu'] == 'ia32' and env['host_cpu'] == 'ia32':
        toolchain = os.path.join(env['vc_dir'], 'bin', '')
    elif env['build_cpu'] == 'ia32' and env['host_cpu'] == 'x86-64':
        toolchain = os.path.join(env['vc_dir'], 'bin', 'x86_amd64', '')
    elif env['build_cpu'] == 'x86-64' and env['host_cpu'] == 'x86-64':
        toolchain = os.path.join(env['vc_dir'], 'bin', 'amd64', '')
    elif env['build_cpu'] == 'x86-64' and env['host_cpu'] == 'ia32':
        toolchain = os.path.join(env['vc_dir'], 'bin', '')
    elif env['compiler'] == 'ms':
        die("Unknown build/target combination. build cpu=%s, " + 
            "host_cpu=%s" % ( env['build_cpu'], env['host_cpu']))
    return toolchain

def _find_msvc_in_registry(env,version):
    if _is_py2:
        import _winreg as winreg
    else:
        import winreg

    vs_ver = str(version) + '.0'
    vs_key = 'SOFTWARE\\Microsoft\\VisualStudio\\' + vs_ver + '\\Setup\\VS'
    vc_key = 'SOFTWARE\\Microsoft\\VisualStudio\\' + vs_ver + '\\Setup\\VC'
    vs_dir = _read_registry(winreg.HKEY_LOCAL_MACHINE, vs_key, 'ProductDir')
    vc_dir = _read_registry(winreg.HKEY_LOCAL_MACHINE, vc_key, 'ProductDir')
    
    # On a 64-bit host, look for a 32-bit installation 

    if (not vs_dir or not vc_dir):
        vs_key = 'SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio\\' + \
            vs_ver + '\\Setup\\VS'
        vc_key = 'SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio\\' + \
            vs_ver + '\\Setup\\VC'
        vs_dir = _read_registry(winreg.HKEY_LOCAL_MACHINE, 
                                vs_key, 'ProductDir')
        vc_dir = _read_registry(winreg.HKEY_LOCAL_MACHINE, 
                                vc_key, 'ProductDir')
    return (vs_dir,vc_dir)

def _figure_out_msvs_version_registry(env):
    # starting with DEV15 (MSVS2017) MS stopped using the
    # registry to store installation information.
    versions = [14,12,11,10,9,8,7,6]
    for v in versions:
        (vs_dir,vc_dir) = _find_msvc_in_registry(env,v)
        if vs_dir and vc_dir:
            return (str(v),vs_dir)
    return (None,None)

def _find_specific_msvs_version(env,uv):
    """Search for (integer) uv version of MSVS in registry & file system"""
    found = False
    # 1. look for specific version in registry
    if uv < 15:
        (vs_dir,vc_dir) = _find_msvc_in_registry(env,uv)
        if vs_dir and vc_dir:
            env['msvs_version'] = str(uv) 
            found = True
        else:
            warn("Could not find specified version of MSVS in registry: {}".format(uv))

    # 2. look in file system for specific version
    if not found:
        env['msvs_version'] = _figure_out_msvs_version_filesystem(env, uv)
        if env['msvs_version']:
            found = True
        else:
            warn("Could not find specified version of MSVS in file system: {}".format(uv))
    return found


        
def set_msvs_env(env):
    versions = []
    if env['msvs_version'] != '' :
        if ',' in env['msvs_version']:    # got a list of versions
            versions = map(str.strip,env['msvs_version'].split(','))
        else:
            versions = [ env['msvs_version'] ]
            
    found = False
    for uv in versions:
        iuv = int(uv)
        if _find_specific_msvs_version(env,iuv):
            found = True
            break
    if versions and not found:
        die("Could not find specified MSVS version(s): [{}]".format(",".join(versions)))
    
    # 3. Trying to locate newest version in file system. Must do this
    # before generic registry search because regitry stopped being
    # updated with DEV15/MSVS2017.
    if not found:
        env['msvs_version'] = _figure_out_msvs_version_filesystem(env)
        if env['msvs_version']:
            found = True

    # 4. try latest version in registry
    if not found:
        env['msvs_version'], vs_dir = _figure_out_msvs_version_registry(env)
        
    if not env['msvs_version']:
        die("Did not find MSVS version!")


            
    x64_target=False
    if  env['host_cpu'] == 'x86-64':
        x64_target=True

    x64_host = False
    if  env['build_cpu'] == 'x86-64':
        x64_host=True

            
    # "express" compiler is 32b only            
    vc = None
    vs_dir = None
    i = int(env['msvs_version'])
    if i == 6: # 32b only
        vc = _set_msvs_dev6(env,x64_host, x64_target)
    elif i == 7: # 32b only
        vc = _set_msvs_dev7(env,x64_host, x64_target)
    elif i == 8: 
        vc = _set_msvs_dev8(env, x64_host, x64_target, vs_dir)
    elif i == 9: 
        vc = _set_msvs_dev9(env, x64_host, x64_target, vs_dir)
    elif i == 10:
        vc = _set_msvs_dev10(env, x64_host, x64_target, vs_dir)
    elif i == 11: 
        vc = _set_msvs_dev11(env, x64_host, x64_target, vs_dir)
    elif i == 12: 
        vc = _set_msvs_dev12(env, x64_host, x64_target, vs_dir)
    # And 12 shall be followed by 14. 13? 13 is Right Out!
    elif i == 14: 
        vc = _set_msvs_dev14(env, x64_host, x64_target, vs_dir)
    elif i == 15:  # vs 2017
        vc = _set_msvs_dev15(env, x64_host, x64_target, vs_dir)
    elif i == 16:  # vs 2019
        vc = _set_msvs_dev16(env, x64_host, x64_target, vs_dir)
    elif i == 17:  # vs 2022
        vc = _set_msvs_dev17(env, x64_host, x64_target, vs_dir)
    else:
        die("Unhandled MSVS version: " + env['msvs_version'])

    msgb("FOUND MS VERSION",env['msvs_version'])
    return vc
    
