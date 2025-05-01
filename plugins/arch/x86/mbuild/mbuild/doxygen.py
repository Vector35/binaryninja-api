#!/usr/bin/env python
# -*- python -*-
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


############################################################################
## START OF IMPORTS SETUP
############################################################################

import sys
import os
import re
import copy
import glob
import types

try:
   from . import base
   from . import dag
   from . import util
   from . import plan
except:
   s = "\nXED ERROR: mfile.py could not find mbuild."  + \
       " Should be a sibling of the xed2 directory.\n\n"
   sys.stderr.write(s)
   sys.exit(1)


###########################################################################
## DOXYGEN SUPPORT
###########################################################################

def _doxygen_version_okay(s, want_major, want_minor, want_fix):
    values = s.split('.')
    
    maj =int(values[0])
    minor = int(values[1])
    fix = 0
    if len(values) > 2:
        # remove everything after the dash for things like: 'Doxygen
        # 1.5.1-p1'
        values[2] = re.sub(r'-.*$','',values[2])
        try:
            fix = int(values[2])
        except ValueError as v:
            pass
    if (maj > 1) or \
           (maj == want_major and minor > want_minor) or \
           (maj == want_major and minor == want_minor and fix >= want_fix):
        return True
    return False

def _find_doxygen(env):
    """Find the right version of doxygen. Return a tuple of the
    command name and a boolean indicating whether or not the version
    checked out."""

    if env['doxygen_cmd'] == '':
        doxygen_cmd_intel  = "/usr/intel/bin/doxygen"
        doxygen_cmd_cygwin = "C:/cygwin/bin/doxygen"
        doxygen_cmd_mac    = \
                    "/Applications/Doxygen.app/Contents/Resources/doxygen"
        doxygen_cmd = "doxygen"

        if env['build_os'] == 'win':
           if os.path.exists(doxygen_cmd_cygwin):
              doxygen_cmd = doxygen_cmd_cygwin
           else:
              base.msgb('DOXYGEN',"Could not find cygwin's doxygen," +
                          "trying doxygen from PATH")
        elif env['build_os'] == 'lin':
           if base.verbose(2):
              base.msgb("CHECKING FOR", doxygen_cmd_intel)
           if  os.path.exists(doxygen_cmd_intel):
              doxygen_cmd = doxygen_cmd_intel
        elif env['build_os'] == 'mac':
           if base.verbose(2):
              base.msgb("CHECKING FOR", doxygen_cmd_mac)
           if  os.path.exists(doxygen_cmd_mac):
              doxygen_cmd = doxygen_cmd_mac
    else:
        doxygen_cmd = env['doxygen_cmd']
        
    doxygen_cmd = env.escape_string(doxygen_cmd)
    doxygen_okay = False
    if base.verbose(2):
        base.msgb('Checking doxygen version','...')
    if base.check_python_version(2,4):
        try:
            (retval, output, error_output) = \
                     util.run_command(doxygen_cmd + " --version")
            if retval==0:
                if len(output) > 0:
                    first_line = output[0].strip()
                    if base.verbose(2):
                        base.msgb("Doxygen version", first_line)
                    doxygen_okay = _doxygen_version_okay(first_line, 1,4,6)
            else:
                for o in output:
                    base.msgb("Doxygen-version-check STDOUT", o)
                if error_output:
                    for line in error_output:
                        base.msgb("STDERR ",line.rstrip())
        except:
            base.die("Doxygen required by the command line options " +
                       "but no doxygen found")
            
    return (doxygen_cmd, doxygen_okay)


def _replace_match(istring, mtch, newstring, group_name):
    """This is a lame way of avoiding regular expression backslashing
    issues"""
    x1= mtch.start(group_name)
    x2= mtch.end(group_name)
    ostring = istring[0:x1] + newstring + istring[x2:]
    return ostring


def _customize_doxygen_file(env, subs):
   
    """Change the $(*) strings to the proper value in the config file.
    Returns True on success"""
    
    # doxygen wants quotes around paths with spaces
    for k,s in iter(subs.items()):
       if re.search(' ',s):
          if not re.search('^".*"$',s):
             base.die("Doxygen requires quotes around strings with spaces: [%s]->[%s]" %
                        ( k,s))
             return False

    # input and output files
    try:
        lines =  open(env['doxygen_config']).readlines()
    except:
        base.msgb("Could not open input file: " + env['doxygen_config'])
        return False

    env['doxygen_config_customized'] = \
             env.build_dir_join(os.path.basename(env['doxygen_config']) + '.customized')
    try:
        ofile =  open(env['doxygen_config_customized'],'w')
    except:
        base.msgb("Could not open output file: " + env['doxygen_config_customized'])
        return False
          
    # compile the patterns
    rsubs = {}
    for k,v in iter(subs.items()):
       rsubs[k]=re.compile(r'(?P<tag>[$][(]' + k + '[)])')

    olines = []
    for line in  lines:
       oline = line
       for k,p in iter(rsubs.items()):
          #print ('searching for', k, 'to replace it with', subs[k])
          m =  p.search(oline)
          while m:
             #print ('replacing', k, 'with', subs[k])
             oline = _replace_match(oline, m, subs[k], 'tag')
             m =  p.search(oline)
       olines.append(oline)

       
    try:
       for line in olines:
          ofile.write(line)
    except:
       ofile.close()
       base.msgb("Could not write output file: " + env['doxygen_config_customized'])
       return False
     
    ofile.close()
    return True

def _build_doxygen_main(args, env):
    """Customize the doxygen input file. Run the doxygen command, copy
    in any images, and put the output in the right place."""

    if isinstance(args, list):
       if len(args) < 2:
          base.die("Need subs dictionary and  dummy file arg for the doxygen command " +
                     "to indicate its processing")       
    else:
       base.die("Need a list for _build_doxygen_main with the subs "  +
                  "dictionary and the dummy file name")
       
    (subs,dummy_file) = args

    (doxygen_cmd, doxygen_okay) = _find_doxygen(env)
    if not doxygen_okay:
        msg = 'No good doxygen available on this system; ' + \
              'Your command line arguments\n\trequire it to be present. ' + \
              'Consider dropping the "doc" and "doc-build" options\n\t or ' + \
              'specify a path to doxygen with the --doxygen knob.\n\n\n'
        return (1, [msg]) # failure
    else:
        env['DOXYGEN'] = doxygen_cmd

    try:
        okay = _customize_doxygen_file(env, subs)
    except:
        base.die("CUSTOMIZE DOXYGEN INPUT FILE FAILED")
    if not okay:
        return (1, ['Doxygen customization failed'])
    
    cmd   = env['DOXYGEN'] + ' ' + \
            env.escape_string(env['doxygen_config_customized'])
    if base.verbose(2):
        base.msgb("RUN DOXYGEN", cmd)    
    (retval, output, error_output) = util.run_command(cmd)

    for line in output:
        base.msgb("DOX",line.rstrip())
    if error_output:
        for line in error_output:
            base.msgb("DOX-ERROR",line.rstrip())
    if retval != 0:
        base.msgb("DOXYGEN FAILED")
        base.die("Doxygen run failed. Retval=", str(retval))
    util.touch(dummy_file)
    base.msgb("DOXYGEN","succeeded")
    return (0, []) # success


###########################################################################
# Doxygen build
###########################################################################
def _empty_dir(d):
    """return True if the directory d does not exist or if it contains no
    files/subdirectories."""
    if not os.path.exists(d):
        return True
    for (root, subdirs, subfiles) in  os.walk(d):
        if len(subfiles) or len(subdirs):
            return False
        return True

def _make_doxygen_reference_manual(env, doxygen_inputs, subs, work_queue,
                                   hash_file_name='dox'):
    """Install the doxygen reference manual the doyxgen_output_dir
    directory. doxygen_inputs is a list of files """
    
    dox_dag = dag.dag_t(hash_file_name,env=env)
    
    # so that the scanner can find them
    dirs = {}
    for f in doxygen_inputs:
       dirs[os.path.dirname(f)]=True
    for d in dirs.keys():
       env.add_include_dir(d)

    # make sure the config and top file are in the inptus list
    doxygen_inputs.append(env['doxygen_config'])
    doxygen_inputs.append(env['doxygen_top_src'])
    
    dummy = env.build_dir_join('dummy-doxygen-' + hash_file_name)

    # Run it via the builder to make it dependence driven
    run_always = False
    if _empty_dir(env['doxygen_install']):
        run_always = True
        
    if run_always:
       _build_doxygen_main([subs,dummy], env)
    else:
       c1 = plan.plan_t(command=_build_doxygen_main,
                          args=   [subs,dummy],
                          env=    env,
                          input=  doxygen_inputs,
                          output= dummy)
       dox1 = dox_dag.add(env,c1)

       okay = work_queue.build(dag=dox_dag)
       phase = "DOXYGEN"
       if not okay:
           base.die("[%s] failed. dying..." % phase)
       if base.verbose(2):
           base.msgb(phase, "build succeeded")


############################################################

def doxygen_env(env):
   """Add the doxygen variables to the environment"""
   doxygen_defaults = dict(    doxygen_config='',
                               doxygen_top_src='',
                               doxygen_install='',
                               doxygen_cmd='' )
   env.update_dict(doxygen_defaults)
   
def doxygen_args(env):
   """Add the knobs to the command line knobs parser"""
    
   env.parser.add_option("--doxygen-install",
                         dest="doxygen_install",
                         action="store",
                         default='',
                         help="Doxygen installation directory")
   
   env.parser.add_option("--doxygen-config",
                         dest="doxygen_config",
                         action="store",
                         default='',
                         help="Doxygen config file")
   
   env.parser.add_option("--doxygen-top-src",
                         dest="doxygen_top_src",
                         action="store",
                         default='',
                         help="Doxygen top source file")
   
   env.parser.add_option("--doxygen-cmd",
                         dest="doxygen_cmd",
                         action="store",
                         default='',
                         help="Doxygen command name")
   
   
def doxygen_run(env, inputs, subs, work_queue, hash_file_name='dox'):
   """Run doxygen assuming certain values are in the environment env.
   
   @type  env: env_t
   @param env: the environment

   @type  inputs: list 
   @param inputs: list of input files to scan for dependences

   @type  subs: dictionary
   @param subs: replacements in the config file

   @type  work_queue: work_queue_t
   @param work_queue: a work queue for the build

   @type hash_file_name: string
   @param hash_file_name: used for the dummy file and mbuild hash suffix
   """
   _make_doxygen_reference_manual(env, inputs, subs, work_queue, hash_file_name)


    

 
