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

"""Basic useful utilities: file copying, removal, permissions,
path-name manipulation, and command execution."""

import os
import re
import glob
import io # for io.open
import sys
import shutil
import stat
import types
import time
import subprocess
import tempfile
import shlex
import traceback
try:
    import cPickle as apickle
except:
    import pickle as apickle

from .base import *


def find_python(env):
    """return path to NON cygwin"""
    pycmd = sys.executable # use whatever the user invoked us with
    if env.on_windows() and env.on_cygwin():
      # avoid cygwin python
      if pycmd in ['/usr/bin/python', '/bin/python']:
          python_commands = [ 'c:/python27/python.exe',
                              'c:/python26/python.exe',
                              'c:/python25/python.exe' ]
          pycmd  = None
          for p in python_commands:
              if os.path.exists(p):
                  return p
          if not pycmd:
              die("Could not find win32 python at these locations: %s" %
                         "\n\t" + "\n\t".join(python_commands))
    
    return pycmd                     
def copy_file(src,tgt):
    """Copy src to tgt."""
    if verbose(2):
        msgb("COPY", tgt + " <- " + src)
    shutil.copy(src,tgt)
def move_file(src,tgt):
    """Move/Rename src to tgt."""
    if verbose(2):
        msgb("MOVE", src + " -> " + tgt)
    shutil.move(src,tgt)
def symlink(env,src,tgt):
    """Make a symlink from src to target. Not available on windows."""
    if env.on_windows():
        die("symlink() not available on windows")
    if verbose(2):
        msgb("SYMLINK", src + " -> " + tgt)
    os.symlink(src,tgt)

def copy_tree(src,tgt, ignore_patterns=None, symlinks=False):
    """Copy the tree at src to tgt. This will first remove tgt if it
    already exists."""
    if verbose(2):
        msgb("COPYTREE", tgt + " <- " + src)
    if not os.path.exists(src):
        error_msg("SRC TREE DOES NOT EXIST", src)
        raise Exception
    if os.path.exists(tgt):
        if verbose(2):
            msgb("Removing existing target tree", tgt)
        shutil.rmtree(tgt, ignore_errors=True)
    if verbose(2):
        msgb("Copying to tree", tgt)
    if ignore_patterns:
        sp = shutil.ignore_patterns(ignore_patterns)
    else:
        sp = None
    shutil.copytree(src,tgt,ignore=sp, symlinks=symlinks)
    if verbose(2):
        msgb("Done copying tree", tgt)

def cmkdir(path_to_dir):
    """Make a directory if it does not exist"""
    if not os.path.exists(path_to_dir):
        if verbose(2):
            msgb("MKDIR", path_to_dir)
        os.makedirs(path_to_dir)
def list2string(ls):
    """Print a list as a string"""
    s = " ".join(ls)
    return s

def util_add_to_list(olst, v):
    """Add v to olst. v can be a list or a non-list object. If v is a
       list, extend olst. If v is not a list, append to olst. """
    if isinstance(v,list):
        olst.extend(v)
    else:
        olst.append(v)

def remove_file(fn, env=None, quiet=True):
    """Remove a file or link if it exists. env parameter is not used."""
    if os.path.exists(fn):
       make_writable(fn)
    if os.path.exists(fn) or os.path.lexists(fn):
       if not quiet:
           vmsgb(2, "REMOVING", fn)
       os.unlink(fn)
    return (0, [])
def remove_tree(dir_name, env=None, dangerous=False):
    """Remove a directory if it exists. env parameter is not
    used. This will not remove a directory that has a .svn or .git
    subdirectory indicating it is a source directory. Warning: It does
    not look recursively for .svn/.git subdirectories.
    @type  dir_name: string
    @param dir_name: a directory name
    @type env: L{env_t}
    @param env: optional. Not currently used.
    @type  dangerous: bool 
    @param dangerous: optional. If True,will delete anything including svn trees!! BE CAREFUL! default False.
    """

    def _important_file(dir_name):
        for idir in ['.git', '.svn']:
            if os.path.exists(os.path.join(dir_name, idir)):
                return True
        return False
    
    vmsgb(2, "CHECKING", dir_name)
    if os.path.exists(dir_name):
       if not dangerous and _important_file(dir_name):
           s = 'Did not remove directory {} because of a .svn/.git subdirectory'.format(dir_name)
           warn(s)
           return (1, [ s ])
       vmsgb(2, "REMOVING", dir_name)
       make_writable(dir_name)
       shutil.rmtree(dir_name, ignore_errors = True)
    return (0, [])
def remove_files(lst, env=None):
    """Remove all the files in the list of files, lst. The env
    parameter is not used"""
    for fn in lst:
        remove_file(fn)
    return (0, [])

def remove_files_glob(lst,env=None):
    """Remove all files in the list of wild card expressions. The env
    parameter is not used"""
    for fn_glob in lst:
        #msgb("REMOVING", fn_glob)
        for file_name in glob(fn_glob):
            remove_file(file_name)
    return (0, [])

def remove_files_from_tree(dir, file_patterns):
    """Remove files that match the re object compiled pattern provided"""
    for (dir, subdirs, subfiles) in  os.walk(dir):
        for file_name  in subfiles:
            fn = os.path.join(dir,file_name)
            if file_patterns.search(fn):
                remove_file(fn)


_readable_by_all   =  stat.S_IRUSR|stat.S_IRGRP|stat.S_IROTH
_readable_by_ug    =  stat.S_IRUSR|stat.S_IRGRP
_executable_by_all =  stat.S_IXUSR|stat.S_IXGRP|stat.S_IXOTH
_executable_by_ug  =  stat.S_IXUSR|stat.S_IXGRP
_writeable_by_me   =  stat.S_IWUSR
_rwx_by_me         =  stat.S_IWUSR| stat.S_IRUSR|stat.S_IXUSR
_writeable_by_ug   = stat.S_IWUSR|stat.S_IWGRP

def make_writable(fn):
    """Make the file or directory readable/writable/executable by me"""
    global _rwx_by_me
    os.chmod(fn, _rwx_by_me)

def make_executable(fn):
    """Make the file or directory readable & executable by user/group, writable by user"""
    global _executable_by_ug
    global _readable_by_ug
    global _writeable_by_me
    os.chmod(fn, _readable_by_ug|_writeable_by_me|_executable_by_ug)

def modify_dir_tree(path, dir_fn=None, file_fn=None):
    """Walk the tree rooted at path and apply the function dir_fn to
    directories and file_fn to files. This is intended for doing
    recursive chmods, etc."""
    if dir_fn:
        dir_fn(path)
    for (dir, subdirs, subfiles) in  os.walk(path):
        if dir_fn:
            for subdir in subdirs:
                dir_fn(os.path.join(dir,subdir))
        if file_fn:
            for file_name  in subfiles:
                file_fn(os.path.join(dir,file_name))
    

def make_read_only(fn):
    """Make the file fn read-only"""
    global _readable_by_all
    os.chmod(fn, _readable_by_all)
    
def make_web_accessible(fn):
    """Make the file readable by all and writable by the current owner"""
    global _readable_by_all
    global _writeable_by_me
    if verbose(8):
        msgb("make_web_accessible", fn)
    os.chmod(fn, _writeable_by_me|_readable_by_all)
def make_web_accessible_dir(dir):
    """Make the directory readable and executable by all and writable
    by the current owner"""
    global _readable_by_all
    global _executable_by_all
    global _writeable_by_me
    if verbose(8):
        msgb("make_web_accessible_dir", dir)
    os.chmod(dir, _writeable_by_me|_readable_by_all|_executable_by_all)

def make_documentation_tree_accessible(dir):
    """Make the directory teree rooted at dir web-accessible. That is,
    the directories are readable and executable by anyone and the
    files are readable by anyone."""
    msgb("CHMOD TREE", dir)
    modify_dir_tree(dir, make_web_accessible_dir, make_web_accessible)


    
def prefix_files(dir,input_files):
    """Add dir on to the front of the input file or files. Works with
    strings or lists of strings.
    @type dir: string
    @param dir: prefix directory

    @type input_files: string or list of strings
    @param input_files: name(s) of files

    @rtype: string or list of strings
    @return: input file(s) prefixed with dir sp
    """
    if isinstance(input_files,list):
        new_files = [join(dir,x) for x in input_files]
        return new_files
    elif is_stringish(input_files):
        new_file = join(dir, input_files)
        return new_file
    die("Unhandled type in prefix_files: "+ str(type(input_files)))

def quote(fn):
    """Add quotes around the file nameed fn. Return a string"""
    return "\"%s\"" % fn

def qdip(fn):
    """Add quotes to a string if there are spaces in the name"""
    if re.search(' ',fn):
        return '"%s"' % fn
    return fn


def touch(fn):
    """Open a file for append. Write nothing to it"""
    vmsgb(1, "TOUCH", fn)
    f=open(fn,"a")
    f.close()

############################################################
if on_native_windows():
    _mysep = "\\"
else:
    _mysep = "/"

def myjoin( *args ):
   """join all the args supplied as arguments using _mysep as the
   separator. _mysep is a backslash on native windows and a forward
   slash everywhere else.
   @type args: strings
   @param args: path component strings

   @rtype: string
   @return: string with _mysep slashes
   """
   s = ''
   first = True
   for a in args:
      if first:
         first = False
      else:
         s = s + _mysep
      s = s + a
   return s

def strip_quotes(a):
   """Conditionally remove leading/trailing quotes from a string
   @type a: string
   @param a: a string potentially with quotes

   @rtype: string
   @return: same string without the leading and trailing quotes
   """
   ln = len(a)
   if ln >= 2:
      strip_quotes = False
      if a[0] == '"' and a[-1] == '"':
         strip_quotes=True
      elif a[0] == "'" and a[-1] == "'":
         strip_quotes=True
      if strip_quotes:
         b = a[1:ln-1]
         return b
   return a

def join( *args ):
   """join all the args supplied as arguments using a forward slash as
   the separator
   
   @type args: strings
   @param args: path component strings

   @rtype: string
   @return: string with forward-slashes
   """
   s = ''
   first = True
   for a in args:
      ln = len(s)
      if first:
         first = False
      elif ln == 0 or  s[-1] != '/':
          # if the last character is not a fwd slash already, add a slash
          s = s + '/'
      a = strip_quotes(a)
      s = s + a
   return s


def flip_slashes(s):
   """convert to backslashes to _mysep slashes. _mysep slashes are
   defined to be backslashes on native windows and forward slashes
   everywhere else.
   @type s: string or list of strings
   @param s: path name(s)
   
   @rtype: string or list of strings
   @return: string(s) with _mysep slashes
   """

   if on_native_windows():
      return s
   if isinstance(s, list):
       return  list(map(flip_slashes, s))
   t = re.sub(r'\\',_mysep,s,0) # replace all
   return t

def posix_slashes(s):
   """convert to posix slashes. Do not flip slashes immediately before spaces
   @type s: string  or list of strings
   @param s: path name(s)
   
   @rtype: string or list of strings
   @return: string(s) with forward slashes
   """
   if isinstance(s,list):
       return  list(map(posix_slashes, s))
   #t = re.sub(r'\\','/',s,0) # replace all
   last = len(s)-1
   t=[]
   for i,a in enumerate(s):
       x=a
       if a == '\\':
           if i == last:
               x = '/'
           elif s[i+1] != ' ': 
               x = '/'
       t.append(x)
   return ''.join(t)

def glob(*s):
    """If multiple arguments are passed, we run them through mbuild.join()
    first. Run the normal glob.glob() on s but make sure all the
    slashes are flipped forward afterwards. This is shorthand for
    posix_slashes(glob.glob(s))    """
    import glob
    if len(s) > 1:
        t = join(*s)
    else:
        t = s[0]
    return posix_slashes(glob.glob(t))

def cond_add_quotes(s):
   """If there are spaces in the input string s, put quotes around the
   string and return it... if there are not already quotes in the
   string.

   @type s: string
   @param s: path name
   
   @rtype: string
   @return: string with quotes, if necessary
   """
   if re.search(r'[ ]',s) and not ( re.search(r'["].*["]',s) or
                                    re.search(r"['].*[']",s) ):
      return '\"' + s + '\"'
   return s
    
def escape_string(s):
    return cond_add_quotes(s)    

def escape_special_characters(s):
    """Add a backslash before characters that have special meanings in
    regular expressions. Python does not handle backslashes in regular
    expressions or substitution text so they must be escaped before
    processing.""" 

    special_chars = r'\\'
    new_string = ''
    for c in s:
        if c in special_chars:
            new_string += '\\'
        new_string += c
    return new_string
        
###############################################################

if check_python_version(2,5):
    import hashlib
    hasher = hashlib.sha1
else:
    import sha
    hasher = sha.new

def hash_list(list_of_strings):
    """Compute a sha1 hash of a list of strings and return the hex digest"""
    m = hasher()
    for l in list_of_strings:
        m.update(l.encode(unicode_encoding()))
    return m.hexdigest()


def hash_file(fn):
    if not os.path.exists(fn):
        return None
    m = hasher()
    with open(fn,'rb') as afile:
        buf = afile.read()
        m.update(buf)
    return m.hexdigest()



def write_signatures(fn,d):
    """Write a dictionary of d[file]=hash to the specified file"""
    # FIXME: binary protocol 2, binary file write DOES NOT WORK ON win32/win64
    f = open(fn,"wb")
    apickle.dump(d,f)
    f.close()

def read_signatures(fn):
    """Return a dictionary of d[file]=hash from the specified file"""
    try:
        f = open(fn,"rb")
        d = apickle.load(f)
        f.close()
        return d
    except:
        return None


def hash_string(s):
    """Compute a sha1 hash of a string and return the hex digest"""
    if check_python_version(2,5):
        m = hashlib.sha1()
    else:
        m = sha.new()
    m.update(s)
    d = m.hexdigest()
    return d


def hash_files(list_of_files, fn):
    """Hash the files in the list of files and write the hashes to fn"""
    d = {}
    for f in list_of_files:
        d[f] = hash_file(f)
    write_signatures(fn,d)
    
def file_hashes_are_valid(list_of_files, fn):
    """Return true iff the old hashes in the file fn are valid for all
    of the specified list of files."""
    if not os.path.exists(fn):
        return False
    d = read_signatures(fn)
    if d == None:
        return False
    for f in list_of_files:
        if os.path.exists(f):
            nhash = hash_file(f)
        else:
            return False
        if nhash == None:
            return False
        if f not in d:
            return False
        elif d[f] != nhash:
            return False;
    return True

###############################################################
# Time functions
def get_time_str():
   """@rtype: string
      @returns: current time as string
   """
   # include time zone
   return time.strftime('%Y-%m-%d %H:%M:%S %Z')
  
def get_time():
   """@rtype: float
      @returns: current time as float
   """
   return time.time()

def get_elapsed_time(start_time, end_time=None):
   """compute the elapsed time in seconds or minutes
   @type start_time: float
   @param start_time: starting time.
   @type end_time: float
   @param end_time: ending time.
   @rtype: string
   """
   if end_time == None:
      end_time = get_time()
   seconds = end_time - start_time
   negative_prefix = ''
   if seconds < 0:
       negative_prefix = '-'
       seconds = -seconds
   if seconds < 120:
      if int(seconds) == 0:
         milli_seconds = seconds * 1000
         timestr = "%d" % int(milli_seconds)
         suffix = " msecs"
      else:
         timestr = "%d" % int(seconds)
         suffix = " secs"
   else:
      minutes  = int(seconds/60.0)
      remainder_seconds = int(seconds - (minutes*60))
      timestr = "%.d:%02d" % (minutes,remainder_seconds)
      suffix = " min:sec"
   return  "".join([negative_prefix, timestr, suffix])
 
def print_elapsed_time(start_time, end_time=None, prefix=None, current=False):
   """print the elapsed time in seconds or minutes.
   
   @type  start_time: float
   @param start_time: the starting time
   @type  end_time: float
   @param end_time: the ending time (optional)
   @type  prefix: string
   @param prefix: a string to print at the start of the line (optional)
   """
   if end_time == None:
      end_time = get_time()
   ets = "ELAPSED TIME"
   if prefix:
       s = "%s %s" % (prefix, ets)
   else:
       s = ets

   t = get_elapsed_time(start_time, end_time)
   if current:
       t = t + "  / NOW: " + get_time_str()
   vmsgb(1,s,t)


###############################################################
def _prepare_cmd(cmd):
    """Tokenize the cmd string input. Return as list on non-windows
       platforms. On windows, it returns the raw command string."""

    if on_native_windows():
        # the posix=False is required to keep shlex from eating
        # backslashed path characters on windows. But
        # the nonposix chokes on /Dfoo="xxx yyy" in that it'll
        # split '/Dfoo="xxx' and 'yyy"' in to two different args.
        # so we cannot use that
        #args = shlex.split(cmd,posix=False)

        # using posix mode (default) means that all commands must must
        # forward slashes. So that is annoying and we avoid that
        #args = shlex.split(cmd)

        # passing the args through works fine. Make sure not to have
        # any carriage returns or leading white space in the supplied
        # command.
        args = cmd

    else:
        args = shlex.split(cmd)
    return args

def _cond_open_input_file(directory,input_file_name):
    if input_file_name:
        if directory and not os.path.isabs(input_file_name):
            fn = os.path.join(directory, input_file_name)
        else:
            fn  = input_file_name
        input_file_obj = open(fn,"r")
        return input_file_obj
    return None

def run_command(cmd, 
                separate_stderr=False, 
                shell_executable=None,
                directory=None,
                osenv=None,
                input_file_name=None,
                **kwargs):
   """
      Run a command string using the subprocess module.
      
      @type  cmd: string
      @param cmd: command line to execut with all args.
      @type  separate_stderr: bool
      @param separate_stderr: If True, the return tuple has a list of stderr lines as the 3rd element
      @type  shell_executable: string
      @param shell_executable:  the shell executable
      @type  directory: string
      @param directory: a directory to change to before running the command.
      @type  osenv: dictionary
      @param osenv: dict of environment vars to be passed to the new process  
      @type  input_file_name: string
      @param input_file_name: file name to read stdin from. Default none

      @rtype: tuple
      @return: (return code, list of stdout lines, list of lines of stderr)
   """
   use_shell = False
   if verbose(99):
      msgb("RUN COMMAND", cmd)
      msgb("RUN COMMAND repr", repr(cmd))
   stdout = None
   stderr = None
   cmd_args = _prepare_cmd(cmd)
   try:
      input_file_obj = _cond_open_input_file(directory, input_file_name)

      if separate_stderr:
         sub = subprocess.Popen(cmd_args,
                                shell=use_shell,
                                executable=shell_executable,
                                stdin = input_file_obj,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.PIPE,
                                cwd=directory,
                                env=osenv,
                                universal_newlines=True,
                                **kwargs)
         (stdout, stderr ) = sub.communicate()
         if not isinstance(stderr,list):
             stderr = stderr.splitlines(True)
         if not isinstance(stdout,list):
             stdout = stdout.splitlines(True)
         stdout = ensure_string(stdout)
         stderr = ensure_string(stderr)
         return (sub.returncode, stdout, stderr)
      else:
         sub = subprocess.Popen(cmd_args,
                                shell=use_shell,
                                executable=shell_executable,
                                stdin = input_file_obj,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.STDOUT,
                                cwd=directory,
                                env=osenv,
                                universal_newlines=True,
                                **kwargs)
         stdout = sub.stdout.readlines()
         sub.wait()
         if not isinstance(stdout,list):
             stdout = stdout.splitlines(True)
         stdout = ensure_string(stdout)
         return (sub.returncode, stdout, None)
   except OSError as e:
       s= [u"Execution failed for: %s\n" % (cmd) ]
       uappend(s,"Result is %s\n" % (str(e)))
       # put the error message in stderr if there is a separate
       # stderr, otherwise put it in stdout.
       if separate_stderr:
           if stderr == None:
               stderr = []
           elif not isinstance(stderr,list):
               stderr = stderr.splitlines(True)
       if stdout == None:
           stdout = []
       elif not isinstance(stdout,list):
           stdout = stdout.splitlines(True)
       stderr = ensure_string(stderr)
       stdout = ensure_string(stdout) 
       if separate_stderr:
           stderr.extend(s)
       else:
           stdout.extend(s)
       return (1, stdout, stderr)
   

def run_command_unbufferred(cmd, 
                            prefix_line=None,
                            shell_executable=None,
                            directory=None,
                            osenv=None,
                            input_file_name=None,
                            **kwargs):
   """
      Run a command string using the subprocess module.
      
      @type  cmd: string
      @param cmd: command line to execut with all args.
      @type  prefix_line: string
      @param prefix_line: a string to prefix each output line. Default None
      @type  shell_executable: string
      @param shell_executable:  NOT USED BY THIS FUNCTION
      @type  directory: string
      @param directory: a directory to change to before running the command.
      @type  osenv: dictionary
      @param osenv: dict of environment vars to be passed to the new process
      @type  input_file_name: string
      @param input_file_name: file name to read stdin from. Default none
        
      @rtype: tuple
      @return: (return code, list of stdout lines, empty list)

   """
   use_shell = False
   if verbose(99):
       msgb("RUN COMMAND", cmd)
       msgb("RUN COMMAND repr", repr(cmd))
   lines = []
   cmd_args = _prepare_cmd(cmd)
   try:
       input_file_obj = _cond_open_input_file(directory, input_file_name)
       sub = subprocess.Popen(cmd_args,
                              shell=use_shell,
                              executable=shell_executable,
                              stdin = input_file_obj,
                              stdout = subprocess.PIPE,
                              stderr = subprocess.STDOUT,
                              env=osenv,
                              cwd=directory,
                              universal_newlines=True,
                              **kwargs)
       while 1:
           # FIXME: 2008-12-05 bad for password prompts without newlines.
           line = sub.stdout.readline()
           if line == '':
               break
           line = line.rstrip()
           if prefix_line:
               msgn(prefix_line)
           msg(line)
           lines.append(ensure_string(line)  + u"\n")
           
       sub.wait()
       return (sub.returncode, lines, [])
   except OSError as e:
       uappend(lines, u"Execution failed for: %s\n" % (cmd))
       uappend(lines, u"Result is %s\n" % (str(e)))
       return (1, lines, [])

def run_command_output_file(cmd,
                            output_file_name,
                            shell_executable=None,
                            directory=None,
                            osenv=None,
                            input_file_name=None,
                            **kwargs):
   """
      Run a command string using the subprocess module.
      
      @type  cmd: string
      @param cmd: command line to execut with all args.
      @type  output_file_name: string
      @param output_file_name: output file name
      @type  shell_executable: string
      @param shell_executable:  the shell executable
      @type  directory: string
      @param directory: a directory to change to before running the command.
      @type  osenv: dictionary
      @param osenv: dict of environment vars to be passed to the new process
      @type  input_file_name: string
      @param input_file_name: file name to read stdin from. Default none

      @rtype: tuple
      @return: (return code, list of stdout lines)
   """
   use_shell = False
   if verbose(99):
       msgb("RUN COMMAND", cmd)
   lines = []
   cmd_args = _prepare_cmd(cmd)
   try:
       output = io.open(output_file_name,"wt",encoding=unicode_encoding())
       input_file_obj = _cond_open_input_file(directory, input_file_name)
       sub = subprocess.Popen(cmd_args,
                              shell=use_shell,
                              executable=shell_executable,
                              stdin  = input_file_obj,
                              stdout = subprocess.PIPE,
                              stderr = subprocess.STDOUT,
                              env=osenv,
                              cwd=directory,
                              universal_newlines=True,
                              **kwargs)
       
       (stdout, stderr) = sub.communicate()
       if not isinstance(stdout,list):
             stdout = stdout.splitlines(True)
       stdout = ensure_string(stdout)
       for line in stdout:
           output.write(line)
           lines.append(line)
       output.close()
       return (sub.returncode, lines, [])
   except OSError as e:
       uappend(lines,"Execution failed for: %s\n" % (cmd))
       uappend(lines,"Result is %s\n" % (str(e)))
       return (1, lines, [])
   except:
       print("Unxpected error:", sys.exc_info()[0])
       raise

def run_cmd_io(cmd, fn_i, fn_o,shell_executable=None, directory=None):
   """
      Run a command string using the subprocess module. Read standard
      input from fn_i and write stdout/stderr to fn_o.
      
      @type  cmd: string
      @param cmd: command line to execut with all args.
      @type  fn_i: string
      @param fn_i: input file name
      @type  fn_o: string
      @param fn_o: output file name
      @type  shell_executable: string
      @param shell_executable:  the shell executable
      @type  directory: string
      @param directory: a directory to change to before running the command.

      @rtype: integer
      @return: return code
      """
   use_shell = False
   cmd_args = _prepare_cmd(cmd)
   try:
       fin = io.open(fn_i, 'rt', encoding=unicode_encoding())
       fout = io.open(fn_o, 'wt', encoding=unicode_encoding())
       sub = subprocess.Popen(cmd_args, 
                              shell=use_shell, 
                              executable=shell_executable, 
                              stdin=fin, 
                              stdout=fout, 
                              stderr=subprocess.STDOUT,
                              universal_newlines=True,
                              cwd=directory)
       retval = sub.wait()
       fin.close()
       fout.close()
       return retval
   except OSError as e:
       die(u"Execution failed for cmd %s\nResult is %s\n" % (cmd,str(e)))

def find_dir(d):
    """Look upwards for a particular filesystem directory d as a
    subdirectory of one of the ancestors. Return None on failure"""
    dir = os.getcwd()
    last = ''
    while dir != last:
        target_dir = os.path.join(dir,d)
        if os.path.exists(target_dir):
            return target_dir
        last = dir
        (dir,tail) = os.path.split(dir)
    return None

def peel_dir(s,n):
    """Remove n trailing path components from s by calling
    os.path.dirname()"""
    t = s
    for i in range(0,n):
        t = os.path.dirname(t)
    return t

def get_gcc_version(gcc):
    """Return the compressed version number of gcc"""
    cmd = gcc + " -dumpversion"
    try:
        (retcode, stdout, stderr) = run_command(cmd)
        if retcode == 0:
            version = stdout[0]
            return version.strip()
    except:
        return 'unknown'

def get_clang_version(full_path):
    cmd = full_path + " -dM -E -x c "
    try:
        (retcode, stdout, stderr) = run_command(cmd,
                                                input_file_name="/dev/null")
        if retcode == 0:
            major=minor=patchlevel='x'
            for line in stdout:
                line = line.strip()
                chunks = line.split()
                if len(chunks) == 3:
                    if chunks[1] == '__clang_major__':
                        major = chunks[2]
                    elif chunks[1] == '__clang_minor__':
                        minor = chunks[2]
                    elif chunks[1] == '__clang_patchlevel__':
                        patchlevel = chunks[2]
            version = "{}.{}.{}".format(major,minor,patchlevel)
            return version
    except:
        pass
    # Try the --version knob
    try:
        (retcode, stdout, stderr) = run_command(f'{full_path} --version')
        if retcode == 0:
            for line in stdout:
                r = re.search('version[ ]+(?P<version>(\d+\.)+\d+)', line.lower())
                if r:
                    return r.group('version')
    except:
        pass
    return 'unknown'

# unify names for clang/gcc version checkers
def compute_clang_version(full_path):
    return get_clang_version(full_path)

def compute_gcc_version(full_path):
    return get_gcc_version(full_path)

def gcc_version_test(major,minor,rev,gstr):
    """Return True if the specified gcc version string (gstr) is at or
    after the specified major,minor,revision args"""

    n = gstr.split('.')
    if len(n) not in [2,3]:
        die("Cannot compute gcc version from input string: [%s]" % (gstr))
    ga = int(n[0])
    gb = int(n[1])
    if len(n) == 2:
        gc = 0
    else:
        gc = int(n[2])

    if ga > major:
        return True
    if ga == major and gb > minor:
        return True
    if ga == major and gb == minor and gc >= rev:
        return True
    return False

import threading
# requires Python2.6 or later
class _timed_command_t(threading.Thread):
    """
    Internal function to mbuild util.py. Do not call directly.

    Examples of use
    env = os.environ
    env['FOOBAR'] = 'hi'
    # the command a.out prints out the getenv("FOOBAR") value
    rc = _timed_command_t(["./a.out", "5"], seconds=4, env=env)
    rc.timed_run()

    rc = _timed_command_t(["/bin/sleep", "5"], seconds=4)
    rc.timed_run()
    """

    def __init__(self, cmd, 
                shell_executable=None,
                directory=None,
                osenv=None,
                seconds=0,
                input_file_name=None,
                **kwargs):
        """The kwargs are for the other parameters to Popen"""
        threading.Thread.__init__(self)
        self.cmd = cmd
        self.kwargs = kwargs
        self.seconds = seconds
        self.timed_out = False
        self.sub = None
        self.osenv= osenv
        self.input_file_name = input_file_name
        self.directory = directory
        self.shell_executable = shell_executable
        self.exception_type = None
        self.exception_object = None
        self.exception_trace = None
        self.exitcode = 0,
        self.output = "",
        self.stderr = "",

    def run(self): # executed by calling start()
        cmd = self.cmd
        #run a python command
        if _is_python_cmd(cmd):
            kwargs = self.kwargs
            xenv = kwargs.get('xenv')
            args_lst = kwargs.get('args_lst')
            if args_lst == None:
                args_lst = []
            if xenv == None:
                (self.exitcode,self.output,self.stderr) = cmd(*args_lst) 
            else:
                (self.exitcode,self.output,self.stderr) = cmd(xenv, *args_lst) 
            return

        #run an executable
        use_shell = False
        cmd_args = _prepare_cmd(cmd)
        input_file_obj = _cond_open_input_file(self.directory,
                                               self.input_file_name)
        try:
            self.sub = subprocess.Popen(cmd_args,
                                        shell=use_shell,
                                        executable=self.shell_executable,
                                        cwd=self.directory,
                                        env=self.osenv,
                                        stdin = input_file_obj,
                                        universal_newlines=True,
                                        **self.kwargs)
        except:
            (self.exception_type,
             self.exception_object,
             self.exception_trace) = sys.exc_info()
        else:
            self.sub.wait()

    def timed_run(self):
        """Returns False if the process times out. Also sets
        self.timed_out to True."""

        self.timed_out=False
        self.start() # calls run()
        if self.seconds:
            self.join(self.seconds)
        else:
            self.join()
        
        if self.is_alive():
            try:
                if self.sub:
                    if on_windows():
                        # On Windows terminate() does not always kill
                        # the process So we need specific handling for
                        # Windows here.
                        kill_cmd = "taskkill /F /T /PID %i" % (self.sub.pid)
                        cmd_args = _prepare_cmd(kill_cmd)
                        subprocess.Popen(cmd_args, shell=True)
                    else:
                        self.sub.kill()
            except:
                pass

            self.join()
            self.timed_out=True
            return False
        return True


def _is_python_cmd(cmd):
    return isinstance(cmd,types.FunctionType)


def run_command_timed( cmd, 
                       shell_executable=None,
                       directory=None,
                       osenv=None,
                       seconds=0,
                       input_file_name=None,
                       **kwargs ):
    """Run a timed command. kwargs are keyword args for subprocess.Popen.

     @type  cmd: string or python function
     @param cmd: command to run

     @type  shell_executable: string
     @param shell_executable:  the shell executable

     @type  directory: string
     @param directory:  the directory to run the command in

     @type  osenv: dictionary
     @param osenv: dict of environment vars to be passed to the new process

     @type  seconds: number
     @param seconds: maximum execution time in seconds

     @type  input_file_name: string
     @param input_file_name: input filename when redirecting stdin.

     @type  kwargs: keyword args
     @param kwargs: keyword args for subprocess.Popen

     @rtype: tuple
     return: (return code, list of stdout+stderr lines)
    """
    
    def _get_exit_code(tc):
        exit_code = 399
        if tc.sub:
            # if tc.sub does not have a returncode, then something went
            # very wrong, usually an exception running the subprocess.
            if hasattr(tc.sub, 'returncode'):
                exit_code = tc.sub.returncode
        return exit_code

    # we use a temporary file to hold the output because killing the
    # process disrupts the normal output collection mechanism.
    fo = tempfile.SpooledTemporaryFile() # FIXME: PY3 mode='w+'?
    fe = tempfile.SpooledTemporaryFile() # FIXME: PY3 mode='w+'?
    tc = _timed_command_t(cmd,
                          shell_executable,
                          directory,
                          osenv,
                          seconds,
                          input_file_name,
                          stdout=fo,
                          stderr=fe,
                          **kwargs)                            

    tc.timed_run()
    
    if _is_python_cmd(tc.cmd):
        exit_code = tc.exitcode
        output = tc.output
        stderr = tc.stderr
    else:    
        fo.seek(0)
        output = fo.readlines()
        fo.close()
        output = ensure_string(output)
        
        fe.seek(0)
        stderr = fe.readlines()
        fe.close()
        stderr = ensure_string(stderr)
        exit_code = _get_exit_code(tc)

    nl = u'\n'
    if tc.timed_out:
        stderr.extend([ nl,
                        u'COMMAND TIMEOUT'+nl,
                        u'KILLING PROCCESS'+nl])
    if tc.exception_type:
        stderr.extend([ nl,
                        u'COMMAND ENCOUNTERD AN EXCEPTION' + nl])
        stderr.extend(traceback.format_exception(tc.exception_type, 
                                                 tc.exception_object,
                                                 tc.exception_trace))

    return (exit_code, output, stderr)


def make_list_of_str(lst):
   return [ str(x) for x in lst]
def open_readlines(fn, mode='rt',enc=None):
   if enc==None:
       enc = unicode_encoding()
   return io.open(f,mode,encoding=enc).readlines()
