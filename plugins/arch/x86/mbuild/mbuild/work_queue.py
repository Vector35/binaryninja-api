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

"""Command objects and parallel work queue"""
from __future__ import print_function
import os
import sys
import types
is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue
from threading import Thread
from collections import deque

from .base import *
from .util import *
from .dag import *


############################################################################
class dir_cmd_t(object):
   """For holding a directory and a command. When you call
   execute(), it changes to the directory an executes the command"""
   
   def __init__(self, dir, command, output_file=None):
      self.dir= dir
      self.command= command
      self.output_file = output_file
   def __str__(self):
      return "DIR: %s\nCOMMAND: %s" % (self.dir, self.command)

   def execute(self,args=None, env=None):
      """Change to the specified directory and execute the command,
      unbufferred"""
      orig = os.getcwd()
      try:
         msgb("CHDIR TO",  self.dir)
         os.chdir(self.dir)
      except:
         return (-1, ["no such dir: " + self.dir])
      msgb("EXECUTING",  self.command)
      if self.output_file:
          (retcode, out, err) = \
             run_command_output_file(self.command, self.output_file) 
          msgb("WROTE", self.output_file)
      else:
          (retcode, out, err) = run_command_unbufferred(self.command) 
      os.chdir(orig)
      if not err:
         err = []
      if not out:
         out = []
      if err:
         return (retcode, out+err)
      else:
         return (retcode, out)

class command_t(object):
   """The primary data structure used to track jobs in this script. It
   is created when you add L{plan_t} objects to the DAG
   L{dag_t}."""

   _ids = 0
   
   def __init__(self, 
                command=None, 
                args=None, 
                xenv=None,
                unbufferred=False, 
                output_file_name=None,
                shell_executable=None, 
                directory=None, 
                name=None,
                show_output=True, 
                osenv=None, 
                seconds=0,
                input_file_name=None):
      """
      This is the unit of work for the L{work_queue_t}. These are
      typically created by the L{dag_t} but they can also be created
      by hand and added to the L{work_queue_t} to execute arbitrary
      commands.

      @type command: string or python function, or a list of both
      @param command: command line string to execute or a python function

      @type args: anything 
      @param args: (optional) typically a list of arguments for the python function.

      @type xenv: L{env_t}
      @param xenv: (optional) environment for used by the python
      function. Passed as the second argument to the python function.

      @type osenv: dictionary
      @param osenv: (optional) the environment that will be set in the new subprocess. 
      
      @type unbufferred: L{bool}
      @param unbufferred: (optional) true if the output should be unbufferred.

      @type output_file_name: string
      @param output_file_name: (optional) file name for stderr/stdout

      @type show_output: L{bool}
      @param show_output: (optional) show output, default True

      @type input_file_name: string
      @param input_file_name: (optional) file name for stdin

      """
      self.id = command_t._ids
      command_t._ids += 1
      # store the command as a list
      if isinstance(command,list):
         self.command = command
      else:
         self.command = [ command ]
      self.name = name
      self.shell_executable = shell_executable
      self.args = args
      self.xenv = xenv
      self.osenv = osenv
      self.exit_status = 0
      self.output = []
      self.stderr = []
      self.unbufferred = unbufferred
      self.input_file_name = input_file_name
      self.output_file_name = output_file_name
      self.start_time = 0
      self.end_time = 0
      self.directory = directory
      self.show_output = show_output
      self.input_file_name = input_file_name

      # Has this command be submitted to the work queue?
      self.submitted = False

      # executed is set to True when this command tries to execute.
      self.executed = False

      # all prerequisite commands are ready
      self.ready  = False

      # completed is set to True when this command exits successfully.
      self.completed = False

      # things that depend on this command completing sucessfully
      self.after_me = []

      # things that must complete before this command can run
      self.before_me = []

      # from the file DAG. A list of inputs upon which this command depends
      self.inputs  = []
      # from the file DAG. A list of things generated by this command
      self.targets = []

      # used for special signals to the worker threads to tell them to
      # shut down.
      self.terminator = False
      self.timeout = seconds

   def failed(self):
      """
      Return the exit status.
      @rtype: bool
      @return: True if the command failed (exit status != 0)
      """
      if self.exit_status != 0:
         return True
      return False
  
   def _complete(self):
      self.completed = True
      
   def _ready(self):
      """Return true if all things that must execute before this node
      have completed and false otherwise. Updates self.ready."""
      if self.ready:
         return True

      for n in self.before_me:
         if not n.completed:
            return False

      self.ready=True
      return True
   
   def is_python_command(self, i=0):
      """Return true if the command list element is a python function
      @rtype: bool
      """
      if isinstance(self.command[i],types.FunctionType):
         return True
      return False

   def is_dir_cmd(self, i=0):
      """Return true if the command list element is a python dir_cmd_t object
      @rtype: bool
      """
      if isinstance(self.command[i],dir_cmd_t):
         return True
      return False

   def has_python_subcommand(self):
      """Return true if the command list has a python function
      @rtype: bool
      """
      for c in self.command:
         if isinstance(c,types.FunctionType):
            return True
      return False

   def is_command_line(self, i=0):
      """Return true if the command list element is normal string command
      line.
      @rtype: bool
      """
      if not isinstance(self.command[i],types.FunctionType) and \
         not isinstance(self.command[i],dir_cmd_t):
         return True
      return False

   def dagkey(self):
      s = []
      for i in self.command:
         if not isinstance(i,types.FunctionType):
            s.append(i)
      t = "MBUILD_COMMAND_KEY " + (" - ".join(s))
      return t

   def hash(self):
      s = []
      for i in self.command:
         if not isinstance(i,types.FunctionType):
            s.append(i)
      t = " - ".join(s)
      h = hash_string(t.encode(unicode_encoding()))
      return h
   
   def add_before_me(self,n):
      """Make the current command execute after command n
      @type n: L{command_t}
      @param n: another (earlier) command
      """
      if isinstance(n,list):
         for x in n:
            self.before_me.append(x)
            x.after_me.append(self)
      else:
         self.before_me.append(n)
         n.after_me.append(self)
    
   def add_after_me(self,n):
      """Make the current command execute before command n.
      @type n: L{command_t}
      @param n: another (later) command
      """
      if isinstance(n, list):
         for x in n:
            self.after_me.append(x)
            x.before_me.append(self)
      else:
         self.after_me.append(n)
         n.before_me.append(self)

   def _check_afters(self):
      """Return a list of after nodes that are as-yet not submitted
      but now ready"""
      ready = []
      for x in self.after_me:
         if not x.submitted and x._ready():
            ready.append(x)
      return ready

   def elapsed_time(self):
      """Return the elapsed time as an number of seconds"""
      if self.end_time == None:
         self.end_time =  get_time()
      return self.end_time - self.start_time
        
   def elapsed(self):
      """Return the elapsed time.
      @rtype: string
      @returns: the elapsed wall clock  time of execution.
      """
      if self.end_time == None:
         self.end_time = get_time()
      elapsed = get_elapsed_time(self.start_time, self.end_time)
      return elapsed

   def dump_cmd(self):
      return self._pretty_cmd_str()

   def stderr_exists(self):
      if self.stderr and len(self.stderr) > 0:
         if len(self.stderr) == 1 and len(self.stderr[0]) == 0:
            return False
         return True
      return False

   def stdout_exists(self):
      if self.output and len(self.output) > 0:
         if len(self.output) == 1 and len(self.output[0]) == 0:
            return False
         return True
      return False
   
   def _pretty_cmd_str(self):
      s = []
      for cmd in self.command:
         if isinstance(cmd,types.FunctionType):
            s.append("PYTHON FN: " + cmd.__name__)
         elif is_stringish(cmd):
            s.append(cmd)
         else:
            s.append(str(cmd))
      return " ;;;; ".join(s)
            

   def dump(self, tab_output=False, show_output=True):
      s = []
      nl = '\n'
      if verbose(2):
         pass
      elif self.failed():
         pass
      elif self.targets:
         s.append(bracket('TARGET      ', " ".join(self.targets)))
         s.append(nl)
      if self.name:
         s.append(bracket('NAME        ', self.name))
         s.append(nl)
      if self.command:
         s.append(bracket('COMMAND     ', self._pretty_cmd_str()))
         s.append(nl)
      else:
         s.append( bracket('COMMAND     ', 'none') )
         s.append(nl)
      if self.args:
         args_string = str(self.args)
         print_limit = 400
         if len(args_string) > print_limit:
            args_string = args_string[:print_limit]
         s.append(bracket('ARGS        ', args_string))
         s.append(nl)
      if self.xenv:
         s.append(bracket('ENV         ', 'some env'))
         s.append(nl)
      #if self.submitted:
      #  s.append(bracket('START_TIME  ', self.start_time))
      #  s.append(nl)
      if self.input_file_name:
          s.append(bracket('INPUT_FILE  ', self.input_file_name))
          s.append(nl)
       
      if self.completed or self.failed():
         if self.exit_status != 0:
            s.append(bracket('EXIT_STATUS ', str(self.exit_status)))
            s.append(nl)
         if self.elapsed_time() > 1:
            s.append(bracket('ELAPSED_TIME', self.elapsed()))
            s.append(nl)
         if self.input_file_name:
            s.append(bracket('INPUT FILE', self.input_file_name))
            s.append(nl)
         if self.output_file_name:
            s.append(bracket('OUTPUT FILE', self.output_file_name))
            s.append(nl)
            
         # stdout and stderr frequently have unicode   
         s = ensure_string(s)
         if self.unbufferred == False and self.output_file_name==None:
            if show_output and self.show_output and self.stdout_exists():
               uappend(s,bracket('OUTPUT'))
               uappend(s,nl)
               for line in self.output:
                  if tab_output:
                     uappend(s,'\t')
                  uappend(s,line)
            if show_output and self.show_output and self.stderr_exists():
               uappend(s,bracket('STDERR'))
               uappend(s,nl)
               
               for line in self.stderr:
                  if tab_output:
                     uappend(s,'\t')
                  uappend(s,line)
      return u"".join(s)
   
   def __str__(self):
      return self.dump()

   def _extend_output(self, lines):
      if lines:
           util_add_to_list(self.output,ensure_string(lines))

   def _extend_stderr(self, lines):
      if lines:
           util_add_to_list(self.stderr,ensure_string(lines))
           
   def _extend_output_stderr(self, output, stderr):
      self._extend_output(output)
      self._extend_stderr(stderr)

   
   def execute(self):
      """Execute the command whether it be a python function or a
      command string. This is executed by worker threads but is made
      available here for potential debugging.  Record execution exit/return
      status and output.

      Sets the exit_status, output and stderr error fields of the
      command object.
      """
      self.executed = True
      self.start_time = get_time()
      self.output = []
      self.stderr = []
      for cmd in self.command:
         try:
            if isinstance(cmd, dir_cmd_t):
               # execute dir_cmd_t objects
               (self.exit_status, output) = cmd.execute( self.args, self.xenv )
               self._extend_output(output)

            elif isinstance(cmd,types.FunctionType):
               # execute python functions
               (self.exit_status, output) = cmd( self.args, self.xenv )
               self._extend_output(output)
               
            elif is_stringish(cmd):
               # execute command strings
               if self.output_file_name:
                  (self.exit_status, output, stderr) = \
                      run_command_output_file(cmd, 
                                         self.output_file_name, 
                                         shell_executable=self.shell_executable,
                                         directory=self.directory,
                                         osenv=self.osenv,
                                         input_file_name=self.input_file_name)
                  self._extend_output_stderr(output,stderr)

               elif self.unbufferred:
                  (self.exit_status, output, stderr) = \
                      run_command_unbufferred(cmd,
                                              shell_executable=
                                              self.shell_executable,
                                              directory = self.directory,
                                              osenv = self.osenv,
                                              input_file_name=self.input_file_name)
                  self._extend_output_stderr(output, stderr)
               else:
                   # execute timed_cmd_t objects
                   (self.exit_status, output, stderr) = \
                            run_command_timed(cmd,
                                              shell_executable=self.shell_executable,
                                              directory = self.directory,
                                              osenv = self.osenv,
                                              seconds=self.timeout,
                                              input_file_name = self.input_file_name)               
                   self._extend_output_stderr(output, stderr)
                      
            else:
               self.exit_status = 1
               self._extend_output("Unhandled command object: " + self.dump())

            # stop if something failed
            if self.exit_status != 0:
               break;
         except Exception as e:
            self.exit_status = 1
            self._extend_stderr(u"Execution error for: %s\n%s" % (ustr(e), self.dump()))
            break

      self.end_time = get_time()
   


def _worker_one_task(incoming,outgoing):
   """A thread. Takes stuff from the incoming queue and puts stuff on
   the outgoing queue. calls execute for each command it takes off the
   in queue. Return False when we receive a terminator command"""
   #msgb("WORKER WAITING")
   item = incoming.get()
   #msgb("WORKER GOT A TASK")
   if item.terminator:
      outgoing.put(item)
      return False
   item.execute()
   incoming.task_done()
   outgoing.put(item)
   return True

def _worker(incoming,outgoing):
   """A thread. Takes stuff from the incoming queue and puts stuff on
   the outgoing queue. calls execute for each command it takes off the
   in queue. Return when we get a terminator command"""
   keep_going = True
   while keep_going:
      keep_going = _worker_one_task(incoming, outgoing)
    
class work_queue_t(object):
   """This stores the threads and controls their execution"""
   def __init__(self, max_parallelism=4):
      """
      @type max_parallelism: int
      @param max_parallelism: the number of worker threads to start
      """
      max_parallelism = int(max_parallelism)
      if max_parallelism <= 0:
         die("Bad value for --jobs option: " + str(max_parallelism))
      self.max_parallelism = max_parallelism
      self.use_threads = True
      self.threads = []
      
      # worker threads can add stuff to the new_queue so we
      # use an MT-safe queue.
      self.new_queue = queue.Queue(0)
      self.out_queue = queue.Queue(0)
      self.back_queue = queue.Queue(0)
      self.pending_commands = deque()
      
      self.message_delay = 10
      self.min_message_delay = 10
      self.message_delay_delta = 10            

      self.job_num = 0
      self.pending = 0
      self._clean_slate()
      
      if self.use_threads:
          if len(self.threads) == 0:
              self._start_daemons()

   def _empty_queue(self, q):
       while not q.empty():
           item = q.get_nowait()

   def _cleanup(self):
      """After a failed build we want to clean up our any in-progress state
         so we can re-use the work queue object"""

      # the new_queue, job_num and pending get updated by add() before we build.
      # so we must clean them up after every build. Also good hygene to clean out
      # the task queues that we use to talk to the workers.
      self.pending_commands = deque()
      self._empty_queue(self.new_queue)
      self._empty_queue(self.out_queue)
      self._empty_queue(self.back_queue)
      self.job_num = 0
      self.pending = 0
      
   def _clean_slate(self):
      self.running_commands = []
      self.all_commands = []
      self.running = 0
      self.sent = 0
      self.finished = 0
      self.errors = 0
      self.dag = None

      # for message limiting in _status()
      self.last_time = 0
      self.last_pending = 0
      self.last_finished = 0
      self.last_running = 0

      self.start_time = get_time()
      self.end_time = None

      # we set dying to to True when we are trying to stop because of an error
      self.dying = False

      self._empty_queue(self.out_queue)
      self._empty_queue(self.back_queue)


   def clear_commands(self):
      """Remove any previously remembered commands"""
      self.all_commands = []
   def commands(self):
      """Return list of all commands involved in last build"""
      return self.all_commands

   def elapsed_time(self):
      """Return the elapsed time as an a number"""
      if self.end_time == None:
         self.end_time =  get_time()
      return self.end_time - self.start_time

   def elapsed(self):
      """Return the elapsed time as a pretty string
      @rtype: string
      @returns: the elapsed wall clock  time of execution.
      """
      if self.end_time == None:
         self.end_time = get_time()
      elapsed = get_elapsed_time(self.start_time, self.end_time)
      return elapsed
      
   def _terminate(self):
      """Shut everything down. Kill the worker threads if any were
      being used. This is called when the work_queue_t is garbage
      collected, but can be called directly."""
      self.dying = True
      if self.use_threads:
         self._stop_daemons()
         self._join_threads()

   def _start_daemons(self):
      """Start up a bunch of daemon worker threads to process jobs from
      the queue."""
      for i in range(self.max_parallelism):
         t = Thread(target=_worker, args=(self.out_queue, self.back_queue))
         t.setDaemon(True)
         t.start()
         self.threads.append(t)

   def _stop_daemons(self):
      """Send terminator objects to all the workers"""
      for i in range(self.max_parallelism):
         t = command_t()
         t.terminator = True
         if verbose(4):
            msgb("SENT TERMINATOR", str(i))
         self._start_a_job(t)

   def _join_threads(self):
      """Use this when not running threads in daemon-mode"""
      for t in self.threads:
         t.join()
         if verbose(4):
            msgb("WORKER THREAD TERMINATED")
      self.threads = []

   def _add_one(self,command):
      """Add a single command of type L{command_t} to the list
      of jobs to run."""
      # FIXME: make this take a string and build a command_t

      if command.completed:
         if verbose(5):
            msgb("SKIPPING COMPLETED CMD", str(command.command))
         msgb("SKIPPING COMPLETED CMD", str(command.command))
         self.add(command._check_afters())
         return
      if command.submitted:
         if verbose(5):
            msgb("SKIPPING SUBMITTED CMD", str(command.command))
         msgb("SKIPPING SUBMITTED CMD", str(command.command))
         return
      command.submitted = True
      if verbose(6):
         msgb("WQ ADDING", str(command.command))
      self.job_num += 1
      self.new_queue.put( command )
      self.pending += 1
      
   def add_sequential(self,command_strings, unbufferred=False):
      """
      Add a list of command strings as sequential tasks to the work queue.

      @type  command_strings: list of strings
      @param command_strings: command strings to add to the L{work_queue_t}

      @rtype:  list of L{command_t}
      @return: the commands created      
      """
      last_cmd = None
      cmds = []
      for c in command_strings:
         co = command_t(c, unbufferred=unbufferred)
         cmds.append(co)
         self.add(co)
         if last_cmd:
            last_cmd.add_after_me(co)
         last_cmd = co
      return cmds

   def add(self,command):
      """Add a command or list of commands of type L{command_t}
      to the list of jobs to run.

      @type command: L{command_t}
      @param  command: the command to run
      """
      if verbose(5):
         msgb("ADD CMD", str(type(command)))

      if command:
         if isinstance(command,list):
            for c in command:
               if verbose(5):
                  msgb("ADD CMD", str(type(c)))
               self._add_one(c)
         else:
            self._add_one(command)

   def _done(self):
      if self.running > 0:
         return False
      if not self.dying and self.pending > 0:
         return False
      return True

   def _status(self):
      if self.show_progress or verbose(2):
         s = ( '[STATUS] RUNNING: %d    PENDING: %d    COMPLETED: %d   ' +
               'ERRORS: %d   ELAPSED: %s %s' )
         s = ( 'R: %d P: %d C: %d E: %d / %s %s' )
         cur_time = get_time()
         
         changed = False
         if (self.running != self.last_running or
             self.pending != self.last_pending or 
             self.finished != self.last_finished):
             changed = True

         if (changed or
             # have we waited sufficiently long?
             cur_time >= self.last_time + self.message_delay):

             # speed back up when anything finishes
             if self.finished != self.last_finished:
                 self.message_delay = self.min_message_delay
             elif self.last_time != 0:
                 # only printing because of timeout delay, so
                 # we increase the time a little bit.
                 self.message_delay += self.min_message_delay

             # store the other limiters for next time
             self.last_time = cur_time
             self.last_pending = self.pending
             self.last_finished = self.finished
             self.last_running = self.running
             
             vmsg(1, s % (self.running,
                      self.pending,
                      self.finished,
                      self.errors,
                      get_elapsed_time(self.start_time, get_time()),
                      self._command_names()))

   def _start_more_jobs(self):
      """If there are jobs to start and we didn't hit our parallelism
      limit, start more jobs"""

      # copy from new_queue to pending_commands to avoid data
      # race on iterating over pending commands.
      started = False
      while not self.new_queue.empty():
         self.pending_commands.append( self.new_queue.get() ) 
         
      ready = deque()
      for cmd in self.pending_commands:
         if cmd._ready():
            ready.append(cmd)
         
      while self.running < self.max_parallelism and ready:
         cmd = ready.popleft()
         # FIXME: small concern that this could be slow
         self.pending_commands.remove(cmd)
         if verbose(3):
            msgb("LAUNCHING", cmd.dump_cmd())
         self._start_a_job(cmd)
         self.pending -= 1
         started = True
      return started
         
   def _start_a_job(self,cmd):
      """Private function to kick off a command"""
      self.out_queue.put(cmd)
      self.running_commands.append(cmd)
      if not cmd.terminator:
         self.all_commands.append(cmd)
      self.sent += 1
      self.running += 1

   def _command_names(self):
       s = []
       anonymous_jobs = 0
       for r in self.running_commands:
           if hasattr(r,'name') and r.name:
               s.append(r.name)
           else:
               anonymous_jobs += 1
       if s:
           if anonymous_jobs:
               s.append('%d-anonymous' % (anonymous_jobs))
           return '[' + ' '.join(s) + ']'
       else:
           return ''
               
   def _wait_for_jobs(self):
     """Return one command object when it finishes, or None on timeout (or
        other non-keyboard-interrupt exceptions)."""
     if self.running > 0:
        try:
           cmd = self.back_queue.get(block=True, timeout=self.join_timeout)
           self.running -= 1
           self.finished += 1
           self.running_commands.remove(cmd)
           self.back_queue.task_done()
           return cmd
        except queue.Empty:
           return None
        except KeyboardInterrupt:
           msgb('INTERRUPT')
           self._terminate()
           self.dying = True
           sys.exit(1)
           return None # NOT REACHED
        except:
           return None
     return None
  
   def build(self,
             dag=None,
             targets=None, 
             die_on_errors=True,
             show_output=True,
             error_limit=0,
             show_progress=False,
             show_errors_only=False,
             join_timeout=10.0):
      """
      This makes the work queue start building stuff. If no targets
      are specified then all the targets are considered and built if
      necessary. All commands that get run or generated are stored in
      the all_commands attribute. That attribute gets re-initialized
      on each call to build.
      
      @type  dag: L{dag_t}
      @param dag: the dependence tree object

      @type  targets: list
      @param targets: specific targets to build

      @type  die_on_errors: bool
      @param die_on_errors: keep going or die on errors

      @type  show_output: bool
      @param show_output: show stdout/stderr (or just buffer it in
      memory for later processing).  Setting this to False is good for
      avoiding voluminous screen output. The default is True.

      @type  show_progress: bool
      @param show_progress: show the running/pending/completed/errors msgs

      @type  show_errors_only: bool
      @param show_errors_only: normally print the commands as they complete.
      If True, only show the commands that fail.

      @type  join_timeout: float
      @param join_timeout: how long to wait for thread to terminate. default 10s
      """
      self._clean_slate()
            
      self.show_progress = show_progress
      self.join_timeout = join_timeout
      self.errors = 0
      self.show_errors_only = show_errors_only
      self.message_delay = self.min_message_delay
      self.last_time = 0
      self.clear_commands()
      self.dag = dag
      if self.dag:
         for x in self.dag._leaves_with_changes(targets):
            self.add(x.creator)
      okay = self._build_blind(die_on_errors, show_output, error_limit)
      if okay and self.dag:
         did_not_build = self.dag.check_for_skipped()
         if len(did_not_build) > 0:
            # some stuff did not build, force an error status return
            msgb("ERROR: DID NOT BUILD SOME STUFF", "\n\t".join(did_not_build))
            if self.dag:
                  uprint(self.dag.dump())
            self.end_time = get_time()
            self._cleanup()
            return False
      # normal exit path
      self.end_time = get_time()
      if self.dag:
         self.dag.dag_write_signatures()
      self._cleanup()
      return okay
   
   def _build_blind(self, die_on_errors=True, show_output=True, error_limit=0):
      """Start running the commands that are pending and kick off
      dependent jobs as those complete. If die_on_errors is True, the
      default, we stop running new jobs after one job returns a nonzero
      status. Returns True if no errors"""
      if self.use_threads:
         return self._build_blind_threads(die_on_errors, 
                                          show_output,
                                          error_limit)
      else:
          return self._build_blind_no_threads(die_on_errors, 
                                              show_output,
                                              error_limit)
      
   def _build_blind_threads(self,
                            die_on_errors=True, 
                            show_output=True,
                            error_limit=0):
      """Start running the commands that are pending and kick off
      dependent jobs as those complete. If die_on_errors is True, the
      default, we stop running new jobs after one job returns a nonzero
      status. Returns True if no errors"""
      okay = True
      started = False
      while 1:
         c = None 
         if started:
             c = self._wait_for_jobs()
         if c:
            if verbose(4):
               msgb("JOB COMPLETED")
            if c.failed():
               self.errors += 1
               okay = False
               if die_on_errors or (error_limit != 0 and
                                    self.errors > error_limit):
                  warn("Command execution failed. " + 
                       "Waiting for remaining jobs and exiting.")
                  self.dying = True

         if not self.dying:
            started |= self._start_more_jobs()
         self._status()
         
         if c and not self.dying:
            c._complete()
            # Command objects can depend on each other
            # directly. Enable execution of dependent commands.
            if verbose(4):
               msgb("ADD CMD-AFTERS")
            self.add(c._check_afters())
            # Or we might find new commands from the file DAG.
            if self.dag:
               for x in self.dag._enable_successors(c):
                  self.add(x.creator)
         if c:
            if self.show_errors_only==False or c.failed():
               uprint(c.dump(show_output=show_output))
            elif c.targets:
                for x in c.targets:
                    vmsg(1, u'\tBUILT: {}'.format(x))
         if self._done():
            break;
      return okay
             
   def _build_blind_no_threads(self, die_on_errors=True, 
                               show_output=True, error_limit=0):
      """Start running the commands that are pending and kick off
      dependent jobs as those complete. If die_on_errors is True, the
      default, we stop running new jobs after one job returns a nonzero
      status. Returns True if no errors"""
      okay = True
      while 1:
         started = False
         if not self.dying:
            started = self._start_more_jobs()
         if started:
             self._status()
             
         # EXECUTE THE TASK OURSELVES
         if self.running > 0:
            _worker_one_task(self.out_queue, self.back_queue)
            c = self._wait_for_jobs()
            if c:
               if verbose(4):
                  msgb("JOB COMPLETED")
               if c.failed():
                  okay = False
                  self.errors += 1
                  if die_on_errors or (error_limit !=0 and
                                       self.errors > error_limit):
                     warn("Command execution failed. " + 
                          "Waiting for remaining jobs and exiting.")
                     self.dying = True
               if not self.dying:
                  c._complete()
                  # Command objects can depende on each other
                  # directly. Enable execution of dependent commands.
                  if verbose(4):
                     msgb("ADD CMD-AFTERS")
                  self.add(c._check_afters())
                  # Or we might find new commands from the file DAG.
                  if self.dag:
                     for x in self.dag._enable_successors(c):
                        self.add(x.creator)
               if self.show_errors_only==False or c.failed():
                  uprint(c.dump(show_output=show_output))
               self._status()
         if self._done():
            break;
      return okay
             


