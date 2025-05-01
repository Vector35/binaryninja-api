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

"""dependence tracking using a directed acyclic graph (DAG)"""

# Originally, we decided that if we could not find a header then it
# was an error. And there was an ignored file list for headers that
# were conditionally included on some platforms but not others. The
# idea was that you'd list the files that were ignorable on your
# platform and they would not trigger a rebuild. Any other missing
# file would trigger a rebuild though!! That's problematic though as
# users must maintain lists of ignorable files.
#
# Another school of thought is that if the scanner cannot find the
# file and all the include paths were specified properly, then the
# compilation will fail if the header is required. Missing headers
# files in this regime will not trigger downstream rebuilds.
#
#   This precludes users from manually specifying -I flags and
#   skipping the mbuild's add_include_dir() API.  They'll get okay
#   build but incomplete dependence checks. So don't bypass
#   add_include_dir()!
# 
# Even so, there is a problem with ignoring missing files: What about
# dependences on generated header files that have not been generated
# yet? That is THE problem that motivates this design. If we ignore
# missing headers, then the "dependent" file will either be marked as:
# 
#      (a) "ready to compile" (assuming the other headers are found but one
#      or more might have changed)
#  or
#      (b) "does not need compilation" (if none of the found headers
#      have changed).
#
# In the former case (a), the compilation will fail
# nondeterministically depending on whether or not the header file is
# created at the compilation time of the "including" file. Or in the
# latter case (b), we won't rebuild things that need
# rebuilding. Either way, the idea of ignoring missing header files is
# very broken.
#
# A third option is to ignore most header missing files but specify
# that certain generated missing header files cannot be ignored. Since
# there are way fewer generated header files, this is a much more
# convenient option.
#
# NOTE: If there is a cmd in the dag that produces the missing header
# file, we must run it to produce the missing header.
#

from __future__ import print_function
import os
import sys
import platform
import types
import collections
import atexit
try:
    import cPickle as apickle
except:
    import pickle as apickle


from .base import *
from .work_queue import *
from .env import *
from .util import *
from .plan import *
from . import scanner
from . import dfs
from . import util

class _mbuild_dep_record_t(object):
    """This stores the basic dependence structure for the
    build. Creators are listed for files that are generated. The
    signature is the last signature we saw for this."""
    def __init__(self, file_name, creator=None):
        self.file_name = file_name

        self.old_signature = None
        self.signature = None
        self.scanned_header = False

        # If this file has a creator, we check the signature of the
        # thing that created it to see if it is the same as it was the
        # last time we made this target.
        self.old_command_signature = None
        self.command_signature = None
        
        # did we do the header scan for this file yet?
        self.scanned = False

        # When a changed input reaches this node, it sets needs_to_run
        # to True.
        self.needs_to_run = False
        self.visited = False
        self.added = False
        
        # before building, we mark all the nodes that are required for
        # the build to True (by search for ancestors from targets) so
        # that we know which commands to enable for execution.
        self.required = False
        
        self.changed = None
        
        self.creator = creator # command_t
        self.files_that_are_inputs = []
        self.files_that_depend_on_this = []

        self.part_of_loop = False
        self.index  = 0
        self.lowlink = 0

        self.hash_file()

    def hash_file(self):
        #msgb("HASHING", str(self.file_name))
        if os.path.exists(self.file_name):
            self.signature = util.hash_file(self.file_name)
        else:
            if verbose(99):
                msgb("COULD NOT HASH MISSING FILE", self.file_name)
            
    def hash_if_needed(self):
        if self.signature == None:
            self.hash_file()

            
    def missing(self):
        if not os.path.exists(self.file_name):
            return True
        return False


    def _check_required(self, required_files):
        if self.file_name in required_files:
            return True
        if os.path.basename(self.file_name) in required_files:
            return True
        return False

    
    def _compute_changed_bit(self, required_files):
        """Return True if there is no old signature or the old
        signature does not equal the current signature, or the file
        does not exist"""
        if self.missing():
            # A missing required file during the scan implies either
            # the build is going to fail or something upstream better
            # create it. And if it is created we are going to have to
            # assume it is changing since we don't have one now.
            if verbose(10):
                msgb("MISSING FILE", self.file_name)
            if self._check_required(required_files):
                if verbose(10):
                    msgb("MISSING REQUIRED FILE->CHANGED")
                return True
            # we let scanned headers slide if they don't exist
            if self.scanned_header:
                if verbose(10):
                    msgb("MISSING SCANNED HEADER FILE->UNCHANGED")
                return False
            if verbose(10):
                msgb("MISSING FILE->ASSUME CHANGED")
            return True
        else:
            if self.old_signature:
                self.hash_if_needed()
                if self.old_signature == self.signature:
                    return False
                elif verbose(10):
                    msgb("SIG MISMATCH for %s" % self.file_name)
                    msgb("OLD SIG %s" % str(self.old_signature))
                    msgb("NEW SIG %s" % str(self.signature))
            elif verbose(10):
                msgb("NO OLD SIG for %s" % self.file_name)
        return True

    def change_bit(self, required_files):
        """Compute changed bit if it has not been computed yet. Return
        the value."""
        if self.changed == None:
            self.changed = self._compute_changed_bit(required_files)
            if verbose(10):
                msgb("COMPUTE CHANGE BIT", "%s for %s" %
                     ( str(self.changed), self.file_name))
        return self.changed


    def format_string(self,s):
        o = "\n\t".join(s)
        return o

    def dump_str(self):
        
        s = "\tANCESTORS: %s\nTARGET: %s\n\tDESCENDENTS: %s\n" % \
              (self.format_string(self.files_that_are_inputs),
               self.file_name,
               self.format_string(self.files_that_depend_on_this))
     
        if self.creator:
            s += "\tCREATOR: %s\n" % self.creator.dump()
        if self.visited:
            s += "\tVISITED\n"
        else:
            s += "\tNOT-VISITED\n"

        if self.part_of_loop:
            s += "\tIN-LOOP\n"
        else:
            s += "\tNOT-IN-LOOP\n"

        if self.required:
            s += "\tREQUIRED\n"
        else:
            s += "\tNOT-REQUIRED\n"

        if self.changed:
            s += "\tCHANGED\n"
        else:
            s += "\tNOT-CHANGED\n"
        return s
    
    def dump(self):
        """print a string representing this node of the DAG. The
        string comes from the __str__ function"""
        print(self.dump_str())
    def __str__(self):
        return self.dump_str()

class _mbuild_storage_object_t(object):
    def __init__(self, signature):
        self.signature = signature
        
def _do_terminate(d):
    """called by atexit function for dag_t objects"""
    d.terminate()
    
class dag_t(object):
    """
    This object builds a DAG of files an sequences their submission to
    the parallel work queue of type L{work_queue_t}.
    
    This takes L{plan_t} objects representing command
    strings or python functions, and creates L{command_t}
    objects suitable for use in the L{work_queue_t}.

    As the L{work_queue_t} executes, it queries this DAG for more
    ready commands or functions to execute.
    """
    
    
    def __init__(self, name='default', env=None):
        self.name = name
        self.recs = {}  # _mbuild_dep_record_t's
        
        # dictionary of _mbuild_storage_object_t's by file name.
        self.old_signatures = {}

        # if you care about changes to the python functions, then
        # include the python sources in the list of inputs. This
        # feature _python_commands_changed is deprecated.
        self._python_commands_changed = False
        
        self.signature_file_name = ".mbuild.hash." + self.name
        if env:
            self.signature_file_name = env.build_dir_join(
                self.signature_file_name)
        # some users change directories during the build and we do not
        # want relative paths to mess us up when we go to write the
        # signature file at the end of the build.
        self.signature_file_name = os.path.abspath(self.signature_file_name)

        if os.path.exists(self.signature_file_name):
            self._read_signatures(self.signature_file_name)

        if env and 'required' in env:
            self.required_set = \
                set(self._canonize_if_exists_fn(env['required']))
        else:
            self.required_set = set()
            
        atexit.register(_do_terminate, self)

    def cycle_check(self):
        """Check the DAG for illegal cycles in the include structure.
        @rtype: bool
        @return: True if the DAG contains cycles (and thus is not a DAG).
        """
        node_dict = {}
        # build the graph for the DFS
        for k,v in iter(self.recs.items()):
            if k in node_dict:
                node = node_dict[k] 
            else:
                node = dfs.node_t(k)
                node_dict[k] = node
            for p in v.files_that_are_inputs:
                if p in node_dict:
                    pnode = node_dict[p]
                else:
                    pnode = dfs.node_t(p)
                    node_dict[p] = pnode
                node.add_successor(pnode)
        # Traverse the graph
        cycle = dfs.dfs(node_dict.values())
        if cycle:
            msgb("CYCLE DETECTED IN DAG")
        return cycle

    def terminate(self):
        self.dag_write_signatures()

    def dump(self):
        """print a string representing   the DAG. """
        print("DAG DUMP")
        for v in iter(self.recs.values()):
            v.dump()

    def _hash_mixed_list(l):

        if isinstance(l, list): 
            il = l
        else:
            il = [l]
        s = []
        for i in il:
            if i.is_command_line():
                s.append(i.command)
        t = " - ".join(s)
        h = hash_string(t)
        return h

    def dag_write_signatures(self):
        """Write a dictionary of _mbuild_storage_object_t's to the
        given file name"""
        vmsgb(10, "WRITING SIGNATURES", self.signature_file_name)
        d = {}
        for (k,v) in iter(self.recs.items()):
            # get the new hash values for anything that had a command
            # execute for it.
            if v.creator:
                if v.creator.is_command_line() and v.creator.completed:
                    # store the command line hashes in the same
                    # dictionary with a prefix
                    command_hash = v.creator.hash()
                    full_key = v.creator.dagkey()
                    d[full_key]= _mbuild_storage_object_t(command_hash)
                    if verbose(99):
                        msgb("SIGWRITE", "%s -> %s" % (str(command_hash),
                                                       full_key))
                if v.creator.completed and v.creator.exit_status == 0:
                    v.hash_file()
            if v.creator  and v.creator.failed():
                if verbose(99):
                    msgb("NULLIFY SIG", k)
                v.signature = None
            if not v.signature:
                if verbose(99):
                    msgb("FIXING NULL SIGNATURE", k)
                v.hash_file()

            if verbose(99):
                msgb("SIGWRITE", "%s -> %s" % (str(v.signature),k))
            d[k] = _mbuild_storage_object_t(v.signature)
            
        # FIXME: binary protocol 2, binary file write DOES NOT WORK ON
        # win32/win64
        f = open(self.signature_file_name,"wb")
        apickle.dump(d,f)
        f.close()
        
    def _check_command_signature(self, co):
        """Return True if the signature matches the command object."""

        # if the command is not a list of strings, we just assume that
        # is has changed.
        if co.has_python_subcommand():
            if self._python_commands_changed:
                return False
            else:
                return True # assume the command has not changed

        full_key = co.dagkey()
        try:
            old_hash = self.old_signatures[full_key].signature
            if verbose(99):
                msgb('COMMAND HASH', full_key)
                msgb('COMMAND HASH', old_hash)
            new_hash = co.hash()
            if old_hash == new_hash:
                if verbose(99):
                    msgb('COMMAND HASH','\tMATCH')
                
                return True
        except:
            if verbose(99):
                msgb('COMMAND HASH','\tNO OLD HASH')
            
        if verbose(99):
            msgb('COMMAND HASH','\tDOES NOT MATCH')
        return False

        
    def _read_signatures(self, file_name):
        """Read a dictionary of _mbuild_storage_object_t's from the
        given file name."""
        if verbose(10):
            msgb("READING SIGNATURES", file_name)
        try:
            f = open(file_name,"rb")
            self.old_signatures = apickle.load(f)
            f.close()
        except:
            warn("READING SIGNATURES FAILED FOR "+ file_name)
            return
        if verbose(99):
            for k, v in iter(self.old_signatures.items()):
                msgb("SIGREAD", "%s -> %s" % (str(v.signature),k))

        # Add old signatures to any existing files
        for k, v in iter(self.recs.items()):
            if k in self.old_signatures:
                v.old_signature = self.old_signatures[k].signature

    def _check_required_file(self,fn):
        if fn in self.required_set:
            return True
        if os.path.basename(fn) in self.required_set:
            return True
        return False


    def _compute_all_parents_visited(self, n):
        """Returns (all_parents_visited, some_parents_changed)"""
        all_parents_visited = True
        some_parents_changed = False
        for ancestor_fn in n.files_that_are_inputs:
            try:
                ancestor_rec = self.recs[ancestor_fn]
                if ancestor_rec.visited:
                    if ancestor_rec.changed:
                        some_parents_changed = True
                else:
                    all_parents_visited = False
            except:
                if  self._check_required_file(ancestor_fn):
                    warn("[1] node %s: did not find ancestor node: %s" % 
                         (n.file_name, ancestor_fn))

        return (all_parents_visited, some_parents_changed)

    def _just_compute_parent_changed(self, n):
        """Returns True if some parent changed"""
        for ancestor_fn in n.files_that_are_inputs:
            try:
                ancestor_rec = self.recs[ancestor_fn]
                if ancestor_rec.visited:
                    if ancestor_rec.changed:
                        return True
            except:
                if self._check_required_file(ancestor_fn):
                    warn("[2] node %s: did not find ancestor node: %s" %
                         (n.file_name, ancestor_fn))
        return False


    def _just_compute_all_parents_visited(self, n):
        """Returns True if all parents were visited or parents are part of a loop"""
        for ancestor_fn in n.files_that_are_inputs:
            try:
                ancestor_rec = self.recs[ancestor_fn]
                if not ancestor_rec.visited:
                    if verbose(10):
                        msgb("PARENT UNVISITED", "%s <- %s" % 
                             (n.file_name, ancestor_fn))
                    if n.part_of_loop:
                        warn("Circularity involving %s" % (n.file_name))
                        return True # FIXME HACK
                    return False
            except:
                if self._check_required_file(ancestor_fn):
                    warn("[3] node %s: did not find ancestor node: %s" % 
                         (n.file_name, ancestor_fn))
        return True

    def _just_compute_all_parents_completed(self, n):
        """Returns True if all parents that have to execute have completed"""
        for ancestor_fn in n.files_that_are_inputs:
            try:
                ancestor_rec = self.recs[ancestor_fn]
                if ancestor_rec.creator:
                    if not ancestor_rec.creator.completed:
                        return False
            except:
                if self._check_required_file(ancestor_fn):
                    warn("[4] node %s: did not find ancestor node: %s" % 
                         (n.file_name, ancestor_fn))
        return True

    def _set_ancestors_to_required(self, lof):
        """Set all the ancestors of the files in the list of files lof
        argument to be required nodes."""
        nodes = collections.deque() # work list
        for f in lof:
            nodes.append(f)
            
        while len(nodes) != 0:
            f = nodes.popleft()
            r = self.recs[f]
            if not r.required:
                if verbose(10):
                    msgb("MARKING-ANCESTORS AS REQUIRED", r.file_name)
                                        
                r.required = True
                for g in r.files_that_are_inputs:
                    nodes.append(g)
                
    def _find_required_nodes(self, targets):
        """Look at the targets list and mark the ancestors as
        required for the build. Internal function"""
        if verbose(10):
            msgb("INPUT TARGETS", str(targets))
        for v in iter(self.recs.values()):
            v.required = False

        target_dictionary = dict.fromkeys(targets, True)
        if verbose(10):
            msgb("TARGETS", str(target_dictionary))
        for v in iter(self.recs.values()):
            if v.creator:
                if v.file_name in target_dictionary:
                    if not v.required:
                        if verbose(10):
                            msgb("MARK AS REQUIRED", v.file_name)
                        v.required = True
                        self._set_ancestors_to_required(v.files_that_are_inputs)
        
    def check_for_skipped(self):
        """Return a list of things that did not build but were tagged
        as required for the build. This list could be nonempty because
        (1)there was an error in the build or (2) there is a
        circularity in the dependence structure."""
        did_not_build = []
        for v in iter(self.recs.values()):
            if v.required and not v.visited:
                did_not_build.append(v.file_name)
        return did_not_build

    def _find_loops(self, root_nodes):

        def _mark_loop(level,n,stack,all_sccs):
            # Tarjan's algorithm for strongly connected components
            n.index = level
            n.lowlink = level
            level = level + 1
            stack.append(n)

            for cfn in n.files_that_depend_on_this:
                child = self.recs[cfn]
                if child.index == 0:
                    _mark_loop(level,child,stack,all_sccs)
                    n.lowlink = min(n.lowlink, child.lowlink)
                elif child in stack:
                    n.lowlink = min(n.lowlink, child.index)

            if n.lowlink == n.index:
                # collect each strongly connected component
                scc = []

                while 1:
                    child = stack.pop()
                    scc.append(child)
                    if child == n:
                        break
                all_sccs.append(scc)

        stack = collections.deque()
        all_sccs = [] # list of lists of nodes
        level = 1

        for v in root_nodes:     
            _mark_loop(level,v,stack,all_sccs)

        # mark nodes that are part of include-loops (and print them out)
        for scc in all_sccs:
            if len(scc) > 1:
                msg("===================================")
                msg("CYCLE INVOLVING THESE FILES (will assume all ready):")
                for n in scc:
                    msg("\t" +  n.file_name)
                    n.part_of_loop = True
                msg("===================================")

    def _leaves_with_changes(self, targets=None):
        """Return a list of mbuild_dep_records_t for things with no
        ancestors but with associated commands. targets is an optional
        list of things to build. (called from work_queue.py)
        """
        nodes = collections.deque() # work list

        if targets:
            if not isinstance(targets, list): # make it a list
                targets = [ targets ]
            self._find_required_nodes(targets)
        else:
            # mark all nodes required since no targets are specified
            for v in iter(self.recs.values()):
                v.required = True
        
        self._find_loops(iter(self.recs.values()))        

        # build a list of roots -- files that have nothing they depend on.
        # store that list in the nodes list
        for v in iter(self.recs.values()):
            v.visited = False # initialize all to false
            v.added = False # initialize all to false
            if (v.part_of_loop or len(v.files_that_are_inputs) == 0) and v.required:
                v.needs_to_run = v.change_bit(self.required_set)
                v.added = True
                nodes.append(v)

                if verbose(9):
                    if v.needs_to_run:
                        s = ": CHANGED"
                    else:
                        s = ''
                    msgb("ROOTSEARCH", v.file_name + s)
            else:
                v.needs_to_run = False # clear all the other nodes
                
        ready = self._ready_scan(nodes)
        del nodes
        return ready
    
    def _enable_successors(self,cmd):
        """When a command completes, it must notify things that
        depend on its stated target files. Return a list of ready
        commands (called from work_queue.py)
        """
        if verbose(10):
            msgb('ENABLE SUCCESSORS', str(cmd))
        nodes = collections.deque() # work list
        for tgt in cmd.targets:
            rtgt = os.path.realpath(tgt)
            if verbose(11):
                msgb('SUCCESSOR', tgt + " --> " + rtgt)
            n = self.recs[ rtgt ]
            self._scan_successors(nodes,n)
        ready = self._ready_scan(nodes)
        if verbose(10):
            msgb("NEW READY VALUES", str(ready))
        del nodes
        return ready
        
    def _scan_successors(self, nodes,n):
        """Add ready successors of n to nodes list"""
        if verbose(10):
            msgb('SCAN SUCCESSORS', n.file_name + " -> " +
                 str(n.files_that_depend_on_this))
        for successor_fn in n.files_that_depend_on_this:
            try:
                successor_rec = self.recs[successor_fn]
                if successor_rec.required and not successor_rec.needs_to_run:
                    if self._just_compute_all_parents_visited(successor_rec):
                        if self._just_compute_all_parents_completed(successor_rec):
                            if verbose(10):
                                msgb("LEAFSEARCH", "\tADDING: " + 
                                     successor_rec.file_name)
                            # Make sure we are not scanning things
                            # multiple times. 
                            if successor_rec.added:
                                warn("Already added: " + successor_rec.file_name)
                            else:
                                successor_rec.added = True
                                successor_rec.needs_to_run = True
                                nodes.append(successor_rec)
                        else:
                            if verbose(10):
                                msgb("NOT ALL PARENTS COMPLETED", successor_fn)
                    else:
                        if verbose(10):
                            msgb("NOT ALL PARENTS VISITED", successor_fn)
                else:
                    if verbose(10):
                        msgb("NOT REQUIRED/NOT NEEDED TO RUN", successor_fn)

            except:
                warn("node %s: did not find child node: %s" %
                     (n.file_name, successor_fn))
        if verbose(10):
            msgb('SCAN SUCCESSORS DONE')

    def _cmd_all_outputs_visited_and_unchanged(self, cmd):
        """Return True if all the outputs of the command are visited
        and unchanged. If any are not visited or any are changed,
        return False."""
        if not cmd.targets:
            return True
        for fn in cmd.targets:
            rfn  = os.path.realpath(fn)
            vmsgb(20,"TESTING CMD TARGET:", rfn, pad = 4*' ')
            if rfn in self.recs:
                d = self.recs[rfn]
                if d.visited == False:
                    vmsgb(20,"CMD TARGET NOT VISITED YET:", fn, pad=8*' ')
                    return False
                if d.changed:
                    vmsgb(20,"CMD TARGET CHANGED:", fn, pad=8*' ')
                    return False
            else:
                vmsgb(20,"CMD TARGET NOT FOUND IN DAG:", fn, pad=8*' ')
        vmsgb(20,"CMD TARGETS ALL VISITED AND UNCHANGED:", fn)
        return True
            
    def _ready_scan(self,nodes):
        """Process the nodes list and return a list of ready commands"""
        vmsgb(20,'READY SCAN', '%d' % (len(nodes)))
        readyd = dict() # ready dictionary for fast searching
        vmsgb(20,"READYD0", str(readyd))
        # Pop a node off the nodes list. If that node has a creator,
        # put it in the ready list. If the node has no creator put then its
        # children on the nodes list.
        iters = 0
        while len(nodes) != 0:
            n = nodes.popleft()
            iters+=1
            # see if all parents have been visited yet
            parents_changed = self._just_compute_parent_changed(n)
            vmsgb(20,"VISITING", n.file_name)
            n.visited = True
            if n.change_bit(self.required_set):
                vmsgb(20,"LEAFSEARCH", "%d \tthis node %s CHANGED." % 
                     (iters,n.file_name))
                propagate_changed = True
                n.needs_to_run = True
            elif parents_changed:
                vmsgb(20,"LEAFSEARCH", "%d \tsome parent of %s CHANGED." % 
                      (iters,n.file_name))
                n.changed = True # we changed because our parents changed
                propagate_changed = True
                n.needs_to_run = True
            elif n.creator and \
                    not self._check_command_signature(n.creator):
                vmsgb(20,"LEAFSEARCH", "%d\tthis node's command changed: %s." %
                      (iters,n.file_name))
                n.changed = True # we changed because our command line changed
                propagate_changed = True
                n.needs_to_run = True
            else:
                vmsgb(20,"LEAFSEARCH", "%d\tUNCHANGED: %s." %
                      (iters,n.file_name))
                propagate_changed = False
                
            if n.creator:
                # if the inputs have not changed and the signtures of
                # the outputs match, then do not build the thing. Just
                # mark it complete so it won't run.

                # we only mark a creator completed if all the
                # command_t targets are visited unchanged.

                if not propagate_changed:
                    vmsgb(20,"LEAFSEARCH", "\tTESTING CMD SUCCESSORS: " + 
                          n.file_name)
                    if self._cmd_all_outputs_visited_and_unchanged(n.creator):
                        n.creator._complete()
                        vmsgb(20,"LEAFSEARCH", "\tMARK CREATOR CMD COMPLETED: " + 
                              n.file_name)
                    else:
                        vmsgb(20,"LEAFSEARCH", "\tCMD OUTPUTS NOT FULLY SCANNED YET: " + 
                              n.file_name)

                else:
                    if n.creator._ready():
                        vmsgb(20,"LEAFSEARCH", "\tCMD READY: " + n.file_name)
                        if n.file_name not in readyd:
                            vmsgb(20,"LEAFSEARCH", 
                                  "\tADDING CREATOR TO READYD: " + 
                                  n.file_name)
                            readyd[n.file_name] = n
                        else:
                            vmsgb(20,"LEAFSEARCH", 
                                  "\tCREATOR ALREADY IN READYD: " + 
                                  n.file_name)

            self._scan_successors(nodes,n)
        vmsgb(20,"READYD", str(readyd))
        ready = readyd.values()
        return ready

    def _find_rec_for_missing_file(self, fn, assumed_directory):
        vmsgb(20,"LOOKING FOR MISSING FILE", "%s assuming %s" %
             (fn, assumed_directory))

        if fn in self.recs:
            vmsgb(20,"FOUND DEP REC FOR MISSING FILE", fn)
            return self.recs[fn]
        if assumed_directory:
            nfn = util.join(assumed_directory, fn)
            if nfn in self.recs:
                vmsgb(20,"FOUND DEP REC FOR MISSING FILE(2)", nfn)
                return self.recs[nfn]
            nfn = os.path.realpath(nfn)
            if nfn in self.recs:
                vmsgb(20,"FOUND DEP REC FOR MISSING FILE(3)", nfn)
                return self.recs[nfn]
        vmsgb(20,"NO DEP REC FOR MISSING FILE", fn)
        return None
        
    def _make_list(self, x): # private
        """Make a list from a single object if the thing is not
        already a list. If it is a list, just return the list"""
        if isinstance(x,list):
            return x
        return [ x ]

    def _scan_headers(self, xinput, header_paths, assumed_directory=None):
        """Scan xinput for headers. Add those headers to the list of
        files that are inputs."""
        to_scan = collections.deque()
        to_scan.append(xinput)
        #msgb("HDRSCAN1", xinput)
        # loop scanning headers of headers...
        while len(to_scan) != 0:
            fn = to_scan.popleft()
            #msgb("HDRSCAN2", "\t" + fn)
            # r is the record of the thing we are scanning
            r = self._check_add_dep_rec(fn)
                
            # sometimes we add stuff to the work list twice. Catch the
            # dups here
            if r.scanned:
                continue
            #msgb("HDRSCAN3", fn)
            # headers is all the files that fn includes directly. One
            # level scan
            headers = scanner.mbuild_scan(fn, header_paths)
            if verbose(4):
                for hr in headers:
                    if hr.system:
                        sys="System   "
                    else:
                        sys="NotSystem"
                    if hr.found:
                        fnd="Found  "
                    else:
                        fnd="Missing"
                    msgb('HDR',"%s| %s| %s" % 
                         ( sys, fnd, hr.file_name) )
            
            r.scanned = True

            for hr in headers:
                # we ignore system include files and process normal files

                if not hr.system:
                    scanned_header = True
                    if not hr.found:
                        # check if we have a dep record for this
                        # header. It might be a generated header that
                        # we are expecting to build.
                        ah = self._find_rec_for_missing_file(hr.file_name, assumed_directory)
                        if ah:
                            if verbose(4):
                                msgb("FOUND DEP REC FOR MISSING HEADER. WE WILL BUILD IT")
                            hr.file_name = ah.file_name
                            scanned_header = False
                        elif not self._check_required_file(hr.file_name):
                            if verbose(4):
                                msgb("MISSING HEADER NOT REQUIRED")
                            continue
                        elif assumed_directory:
                            ofn = hr.file_name
                            hr.file_name = util.join(assumed_directory, ofn)
                            if verbose(4):
                                msgb("ASSUMING",
                                     "%s is in %s" % (ofn, assumed_directory))

                                
                    # make the hdr file name canonical.
                    hr.file_name = os.path.realpath(hr.file_name)
                                
                    # Make the forward & backwards links.
                    r.files_that_are_inputs.append(hr.file_name)
                    hdr_node = self._check_add_dep_rec(hr.file_name)
                    hdr_node.scanned_header = scanned_header
                    hdr_node.files_that_depend_on_this.append(fn)
                    
                    if not hdr_node.scanned:
                        to_scan.append(hr.file_name)


    def _make_dep_record(self, file_name, creator=None):
        if verbose(10):
            msgb("MKDEP", file_name)
        r =  _mbuild_dep_record_t(file_name, creator)
        if file_name in self.old_signatures:
            r.old_signature = self.old_signatures[file_name].signature
        return r

    def _check_add_dep_rec(self, fn, creator=None):
        """Look to see if the file exists in our list of dependence
        records. If not, add it. Return the found or created
        record."""
        
        rfn  = os.path.realpath(fn)
            
        if rfn not in self.recs:
            r =  self._make_dep_record(rfn, creator)
            self.recs[rfn] =  r
        else:
            r = self.recs[rfn]
        return r

    def _add_one_input(self, xinput, consumer_cmd):
        r = self._check_add_dep_rec(xinput)
        r.files_that_depend_on_this.extend(consumer_cmd.targets)

    def _add_one_output(self, output, creator=None):
        r = self._check_add_dep_rec(output)
        self.required_set.add(r.file_name)
        if creator != None:
            if r.creator:
                die("Two commands create " + output)
            r.creator = creator
            r.files_that_are_inputs.extend(creator.inputs)
        
    def _make_command_object(self,d):
        """Produce a command_t to add to the workqueue or for
        connecting to other commands by dependence chains"""
        if d.env:
            # FIXME: assumes args is present
            c = command_t( d.command, d.args, d.env )
        elif d.args:
            c = command_t( d.command, d.args)
        else:
            c = command_t( d.command )
        if d.input:
            c.inputs = self._make_list( d.input)
        if d.output:
            c.targets = self._make_list( d.output)
            
        if hasattr(d,'name'):
            c.name = d.name
        return c

    def _make_commands_depend_on_each_other(self,c):
        """We just added a new command c. Now we must make sure that
        the commands that create this command's inputs come before
        this command. Also the commands that use this command's output
        output files as inputs come after it. Not all the commands may
        be known yet, but by working symmetrically here, we'll get
        them all eventually."""

        # Look at the inputs and see if any have commands we can make
        # preceded this one.
        for xinput in c.inputs:
            try:
                t = self.recs[xinput]
                if t.creator:
                    if verbose(10):
                        msgb("CMD IDEP", xinput + " ->  " + str(c.targets))
                    t.creator.add_after_me(c)
            except:
                pass

        # Look at the outputs and see if the files that depend on
        # these outputs have creator commands that should be after
        # this one.
        for output in  c.targets:
            # We just added this so it better be there.
            if output not in self.recs:
                die("Missing command for target " + output)
            t = self.recs[output]
            for f in t.files_that_depend_on_this:
                if f in self.recs:
                    u = self.recs[f]
                    if u.creator:
                        if verbose(10):
                            msgb("ODEP", output + ' -> ' + 
                                 str(u.creator.targets))
                        u.creator.add_before_me(c)

            
    def results(self):
        """Return a list of L{command_t}'s that were executed for
        analysis of the build. If a command was not executed, it is
        not returned.
        
        @rtype: list
        @return: A list of L{command_t} objects.
        """
        executed_commands = []
        for r in iter(self.recs.values()):
            if r.creator:
                if r.creator.completed:
                    executed_commands.append(r.creator)
        return executed_commands
            

    def add(self,env,d):
        """Create a command based on the input dictionary or
        L{plan_t} object.  It  may have inputs and
        outputs. Things may have no input or output files. Return the
        created L{command_t}. The command object dependence
        tracking mechanism will control their execution.
        
        @type env: L{env_t}
        @param env: the environment
        @type d: dict or L{plan_t}
        @param d: a dictionary or L{plan_t}
        from a builder describing the command.
        @rtype: L{command_t}
        @return: A command object for the dependence DAG
        """
        if verbose(12):
            msgb("DAG ADDING", str(d))
        if isinstance(d,dict):
            q = self._convert_to_dagfood(d)
            c = self._add_dagfood(env,q)
        elif isinstance(d,plan_t):
            c = self._add_dagfood(env,d)
        else:
            die("Unhandled type: " + str(type(d)))
        if verbose(12):
            msgb("DAG ADDING", 'DONE')

        return c 


    def _canonize_one_fn(self,fn):
        nfn = strip_quotes(fn)
        r =  os.path.realpath(nfn)
        if verbose(12):
            msgb("REALPATH", "%s -> %s" %(nfn, r), pad='    ')
        return r

    def _canonize_fn(self,x):
        x = self._make_list(x)
        n = []
        for fn in x:
            r = self._canonize_one_fn(fn)
            n.append( r )
        return n

    def _canonize_if_exists_fn(self,x):
        x = self._make_list(x)
        n = []
        for fn in x:
            if os.path.exists(fn):
                r = self._canonize_one_fn(fn)
                n.append( r )
            else:
                n.append(fn)
        return n
    
    def _add_dagfood(self,env,d):
        # make sure all the command line substition has been done
        if d.input:
            d.input = env.expand_string(d.input)
        if d.output:
            d.output = env.expand_string(d.output)
        
        c = self._make_command_object(d)

        if verbose(12):
            msgb("CANONIZE INPUTS", pad='    ')
        c.inputs = self._canonize_fn(c.inputs)
        if verbose(12):
            msgb("CANONIZE TARGETS", pad='    ')
        c.targets = self._canonize_fn(c.targets)
        
        for s in c.inputs:
            if verbose(10):
                msgb("ADD-INPUT", s, pad='    ')
            self._add_one_input(s,c)
            
        for t in c.targets:
            if verbose(10):
                msgb("ADD-OUTPUT", t, pad='    ')
            self._add_one_output(t,c)

        header_paths = env['CPPPATH']
        for s in c.inputs:
            self._scan_headers(s, header_paths, env['gen_dir'])
        return c

    def _convert_to_dagfood(self,d):
        """Convert a dictionary to a plan_t"""
        q = plan_t(d['command'])
        try:
            q.args = d['args']
        except:
            pass
        try:
            q.input = d['input']
        except:
            pass
        try:
            q.output = d['output']
        except:
            pass
        try:
            q.env = d['env']
        except:
            pass
        return q


            

            
