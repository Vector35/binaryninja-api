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

"""Intermediate data structure produced by builders and sent to the
dependence directed acyclic graph (DAG) that sequences execution.

Users who create their own builders to call python functions should emit
an plan_t object and add it to the DAG.
"""

class plan_t(object):
    """
    An object that the builders create and is passed to the DAG L{dag_t} to
    order the tasks. This is used exclusively to create
    L{command_t}'s.
    """
    def __init__(self, command, args=None, env=None, input=None, output=None, name=None):
        """
        Create an input record for the L{dag_t} describing a
        command. The command can be a string to execute or a python
        function or a list of strings and python functions. The python
        function will be passed two arguments: args and env. args is
        typically a list, but could be anything.

        The input and output lists of files are used by the L{dag_t} to
        order this command relative to other commands.

        When the command is a python function, the python function is
        called with two arguments: args and an env of type
        L{env_t}. The args can be anything but are typically the
        inputs to the python function and any information required to
        generate the corresponding outputs. The python functions return
        a 2-typle (retcode, stdout).

        The input list: When the command is a python function, the
        plan_t's input list contains at least the input files names
        passed via args variable. The input list can be a superset
        containing more stuff that might trigger the command
        execution.

        If the command does not produce a specific output, you can
        specify a dummy file name to allow sequencing relative to
        other commands.
 
        @type command: string or python function or a list
        @param command: string  or python function.

        @type args: list
        @param args: (optional) arguments to the command if it is a python function

        @type env: L{env_t}
        @param env: (optional) an environment to pass to the python function

        @type input: list
        @param input: (optional) files upon which this command depends.

        @type output: list
        @param output: (optional) files which depend on this command.

        @type name: string
        @param name: (optional) short name to be used to identify the work/task
        """
        self.command = command
        self.args = args
        self.env = env
        self.input = input
        self.output = output
        self.name = name

    def __str__(self):
        s = []
        if self.name:
            s.append('NAME: ' + str(self.name))
        s.append('CMD: ' + str(self.command))
        s.append('INPUT: ' + str(self.input))
        s.append('OUTPUT: ' + str(self.output))
        return " ".join(s)
