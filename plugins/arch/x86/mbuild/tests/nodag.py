#!/usr/bin/env python
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

# Example of using the connections between commands to enforce
# execution ordering. A dag_t requires that you have files and that
# doesn't help for things that are not file oriented.

import os
import sys
import find
import mbuild

env = mbuild.env_t()
env.parse_args()
work_queue = mbuild.work_queue_t(env['jobs'])

last_command_in_sequence = {}
for i in range(0,99):
    cmd = "/bin/echo %d" %  (i)
    c = mbuild.command_t(cmd)

    # break the commmands in to 7 sequences
    seq = i % 7

    # enforce a dependence between commands in the same sequence
    try:
        prev = last_command_in_sequence[seq]
        prev.add_after_me(c)
    except:
        pass
    last_command_in_sequence[seq]=c
    mbuild.msgb('ADDING',i)
    # add it to the work queue
    work_queue.add(c)

# run the commands. Use --jobs N to set the number of workers to N. 
okay = work_queue.build()
if not okay:
    mbuild.die("build failed")
mbuild.msgb("SUCCESS")
