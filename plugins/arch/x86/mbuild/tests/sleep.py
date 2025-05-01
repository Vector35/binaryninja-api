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

import os,sys
sys.path = ['..'] + sys.path
import mbuild

env = mbuild.env_t()
env.parse_args()

env['jobs']=4
work_queue = mbuild.work_queue_t(env['jobs'])
all_cmds = 2 * [ './delay 40000' ]
subs = {}
command_list = []
for cmd in all_cmds:
    cmd  = cmd % (subs)
    mbuild.msgb('ADDING', cmd)
    command_list.append(cmd)
work_queue.add_sequential(command_list, unbufferred=True)


phase = "BUILD"
okay = work_queue.build(show_progress=True)
if not okay:
    mbuild.die("[%s] failed. dying..." % phase)
mbuild.msgb(phase, "succeeded")
