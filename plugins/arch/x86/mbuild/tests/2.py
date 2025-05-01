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

import os,sys
sys.path = ['..'] + sys.path
import mbuild

env = mbuild.env_t()
env.parse_args()

env['jobs']=1
work_queue = mbuild.work_queue_t(env['jobs'])
all_cmds = [ 'python -c "print(1+1)"' ]
out_file_name = 'foo'
subs = {}
command_list = []
for cmd in all_cmds:
    cmd  = cmd % (subs)
    mbuild.msgb('ADDING', cmd)
    c = mbuild.command_t(cmd, output_file_name=out_file_name)
    work_queue.add(c)
    command_list.append(cmd)


phase = "BUILD"
okay = work_queue.build()
if not okay:
    mbuild.die("[%s] failed. dying..." % phase)
with open(out_file_name) as f:
    if int(f.readline()) != 2:
        mbuild.die("[%s] failed. Unexpected output, dying..." % phase)

mbuild.msgb(phase, "succeeded")
