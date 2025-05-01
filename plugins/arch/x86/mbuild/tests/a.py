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

import sys
import find
import mbuild

env = mbuild.env_t()
env.parse_args()

if 'clean' in env['targets']:
    mbuild.remove_tree(env['build_dir'])
    sys.exit(0)    
mbuild.cmkdir(env['build_dir'])
if not env.on_windows():
    env['LINK'] = env['CC'] # not g++ for this program
    
dep_tracker = mbuild.dag_t()
prog = env.build_dir_join('hello' + env['EXEEXT'])
cmd1 = dep_tracker.add(env, env.cc_compile('hello.c'))
cmd2 = dep_tracker.add(env, env.link(cmd1.targets, prog))

work_queue = mbuild.work_queue_t(env['jobs'])
okay = work_queue.build(dag=dep_tracker)
if not okay:
    mbuild.die("build failed")
mbuild.msgb("SUCCESS")
