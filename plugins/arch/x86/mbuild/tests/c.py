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
# find.py is in the tests dir. It finds mbuild and puts it on the
# sys.path.
import find
import mbuild

env = mbuild.env_t(init_verbose=0)
env.parse_args()
if not env.on_windows():
    print ("This is a windows only test"   )
    sys.exit(0)    

#mbuild.build_env.set_env_icl(env)
mbuild.cmkdir(env['build_dir'])
dag  = mbuild.dag_t()
res  = env.compile(dag,['VersionInfo.rc'])
objs = env.compile(dag,['hello.c'])
cmd  = dag.add(env,
               env.dynamic_lib(objs + res, 
                               env.build_dir_join('hello.dll')))

work_queue = mbuild.work_queue_t(env['jobs'])
okay = work_queue.build(dag=dag)
if not okay:
    mbuild.die("build failed")
mbuild.msgb("SUCCESS")
