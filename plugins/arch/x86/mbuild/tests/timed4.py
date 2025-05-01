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
from __future__ import print_function
import find
import mbuild

env = mbuild.env_t(0)
env.parse_args()
work_queue = mbuild.work_queue_t(env['jobs'])


c = mbuild.command_t("/bin/sleep 1", seconds=2, show_output=False)
#work_queue.add(c)

c2 = mbuild.command_t("./spew", seconds=2, show_output=False)
#work_queue.add(c2)


def some_python_fn(a,b):
    n = 10
    x = 0
    for i in range(0,n):
        for j in range(0,n):
            for k in range(0,n):
                x += i*j*k
    return (0, [str(x)])

c3 = mbuild.command_t(some_python_fn, seconds=2, show_output=True) 
work_queue.add(c3)



# run the commands. Use --jobs N to set the number of workers to N. 
okay = work_queue.build(die_on_errors=False)
if okay:
    mbuild.msgb('BUILD', 'pass')
else:
    mbuild.msgb('BUILD', 'failed')

print (len(c2.output))
print (c2.output[0:10])
print (str(c2.stderr))
print (str(c3.output))

