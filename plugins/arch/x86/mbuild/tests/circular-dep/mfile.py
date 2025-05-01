#!/usr/bin/env python
# -*- python -*-

import sys
import find
import mbuild

def setup():
    env = mbuild.env_t()
    env.parse_args()
    mbuild.cmkdir(env['build_dir'])
    if not env.on_windows():
        env['LINK'] = env['CC'] # not g++ for this program
    return env

def work(env):
    #with then env, the dag hash file is put in the build_dir.
    dag = mbuild.dag_t('circular-test',env=env)
    work_queue = mbuild.work_queue_t(env['jobs'])

    env.compile_and_link(dag, ['main.c'], 'main' + env['EXEEXT'])

    okay = work_queue.build(dag=dag)
    if not okay:
        mbuild.die("build failed")
    mbuild.msgb("SUCCESS")


if __name__ == "__main__":
    env = setup()
    work(env)
