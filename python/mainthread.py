# Copyright (c) 2015-2024 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""
.. py:module:: mainthread

This module provides two ways to execute "jobs":

1. On the Binary Ninja main thread (the UI event thread when running in the GUI application):
	* :py:func:`.execute_on_main_thread`
	* :py:func:`.execute_on_main_thread_and_wait`
2. On a worker thread

Any manipulation of the GUI should be performed on the main thread, but any
non-GUI work is generally better to be performed using a worker. This is
especially true for any longer-running work, as the user interface will
be unable to update itself while a job is executing on the main thread.

There are three worker queues, in order of decreasing priority:

	1. The Interactive Queue (:py:func:`.worker_interactive_enqueue`)
	2. The Priority Queue (:py:func:`.worker_priority_enqueue`)
	3. The Worker Queue (:py:func:`.worker_enqueue`)

All of these queues are serviced by the same pool of worker threads. The
difference between the queues is basically one of priority: one queue must
be empty of jobs before a worker thread will execute a job from a lower
priority queue.

The default maximum number of concurrent worker threads is controlled by the
`analysis.limits.workerThreadCount` setting but can be adjusted at runtime via
:py:func:`.set_worker_thread_count`.

The worker threads are native threads, managed by the Binary Ninja core. If
more control over the thread is required, consider using the
:py:class:`~binaryninja.plugin.BackgroundTaskThread` class.
"""

# Binary Ninja components
from . import _binaryninjacore as core
from . import scriptingprovider
from . import plugin


def execute_on_main_thread(func):
	"""
	The ``execute_on_main_thread`` function takes a single parameter which is a function that will be executed
	on the main Binary Ninja thread.

		.. warning:: May be required for some GUI operations, but should be used sparingly as it can block the UI.
	"""
	action = scriptingprovider._ThreadActionContext(func)
	obj = core.BNExecuteOnMainThread(0, action.callback)
	if obj:
		return plugin.MainThreadAction(obj)
	return None


def execute_on_main_thread_and_wait(func):
	"""
	The ``execute_on_main_thread`` function takes a single parameter which is a function that will be
	executed on the main Binary Ninja thread and will block execution of further python until the function returns.

		.. warning:: May be required for some GUI operations, but should be used sparingly as it can block the UI.
	"""
	action = scriptingprovider._ThreadActionContext(func)
	core.BNExecuteOnMainThreadAndWait(0, action.callback)


def worker_enqueue(func, name=""):
	action = scriptingprovider._ThreadActionContext(func)
	core.BNWorkerEnqueueNamed(0, action.callback, "Python " + name)


def worker_priority_enqueue(func, name=""):
	action = scriptingprovider._ThreadActionContext(func)
	core.BNWorkerPriorityEnqueueNamed(0, action.callback, "Python " + name)


def worker_interactive_enqueue(func, name=""):
	action = scriptingprovider._ThreadActionContext(func)
	core.BNWorkerInteractiveEnqueueNamed(0, action.callback, "Python " + name)


def get_worker_thread_count():
	"""
	The ``get_worker_thread_count`` function returns the number of worker threads that are currently running.
	By default, this is the number of cores on the system minus one, however this can be changed with
	``set_worker_thread_count``.
	"""
	return core.BNGetWorkerThreadCount()


def set_worker_thread_count(count):
	"""
	The ``set_worker_thread_count`` function sets the number of worker threads that are currently running.
	By default, this is the number of cores on the system minus one.
	"""
	core.BNSetWorkerThreadCount(count)


def is_main_thread():
	return core.BNIsMainThread()
