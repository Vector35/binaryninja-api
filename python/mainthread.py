# Copyright (c) 2015-2021 Vector 35 Inc
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

# Binary Ninja components
from . import _binaryninjacore as core
from . import scriptingprovider
from . import plugin


def execute_on_main_thread(func):
	action = scriptingprovider._ThreadActionContext(func)
	obj = core.BNExecuteOnMainThread(0, action.callback)
	if obj:
		return plugin.MainThreadAction(obj)
	return None


def execute_on_main_thread_and_wait(func):
	action = scriptingprovider._ThreadActionContext(func)
	core.BNExecuteOnMainThreadAndWait(0, action.callback)


def worker_enqueue(func):
	action = scriptingprovider._ThreadActionContext(func)
	core.BNWorkerEnqueue(0, action.callback)


def worker_priority_enqueue(func):
	action = scriptingprovider._ThreadActionContext(func)
	core.BNWorkerPriorityEnqueue(0, action.callback)


def worker_interactive_enqueue(func):
	action = scriptingprovider._ThreadActionContext(func)
	core.BNWorkerInteractiveEnqueue(0, action.callback)


def get_worker_thread_count():
	return core.BNGetWorkerThreadCount()


def set_worker_thread_count(count):
	core.BNSetWorkerThreadCount(count)


def is_main_thread():
	return core.BNIsMainThread()
