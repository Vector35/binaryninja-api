# Copyright (c) 2015-2017 Vector 35 LLC
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

import inspect

from binaryninja import BinaryDataNotification
from binaryninja import PluginCommand


def reg_notif(view):
	demo_notification = DemoNotification(view)
	view.register_notification(demo_notification)

class DemoNotification(BinaryDataNotification):
	def __init__(self, view):
		self.view = view

	def data_written(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def data_inserted(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def data_removed(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def function_added(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def function_removed(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def function_updated(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def data_var_added(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def data_var_updated(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def data_var_removed(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def string_found(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def string_removed(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def type_defined(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

	def type_undefined(self, *args):
		log.log_info(inspect.stack()[0][3] + str(args))

PluginCommand.register("Register Notification", "", reg_notif)
