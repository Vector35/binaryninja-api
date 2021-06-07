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
from .enums import LogLevel


_output_to_log = False


def redirect_output_to_log():
	global _output_to_log
	_output_to_log = True


def is_output_redirected_to_log():
	global _output_to_log
	return _output_to_log


def log(level, text):
	"""
	``log`` writes messages to the log console for the given log level.

		============ ======== =======================================================================
		LogLevelName LogLevel  Description
		============ ======== =======================================================================
		DebugLog        0     Logs debugging information messages to the console.
		InfoLog         1     Logs general information messages to the console.
		WarningLog      2     Logs message to console with **Warning** icon.
		ErrorLog        3     Logs message to console with **Error** icon, focusing the error console.
		AlertLog        4     Logs message to pop up window.
		============ ======== =======================================================================

	:param LogLevel level: Log level to use
	:param str text: message to print
	:rtype: None
	"""
	core.BNLogString(level, text)


def log_debug(text):
	"""
	``log_debug`` Logs debugging information messages to the console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_debug("Hotdogs!")
		Hotdogs!
	"""
	core.BNLogString(LogLevel.DebugLog, text)


def log_info(text):
	"""
	``log_info`` Logs general information messages to the console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_info("Saucisson!")
		Saucisson!
		>>>
	"""
	core.BNLogString(LogLevel.InfoLog, text)


def log_warn(text):
	"""
	``log_warn`` Logs message to console, if run through the GUI it logs with **Warning** icon.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_info("Chilidogs!")
		Chilidogs!
		>>>
	"""
	core.BNLogString(LogLevel.WarningLog, text)


def log_error(text):
	"""
	``log_error`` Logs message to console, if run through the GUI it logs with **Error** icon, focusing the error console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_error("Spanferkel!")
		Spanferkel!
		>>>
	"""
	core.BNLogString(LogLevel.ErrorLog, text)


def log_alert(text):
	"""
	``log_alert`` Logs message console and to a pop up window if run through the GUI.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_alert("Kielbasa!")
		Kielbasa!
		>>>
	"""
	core.BNLogString(LogLevel.AlertLog, text)


def log_to_stdout(min_level=LogLevel.InfoLog):
	"""
	``log_to_stdout`` redirects minimum log level to standard out.

	:param enums.LogLevel log_level: minimum level to log to
	:rtype: None
	:Example:

		>>> log_debug("Hotdogs!")
		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_debug("Hotdogs!")
		Hotdogs!
		>>>
	"""
	core.BNLogToStdout(min_level)


def log_to_stderr(min_level):
	"""
	``log_to_stderr`` redirects minimum log level to standard error.

	:param enums.LogLevel min_level: minimum level to log to
	:rtype: None
	"""
	core.BNLogToStderr(min_level)


def log_to_file(min_level, path, append = False):
	"""
	``log_to_file`` redirects minimum log level to a file named ``path``, optionally appending rather than overwriting.

	:param enums.Log_Level min_level: minimum level to log to
	:param str path: path to log to
	:param bool append: optional flag for specifying appending. True = append, False = overwrite.
	:rtype: None
	"""
	core.BNLogToFile(min_level, str(path), append)


def close_logs():
	"""
	``close_logs`` close all log files.

	:rtype: None
	"""
	core.BNCloseLogs()
