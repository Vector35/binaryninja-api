# Copyright (c) 2015-2022 Vector 35 Inc
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

from typing import Optional, Union, Any

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import LogLevel
import threading

_output_to_log = False


def redirect_output_to_log():
	global _output_to_log
	_output_to_log = True


def is_output_redirected_to_log():
	global _output_to_log
	return _output_to_log


def log(level: LogLevel, text: Union[str, Any], logger: Optional[str]="", session:int=0):
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
	if not isinstance(text, str):
		text = str(text)
	core.BNLogString(session, level, logger, threading.current_thread().ident, text)


def log_debug(text: Union[str, Any], logger: Optional[str]=""):
	"""
	``log_debug`` Logs debugging information messages to the console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_debug("Hotdogs!")
		Hotdogs!
	"""
	if not isinstance(text, str):
		text = str(text)
	core.BNLogString(0, LogLevel.DebugLog, logger, threading.current_thread().ident, text)


def log_info(text: Union[str, Any], logger: Optional[str]=""):
	"""
	``log_info`` Logs general information messages to the console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_info("Saucisson!")
		Saucisson!
		>>>
	"""
	if not isinstance(text, str):
		text = str(text)
	core.BNLogString(0, LogLevel.InfoLog, logger, threading.current_thread().ident, text)


def log_warn(text: Union[str, Any], logger: Optional[str]=""):
	"""
	``log_warn`` Logs message to console, if run through the GUI it logs with **Warning** icon.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_warn("Chilidogs!")
		Chilidogs!
		>>>
	"""
	if not isinstance(text, str):
		text = str(text)
	core.BNLogString(0, LogLevel.WarningLog, logger, threading.current_thread().ident, text)


def log_error(text: Union[str, Any], logger: Optional[str]=""):
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
	if not isinstance(text, str):
		text = str(text)
	core.BNLogString(0, LogLevel.ErrorLog, logger, threading.current_thread().ident, text)


def log_alert(text: Union[str, Any], logger: Optional[str]=""):
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
	if not isinstance(text, str):
		text = str(text)
	core.BNLogString(0, LogLevel.AlertLog, logger, threading.current_thread().ident, text)


def log_to_stdout(min_level: Optional[LogLevel]=LogLevel.InfoLog):
	"""
	``log_to_stdout`` redirects minimum log level to standard out.

	:param enums.LogLevel min_level: minimum level to log to
	:rtype: None
	:Example:

		>>> log_debug("Hotdogs!")
		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_debug("Hotdogs!")
		Hotdogs!
		>>>
	"""
	core.BNLogToStdout(min_level)


def log_to_stderr(min_level: LogLevel):
	"""
	``log_to_stderr`` redirects minimum log level to standard error.

	:param enums.LogLevel min_level: minimum level to log to
	:rtype: None
	"""
	core.BNLogToStderr(min_level)


def log_to_file(min_level: LogLevel, path: str, append: bool=False):
	"""
	``log_to_file`` redirects minimum log level to a file named ``path``, optionally appending rather than overwriting.

	:param enums.Log_Level min_level: minimum level to log
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


class Logger:
	def __init__(self, session_id:int, logger_name:str):
		self.session_id = session_id
		self.logger_name = logger_name
		self.handle = core.BNLogCreateLogger(logger_name, session_id)

	def log(self, level:LogLevel, message:str) -> None:
		log(level, message, self.logger_name, self.session_id)

	def log_debug(self, message:str) -> None:
		log(LogLevel.DebugLog, message, self.logger_name, self.session_id)

	def log_info(self, message:str) -> None:
		log(LogLevel.InfoLog, message, self.logger_name, self.session_id)

	def log_warn(self, message:str) -> None:
		log(LogLevel.WarningLog, message, self.logger_name, self.session_id)

	def log_error(self, message:str) -> None:
		log(LogLevel.ErrorLog, message, self.logger_name, self.session_id)

	def log_alert(self, message:str) -> None:
		log(LogLevel.AlertLog, message, self.logger_name, self.session_id)