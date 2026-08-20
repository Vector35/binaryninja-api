# Copyright (c) 2015-2026 Vector 35 Inc
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
import traceback

_output_to_log = False


def redirect_output_to_log():
	global _output_to_log
	_output_to_log = True


def is_output_redirected_to_log():
	global _output_to_log
	return _output_to_log


def log(level: LogLevel, text: Any, logger: str = "", session: int = 0):
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


def log_debug(text: Any, logger: str = ""):
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


def log_info(text: Any, logger: str = ""):
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


def log_warn(text: Any, logger: str = ""):
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


def log_error(text: Any, logger: str = ""):
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


def log_alert(text: Any, logger: str = ""):
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


def log_for_exception(level: LogLevel, text: Any, logger: str = "", session: int = 0):
	"""
	``log_for_exception`` writes messages to the log console for the given log level, including a stack trace for the current exception.

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
	core.BNLogStringWithStackTrace(session, level, logger, threading.current_thread().ident, traceback.format_exc(), text)


def log_debug_for_exception(text: Any, logger: str = ""):
	"""
	``log_debug_for_exception`` Logs debugging information messages to the console, including a stack trace for the current exception.

	:param str text: message to print
	:rtype: None
	"""
	if not isinstance(text, str):
		text = str(text)
	core.BNLogStringWithStackTrace(0, LogLevel.DebugLog, logger, threading.current_thread().ident, traceback.format_exc(), text)


def log_info_for_exception(text: Any, logger: str = ""):
	"""
	``log_info_for_exception`` Logs general information messages to the console, including a stack trace for the current exception.

	:param str text: message to print
	:rtype: None
	"""
	if not isinstance(text, str):
		text = str(text)
	core.BNLogStringWithStackTrace(0, LogLevel.InfoLog, logger, threading.current_thread().ident, traceback.format_exc(), text)


def log_warn_for_exception(text: Any, logger: str = ""):
	"""
	``log_warn_for_exception`` Logs message to console, including a stack trace for the current exception. When run through the GUI it logs with **Warning** icon.

	:param str text: message to print
	:rtype: None
	"""
	if not isinstance(text, str):
		text = str(text)
	core.BNLogStringWithStackTrace(0, LogLevel.WarningLog, logger, threading.current_thread().ident, traceback.format_exc(), text)


def log_error_for_exception(text: Any, logger: str = ""):
	"""
	``log_error_for_exception`` Logs message to console, including a stack trace for the current exception. When run through the GUI it logs with **Error** icon, focusing the error console.

	:param str text: message to print
	:rtype: None
	"""
	if not isinstance(text, str):
		text = str(text)
	core.BNLogStringWithStackTrace(0, LogLevel.ErrorLog, logger, threading.current_thread().ident, traceback.format_exc(), text)


def log_alert_for_exception(text: Any, logger: str = ""):
	"""
	``log_alert_for_exception`` Logs message console, including a stack trace for the current exception. A pop up window is created if run through the GUI.

	:param str text: message to print
	:rtype: None
	"""
	if not isinstance(text, str):
		text = str(text)
	core.BNLogStringWithStackTrace(0, LogLevel.AlertLog, logger, threading.current_thread().ident, traceback.format_exc(), text)


def log_with_traceback(level: LogLevel, text: Any, logger: str = "", session: int = 0, stack_trace: Optional[str] = None):
	"""
	``log_with_traceback`` writes messages to the log console for the given log level, including a stack trace.

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
	:param str stack_trace: optional explicit trace string to attach (shown behind the log entry's "Details..." link). \
		If omitted, the current Python stack is used. Callers can pass subprocess output, a decoded exception, etc.
	:rtype: None
	"""
	if not isinstance(text, str):
		text = str(text)
	if stack_trace is None:
		stack_trace = ''.join(traceback.format_stack())
	core.BNLogStringWithStackTrace(session, level, logger or "", threading.current_thread().ident, stack_trace, text)


def log_debug_with_traceback(text: Any, logger: str = "", stack_trace: Optional[str] = None):
	"""
	``log_debug_with_traceback`` Logs debugging information messages to the console, including a stack trace.

	:param str text: message to print
	:param str stack_trace: optional explicit trace string to attach; if omitted, the current Python stack is used.
	:rtype: None
	"""
	log_with_traceback(LogLevel.DebugLog, text, logger, 0, stack_trace)


def log_info_with_traceback(text: Any, logger: str = "", stack_trace: Optional[str] = None):
	"""
	``log_info_with_traceback`` Logs general information messages to the console, including a stack trace.

	:param str text: message to print
	:param str stack_trace: optional explicit trace string to attach; if omitted, the current Python stack is used.
	:rtype: None
	"""
	log_with_traceback(LogLevel.InfoLog, text, logger, 0, stack_trace)


def log_warn_with_traceback(text: Any, logger: str = "", stack_trace: Optional[str] = None):
	"""
	``log_warn_with_traceback`` Logs message to console, including a stack trace. When run through the GUI it logs with **Warning** icon.

	:param str text: message to print
	:param str stack_trace: optional explicit trace string to attach; if omitted, the current Python stack is used.
	:rtype: None
	"""
	log_with_traceback(LogLevel.WarningLog, text, logger, 0, stack_trace)


def log_error_with_traceback(text: Any, logger: str = "", stack_trace: Optional[str] = None):
	"""
	``log_error_with_traceback`` Logs message to console, including a stack trace. When run through the GUI it logs with **Error** icon, focusing the error console.

	:param str text: message to print
	:param str stack_trace: optional explicit trace string to attach; if omitted, the current Python stack is used.
	:rtype: None
	"""
	log_with_traceback(LogLevel.ErrorLog, text, logger, 0, stack_trace)


def log_alert_with_traceback(text: Any, logger: str = "", stack_trace: Optional[str] = None):
	"""
	``log_alert_with_traceback`` Logs message console, including a stack trace. A pop up window is created if run through the GUI.

	:param str text: message to print
	:param str stack_trace: optional explicit trace string to attach; if omitted, the current Python stack is used.
	:rtype: None
	"""
	log_with_traceback(LogLevel.AlertLog, text, logger, 0, stack_trace)


def log_to_stdout(min_level: LogLevel = LogLevel.InfoLog):
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
	def __init__(self, session_id: int, logger_name: str, handle=None):
		self.session_id = session_id
		self.logger_name = logger_name
		if handle:
			self.handle = handle
		else:
			self.handle = core.BNLogCreateLogger(logger_name, session_id)

	def log(self, level: LogLevel, message: str) -> None:
		log(level, message, self.logger_name, self.session_id)

	def log_debug(self, message: str) -> None:
		log(LogLevel.DebugLog, message, self.logger_name, self.session_id)

	def log_info(self, message: str) -> None:
		log(LogLevel.InfoLog, message, self.logger_name, self.session_id)

	def log_warn(self, message: str) -> None:
		log(LogLevel.WarningLog, message, self.logger_name, self.session_id)

	def log_error(self, message: str) -> None:
		log(LogLevel.ErrorLog, message, self.logger_name, self.session_id)

	def log_alert(self, message: str) -> None:
		log(LogLevel.AlertLog, message, self.logger_name, self.session_id)

	def log_for_exception(self, level: LogLevel, message: str) -> None:
		log_for_exception(level, message, self.logger_name, self.session_id)

	def log_debug_for_exception(self, message: str) -> None:
		log_for_exception(LogLevel.DebugLog, message, self.logger_name, self.session_id)

	def log_info_for_exception(self, message: str) -> None:
		log_for_exception(LogLevel.InfoLog, message, self.logger_name, self.session_id)

	def log_warn_for_exception(self, message: str) -> None:
		log_for_exception(LogLevel.WarningLog, message, self.logger_name, self.session_id)

	def log_error_for_exception(self, message: str) -> None:
		log_for_exception(LogLevel.ErrorLog, message, self.logger_name, self.session_id)

	def log_alert_for_exception(self, message: str) -> None:
		log_for_exception(LogLevel.AlertLog, message, self.logger_name, self.session_id)

	def log_with_traceback(self, level: LogLevel, message: str, stack_trace: Optional[str] = None) -> None:
		log_with_traceback(level, message, self.logger_name, self.session_id, stack_trace)

	def log_debug_with_traceback(self, message: str, stack_trace: Optional[str] = None) -> None:
		log_with_traceback(LogLevel.DebugLog, message, self.logger_name, self.session_id, stack_trace)

	def log_info_with_traceback(self, message: str, stack_trace: Optional[str] = None) -> None:
		log_with_traceback(LogLevel.InfoLog, message, self.logger_name, self.session_id, stack_trace)

	def log_warn_with_traceback(self, message: str, stack_trace: Optional[str] = None) -> None:
		log_with_traceback(LogLevel.WarningLog, message, self.logger_name, self.session_id, stack_trace)

	def log_error_with_traceback(self, message: str, stack_trace: Optional[str] = None) -> None:
		log_with_traceback(LogLevel.ErrorLog, message, self.logger_name, self.session_id, stack_trace)

	def log_alert_with_traceback(self, message: str, stack_trace: Optional[str] = None) -> None:
		log_with_traceback(LogLevel.AlertLog, message, self.logger_name, self.session_id, stack_trace)
