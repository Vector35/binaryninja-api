# Copyright (c) 2015-2025 Vector 35 Inc
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

from typing import Any


class _AssociatedDataStore(dict):
	_defaults = {}

	@classmethod
	def set_default(cls, name: str, value: Any):
		cls._defaults[name] = value

	def get(self, key: Any, default: Any = None) -> Any:
		if key in self.keys():
			return self[key]
		if key in self.__class__._defaults:
			return self.__class__._defaults[key]
		return default

	def __getattr__(self, name: str) -> Any:
		if name in self.keys():
			return self[name]
		if name in self.__class__._defaults:
			return self.__class__._defaults[name]
		return self.__getitem__(name)

	def __setattr__(self, name: str, value: Any) -> None:
		self.__setitem__(name, value)

	def __delattr__(self, name: str) -> None:
		self.__delitem__(name)
