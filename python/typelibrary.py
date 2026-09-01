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

"""Compatibility shim. This module was renamed to :py:mod:`binaryninja.importlibrary`."""

import warnings

from .deprecation import DeprecatedWarning
from .importlibrary import *  # noqa: F401,F403
from .importlibrary import ImportLibrary

_RENAMED_ATTRS = {"TypeLibrary": "ImportLibrary"}


def __getattr__(name):
	target = _RENAMED_ATTRS.get(name)
	if target is None:
		raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
	warnings.warn(
	    DeprecatedWarning(f"binaryninja.typelibrary.{name}", "6.1", None, f"Use binaryninja.importlibrary.{target} instead."),
	    stacklevel=2
	)
	return globals()[target]


__all__ = [_n for _n in list(globals()) if not _n.startswith("_")] + list(_RENAMED_ATTRS)
