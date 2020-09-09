# Copyright (c) 2015-2020 Vector 35 Inc
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

# 2-3 compatibility
import sys

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3
PY34 = sys.version_info[0:2] >= (3, 4)


if PY2:
  def range(*args):
    return xrange(*args)

  def valid_import(mod_name):
    import imp
    try:
      imp.find_module(mod_name)
      found = True
    except ImportError:
      found = False
    return found

  def pyNativeStr(arg):
    return arg


if PY3:
  range = range  # Range needs to explicitly be defined or it's an error

  def valid_import(mod_name):
    import importlib
    mod_loader = importlib.find_loader(mod_name)
    found = mod_loader is not None
    return found

  def pyNativeStr(arg):
    if isinstance(arg, str):
      return arg
    else:
      try:
        return arg.decode('utf8')
      except UnicodeDecodeError:
        return arg.decode('charmap')


if PY34:
  def valid_import(mod_name):
    import importlib.util
    return importlib.util.find_spec(mod_name) is not None


def with_metaclass(meta, *bases):
  """Create a base class with a metaclass."""
  class metaclass(type):
    def __new__(cls, name, this_bases, d):
      return meta(name, bases, d)

    @classmethod
    def __prepare__(cls, name, this_bases):
      return meta.__prepare__(name, bases)
  return type.__new__(metaclass, 'temporary_class', (), {})


def cstr(arg):
  if isinstance(arg, bytes) or arg is None:
    return arg
  elif isinstance(arg, bytearray):
    return bytes(arg)
  else:
    try:
      return arg.encode('charmap')
    except UnicodeEncodeError:
      return arg.encode('utf8')
