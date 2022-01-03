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

from binaryninjaui import *

class UINotification(UIContextNotification):
    def __init__(self):
        UIContextNotification.__init__(self)
        UIContext.registerNotification(self)
        print("py UIContext.registerNotification")

    def __del__(self):
        UIContext.unregisterNotification(self)
        print("py UIContext.unregisterNotification")

    def OnContextOpen(self, context):
        print("py OnContextOpen")

    def OnContextClose(self, context):
        print("py OnContextClose")

    def OnBeforeOpenDatabase(self, context, metadata):
        print(f"py OnBeforeOpenDatabase {metadata.filename}")
        return True

    def OnAfterOpenDatabase(self, context, metadata, data):
        print(f"py OnAfterOpenDatabase {metadata.filename} {data.name}")
        return True

    def OnBeforeOpenFile(self, context, file):
        print(f"py OnBeforeOpenFile {file.getFilename()}")
        return True

    def OnAfterOpenFile(self, context, file, frame):
        print(f"py OnAfterOpenFile {file.getFilename()} {frame.getShortFileName()}")

    def OnBeforeSaveFile(self, context, file, frame):
        print(f"py OnBeforeSaveFile {file.getFilename()} {frame.getShortFileName()}")
        return True

    def OnAfterSaveFile(self, context, file, frame):
        print(f"py OnAfterSaveFile {file.getFilename()} {frame.getShortFileName()}")

    def OnBeforeCloseFile(self, context, file, frame):
        print(f"py OnBeforeCloseFile {file.getFilename()} {frame.getShortFileName()}")
        return True

    def OnAfterCloseFile(self, context, file, frame):
        print(f"py OnAfterCloseFile {file.getFilename()} {frame.getShortFileName()}")

    def OnViewChange(self, context, frame, type):
        if frame:
            print(f"py OnViewChange {frame.getShortFileName()} / {type}")
        else:
            print("py OnViewChange")

    def OnAddressChange(self, context, frame, view, location):
        if frame:
            print(f"py OnAddressChange {frame.getShortFileName()} {location.getOffset()}")
        else:
            print(f"py OnAddressChange {location.getOffset()}")

    def GetNameForFile(self, context, file, name):
        # This function only works in C++: Name is an out param (cpp: &name), and not modifiable by python.
        print(f"py GetNameForFile {file.getFilename()} {name}")
        return False

    def GetNameForPath(self, context, path, name):
        # This function only works in C++: Name is an out param (cpp: &name), and not modifiable by python.
        print(f"py GetNameForPath {path} {name}")
        return False


# Register as a global so it doesn't get destructed
notif = UINotification()

