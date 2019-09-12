# Copyright (c) 2015-2019 Vector 35 Inc
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

import struct
import traceback
import ctypes
import abc
import numbers

# Binary Ninja components
from binaryninja import _binaryninjacore as core
import binaryninja
from binaryninja import log
from binaryninja import types
from binaryninja import metadata
from binaryninja import platform
from binaryninja import architecture

# 2-3 compatibility
from binaryninja import range
from binaryninja import with_metaclass

class TypeLibrary(object):
    def __init__(self, handle):
        self.handle = core.handle_of_type(handle, core.BNTypeLibrary)

    def __del__(self):
        core.BNFreeTypeLibrary(self.handle)

    def __repr__(self):
        return "<typelib '{}':{}>".format(self.name, self.arch.name)

    @classmethod
    def new(cls, arch, name):
        handle = core.BNNewTypeLibrary(arch.handle, name)
        return TypeLibrary(handle)

    @classmethod
    def load_from_file(cls, path):
        handle = core.BNLoadTypeLibraryFromFile(path)
        if handle is None:
            return None
        return TypeLibrary(handle)

    def write_to_file(self, path):
        core.BNWriteTypeLibraryToFile(self.handle, path)

    @classmethod
    def from_name(cls, arch, name):
        handle = core.BNLookupTypeLibraryByName(arch.handle, name)
        if handle is None:
            return None
        return TypeLibrary(handle)

    @classmethod
    def from_guid(cls, arch, guid):
        handle = core.BNLookupTypeLibraryByGuid(arch.handle, guid)
        if handle is None:
            return None
        return TypeLibrary(handle)

    @property
    def arch(self):
        arch = core.BNGetTypeLibraryArchitecture(self.handle)
        if arch is None:
            return None
        return binaryninja.architecture.CoreArchitecture._from_cache(handle=arch)

    @property
    def name(self):
        name = core.BNGetTypeLibraryName(self.handle)
        return name

    @name.setter
    def name(self, value):
        core.BNSetTypeLibraryName(self.handle, value)

    @property
    def dependency_name(self):
        return core.BNGetTypeLibraryDependencyName(self.handle)

    @dependency_name.setter
    def dependency_name(self, value):
        core.BNSetTypeLibraryDependencyName(self.handle, value)

    @property
    def guid(self):
        return core.BNGetTypeLibraryGuid(self.handle)

    @guid.setter
    def guid(self, value):
        core.BNSetTypeLibraryGuid(self.handle, value)

    @property
    def alternate_names(self):
        count = ctypes.c_ulonglong(0)
        result = []
        names = core.BNGetTypeLibraryAlternateNames(self.handle, count)
        for i in range(0, count.value):
            result.append(names[i])
        core.BNFreeStringList(names, count.value)
        return result

    def add_alternate_name(self, name):
        core.BNAddTypeLibraryAlternateName(self.handle, name)

    @property
    def platform_names(self):
        count = ctypes.c_ulonglong(0)
        result = []
        platforms = core.BNGetTypeLibraryPlatforms(self.handle, count)
        for i in range(0, count.value):
            result.append(platforms[i])
        core.BNFreeStringList(platforms, count.value)
        return result

    def add_platform(self, plat):
        if not isinstance(plat, platform.Platform):
            raise ValueError("plat must be a Platform object")
        core.BNAddTypeLibraryPlatform(self.handle, plat.handle)

    def clear_platforms(self):
        core.BNClearTypeLibraryPlatforms(self.handle)

    def finalize(self):
        core.BNFinalizeTypeLibrary(self.handle)

    def query_metadata(self, key):
        md_handle = core.BNTypeLibraryQueryMetadata(self.handle, key)
        if md_handle is None:
            return None
        return metadata.Metadata(handle=md_handle).value

    def store_metadata(self, key, md):
        if not isinstance(md, metadata.Metadata):
            md = metadata.Metadata(md)
        core.BNTypeLibraryStoreMetadata(self.handle, key, md.handle)

    def remove_metadata(self, key):
        core.BNTypeLibraryRemoveMetadata(self.handle, key)

    def add_named_object(self, name, t):
        if not isinstance(name, types.QualifiedName):
            name = types.QualifiedName(name)
        if not isinstance(t, types.Type):
            raise ValueError("t must be a Type")
        core.BNAddTypeLibraryNamedObject(self.handle, name._get_core_struct(), t.handle)

    def add_named_type(self, name, t):
        if not isinstance(name, types.QualifiedName):
            name = types.QualifiedName(name)
        if not isinstance(t, types.Type):
            raise ValueError("t must be a Type")
        core.BNAddTypeLibraryNamedType(self.handle, name._get_core_struct(), t.handle)

    def get_named_object(self, name):
        if not isinstance(name, types.QualifiedName):
            name = types.QualifiedName(name)
        t = core.BNGetTypeLibraryNamedObject(self.handle, name._get_core_struct())
        if t is None:
            return None
        return types.Type(t)

    def get_named_type(self, name):
        if not isinstance(name, types.QualifiedName):
            name = types.QualifiedName(name)
        t = core.BNGetTypeLibraryNamedType(self.handle, name._get_core_struct())
        if t is None:
            return None
        return types.Type(t)

    @property
    def named_objects(self):
        count = ctypes.c_ulonglong(0)
        result = {}
        named_types = core.BNGetTypeLibraryNamedObjects(self.handle, count)
        for i in range(0, count.value):
            name = types.QualifiedName._from_core_struct(named_types[i].name)
            result[name] = types.Type(core.BNNewTypeReference(named_types[i].type))
        core.BNFreeQualifiedNameAndTypeArray(named_types, count.value)
        return result

    @property
    def named_types(self):
        count = ctypes.c_ulonglong(0)
        result = {}
        named_types = core.BNGetTypeLibraryNamedTypes(self.handle, count)
        for i in range(0, count.value):
            name = types.QualifiedName._from_core_struct(named_types[i].name)
            result[name] = types.Type(core.BNNewTypeReference(named_types[i].type))
        core.BNFreeQualifiedNameAndTypeArray(named_types, count.value)
        return result

