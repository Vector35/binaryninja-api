from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class JavaClass(KaitaiStruct):
    """
    .. seealso::
       Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.1
    """
    SEQ_FIELDS = ["magic", "version_minor", "version_major", "constant_pool_count", "constant_pool", "access_flags", "this_class", "super_class", "interfaces_count", "interfaces", "fields_count", "fields", "methods_count", "methods", "attributes_count", "attributes"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic']['start'] = self._io.pos()
        self.magic = self._io.ensure_fixed_contents(b"\xCA\xFE\xBA\xBE")
        self._debug['magic']['end'] = self._io.pos()
        self._debug['version_minor']['start'] = self._io.pos()
        self.version_minor = self._io.read_u2be()
        self._debug['version_minor']['end'] = self._io.pos()
        self._debug['version_major']['start'] = self._io.pos()
        self.version_major = self._io.read_u2be()
        self._debug['version_major']['end'] = self._io.pos()
        self._debug['constant_pool_count']['start'] = self._io.pos()
        self.constant_pool_count = self._io.read_u2be()
        self._debug['constant_pool_count']['end'] = self._io.pos()
        self._debug['constant_pool']['start'] = self._io.pos()
        self.constant_pool = [None] * ((self.constant_pool_count - 1))
        for i in range((self.constant_pool_count - 1)):
            if not 'arr' in self._debug['constant_pool']:
                self._debug['constant_pool']['arr'] = []
            self._debug['constant_pool']['arr'].append({'start': self._io.pos()})
            _t_constant_pool = self._root.ConstantPoolEntry(self._io, self, self._root)
            _t_constant_pool._read()
            self.constant_pool[i] = _t_constant_pool
            self._debug['constant_pool']['arr'][i]['end'] = self._io.pos()

        self._debug['constant_pool']['end'] = self._io.pos()
        self._debug['access_flags']['start'] = self._io.pos()
        self.access_flags = self._io.read_u2be()
        self._debug['access_flags']['end'] = self._io.pos()
        self._debug['this_class']['start'] = self._io.pos()
        self.this_class = self._io.read_u2be()
        self._debug['this_class']['end'] = self._io.pos()
        self._debug['super_class']['start'] = self._io.pos()
        self.super_class = self._io.read_u2be()
        self._debug['super_class']['end'] = self._io.pos()
        self._debug['interfaces_count']['start'] = self._io.pos()
        self.interfaces_count = self._io.read_u2be()
        self._debug['interfaces_count']['end'] = self._io.pos()
        self._debug['interfaces']['start'] = self._io.pos()
        self.interfaces = [None] * (self.interfaces_count)
        for i in range(self.interfaces_count):
            if not 'arr' in self._debug['interfaces']:
                self._debug['interfaces']['arr'] = []
            self._debug['interfaces']['arr'].append({'start': self._io.pos()})
            self.interfaces[i] = self._io.read_u2be()
            self._debug['interfaces']['arr'][i]['end'] = self._io.pos()

        self._debug['interfaces']['end'] = self._io.pos()
        self._debug['fields_count']['start'] = self._io.pos()
        self.fields_count = self._io.read_u2be()
        self._debug['fields_count']['end'] = self._io.pos()
        self._debug['fields']['start'] = self._io.pos()
        self.fields = [None] * (self.fields_count)
        for i in range(self.fields_count):
            if not 'arr' in self._debug['fields']:
                self._debug['fields']['arr'] = []
            self._debug['fields']['arr'].append({'start': self._io.pos()})
            _t_fields = self._root.FieldInfo(self._io, self, self._root)
            _t_fields._read()
            self.fields[i] = _t_fields
            self._debug['fields']['arr'][i]['end'] = self._io.pos()

        self._debug['fields']['end'] = self._io.pos()
        self._debug['methods_count']['start'] = self._io.pos()
        self.methods_count = self._io.read_u2be()
        self._debug['methods_count']['end'] = self._io.pos()
        self._debug['methods']['start'] = self._io.pos()
        self.methods = [None] * (self.methods_count)
        for i in range(self.methods_count):
            if not 'arr' in self._debug['methods']:
                self._debug['methods']['arr'] = []
            self._debug['methods']['arr'].append({'start': self._io.pos()})
            _t_methods = self._root.MethodInfo(self._io, self, self._root)
            _t_methods._read()
            self.methods[i] = _t_methods
            self._debug['methods']['arr'][i]['end'] = self._io.pos()

        self._debug['methods']['end'] = self._io.pos()
        self._debug['attributes_count']['start'] = self._io.pos()
        self.attributes_count = self._io.read_u2be()
        self._debug['attributes_count']['end'] = self._io.pos()
        self._debug['attributes']['start'] = self._io.pos()
        self.attributes = [None] * (self.attributes_count)
        for i in range(self.attributes_count):
            if not 'arr' in self._debug['attributes']:
                self._debug['attributes']['arr'] = []
            self._debug['attributes']['arr'].append({'start': self._io.pos()})
            _t_attributes = self._root.AttributeInfo(self._io, self, self._root)
            _t_attributes._read()
            self.attributes[i] = _t_attributes
            self._debug['attributes']['arr'][i]['end'] = self._io.pos()

        self._debug['attributes']['end'] = self._io.pos()

    class FloatCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.5
        """
        SEQ_FIELDS = ["value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['value']['start'] = self._io.pos()
            self.value = self._io.read_f4be()
            self._debug['value']['end'] = self._io.pos()


    class AttributeInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.7
        """
        SEQ_FIELDS = ["name_index", "attribute_length", "info"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name_index']['start'] = self._io.pos()
            self.name_index = self._io.read_u2be()
            self._debug['name_index']['end'] = self._io.pos()
            self._debug['attribute_length']['start'] = self._io.pos()
            self.attribute_length = self._io.read_u4be()
            self._debug['attribute_length']['end'] = self._io.pos()
            self._debug['info']['start'] = self._io.pos()
            _on = self.name_as_str
            if _on == u"SourceFile":
                self._raw_info = self._io.read_bytes(self.attribute_length)
                io = KaitaiStream(BytesIO(self._raw_info))
                self.info = self._root.AttributeInfo.AttrBodySourceFile(io, self, self._root)
                self.info._read()
            elif _on == u"LineNumberTable":
                self._raw_info = self._io.read_bytes(self.attribute_length)
                io = KaitaiStream(BytesIO(self._raw_info))
                self.info = self._root.AttributeInfo.AttrBodyLineNumberTable(io, self, self._root)
                self.info._read()
            elif _on == u"Exceptions":
                self._raw_info = self._io.read_bytes(self.attribute_length)
                io = KaitaiStream(BytesIO(self._raw_info))
                self.info = self._root.AttributeInfo.AttrBodyExceptions(io, self, self._root)
                self.info._read()
            elif _on == u"Code":
                self._raw_info = self._io.read_bytes(self.attribute_length)
                io = KaitaiStream(BytesIO(self._raw_info))
                self.info = self._root.AttributeInfo.AttrBodyCode(io, self, self._root)
                self.info._read()
            else:
                self.info = self._io.read_bytes(self.attribute_length)
            self._debug['info']['end'] = self._io.pos()

        class AttrBodyCode(KaitaiStruct):
            """
            .. seealso::
               Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.7.3
            """
            SEQ_FIELDS = ["max_stack", "max_locals", "code_length", "code", "exception_table_length", "exception_table", "attributes_count", "attributes"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['max_stack']['start'] = self._io.pos()
                self.max_stack = self._io.read_u2be()
                self._debug['max_stack']['end'] = self._io.pos()
                self._debug['max_locals']['start'] = self._io.pos()
                self.max_locals = self._io.read_u2be()
                self._debug['max_locals']['end'] = self._io.pos()
                self._debug['code_length']['start'] = self._io.pos()
                self.code_length = self._io.read_u4be()
                self._debug['code_length']['end'] = self._io.pos()
                self._debug['code']['start'] = self._io.pos()
                self.code = self._io.read_bytes(self.code_length)
                self._debug['code']['end'] = self._io.pos()
                self._debug['exception_table_length']['start'] = self._io.pos()
                self.exception_table_length = self._io.read_u2be()
                self._debug['exception_table_length']['end'] = self._io.pos()
                self._debug['exception_table']['start'] = self._io.pos()
                self.exception_table = [None] * (self.exception_table_length)
                for i in range(self.exception_table_length):
                    if not 'arr' in self._debug['exception_table']:
                        self._debug['exception_table']['arr'] = []
                    self._debug['exception_table']['arr'].append({'start': self._io.pos()})
                    _t_exception_table = self._root.AttributeInfo.AttrBodyCode.ExceptionEntry(self._io, self, self._root)
                    _t_exception_table._read()
                    self.exception_table[i] = _t_exception_table
                    self._debug['exception_table']['arr'][i]['end'] = self._io.pos()

                self._debug['exception_table']['end'] = self._io.pos()
                self._debug['attributes_count']['start'] = self._io.pos()
                self.attributes_count = self._io.read_u2be()
                self._debug['attributes_count']['end'] = self._io.pos()
                self._debug['attributes']['start'] = self._io.pos()
                self.attributes = [None] * (self.attributes_count)
                for i in range(self.attributes_count):
                    if not 'arr' in self._debug['attributes']:
                        self._debug['attributes']['arr'] = []
                    self._debug['attributes']['arr'].append({'start': self._io.pos()})
                    _t_attributes = self._root.AttributeInfo(self._io, self, self._root)
                    _t_attributes._read()
                    self.attributes[i] = _t_attributes
                    self._debug['attributes']['arr'][i]['end'] = self._io.pos()

                self._debug['attributes']['end'] = self._io.pos()

            class ExceptionEntry(KaitaiStruct):
                """
                .. seealso::
                   Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.7.3
                """
                SEQ_FIELDS = ["start_pc", "end_pc", "handler_pc", "catch_type"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['start_pc']['start'] = self._io.pos()
                    self.start_pc = self._io.read_u2be()
                    self._debug['start_pc']['end'] = self._io.pos()
                    self._debug['end_pc']['start'] = self._io.pos()
                    self.end_pc = self._io.read_u2be()
                    self._debug['end_pc']['end'] = self._io.pos()
                    self._debug['handler_pc']['start'] = self._io.pos()
                    self.handler_pc = self._io.read_u2be()
                    self._debug['handler_pc']['end'] = self._io.pos()
                    self._debug['catch_type']['start'] = self._io.pos()
                    self.catch_type = self._io.read_u2be()
                    self._debug['catch_type']['end'] = self._io.pos()

                @property
                def catch_exception(self):
                    if hasattr(self, '_m_catch_exception'):
                        return self._m_catch_exception if hasattr(self, '_m_catch_exception') else None

                    if self.catch_type != 0:
                        self._m_catch_exception = self._root.constant_pool[(self.catch_type - 1)]

                    return self._m_catch_exception if hasattr(self, '_m_catch_exception') else None



        class AttrBodyExceptions(KaitaiStruct):
            """
            .. seealso::
               Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.7.5
            """
            SEQ_FIELDS = ["number_of_exceptions", "exceptions"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['number_of_exceptions']['start'] = self._io.pos()
                self.number_of_exceptions = self._io.read_u2be()
                self._debug['number_of_exceptions']['end'] = self._io.pos()
                self._debug['exceptions']['start'] = self._io.pos()
                self.exceptions = [None] * (self.number_of_exceptions)
                for i in range(self.number_of_exceptions):
                    if not 'arr' in self._debug['exceptions']:
                        self._debug['exceptions']['arr'] = []
                    self._debug['exceptions']['arr'].append({'start': self._io.pos()})
                    _t_exceptions = self._root.AttributeInfo.AttrBodyExceptions.ExceptionTableEntry(self._io, self, self._root)
                    _t_exceptions._read()
                    self.exceptions[i] = _t_exceptions
                    self._debug['exceptions']['arr'][i]['end'] = self._io.pos()

                self._debug['exceptions']['end'] = self._io.pos()

            class ExceptionTableEntry(KaitaiStruct):
                SEQ_FIELDS = ["index"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['index']['start'] = self._io.pos()
                    self.index = self._io.read_u2be()
                    self._debug['index']['end'] = self._io.pos()

                @property
                def as_info(self):
                    if hasattr(self, '_m_as_info'):
                        return self._m_as_info if hasattr(self, '_m_as_info') else None

                    self._m_as_info = self._root.constant_pool[(self.index - 1)].cp_info
                    return self._m_as_info if hasattr(self, '_m_as_info') else None

                @property
                def name_as_str(self):
                    if hasattr(self, '_m_name_as_str'):
                        return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None

                    self._m_name_as_str = self.as_info.name_as_str
                    return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None



        class AttrBodySourceFile(KaitaiStruct):
            """
            .. seealso::
               Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.7.10
            """
            SEQ_FIELDS = ["sourcefile_index"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['sourcefile_index']['start'] = self._io.pos()
                self.sourcefile_index = self._io.read_u2be()
                self._debug['sourcefile_index']['end'] = self._io.pos()

            @property
            def sourcefile_as_str(self):
                if hasattr(self, '_m_sourcefile_as_str'):
                    return self._m_sourcefile_as_str if hasattr(self, '_m_sourcefile_as_str') else None

                self._m_sourcefile_as_str = self._root.constant_pool[(self.sourcefile_index - 1)].cp_info.value
                return self._m_sourcefile_as_str if hasattr(self, '_m_sourcefile_as_str') else None


        class AttrBodyLineNumberTable(KaitaiStruct):
            """
            .. seealso::
               Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.7.12
            """
            SEQ_FIELDS = ["line_number_table_length", "line_number_table"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['line_number_table_length']['start'] = self._io.pos()
                self.line_number_table_length = self._io.read_u2be()
                self._debug['line_number_table_length']['end'] = self._io.pos()
                self._debug['line_number_table']['start'] = self._io.pos()
                self.line_number_table = [None] * (self.line_number_table_length)
                for i in range(self.line_number_table_length):
                    if not 'arr' in self._debug['line_number_table']:
                        self._debug['line_number_table']['arr'] = []
                    self._debug['line_number_table']['arr'].append({'start': self._io.pos()})
                    _t_line_number_table = self._root.AttributeInfo.AttrBodyLineNumberTable.LineNumberTableEntry(self._io, self, self._root)
                    _t_line_number_table._read()
                    self.line_number_table[i] = _t_line_number_table
                    self._debug['line_number_table']['arr'][i]['end'] = self._io.pos()

                self._debug['line_number_table']['end'] = self._io.pos()

            class LineNumberTableEntry(KaitaiStruct):
                SEQ_FIELDS = ["start_pc", "line_number"]
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._debug = collections.defaultdict(dict)

                def _read(self):
                    self._debug['start_pc']['start'] = self._io.pos()
                    self.start_pc = self._io.read_u2be()
                    self._debug['start_pc']['end'] = self._io.pos()
                    self._debug['line_number']['start'] = self._io.pos()
                    self.line_number = self._io.read_u2be()
                    self._debug['line_number']['end'] = self._io.pos()



        @property
        def name_as_str(self):
            if hasattr(self, '_m_name_as_str'):
                return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None

            self._m_name_as_str = self._root.constant_pool[(self.name_index - 1)].cp_info.value
            return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None


    class MethodRefCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.2
        """
        SEQ_FIELDS = ["class_index", "name_and_type_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['class_index']['start'] = self._io.pos()
            self.class_index = self._io.read_u2be()
            self._debug['class_index']['end'] = self._io.pos()
            self._debug['name_and_type_index']['start'] = self._io.pos()
            self.name_and_type_index = self._io.read_u2be()
            self._debug['name_and_type_index']['end'] = self._io.pos()

        @property
        def class_as_info(self):
            if hasattr(self, '_m_class_as_info'):
                return self._m_class_as_info if hasattr(self, '_m_class_as_info') else None

            self._m_class_as_info = self._root.constant_pool[(self.class_index - 1)].cp_info
            return self._m_class_as_info if hasattr(self, '_m_class_as_info') else None

        @property
        def name_and_type_as_info(self):
            if hasattr(self, '_m_name_and_type_as_info'):
                return self._m_name_and_type_as_info if hasattr(self, '_m_name_and_type_as_info') else None

            self._m_name_and_type_as_info = self._root.constant_pool[(self.name_and_type_index - 1)].cp_info
            return self._m_name_and_type_as_info if hasattr(self, '_m_name_and_type_as_info') else None


    class FieldInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.5
        """
        SEQ_FIELDS = ["access_flags", "name_index", "descriptor_index", "attributes_count", "attributes"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['access_flags']['start'] = self._io.pos()
            self.access_flags = self._io.read_u2be()
            self._debug['access_flags']['end'] = self._io.pos()
            self._debug['name_index']['start'] = self._io.pos()
            self.name_index = self._io.read_u2be()
            self._debug['name_index']['end'] = self._io.pos()
            self._debug['descriptor_index']['start'] = self._io.pos()
            self.descriptor_index = self._io.read_u2be()
            self._debug['descriptor_index']['end'] = self._io.pos()
            self._debug['attributes_count']['start'] = self._io.pos()
            self.attributes_count = self._io.read_u2be()
            self._debug['attributes_count']['end'] = self._io.pos()
            self._debug['attributes']['start'] = self._io.pos()
            self.attributes = [None] * (self.attributes_count)
            for i in range(self.attributes_count):
                if not 'arr' in self._debug['attributes']:
                    self._debug['attributes']['arr'] = []
                self._debug['attributes']['arr'].append({'start': self._io.pos()})
                _t_attributes = self._root.AttributeInfo(self._io, self, self._root)
                _t_attributes._read()
                self.attributes[i] = _t_attributes
                self._debug['attributes']['arr'][i]['end'] = self._io.pos()

            self._debug['attributes']['end'] = self._io.pos()

        @property
        def name_as_str(self):
            if hasattr(self, '_m_name_as_str'):
                return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None

            self._m_name_as_str = self._root.constant_pool[(self.name_index - 1)].cp_info.value
            return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None


    class DoubleCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.6
        """
        SEQ_FIELDS = ["value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['value']['start'] = self._io.pos()
            self.value = self._io.read_f8be()
            self._debug['value']['end'] = self._io.pos()


    class LongCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.5
        """
        SEQ_FIELDS = ["value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['value']['start'] = self._io.pos()
            self.value = self._io.read_u8be()
            self._debug['value']['end'] = self._io.pos()


    class InvokeDynamicCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.10
        """
        SEQ_FIELDS = ["bootstrap_method_attr_index", "name_and_type_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['bootstrap_method_attr_index']['start'] = self._io.pos()
            self.bootstrap_method_attr_index = self._io.read_u2be()
            self._debug['bootstrap_method_attr_index']['end'] = self._io.pos()
            self._debug['name_and_type_index']['start'] = self._io.pos()
            self.name_and_type_index = self._io.read_u2be()
            self._debug['name_and_type_index']['end'] = self._io.pos()


    class MethodHandleCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.8
        """

        class ReferenceKindEnum(Enum):
            get_field = 1
            get_static = 2
            put_field = 3
            put_static = 4
            invoke_virtual = 5
            invoke_static = 6
            invoke_special = 7
            new_invoke_special = 8
            invoke_interface = 9
        SEQ_FIELDS = ["reference_kind", "reference_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['reference_kind']['start'] = self._io.pos()
            self.reference_kind = KaitaiStream.resolve_enum(self._root.MethodHandleCpInfo.ReferenceKindEnum, self._io.read_u1())
            self._debug['reference_kind']['end'] = self._io.pos()
            self._debug['reference_index']['start'] = self._io.pos()
            self.reference_index = self._io.read_u2be()
            self._debug['reference_index']['end'] = self._io.pos()


    class NameAndTypeCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.6
        """
        SEQ_FIELDS = ["name_index", "descriptor_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name_index']['start'] = self._io.pos()
            self.name_index = self._io.read_u2be()
            self._debug['name_index']['end'] = self._io.pos()
            self._debug['descriptor_index']['start'] = self._io.pos()
            self.descriptor_index = self._io.read_u2be()
            self._debug['descriptor_index']['end'] = self._io.pos()

        @property
        def name_as_info(self):
            if hasattr(self, '_m_name_as_info'):
                return self._m_name_as_info if hasattr(self, '_m_name_as_info') else None

            self._m_name_as_info = self._root.constant_pool[(self.name_index - 1)].cp_info
            return self._m_name_as_info if hasattr(self, '_m_name_as_info') else None

        @property
        def name_as_str(self):
            if hasattr(self, '_m_name_as_str'):
                return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None

            self._m_name_as_str = self.name_as_info.value
            return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None

        @property
        def descriptor_as_info(self):
            if hasattr(self, '_m_descriptor_as_info'):
                return self._m_descriptor_as_info if hasattr(self, '_m_descriptor_as_info') else None

            self._m_descriptor_as_info = self._root.constant_pool[(self.descriptor_index - 1)].cp_info
            return self._m_descriptor_as_info if hasattr(self, '_m_descriptor_as_info') else None

        @property
        def descriptor_as_str(self):
            if hasattr(self, '_m_descriptor_as_str'):
                return self._m_descriptor_as_str if hasattr(self, '_m_descriptor_as_str') else None

            self._m_descriptor_as_str = self.descriptor_as_info.value
            return self._m_descriptor_as_str if hasattr(self, '_m_descriptor_as_str') else None


    class Utf8CpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.7
        """
        SEQ_FIELDS = ["str_len", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['str_len']['start'] = self._io.pos()
            self.str_len = self._io.read_u2be()
            self._debug['str_len']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = (self._io.read_bytes(self.str_len)).decode(u"UTF-8")
            self._debug['value']['end'] = self._io.pos()


    class StringCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.3
        """
        SEQ_FIELDS = ["string_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['string_index']['start'] = self._io.pos()
            self.string_index = self._io.read_u2be()
            self._debug['string_index']['end'] = self._io.pos()


    class MethodTypeCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.9
        """
        SEQ_FIELDS = ["descriptor_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['descriptor_index']['start'] = self._io.pos()
            self.descriptor_index = self._io.read_u2be()
            self._debug['descriptor_index']['end'] = self._io.pos()


    class InterfaceMethodRefCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.2
        """
        SEQ_FIELDS = ["class_index", "name_and_type_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['class_index']['start'] = self._io.pos()
            self.class_index = self._io.read_u2be()
            self._debug['class_index']['end'] = self._io.pos()
            self._debug['name_and_type_index']['start'] = self._io.pos()
            self.name_and_type_index = self._io.read_u2be()
            self._debug['name_and_type_index']['end'] = self._io.pos()

        @property
        def class_as_info(self):
            if hasattr(self, '_m_class_as_info'):
                return self._m_class_as_info if hasattr(self, '_m_class_as_info') else None

            self._m_class_as_info = self._root.constant_pool[(self.class_index - 1)].cp_info
            return self._m_class_as_info if hasattr(self, '_m_class_as_info') else None

        @property
        def name_and_type_as_info(self):
            if hasattr(self, '_m_name_and_type_as_info'):
                return self._m_name_and_type_as_info if hasattr(self, '_m_name_and_type_as_info') else None

            self._m_name_and_type_as_info = self._root.constant_pool[(self.name_and_type_index - 1)].cp_info
            return self._m_name_and_type_as_info if hasattr(self, '_m_name_and_type_as_info') else None


    class ClassCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.1
        """
        SEQ_FIELDS = ["name_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name_index']['start'] = self._io.pos()
            self.name_index = self._io.read_u2be()
            self._debug['name_index']['end'] = self._io.pos()

        @property
        def name_as_info(self):
            if hasattr(self, '_m_name_as_info'):
                return self._m_name_as_info if hasattr(self, '_m_name_as_info') else None

            self._m_name_as_info = self._root.constant_pool[(self.name_index - 1)].cp_info
            return self._m_name_as_info if hasattr(self, '_m_name_as_info') else None

        @property
        def name_as_str(self):
            if hasattr(self, '_m_name_as_str'):
                return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None

            self._m_name_as_str = self.name_as_info.value
            return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None


    class ConstantPoolEntry(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4
        """

        class TagEnum(Enum):
            utf8 = 1
            integer = 3
            float = 4
            long = 5
            double = 6
            class_type = 7
            string = 8
            field_ref = 9
            method_ref = 10
            interface_method_ref = 11
            name_and_type = 12
            method_handle = 15
            method_type = 16
            invoke_dynamic = 18
        SEQ_FIELDS = ["tag", "cp_info"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['tag']['start'] = self._io.pos()
            self.tag = KaitaiStream.resolve_enum(self._root.ConstantPoolEntry.TagEnum, self._io.read_u1())
            self._debug['tag']['end'] = self._io.pos()
            self._debug['cp_info']['start'] = self._io.pos()
            _on = self.tag
            if _on == self._root.ConstantPoolEntry.TagEnum.interface_method_ref:
                self.cp_info = self._root.InterfaceMethodRefCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.class_type:
                self.cp_info = self._root.ClassCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.utf8:
                self.cp_info = self._root.Utf8CpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.method_type:
                self.cp_info = self._root.MethodTypeCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.integer:
                self.cp_info = self._root.IntegerCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.string:
                self.cp_info = self._root.StringCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.float:
                self.cp_info = self._root.FloatCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.long:
                self.cp_info = self._root.LongCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.method_ref:
                self.cp_info = self._root.MethodRefCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.double:
                self.cp_info = self._root.DoubleCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.invoke_dynamic:
                self.cp_info = self._root.InvokeDynamicCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.field_ref:
                self.cp_info = self._root.FieldRefCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.method_handle:
                self.cp_info = self._root.MethodHandleCpInfo(self._io, self, self._root)
                self.cp_info._read()
            elif _on == self._root.ConstantPoolEntry.TagEnum.name_and_type:
                self.cp_info = self._root.NameAndTypeCpInfo(self._io, self, self._root)
                self.cp_info._read()
            self._debug['cp_info']['end'] = self._io.pos()


    class MethodInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.6
        """
        SEQ_FIELDS = ["access_flags", "name_index", "descriptor_index", "attributes_count", "attributes"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['access_flags']['start'] = self._io.pos()
            self.access_flags = self._io.read_u2be()
            self._debug['access_flags']['end'] = self._io.pos()
            self._debug['name_index']['start'] = self._io.pos()
            self.name_index = self._io.read_u2be()
            self._debug['name_index']['end'] = self._io.pos()
            self._debug['descriptor_index']['start'] = self._io.pos()
            self.descriptor_index = self._io.read_u2be()
            self._debug['descriptor_index']['end'] = self._io.pos()
            self._debug['attributes_count']['start'] = self._io.pos()
            self.attributes_count = self._io.read_u2be()
            self._debug['attributes_count']['end'] = self._io.pos()
            self._debug['attributes']['start'] = self._io.pos()
            self.attributes = [None] * (self.attributes_count)
            for i in range(self.attributes_count):
                if not 'arr' in self._debug['attributes']:
                    self._debug['attributes']['arr'] = []
                self._debug['attributes']['arr'].append({'start': self._io.pos()})
                _t_attributes = self._root.AttributeInfo(self._io, self, self._root)
                _t_attributes._read()
                self.attributes[i] = _t_attributes
                self._debug['attributes']['arr'][i]['end'] = self._io.pos()

            self._debug['attributes']['end'] = self._io.pos()

        @property
        def name_as_str(self):
            if hasattr(self, '_m_name_as_str'):
                return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None

            self._m_name_as_str = self._root.constant_pool[(self.name_index - 1)].cp_info.value
            return self._m_name_as_str if hasattr(self, '_m_name_as_str') else None


    class IntegerCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.4
        """
        SEQ_FIELDS = ["value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['value']['start'] = self._io.pos()
            self.value = self._io.read_u4be()
            self._debug['value']['end'] = self._io.pos()


    class FieldRefCpInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.2
        """
        SEQ_FIELDS = ["class_index", "name_and_type_index"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['class_index']['start'] = self._io.pos()
            self.class_index = self._io.read_u2be()
            self._debug['class_index']['end'] = self._io.pos()
            self._debug['name_and_type_index']['start'] = self._io.pos()
            self.name_and_type_index = self._io.read_u2be()
            self._debug['name_and_type_index']['end'] = self._io.pos()

        @property
        def class_as_info(self):
            if hasattr(self, '_m_class_as_info'):
                return self._m_class_as_info if hasattr(self, '_m_class_as_info') else None

            self._m_class_as_info = self._root.constant_pool[(self.class_index - 1)].cp_info
            return self._m_class_as_info if hasattr(self, '_m_class_as_info') else None

        @property
        def name_and_type_as_info(self):
            if hasattr(self, '_m_name_and_type_as_info'):
                return self._m_name_and_type_as_info if hasattr(self, '_m_name_and_type_as_info') else None

            self._m_name_and_type_as_info = self._root.constant_pool[(self.name_and_type_index - 1)].cp_info
            return self._m_name_and_type_as_info if hasattr(self, '_m_name_and_type_as_info') else None



