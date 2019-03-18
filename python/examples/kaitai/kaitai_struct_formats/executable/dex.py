from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

from vlq_base128_le import VlqBase128Le
class Dex(KaitaiStruct):
    """Android OS applications executables are typically stored in its own
    format, optimized for more efficient execution in Dalvik virtual
    machine.
    
    This format is loosely similar to Java .class file format and
    generally holds the similar set of data: i.e. classes, methods,
    fields, annotations, etc.
    
    .. seealso::
       Source - https://source.android.com/devices/tech/dalvik/dex-format
    """

    class ClassAccessFlags(Enum):
        public = 1
        private = 2
        protected = 4
        static = 8
        final = 16
        interface = 512
        abstract = 1024
        synthetic = 4096
        annotation = 8192
        enum = 16384
    SEQ_FIELDS = ["header"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.HeaderItem(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()

    class HeaderItem(KaitaiStruct):

        class EndianConstant(Enum):
            endian_constant = 305419896
            reverse_endian_constant = 2018915346
        SEQ_FIELDS = ["magic", "version_str", "checksum", "signature", "file_size", "header_size", "endian_tag", "link_size", "link_off", "map_off", "string_ids_size", "string_ids_off", "type_ids_size", "type_ids_off", "proto_ids_size", "proto_ids_off", "field_ids_size", "field_ids_off", "method_ids_size", "method_ids_off", "class_defs_size", "class_defs_off", "data_size", "data_off"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x64\x65\x78\x0A")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['version_str']['start'] = self._io.pos()
            self.version_str = (KaitaiStream.bytes_terminate(self._io.read_bytes(4), 0, False)).decode(u"ascii")
            self._debug['version_str']['end'] = self._io.pos()
            self._debug['checksum']['start'] = self._io.pos()
            self.checksum = self._io.read_u4le()
            self._debug['checksum']['end'] = self._io.pos()
            self._debug['signature']['start'] = self._io.pos()
            self.signature = self._io.read_bytes(20)
            self._debug['signature']['end'] = self._io.pos()
            self._debug['file_size']['start'] = self._io.pos()
            self.file_size = self._io.read_u4le()
            self._debug['file_size']['end'] = self._io.pos()
            self._debug['header_size']['start'] = self._io.pos()
            self.header_size = self._io.read_u4le()
            self._debug['header_size']['end'] = self._io.pos()
            self._debug['endian_tag']['start'] = self._io.pos()
            self.endian_tag = KaitaiStream.resolve_enum(self._root.HeaderItem.EndianConstant, self._io.read_u4le())
            self._debug['endian_tag']['end'] = self._io.pos()
            self._debug['link_size']['start'] = self._io.pos()
            self.link_size = self._io.read_u4le()
            self._debug['link_size']['end'] = self._io.pos()
            self._debug['link_off']['start'] = self._io.pos()
            self.link_off = self._io.read_u4le()
            self._debug['link_off']['end'] = self._io.pos()
            self._debug['map_off']['start'] = self._io.pos()
            self.map_off = self._io.read_u4le()
            self._debug['map_off']['end'] = self._io.pos()
            self._debug['string_ids_size']['start'] = self._io.pos()
            self.string_ids_size = self._io.read_u4le()
            self._debug['string_ids_size']['end'] = self._io.pos()
            self._debug['string_ids_off']['start'] = self._io.pos()
            self.string_ids_off = self._io.read_u4le()
            self._debug['string_ids_off']['end'] = self._io.pos()
            self._debug['type_ids_size']['start'] = self._io.pos()
            self.type_ids_size = self._io.read_u4le()
            self._debug['type_ids_size']['end'] = self._io.pos()
            self._debug['type_ids_off']['start'] = self._io.pos()
            self.type_ids_off = self._io.read_u4le()
            self._debug['type_ids_off']['end'] = self._io.pos()
            self._debug['proto_ids_size']['start'] = self._io.pos()
            self.proto_ids_size = self._io.read_u4le()
            self._debug['proto_ids_size']['end'] = self._io.pos()
            self._debug['proto_ids_off']['start'] = self._io.pos()
            self.proto_ids_off = self._io.read_u4le()
            self._debug['proto_ids_off']['end'] = self._io.pos()
            self._debug['field_ids_size']['start'] = self._io.pos()
            self.field_ids_size = self._io.read_u4le()
            self._debug['field_ids_size']['end'] = self._io.pos()
            self._debug['field_ids_off']['start'] = self._io.pos()
            self.field_ids_off = self._io.read_u4le()
            self._debug['field_ids_off']['end'] = self._io.pos()
            self._debug['method_ids_size']['start'] = self._io.pos()
            self.method_ids_size = self._io.read_u4le()
            self._debug['method_ids_size']['end'] = self._io.pos()
            self._debug['method_ids_off']['start'] = self._io.pos()
            self.method_ids_off = self._io.read_u4le()
            self._debug['method_ids_off']['end'] = self._io.pos()
            self._debug['class_defs_size']['start'] = self._io.pos()
            self.class_defs_size = self._io.read_u4le()
            self._debug['class_defs_size']['end'] = self._io.pos()
            self._debug['class_defs_off']['start'] = self._io.pos()
            self.class_defs_off = self._io.read_u4le()
            self._debug['class_defs_off']['end'] = self._io.pos()
            self._debug['data_size']['start'] = self._io.pos()
            self.data_size = self._io.read_u4le()
            self._debug['data_size']['end'] = self._io.pos()
            self._debug['data_off']['start'] = self._io.pos()
            self.data_off = self._io.read_u4le()
            self._debug['data_off']['end'] = self._io.pos()


    class MapList(KaitaiStruct):
        SEQ_FIELDS = ["size", "list"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['list']['start'] = self._io.pos()
            self.list = [None] * (self.size)
            for i in range(self.size):
                if not 'arr' in self._debug['list']:
                    self._debug['list']['arr'] = []
                self._debug['list']['arr'].append({'start': self._io.pos()})
                _t_list = self._root.MapItem(self._io, self, self._root)
                _t_list._read()
                self.list[i] = _t_list
                self._debug['list']['arr'][i]['end'] = self._io.pos()

            self._debug['list']['end'] = self._io.pos()


    class EncodedValue(KaitaiStruct):

        class ValueTypeEnum(Enum):
            byte = 0
            short = 2
            char = 3
            int = 4
            long = 6
            float = 16
            double = 17
            method_type = 21
            method_handle = 22
            string = 23
            type = 24
            field = 25
            method = 26
            enum = 27
            array = 28
            annotation = 29
            null = 30
            boolean = 31
        SEQ_FIELDS = ["value_arg", "value_type", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['value_arg']['start'] = self._io.pos()
            self.value_arg = self._io.read_bits_int(3)
            self._debug['value_arg']['end'] = self._io.pos()
            self._debug['value_type']['start'] = self._io.pos()
            self.value_type = KaitaiStream.resolve_enum(self._root.EncodedValue.ValueTypeEnum, self._io.read_bits_int(5))
            self._debug['value_type']['end'] = self._io.pos()
            self._io.align_to_byte()
            self._debug['value']['start'] = self._io.pos()
            _on = self.value_type
            if _on == self._root.EncodedValue.ValueTypeEnum.int:
                self.value = self._io.read_s4le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.annotation:
                self.value = self._root.EncodedAnnotation(self._io, self, self._root)
                self.value._read()
            elif _on == self._root.EncodedValue.ValueTypeEnum.long:
                self.value = self._io.read_s8le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.method_handle:
                self.value = self._io.read_u4le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.byte:
                self.value = self._io.read_s1()
            elif _on == self._root.EncodedValue.ValueTypeEnum.array:
                self.value = self._root.EncodedArray(self._io, self, self._root)
                self.value._read()
            elif _on == self._root.EncodedValue.ValueTypeEnum.method_type:
                self.value = self._io.read_u4le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.short:
                self.value = self._io.read_s2le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.method:
                self.value = self._io.read_u4le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.double:
                self.value = self._io.read_f8le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.float:
                self.value = self._io.read_f4le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.type:
                self.value = self._io.read_u4le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.enum:
                self.value = self._io.read_u4le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.field:
                self.value = self._io.read_u4le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.string:
                self.value = self._io.read_u4le()
            elif _on == self._root.EncodedValue.ValueTypeEnum.char:
                self.value = self._io.read_u2le()
            self._debug['value']['end'] = self._io.pos()


    class CallSiteIdItem(KaitaiStruct):
        SEQ_FIELDS = ["call_site_off"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['call_site_off']['start'] = self._io.pos()
            self.call_site_off = self._io.read_u4le()
            self._debug['call_site_off']['end'] = self._io.pos()


    class MethodIdItem(KaitaiStruct):
        SEQ_FIELDS = ["class_idx", "proto_idx", "name_idx"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['class_idx']['start'] = self._io.pos()
            self.class_idx = self._io.read_u2le()
            self._debug['class_idx']['end'] = self._io.pos()
            self._debug['proto_idx']['start'] = self._io.pos()
            self.proto_idx = self._io.read_u2le()
            self._debug['proto_idx']['end'] = self._io.pos()
            self._debug['name_idx']['start'] = self._io.pos()
            self.name_idx = self._io.read_u4le()
            self._debug['name_idx']['end'] = self._io.pos()

        @property
        def class_name(self):
            """the definer of this method."""
            if hasattr(self, '_m_class_name'):
                return self._m_class_name if hasattr(self, '_m_class_name') else None

            self._m_class_name = self._root.type_ids[self.class_idx].type_name
            return self._m_class_name if hasattr(self, '_m_class_name') else None

        @property
        def proto_desc(self):
            """the short-form descriptor of the prototype of this method."""
            if hasattr(self, '_m_proto_desc'):
                return self._m_proto_desc if hasattr(self, '_m_proto_desc') else None

            self._m_proto_desc = self._root.proto_ids[self.proto_idx].shorty_desc
            return self._m_proto_desc if hasattr(self, '_m_proto_desc') else None

        @property
        def method_name(self):
            """the name of this method."""
            if hasattr(self, '_m_method_name'):
                return self._m_method_name if hasattr(self, '_m_method_name') else None

            self._m_method_name = self._root.string_ids[self.name_idx].value.data
            return self._m_method_name if hasattr(self, '_m_method_name') else None


    class TypeItem(KaitaiStruct):
        SEQ_FIELDS = ["type_idx"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type_idx']['start'] = self._io.pos()
            self.type_idx = self._io.read_u2le()
            self._debug['type_idx']['end'] = self._io.pos()

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            self._m_value = self._root.type_ids[self.type_idx].type_name
            return self._m_value if hasattr(self, '_m_value') else None


    class TypeIdItem(KaitaiStruct):
        SEQ_FIELDS = ["descriptor_idx"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['descriptor_idx']['start'] = self._io.pos()
            self.descriptor_idx = self._io.read_u4le()
            self._debug['descriptor_idx']['end'] = self._io.pos()

        @property
        def type_name(self):
            if hasattr(self, '_m_type_name'):
                return self._m_type_name if hasattr(self, '_m_type_name') else None

            self._m_type_name = self._root.string_ids[self.descriptor_idx].value.data
            return self._m_type_name if hasattr(self, '_m_type_name') else None


    class AnnotationElement(KaitaiStruct):
        SEQ_FIELDS = ["name_idx", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name_idx']['start'] = self._io.pos()
            self.name_idx = VlqBase128Le(self._io)
            self.name_idx._read()
            self._debug['name_idx']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = self._root.EncodedValue(self._io, self, self._root)
            self.value._read()
            self._debug['value']['end'] = self._io.pos()


    class EncodedField(KaitaiStruct):
        SEQ_FIELDS = ["field_idx_diff", "access_flags"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['field_idx_diff']['start'] = self._io.pos()
            self.field_idx_diff = VlqBase128Le(self._io)
            self.field_idx_diff._read()
            self._debug['field_idx_diff']['end'] = self._io.pos()
            self._debug['access_flags']['start'] = self._io.pos()
            self.access_flags = VlqBase128Le(self._io)
            self.access_flags._read()
            self._debug['access_flags']['end'] = self._io.pos()


    class EncodedArrayItem(KaitaiStruct):
        SEQ_FIELDS = ["value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['value']['start'] = self._io.pos()
            self.value = self._root.EncodedArray(self._io, self, self._root)
            self.value._read()
            self._debug['value']['end'] = self._io.pos()


    class ClassDataItem(KaitaiStruct):
        SEQ_FIELDS = ["static_fields_size", "instance_fields_size", "direct_methods_size", "virtual_methods_size", "static_fields", "instance_fields", "direct_methods", "virtual_methods"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['static_fields_size']['start'] = self._io.pos()
            self.static_fields_size = VlqBase128Le(self._io)
            self.static_fields_size._read()
            self._debug['static_fields_size']['end'] = self._io.pos()
            self._debug['instance_fields_size']['start'] = self._io.pos()
            self.instance_fields_size = VlqBase128Le(self._io)
            self.instance_fields_size._read()
            self._debug['instance_fields_size']['end'] = self._io.pos()
            self._debug['direct_methods_size']['start'] = self._io.pos()
            self.direct_methods_size = VlqBase128Le(self._io)
            self.direct_methods_size._read()
            self._debug['direct_methods_size']['end'] = self._io.pos()
            self._debug['virtual_methods_size']['start'] = self._io.pos()
            self.virtual_methods_size = VlqBase128Le(self._io)
            self.virtual_methods_size._read()
            self._debug['virtual_methods_size']['end'] = self._io.pos()
            self._debug['static_fields']['start'] = self._io.pos()
            self.static_fields = [None] * (self.static_fields_size.value)
            for i in range(self.static_fields_size.value):
                if not 'arr' in self._debug['static_fields']:
                    self._debug['static_fields']['arr'] = []
                self._debug['static_fields']['arr'].append({'start': self._io.pos()})
                _t_static_fields = self._root.EncodedField(self._io, self, self._root)
                _t_static_fields._read()
                self.static_fields[i] = _t_static_fields
                self._debug['static_fields']['arr'][i]['end'] = self._io.pos()

            self._debug['static_fields']['end'] = self._io.pos()
            self._debug['instance_fields']['start'] = self._io.pos()
            self.instance_fields = [None] * (self.instance_fields_size.value)
            for i in range(self.instance_fields_size.value):
                if not 'arr' in self._debug['instance_fields']:
                    self._debug['instance_fields']['arr'] = []
                self._debug['instance_fields']['arr'].append({'start': self._io.pos()})
                _t_instance_fields = self._root.EncodedField(self._io, self, self._root)
                _t_instance_fields._read()
                self.instance_fields[i] = _t_instance_fields
                self._debug['instance_fields']['arr'][i]['end'] = self._io.pos()

            self._debug['instance_fields']['end'] = self._io.pos()
            self._debug['direct_methods']['start'] = self._io.pos()
            self.direct_methods = [None] * (self.direct_methods_size.value)
            for i in range(self.direct_methods_size.value):
                if not 'arr' in self._debug['direct_methods']:
                    self._debug['direct_methods']['arr'] = []
                self._debug['direct_methods']['arr'].append({'start': self._io.pos()})
                _t_direct_methods = self._root.EncodedMethod(self._io, self, self._root)
                _t_direct_methods._read()
                self.direct_methods[i] = _t_direct_methods
                self._debug['direct_methods']['arr'][i]['end'] = self._io.pos()

            self._debug['direct_methods']['end'] = self._io.pos()
            self._debug['virtual_methods']['start'] = self._io.pos()
            self.virtual_methods = [None] * (self.virtual_methods_size.value)
            for i in range(self.virtual_methods_size.value):
                if not 'arr' in self._debug['virtual_methods']:
                    self._debug['virtual_methods']['arr'] = []
                self._debug['virtual_methods']['arr'].append({'start': self._io.pos()})
                _t_virtual_methods = self._root.EncodedMethod(self._io, self, self._root)
                _t_virtual_methods._read()
                self.virtual_methods[i] = _t_virtual_methods
                self._debug['virtual_methods']['arr'][i]['end'] = self._io.pos()

            self._debug['virtual_methods']['end'] = self._io.pos()


    class FieldIdItem(KaitaiStruct):
        SEQ_FIELDS = ["class_idx", "type_idx", "name_idx"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['class_idx']['start'] = self._io.pos()
            self.class_idx = self._io.read_u2le()
            self._debug['class_idx']['end'] = self._io.pos()
            self._debug['type_idx']['start'] = self._io.pos()
            self.type_idx = self._io.read_u2le()
            self._debug['type_idx']['end'] = self._io.pos()
            self._debug['name_idx']['start'] = self._io.pos()
            self.name_idx = self._io.read_u4le()
            self._debug['name_idx']['end'] = self._io.pos()

        @property
        def class_name(self):
            """the definer of this field."""
            if hasattr(self, '_m_class_name'):
                return self._m_class_name if hasattr(self, '_m_class_name') else None

            self._m_class_name = self._root.type_ids[self.class_idx].type_name
            return self._m_class_name if hasattr(self, '_m_class_name') else None

        @property
        def type_name(self):
            """the type of this field."""
            if hasattr(self, '_m_type_name'):
                return self._m_type_name if hasattr(self, '_m_type_name') else None

            self._m_type_name = self._root.type_ids[self.type_idx].type_name
            return self._m_type_name if hasattr(self, '_m_type_name') else None

        @property
        def field_name(self):
            """the name of this field."""
            if hasattr(self, '_m_field_name'):
                return self._m_field_name if hasattr(self, '_m_field_name') else None

            self._m_field_name = self._root.string_ids[self.name_idx].value.data
            return self._m_field_name if hasattr(self, '_m_field_name') else None


    class EncodedAnnotation(KaitaiStruct):
        SEQ_FIELDS = ["type_idx", "size", "elements"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type_idx']['start'] = self._io.pos()
            self.type_idx = VlqBase128Le(self._io)
            self.type_idx._read()
            self._debug['type_idx']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = VlqBase128Le(self._io)
            self.size._read()
            self._debug['size']['end'] = self._io.pos()
            self._debug['elements']['start'] = self._io.pos()
            self.elements = [None] * (self.size.value)
            for i in range(self.size.value):
                if not 'arr' in self._debug['elements']:
                    self._debug['elements']['arr'] = []
                self._debug['elements']['arr'].append({'start': self._io.pos()})
                _t_elements = self._root.AnnotationElement(self._io, self, self._root)
                _t_elements._read()
                self.elements[i] = _t_elements
                self._debug['elements']['arr'][i]['end'] = self._io.pos()

            self._debug['elements']['end'] = self._io.pos()


    class ClassDefItem(KaitaiStruct):
        SEQ_FIELDS = ["class_idx", "access_flags", "superclass_idx", "interfaces_off", "source_file_idx", "annotations_off", "class_data_off", "static_values_off"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['class_idx']['start'] = self._io.pos()
            self.class_idx = self._io.read_u4le()
            self._debug['class_idx']['end'] = self._io.pos()
            self._debug['access_flags']['start'] = self._io.pos()
            self.access_flags = KaitaiStream.resolve_enum(self._root.ClassAccessFlags, self._io.read_u4le())
            self._debug['access_flags']['end'] = self._io.pos()
            self._debug['superclass_idx']['start'] = self._io.pos()
            self.superclass_idx = self._io.read_u4le()
            self._debug['superclass_idx']['end'] = self._io.pos()
            self._debug['interfaces_off']['start'] = self._io.pos()
            self.interfaces_off = self._io.read_u4le()
            self._debug['interfaces_off']['end'] = self._io.pos()
            self._debug['source_file_idx']['start'] = self._io.pos()
            self.source_file_idx = self._io.read_u4le()
            self._debug['source_file_idx']['end'] = self._io.pos()
            self._debug['annotations_off']['start'] = self._io.pos()
            self.annotations_off = self._io.read_u4le()
            self._debug['annotations_off']['end'] = self._io.pos()
            self._debug['class_data_off']['start'] = self._io.pos()
            self.class_data_off = self._io.read_u4le()
            self._debug['class_data_off']['end'] = self._io.pos()
            self._debug['static_values_off']['start'] = self._io.pos()
            self.static_values_off = self._io.read_u4le()
            self._debug['static_values_off']['end'] = self._io.pos()

        @property
        def type_name(self):
            if hasattr(self, '_m_type_name'):
                return self._m_type_name if hasattr(self, '_m_type_name') else None

            self._m_type_name = self._root.type_ids[self.class_idx].type_name
            return self._m_type_name if hasattr(self, '_m_type_name') else None

        @property
        def class_data(self):
            if hasattr(self, '_m_class_data'):
                return self._m_class_data if hasattr(self, '_m_class_data') else None

            if self.class_data_off != 0:
                _pos = self._io.pos()
                self._io.seek(self.class_data_off)
                self._debug['_m_class_data']['start'] = self._io.pos()
                self._m_class_data = self._root.ClassDataItem(self._io, self, self._root)
                self._m_class_data._read()
                self._debug['_m_class_data']['end'] = self._io.pos()
                self._io.seek(_pos)

            return self._m_class_data if hasattr(self, '_m_class_data') else None

        @property
        def static_values(self):
            if hasattr(self, '_m_static_values'):
                return self._m_static_values if hasattr(self, '_m_static_values') else None

            if self.static_values_off != 0:
                _pos = self._io.pos()
                self._io.seek(self.static_values_off)
                self._debug['_m_static_values']['start'] = self._io.pos()
                self._m_static_values = self._root.EncodedArrayItem(self._io, self, self._root)
                self._m_static_values._read()
                self._debug['_m_static_values']['end'] = self._io.pos()
                self._io.seek(_pos)

            return self._m_static_values if hasattr(self, '_m_static_values') else None


    class TypeList(KaitaiStruct):
        SEQ_FIELDS = ["size", "list"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['list']['start'] = self._io.pos()
            self.list = [None] * (self.size)
            for i in range(self.size):
                if not 'arr' in self._debug['list']:
                    self._debug['list']['arr'] = []
                self._debug['list']['arr'].append({'start': self._io.pos()})
                _t_list = self._root.TypeItem(self._io, self, self._root)
                _t_list._read()
                self.list[i] = _t_list
                self._debug['list']['arr'][i]['end'] = self._io.pos()

            self._debug['list']['end'] = self._io.pos()


    class StringIdItem(KaitaiStruct):
        SEQ_FIELDS = ["string_data_off"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['string_data_off']['start'] = self._io.pos()
            self.string_data_off = self._io.read_u4le()
            self._debug['string_data_off']['end'] = self._io.pos()

        class StringDataItem(KaitaiStruct):
            SEQ_FIELDS = ["utf16_size", "data"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['utf16_size']['start'] = self._io.pos()
                self.utf16_size = VlqBase128Le(self._io)
                self.utf16_size._read()
                self._debug['utf16_size']['end'] = self._io.pos()
                self._debug['data']['start'] = self._io.pos()
                self.data = (self._io.read_bytes(self.utf16_size.value)).decode(u"ascii")
                self._debug['data']['end'] = self._io.pos()


        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            _pos = self._io.pos()
            self._io.seek(self.string_data_off)
            self._debug['_m_value']['start'] = self._io.pos()
            self._m_value = self._root.StringIdItem.StringDataItem(self._io, self, self._root)
            self._m_value._read()
            self._debug['_m_value']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_value if hasattr(self, '_m_value') else None


    class ProtoIdItem(KaitaiStruct):
        SEQ_FIELDS = ["shorty_idx", "return_type_idx", "parameters_off"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['shorty_idx']['start'] = self._io.pos()
            self.shorty_idx = self._io.read_u4le()
            self._debug['shorty_idx']['end'] = self._io.pos()
            self._debug['return_type_idx']['start'] = self._io.pos()
            self.return_type_idx = self._io.read_u4le()
            self._debug['return_type_idx']['end'] = self._io.pos()
            self._debug['parameters_off']['start'] = self._io.pos()
            self.parameters_off = self._io.read_u4le()
            self._debug['parameters_off']['end'] = self._io.pos()

        @property
        def shorty_desc(self):
            """short-form descriptor string of this prototype, as pointed to by shorty_idx."""
            if hasattr(self, '_m_shorty_desc'):
                return self._m_shorty_desc if hasattr(self, '_m_shorty_desc') else None

            self._m_shorty_desc = self._root.string_ids[self.shorty_idx].value.data
            return self._m_shorty_desc if hasattr(self, '_m_shorty_desc') else None

        @property
        def params_types(self):
            """list of parameter types for this prototype."""
            if hasattr(self, '_m_params_types'):
                return self._m_params_types if hasattr(self, '_m_params_types') else None

            if self.parameters_off != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.parameters_off)
                self._debug['_m_params_types']['start'] = io.pos()
                self._m_params_types = self._root.TypeList(io, self, self._root)
                self._m_params_types._read()
                self._debug['_m_params_types']['end'] = io.pos()
                io.seek(_pos)

            return self._m_params_types if hasattr(self, '_m_params_types') else None

        @property
        def return_type(self):
            """return type of this prototype."""
            if hasattr(self, '_m_return_type'):
                return self._m_return_type if hasattr(self, '_m_return_type') else None

            self._m_return_type = self._root.type_ids[self.return_type_idx].type_name
            return self._m_return_type if hasattr(self, '_m_return_type') else None


    class EncodedMethod(KaitaiStruct):
        SEQ_FIELDS = ["method_idx_diff", "access_flags", "code_off"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['method_idx_diff']['start'] = self._io.pos()
            self.method_idx_diff = VlqBase128Le(self._io)
            self.method_idx_diff._read()
            self._debug['method_idx_diff']['end'] = self._io.pos()
            self._debug['access_flags']['start'] = self._io.pos()
            self.access_flags = VlqBase128Le(self._io)
            self.access_flags._read()
            self._debug['access_flags']['end'] = self._io.pos()
            self._debug['code_off']['start'] = self._io.pos()
            self.code_off = VlqBase128Le(self._io)
            self.code_off._read()
            self._debug['code_off']['end'] = self._io.pos()


    class MapItem(KaitaiStruct):

        class MapItemType(Enum):
            header_item = 0
            string_id_item = 1
            type_id_item = 2
            proto_id_item = 3
            field_id_item = 4
            method_id_item = 5
            class_def_item = 6
            call_site_id_item = 7
            method_handle_item = 8
            map_list = 4096
            type_list = 4097
            annotation_set_ref_list = 4098
            annotation_set_item = 4099
            class_data_item = 8192
            code_item = 8193
            string_data_item = 8194
            debug_info_item = 8195
            annotation_item = 8196
            encoded_array_item = 8197
            annotations_directory_item = 8198
        SEQ_FIELDS = ["type", "unused", "size", "offset"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type']['start'] = self._io.pos()
            self.type = KaitaiStream.resolve_enum(self._root.MapItem.MapItemType, self._io.read_u2le())
            self._debug['type']['end'] = self._io.pos()
            self._debug['unused']['start'] = self._io.pos()
            self.unused = self._io.read_u2le()
            self._debug['unused']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['offset']['start'] = self._io.pos()
            self.offset = self._io.read_u4le()
            self._debug['offset']['end'] = self._io.pos()


    class EncodedArray(KaitaiStruct):
        SEQ_FIELDS = ["size", "values"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['size']['start'] = self._io.pos()
            self.size = VlqBase128Le(self._io)
            self.size._read()
            self._debug['size']['end'] = self._io.pos()
            self._debug['values']['start'] = self._io.pos()
            self.values = [None] * (self.size.value)
            for i in range(self.size.value):
                if not 'arr' in self._debug['values']:
                    self._debug['values']['arr'] = []
                self._debug['values']['arr'].append({'start': self._io.pos()})
                _t_values = self._root.EncodedValue(self._io, self, self._root)
                _t_values._read()
                self.values[i] = _t_values
                self._debug['values']['arr'][i]['end'] = self._io.pos()

            self._debug['values']['end'] = self._io.pos()


    @property
    def string_ids(self):
        """string identifiers list.
        
        These are identifiers for all the strings used by this file, either for 
        internal naming (e.g., type descriptors) or as constant objects referred to by code.
        
        This list must be sorted by string contents, using UTF-16 code point values
        (not in a locale-sensitive manner), and it must not contain any duplicate entries.    
        """
        if hasattr(self, '_m_string_ids'):
            return self._m_string_ids if hasattr(self, '_m_string_ids') else None

        _pos = self._io.pos()
        self._io.seek(self.header.string_ids_off)
        self._debug['_m_string_ids']['start'] = self._io.pos()
        self._m_string_ids = [None] * (self.header.string_ids_size)
        for i in range(self.header.string_ids_size):
            if not 'arr' in self._debug['_m_string_ids']:
                self._debug['_m_string_ids']['arr'] = []
            self._debug['_m_string_ids']['arr'].append({'start': self._io.pos()})
            _t__m_string_ids = self._root.StringIdItem(self._io, self, self._root)
            _t__m_string_ids._read()
            self._m_string_ids[i] = _t__m_string_ids
            self._debug['_m_string_ids']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_string_ids']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_string_ids if hasattr(self, '_m_string_ids') else None

    @property
    def method_ids(self):
        """method identifiers list.
        
        These are identifiers for all methods referred to by this file,
        whether defined in the file or not.
        
        This list must be sorted, where the defining type (by type_id index 
        is the major order, method name (by string_id index) is the intermediate
        order, and method prototype (by proto_id index) is the minor order.
        
        The list must not contain any duplicate entries.
        """
        if hasattr(self, '_m_method_ids'):
            return self._m_method_ids if hasattr(self, '_m_method_ids') else None

        _pos = self._io.pos()
        self._io.seek(self.header.method_ids_off)
        self._debug['_m_method_ids']['start'] = self._io.pos()
        self._m_method_ids = [None] * (self.header.method_ids_size)
        for i in range(self.header.method_ids_size):
            if not 'arr' in self._debug['_m_method_ids']:
                self._debug['_m_method_ids']['arr'] = []
            self._debug['_m_method_ids']['arr'].append({'start': self._io.pos()})
            _t__m_method_ids = self._root.MethodIdItem(self._io, self, self._root)
            _t__m_method_ids._read()
            self._m_method_ids[i] = _t__m_method_ids
            self._debug['_m_method_ids']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_method_ids']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_method_ids if hasattr(self, '_m_method_ids') else None

    @property
    def link_data(self):
        """data used in statically linked files.
        
        The format of the data in this section is left unspecified by this document.
        
        This section is empty in unlinked files, and runtime implementations may
        use it as they see fit.
        """
        if hasattr(self, '_m_link_data'):
            return self._m_link_data if hasattr(self, '_m_link_data') else None

        _pos = self._io.pos()
        self._io.seek(self.header.link_off)
        self._debug['_m_link_data']['start'] = self._io.pos()
        self._m_link_data = self._io.read_bytes(self.header.link_size)
        self._debug['_m_link_data']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_link_data if hasattr(self, '_m_link_data') else None

    @property
    def map(self):
        if hasattr(self, '_m_map'):
            return self._m_map if hasattr(self, '_m_map') else None

        _pos = self._io.pos()
        self._io.seek(self.header.map_off)
        self._debug['_m_map']['start'] = self._io.pos()
        self._m_map = self._root.MapList(self._io, self, self._root)
        self._m_map._read()
        self._debug['_m_map']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_map if hasattr(self, '_m_map') else None

    @property
    def class_defs(self):
        """class definitions list.
        
        The classes must be ordered such that a given class's superclass and
        implemented interfaces appear in the list earlier than the referring class.
        
        Furthermore, it is invalid for a definition for the same-named class to
        appear more than once in the list.
        """
        if hasattr(self, '_m_class_defs'):
            return self._m_class_defs if hasattr(self, '_m_class_defs') else None

        _pos = self._io.pos()
        self._io.seek(self.header.class_defs_off)
        self._debug['_m_class_defs']['start'] = self._io.pos()
        self._m_class_defs = [None] * (self.header.class_defs_size)
        for i in range(self.header.class_defs_size):
            if not 'arr' in self._debug['_m_class_defs']:
                self._debug['_m_class_defs']['arr'] = []
            self._debug['_m_class_defs']['arr'].append({'start': self._io.pos()})
            _t__m_class_defs = self._root.ClassDefItem(self._io, self, self._root)
            _t__m_class_defs._read()
            self._m_class_defs[i] = _t__m_class_defs
            self._debug['_m_class_defs']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_class_defs']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_class_defs if hasattr(self, '_m_class_defs') else None

    @property
    def data(self):
        """data area, containing all the support data for the tables listed above.
        
        Different items have different alignment requirements, and padding bytes
        are inserted before each item if necessary to achieve proper alignment.
        """
        if hasattr(self, '_m_data'):
            return self._m_data if hasattr(self, '_m_data') else None

        _pos = self._io.pos()
        self._io.seek(self.header.data_off)
        self._debug['_m_data']['start'] = self._io.pos()
        self._m_data = self._io.read_bytes(self.header.data_size)
        self._debug['_m_data']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_data if hasattr(self, '_m_data') else None

    @property
    def type_ids(self):
        """type identifiers list. 
        
        These are identifiers for all types (classes, arrays, or primitive types) 
        referred to by this file, whether defined in the file or not.
        
        This list must be sorted by string_id index, and it must not contain any duplicate entries.
        """
        if hasattr(self, '_m_type_ids'):
            return self._m_type_ids if hasattr(self, '_m_type_ids') else None

        _pos = self._io.pos()
        self._io.seek(self.header.type_ids_off)
        self._debug['_m_type_ids']['start'] = self._io.pos()
        self._m_type_ids = [None] * (self.header.type_ids_size)
        for i in range(self.header.type_ids_size):
            if not 'arr' in self._debug['_m_type_ids']:
                self._debug['_m_type_ids']['arr'] = []
            self._debug['_m_type_ids']['arr'].append({'start': self._io.pos()})
            _t__m_type_ids = self._root.TypeIdItem(self._io, self, self._root)
            _t__m_type_ids._read()
            self._m_type_ids[i] = _t__m_type_ids
            self._debug['_m_type_ids']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_type_ids']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_type_ids if hasattr(self, '_m_type_ids') else None

    @property
    def proto_ids(self):
        """method prototype identifiers list.
        
        These are identifiers for all prototypes referred to by this file.
        
        This list must be sorted in return-type (by type_id index) major order,
        and then by argument list (lexicographic ordering, individual arguments
        ordered by type_id index). The list must not contain any duplicate entries.
        """
        if hasattr(self, '_m_proto_ids'):
            return self._m_proto_ids if hasattr(self, '_m_proto_ids') else None

        _pos = self._io.pos()
        self._io.seek(self.header.proto_ids_off)
        self._debug['_m_proto_ids']['start'] = self._io.pos()
        self._m_proto_ids = [None] * (self.header.proto_ids_size)
        for i in range(self.header.proto_ids_size):
            if not 'arr' in self._debug['_m_proto_ids']:
                self._debug['_m_proto_ids']['arr'] = []
            self._debug['_m_proto_ids']['arr'].append({'start': self._io.pos()})
            _t__m_proto_ids = self._root.ProtoIdItem(self._io, self, self._root)
            _t__m_proto_ids._read()
            self._m_proto_ids[i] = _t__m_proto_ids
            self._debug['_m_proto_ids']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_proto_ids']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_proto_ids if hasattr(self, '_m_proto_ids') else None

    @property
    def field_ids(self):
        """field identifiers list.
        
        These are identifiers for all fields referred to by this file, whether defined in the file or not. 
        
        This list must be sorted, where the defining type (by type_id index) 
        is the major order, field name (by string_id index) is the intermediate 
        order, and type (by type_id index) is the minor order.
        
        The list must not contain any duplicate entries.
        """
        if hasattr(self, '_m_field_ids'):
            return self._m_field_ids if hasattr(self, '_m_field_ids') else None

        _pos = self._io.pos()
        self._io.seek(self.header.field_ids_off)
        self._debug['_m_field_ids']['start'] = self._io.pos()
        self._m_field_ids = [None] * (self.header.field_ids_size)
        for i in range(self.header.field_ids_size):
            if not 'arr' in self._debug['_m_field_ids']:
                self._debug['_m_field_ids']['arr'] = []
            self._debug['_m_field_ids']['arr'].append({'start': self._io.pos()})
            _t__m_field_ids = self._root.FieldIdItem(self._io, self, self._root)
            _t__m_field_ids._read()
            self._m_field_ids[i] = _t__m_field_ids
            self._debug['_m_field_ids']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_field_ids']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_field_ids if hasattr(self, '_m_field_ids') else None


