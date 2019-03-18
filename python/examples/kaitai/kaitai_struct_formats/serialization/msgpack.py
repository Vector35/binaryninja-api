from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Msgpack(KaitaiStruct):
    """MessagePack (msgpack) is a system to serialize arbitrary structured
    data into a compact binary stream.
    
    .. seealso::
       Source - https://github.com/msgpack/msgpack/blob/master/spec.md
    """
    SEQ_FIELDS = ["b1", "int_extra", "float_32_value", "float_64_value", "str_len_8", "str_len_16", "str_len_32", "str_value", "num_array_elements_16", "num_array_elements_32", "array_elements", "num_map_elements_16", "num_map_elements_32", "map_elements"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['b1']['start'] = self._io.pos()
        self.b1 = self._io.read_u1()
        self._debug['b1']['end'] = self._io.pos()
        self._debug['int_extra']['start'] = self._io.pos()
        _on = self.b1
        if _on == 211:
            self.int_extra = self._io.read_s8be()
        elif _on == 209:
            self.int_extra = self._io.read_s2be()
        elif _on == 210:
            self.int_extra = self._io.read_s4be()
        elif _on == 208:
            self.int_extra = self._io.read_s1()
        elif _on == 205:
            self.int_extra = self._io.read_u2be()
        elif _on == 207:
            self.int_extra = self._io.read_u8be()
        elif _on == 204:
            self.int_extra = self._io.read_u1()
        elif _on == 206:
            self.int_extra = self._io.read_u4be()
        self._debug['int_extra']['end'] = self._io.pos()
        if self.is_float_32:
            self._debug['float_32_value']['start'] = self._io.pos()
            self.float_32_value = self._io.read_f4be()
            self._debug['float_32_value']['end'] = self._io.pos()

        if self.is_float_64:
            self._debug['float_64_value']['start'] = self._io.pos()
            self.float_64_value = self._io.read_f8be()
            self._debug['float_64_value']['end'] = self._io.pos()

        if self.is_str_8:
            self._debug['str_len_8']['start'] = self._io.pos()
            self.str_len_8 = self._io.read_u1()
            self._debug['str_len_8']['end'] = self._io.pos()

        if self.is_str_16:
            self._debug['str_len_16']['start'] = self._io.pos()
            self.str_len_16 = self._io.read_u2be()
            self._debug['str_len_16']['end'] = self._io.pos()

        if self.is_str_32:
            self._debug['str_len_32']['start'] = self._io.pos()
            self.str_len_32 = self._io.read_u4be()
            self._debug['str_len_32']['end'] = self._io.pos()

        if self.is_str:
            self._debug['str_value']['start'] = self._io.pos()
            self.str_value = (self._io.read_bytes(self.str_len)).decode(u"UTF-8")
            self._debug['str_value']['end'] = self._io.pos()

        if self.is_array_16:
            self._debug['num_array_elements_16']['start'] = self._io.pos()
            self.num_array_elements_16 = self._io.read_u2be()
            self._debug['num_array_elements_16']['end'] = self._io.pos()

        if self.is_array_32:
            self._debug['num_array_elements_32']['start'] = self._io.pos()
            self.num_array_elements_32 = self._io.read_u4be()
            self._debug['num_array_elements_32']['end'] = self._io.pos()

        if self.is_array:
            self._debug['array_elements']['start'] = self._io.pos()
            self.array_elements = [None] * (self.num_array_elements)
            for i in range(self.num_array_elements):
                if not 'arr' in self._debug['array_elements']:
                    self._debug['array_elements']['arr'] = []
                self._debug['array_elements']['arr'].append({'start': self._io.pos()})
                _t_array_elements = Msgpack(self._io)
                _t_array_elements._read()
                self.array_elements[i] = _t_array_elements
                self._debug['array_elements']['arr'][i]['end'] = self._io.pos()

            self._debug['array_elements']['end'] = self._io.pos()

        if self.is_map_16:
            self._debug['num_map_elements_16']['start'] = self._io.pos()
            self.num_map_elements_16 = self._io.read_u2be()
            self._debug['num_map_elements_16']['end'] = self._io.pos()

        if self.is_map_32:
            self._debug['num_map_elements_32']['start'] = self._io.pos()
            self.num_map_elements_32 = self._io.read_u4be()
            self._debug['num_map_elements_32']['end'] = self._io.pos()

        if self.is_map:
            self._debug['map_elements']['start'] = self._io.pos()
            self.map_elements = [None] * (self.num_map_elements)
            for i in range(self.num_map_elements):
                if not 'arr' in self._debug['map_elements']:
                    self._debug['map_elements']['arr'] = []
                self._debug['map_elements']['arr'].append({'start': self._io.pos()})
                _t_map_elements = self._root.MapTuple(self._io, self, self._root)
                _t_map_elements._read()
                self.map_elements[i] = _t_map_elements
                self._debug['map_elements']['arr'][i]['end'] = self._io.pos()

            self._debug['map_elements']['end'] = self._io.pos()


    class MapTuple(KaitaiStruct):
        SEQ_FIELDS = ["key", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['key']['start'] = self._io.pos()
            self.key = Msgpack(self._io)
            self.key._read()
            self._debug['key']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = Msgpack(self._io)
            self.value._read()
            self._debug['value']['end'] = self._io.pos()


    @property
    def is_array_32(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-array
        """
        if hasattr(self, '_m_is_array_32'):
            return self._m_is_array_32 if hasattr(self, '_m_is_array_32') else None

        self._m_is_array_32 = self.b1 == 221
        return self._m_is_array_32 if hasattr(self, '_m_is_array_32') else None

    @property
    def int_value(self):
        if hasattr(self, '_m_int_value'):
            return self._m_int_value if hasattr(self, '_m_int_value') else None

        if self.is_int:
            self._m_int_value = (self.pos_int7_value if self.is_pos_int7 else (self.neg_int5_value if self.is_neg_int5 else 4919))

        return self._m_int_value if hasattr(self, '_m_int_value') else None

    @property
    def str_len(self):
        if hasattr(self, '_m_str_len'):
            return self._m_str_len if hasattr(self, '_m_str_len') else None

        if self.is_str:
            self._m_str_len = ((self.b1 & 31) if self.is_fix_str else (self.str_len_8 if self.is_str_8 else (self.str_len_16 if self.is_str_16 else self.str_len_32)))

        return self._m_str_len if hasattr(self, '_m_str_len') else None

    @property
    def is_fix_array(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-array
        """
        if hasattr(self, '_m_is_fix_array'):
            return self._m_is_fix_array if hasattr(self, '_m_is_fix_array') else None

        self._m_is_fix_array = (self.b1 & 240) == 144
        return self._m_is_fix_array if hasattr(self, '_m_is_fix_array') else None

    @property
    def is_map(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-map
        """
        if hasattr(self, '_m_is_map'):
            return self._m_is_map if hasattr(self, '_m_is_map') else None

        self._m_is_map =  ((self.is_fix_map) or (self.is_map_16) or (self.is_map_32)) 
        return self._m_is_map if hasattr(self, '_m_is_map') else None

    @property
    def is_array(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-array
        """
        if hasattr(self, '_m_is_array'):
            return self._m_is_array if hasattr(self, '_m_is_array') else None

        self._m_is_array =  ((self.is_fix_array) or (self.is_array_16) or (self.is_array_32)) 
        return self._m_is_array if hasattr(self, '_m_is_array') else None

    @property
    def is_float(self):
        if hasattr(self, '_m_is_float'):
            return self._m_is_float if hasattr(self, '_m_is_float') else None

        self._m_is_float =  ((self.is_float_32) or (self.is_float_64)) 
        return self._m_is_float if hasattr(self, '_m_is_float') else None

    @property
    def is_str_8(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-str
        """
        if hasattr(self, '_m_is_str_8'):
            return self._m_is_str_8 if hasattr(self, '_m_is_str_8') else None

        self._m_is_str_8 = self.b1 == 217
        return self._m_is_str_8 if hasattr(self, '_m_is_str_8') else None

    @property
    def is_fix_map(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-map
        """
        if hasattr(self, '_m_is_fix_map'):
            return self._m_is_fix_map if hasattr(self, '_m_is_fix_map') else None

        self._m_is_fix_map = (self.b1 & 240) == 128
        return self._m_is_fix_map if hasattr(self, '_m_is_fix_map') else None

    @property
    def is_int(self):
        if hasattr(self, '_m_is_int'):
            return self._m_is_int if hasattr(self, '_m_is_int') else None

        self._m_is_int =  ((self.is_pos_int7) or (self.is_neg_int5)) 
        return self._m_is_int if hasattr(self, '_m_is_int') else None

    @property
    def is_bool(self):
        if hasattr(self, '_m_is_bool'):
            return self._m_is_bool if hasattr(self, '_m_is_bool') else None

        self._m_is_bool =  ((self.b1 == 194) or (self.b1 == 195)) 
        return self._m_is_bool if hasattr(self, '_m_is_bool') else None

    @property
    def is_str_16(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-str
        """
        if hasattr(self, '_m_is_str_16'):
            return self._m_is_str_16 if hasattr(self, '_m_is_str_16') else None

        self._m_is_str_16 = self.b1 == 218
        return self._m_is_str_16 if hasattr(self, '_m_is_str_16') else None

    @property
    def is_float_64(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-float
        """
        if hasattr(self, '_m_is_float_64'):
            return self._m_is_float_64 if hasattr(self, '_m_is_float_64') else None

        self._m_is_float_64 = self.b1 == 203
        return self._m_is_float_64 if hasattr(self, '_m_is_float_64') else None

    @property
    def is_map_16(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-map
        """
        if hasattr(self, '_m_is_map_16'):
            return self._m_is_map_16 if hasattr(self, '_m_is_map_16') else None

        self._m_is_map_16 = self.b1 == 222
        return self._m_is_map_16 if hasattr(self, '_m_is_map_16') else None

    @property
    def is_neg_int5(self):
        if hasattr(self, '_m_is_neg_int5'):
            return self._m_is_neg_int5 if hasattr(self, '_m_is_neg_int5') else None

        self._m_is_neg_int5 = (self.b1 & 224) == 224
        return self._m_is_neg_int5 if hasattr(self, '_m_is_neg_int5') else None

    @property
    def pos_int7_value(self):
        if hasattr(self, '_m_pos_int7_value'):
            return self._m_pos_int7_value if hasattr(self, '_m_pos_int7_value') else None

        if self.is_pos_int7:
            self._m_pos_int7_value = self.b1

        return self._m_pos_int7_value if hasattr(self, '_m_pos_int7_value') else None

    @property
    def is_nil(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-nil
        """
        if hasattr(self, '_m_is_nil'):
            return self._m_is_nil if hasattr(self, '_m_is_nil') else None

        self._m_is_nil = self.b1 == 192
        return self._m_is_nil if hasattr(self, '_m_is_nil') else None

    @property
    def float_value(self):
        if hasattr(self, '_m_float_value'):
            return self._m_float_value if hasattr(self, '_m_float_value') else None

        if self.is_float:
            self._m_float_value = (self.float_32_value if self.is_float_32 else self.float_64_value)

        return self._m_float_value if hasattr(self, '_m_float_value') else None

    @property
    def num_array_elements(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-array
        """
        if hasattr(self, '_m_num_array_elements'):
            return self._m_num_array_elements if hasattr(self, '_m_num_array_elements') else None

        if self.is_array:
            self._m_num_array_elements = ((self.b1 & 15) if self.is_fix_array else (self.num_array_elements_16 if self.is_array_16 else self.num_array_elements_32))

        return self._m_num_array_elements if hasattr(self, '_m_num_array_elements') else None

    @property
    def neg_int5_value(self):
        if hasattr(self, '_m_neg_int5_value'):
            return self._m_neg_int5_value if hasattr(self, '_m_neg_int5_value') else None

        if self.is_neg_int5:
            self._m_neg_int5_value = -((self.b1 & 31))

        return self._m_neg_int5_value if hasattr(self, '_m_neg_int5_value') else None

    @property
    def bool_value(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-bool
        """
        if hasattr(self, '_m_bool_value'):
            return self._m_bool_value if hasattr(self, '_m_bool_value') else None

        if self.is_bool:
            self._m_bool_value = self.b1 == 195

        return self._m_bool_value if hasattr(self, '_m_bool_value') else None

    @property
    def is_pos_int7(self):
        if hasattr(self, '_m_is_pos_int7'):
            return self._m_is_pos_int7 if hasattr(self, '_m_is_pos_int7') else None

        self._m_is_pos_int7 = (self.b1 & 128) == 0
        return self._m_is_pos_int7 if hasattr(self, '_m_is_pos_int7') else None

    @property
    def is_array_16(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-array
        """
        if hasattr(self, '_m_is_array_16'):
            return self._m_is_array_16 if hasattr(self, '_m_is_array_16') else None

        self._m_is_array_16 = self.b1 == 220
        return self._m_is_array_16 if hasattr(self, '_m_is_array_16') else None

    @property
    def is_str(self):
        if hasattr(self, '_m_is_str'):
            return self._m_is_str if hasattr(self, '_m_is_str') else None

        self._m_is_str =  ((self.is_fix_str) or (self.is_str_8) or (self.is_str_16) or (self.is_str_32)) 
        return self._m_is_str if hasattr(self, '_m_is_str') else None

    @property
    def is_fix_str(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-str
        """
        if hasattr(self, '_m_is_fix_str'):
            return self._m_is_fix_str if hasattr(self, '_m_is_fix_str') else None

        self._m_is_fix_str = (self.b1 & 224) == 160
        return self._m_is_fix_str if hasattr(self, '_m_is_fix_str') else None

    @property
    def is_str_32(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-str
        """
        if hasattr(self, '_m_is_str_32'):
            return self._m_is_str_32 if hasattr(self, '_m_is_str_32') else None

        self._m_is_str_32 = self.b1 == 219
        return self._m_is_str_32 if hasattr(self, '_m_is_str_32') else None

    @property
    def num_map_elements(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-map
        """
        if hasattr(self, '_m_num_map_elements'):
            return self._m_num_map_elements if hasattr(self, '_m_num_map_elements') else None

        if self.is_map:
            self._m_num_map_elements = ((self.b1 & 15) if self.is_fix_map else (self.num_map_elements_16 if self.is_map_16 else self.num_map_elements_32))

        return self._m_num_map_elements if hasattr(self, '_m_num_map_elements') else None

    @property
    def is_float_32(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-float
        """
        if hasattr(self, '_m_is_float_32'):
            return self._m_is_float_32 if hasattr(self, '_m_is_float_32') else None

        self._m_is_float_32 = self.b1 == 202
        return self._m_is_float_32 if hasattr(self, '_m_is_float_32') else None

    @property
    def is_map_32(self):
        """
        .. seealso::
           Source - https://github.com/msgpack/msgpack/blob/master/spec.md#formats-map
        """
        if hasattr(self, '_m_is_map_32'):
            return self._m_is_map_32 if hasattr(self, '_m_is_map_32') else None

        self._m_is_map_32 = self.b1 == 223
        return self._m_is_map_32 if hasattr(self, '_m_is_map_32') else None


