from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class RubyMarshal(KaitaiStruct):
    """Ruby's Marshal module allows serialization and deserialization of
    many standard and arbitrary Ruby objects in a compact binary
    format. It is relatively fast, available in stdlibs standard and
    allows conservation of language-specific properties (such as symbols
    or encoding-aware strings).
    
    Feature-wise, it is comparable to other language-specific
    implementations, such as:
    
    * Java's
      [Serializable](https://docs.oracle.com/javase/8/docs/api/java/io/Serializable.html)
    * .NET
      [BinaryFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter)
    * Python's
      [marshal](https://docs.python.org/3/library/marshal.html),
      [pickle](https://docs.python.org/3/library/pickle.html) and
      [shelve](https://docs.python.org/3/library/shelve.html)
    
    From internal perspective, serialized stream consists of a simple
    magic header and a record.
    
    .. seealso::
       Source - https://docs.ruby-lang.org/en/2.4.0/marshal_rdoc.html#label-Stream+Format
    """

    class Codes(Enum):
        ruby_string = 34
        const_nil = 48
        ruby_symbol = 58
        ruby_symbol_link = 59
        const_false = 70
        instance_var = 73
        ruby_struct = 83
        const_true = 84
        ruby_array = 91
        packed_int = 105
        bignum = 108
        ruby_hash = 123
    SEQ_FIELDS = ["version", "records"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['version']['start'] = self._io.pos()
        self.version = self._io.ensure_fixed_contents(b"\x04\x08")
        self._debug['version']['end'] = self._io.pos()
        self._debug['records']['start'] = self._io.pos()
        self.records = self._root.Record(self._io, self, self._root)
        self.records._read()
        self._debug['records']['end'] = self._io.pos()

    class RubyArray(KaitaiStruct):
        SEQ_FIELDS = ["num_elements", "elements"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_elements']['start'] = self._io.pos()
            self.num_elements = self._root.PackedInt(self._io, self, self._root)
            self.num_elements._read()
            self._debug['num_elements']['end'] = self._io.pos()
            self._debug['elements']['start'] = self._io.pos()
            self.elements = [None] * (self.num_elements.value)
            for i in range(self.num_elements.value):
                if not 'arr' in self._debug['elements']:
                    self._debug['elements']['arr'] = []
                self._debug['elements']['arr'].append({'start': self._io.pos()})
                _t_elements = self._root.Record(self._io, self, self._root)
                _t_elements._read()
                self.elements[i] = _t_elements
                self._debug['elements']['arr'][i]['end'] = self._io.pos()

            self._debug['elements']['end'] = self._io.pos()


    class Bignum(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.ruby-lang.org/en/2.4.0/marshal_rdoc.html#label-Bignum
        """
        SEQ_FIELDS = ["sign", "len_div_2", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['sign']['start'] = self._io.pos()
            self.sign = self._io.read_u1()
            self._debug['sign']['end'] = self._io.pos()
            self._debug['len_div_2']['start'] = self._io.pos()
            self.len_div_2 = self._root.PackedInt(self._io, self, self._root)
            self.len_div_2._read()
            self._debug['len_div_2']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            self.body = self._io.read_bytes((self.len_div_2.value * 2))
            self._debug['body']['end'] = self._io.pos()


    class RubyStruct(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.ruby-lang.org/en/2.4.0/marshal_rdoc.html#label-Struct
        """
        SEQ_FIELDS = ["name", "num_members", "members"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = self._root.Record(self._io, self, self._root)
            self.name._read()
            self._debug['name']['end'] = self._io.pos()
            self._debug['num_members']['start'] = self._io.pos()
            self.num_members = self._root.PackedInt(self._io, self, self._root)
            self.num_members._read()
            self._debug['num_members']['end'] = self._io.pos()
            self._debug['members']['start'] = self._io.pos()
            self.members = [None] * (self.num_members.value)
            for i in range(self.num_members.value):
                if not 'arr' in self._debug['members']:
                    self._debug['members']['arr'] = []
                self._debug['members']['arr'].append({'start': self._io.pos()})
                _t_members = self._root.Pair(self._io, self, self._root)
                _t_members._read()
                self.members[i] = _t_members
                self._debug['members']['arr'][i]['end'] = self._io.pos()

            self._debug['members']['end'] = self._io.pos()


    class RubySymbol(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.ruby-lang.org/en/2.4.0/marshal_rdoc.html#label-Symbols+and+Byte+Sequence
        """
        SEQ_FIELDS = ["len", "name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._root.PackedInt(self._io, self, self._root)
            self.len._read()
            self._debug['len']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = (self._io.read_bytes(self.len.value)).decode(u"UTF-8")
            self._debug['name']['end'] = self._io.pos()


    class PackedInt(KaitaiStruct):
        """Ruby uses sophisticated system to pack integers: first `code`
        byte either determines packing scheme or carries encoded
        immediate value (thus allowing smaller values from -123 to 122
        (inclusive) to take only one byte. There are 11 encoding schemes
        in total:
        
        * 0 is encoded specially (as 0)
        * 1..122 are encoded as immediate value with a shift
        * 123..255 are encoded with code of 0x01 and 1 extra byte
        * 0x100..0xffff are encoded with code of 0x02 and 2 extra bytes
        * 0x10000..0xffffff are encoded with code of 0x03 and 3 extra
          bytes
        * 0x1000000..0xffffffff are encoded with code of 0x04 and 4
          extra bytes
        * -123..-1 are encoded as immediate value with another shift
        * -256..-124 are encoded with code of 0xff and 1 extra byte
        * -0x10000..-257 are encoded with code of 0xfe and 2 extra bytes
        * -0x1000000..0x10001 are encoded with code of 0xfd and 3 extra
           bytes
        * -0x40000000..-0x1000001 are encoded with code of 0xfc and 4
           extra bytes
        
        Values beyond that are serialized as bignum (even if they
        technically might be not Bignum class in Ruby implementation,
        i.e. if they fit into 64 bits on a 64-bit platform).
        
        .. seealso::
           Source - https://docs.ruby-lang.org/en/2.4.0/marshal_rdoc.html#label-Fixnum+and+long
        """
        SEQ_FIELDS = ["code", "encoded", "encoded2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = self._io.read_u1()
            self._debug['code']['end'] = self._io.pos()
            self._debug['encoded']['start'] = self._io.pos()
            _on = self.code
            if _on == 4:
                self.encoded = self._io.read_u4le()
            elif _on == 1:
                self.encoded = self._io.read_u1()
            elif _on == 252:
                self.encoded = self._io.read_u4le()
            elif _on == 253:
                self.encoded = self._io.read_u2le()
            elif _on == 3:
                self.encoded = self._io.read_u2le()
            elif _on == 2:
                self.encoded = self._io.read_u2le()
            elif _on == 255:
                self.encoded = self._io.read_u1()
            elif _on == 254:
                self.encoded = self._io.read_u2le()
            self._debug['encoded']['end'] = self._io.pos()
            self._debug['encoded2']['start'] = self._io.pos()
            _on = self.code
            if _on == 3:
                self.encoded2 = self._io.read_u1()
            elif _on == 253:
                self.encoded2 = self._io.read_u1()
            self._debug['encoded2']['end'] = self._io.pos()

        @property
        def is_immediate(self):
            if hasattr(self, '_m_is_immediate'):
                return self._m_is_immediate if hasattr(self, '_m_is_immediate') else None

            self._m_is_immediate =  ((self.code > 4) and (self.code < 252)) 
            return self._m_is_immediate if hasattr(self, '_m_is_immediate') else None

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            self._m_value = (((self.code - 5) if self.code < 128 else (4 - (~(self.code) & 127))) if self.is_immediate else (0 if self.code == 0 else ((self.encoded - 256) if self.code == 255 else ((self.encoded - 65536) if self.code == 254 else ((((self.encoded2 << 16) | self.encoded) - 16777216) if self.code == 253 else (((self.encoded2 << 16) | self.encoded) if self.code == 3 else self.encoded))))))
            return self._m_value if hasattr(self, '_m_value') else None


    class Pair(KaitaiStruct):
        SEQ_FIELDS = ["key", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['key']['start'] = self._io.pos()
            self.key = self._root.Record(self._io, self, self._root)
            self.key._read()
            self._debug['key']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = self._root.Record(self._io, self, self._root)
            self.value._read()
            self._debug['value']['end'] = self._io.pos()


    class InstanceVar(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.ruby-lang.org/en/2.4.0/marshal_rdoc.html#label-Instance+Variables
        """
        SEQ_FIELDS = ["obj", "num_vars", "vars"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['obj']['start'] = self._io.pos()
            self.obj = self._root.Record(self._io, self, self._root)
            self.obj._read()
            self._debug['obj']['end'] = self._io.pos()
            self._debug['num_vars']['start'] = self._io.pos()
            self.num_vars = self._root.PackedInt(self._io, self, self._root)
            self.num_vars._read()
            self._debug['num_vars']['end'] = self._io.pos()
            self._debug['vars']['start'] = self._io.pos()
            self.vars = [None] * (self.num_vars.value)
            for i in range(self.num_vars.value):
                if not 'arr' in self._debug['vars']:
                    self._debug['vars']['arr'] = []
                self._debug['vars']['arr'].append({'start': self._io.pos()})
                _t_vars = self._root.Pair(self._io, self, self._root)
                _t_vars._read()
                self.vars[i] = _t_vars
                self._debug['vars']['arr'][i]['end'] = self._io.pos()

            self._debug['vars']['end'] = self._io.pos()


    class Record(KaitaiStruct):
        """Each record starts with a single byte that determines its type
        (`code`) and contents. If necessary, additional info as parsed
        as `body`, to be determined by `code`.
        """
        SEQ_FIELDS = ["code", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = KaitaiStream.resolve_enum(self._root.Codes, self._io.read_u1())
            self._debug['code']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.code
            if _on == self._root.Codes.packed_int:
                self.body = self._root.PackedInt(self._io, self, self._root)
                self.body._read()
            elif _on == self._root.Codes.bignum:
                self.body = self._root.Bignum(self._io, self, self._root)
                self.body._read()
            elif _on == self._root.Codes.ruby_array:
                self.body = self._root.RubyArray(self._io, self, self._root)
                self.body._read()
            elif _on == self._root.Codes.ruby_symbol_link:
                self.body = self._root.PackedInt(self._io, self, self._root)
                self.body._read()
            elif _on == self._root.Codes.ruby_struct:
                self.body = self._root.RubyStruct(self._io, self, self._root)
                self.body._read()
            elif _on == self._root.Codes.ruby_string:
                self.body = self._root.RubyString(self._io, self, self._root)
                self.body._read()
            elif _on == self._root.Codes.instance_var:
                self.body = self._root.InstanceVar(self._io, self, self._root)
                self.body._read()
            elif _on == self._root.Codes.ruby_hash:
                self.body = self._root.RubyHash(self._io, self, self._root)
                self.body._read()
            elif _on == self._root.Codes.ruby_symbol:
                self.body = self._root.RubySymbol(self._io, self, self._root)
                self.body._read()
            self._debug['body']['end'] = self._io.pos()


    class RubyHash(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.ruby-lang.org/en/2.4.0/marshal_rdoc.html#label-Hash+and+Hash+with+Default+Value
        """
        SEQ_FIELDS = ["num_pairs", "pairs"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_pairs']['start'] = self._io.pos()
            self.num_pairs = self._root.PackedInt(self._io, self, self._root)
            self.num_pairs._read()
            self._debug['num_pairs']['end'] = self._io.pos()
            self._debug['pairs']['start'] = self._io.pos()
            self.pairs = [None] * (self.num_pairs.value)
            for i in range(self.num_pairs.value):
                if not 'arr' in self._debug['pairs']:
                    self._debug['pairs']['arr'] = []
                self._debug['pairs']['arr'].append({'start': self._io.pos()})
                _t_pairs = self._root.Pair(self._io, self, self._root)
                _t_pairs._read()
                self.pairs[i] = _t_pairs
                self._debug['pairs']['arr'][i]['end'] = self._io.pos()

            self._debug['pairs']['end'] = self._io.pos()


    class RubyString(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.ruby-lang.org/en/2.4.0/marshal_rdoc.html#label-String
        """
        SEQ_FIELDS = ["len", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._root.PackedInt(self._io, self, self._root)
            self.len._read()
            self._debug['len']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            self.body = self._io.read_bytes(self.len.value)
            self._debug['body']['end'] = self._io.pos()



