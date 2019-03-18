from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ....kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Asn1Der(KaitaiStruct):
    """ASN.1 (Abstract Syntax Notation One) DER (Distinguished Encoding
    Rules) is a standard-backed serialization scheme used in many
    different use-cases. Particularly popular usage scenarios are X.509
    certificates and some telecommunication / networking protocols.
    
    DER is self-describing encoding scheme which allows representation
    of simple, atomic data elements, such as strings and numbers, and
    complex objects, such as sequences of other elements.
    
    DER is a subset of BER (Basic Encoding Rules), with an emphasis on
    being non-ambiguous: there's always exactly one canonical way to
    encode a data structure defined in terms of ASN.1 using DER.
    
    This spec allows full parsing of format syntax, but to understand
    the semantics, one would typically require a dictionary of Object
    Identifiers (OIDs), to match OID bodies against some human-readable
    list of constants. OIDs are covered by many different standards,
    so typically it's simpler to use a pre-compiled list of them, such
    as:
    
    * https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
    * http://oid-info.com/
    * https://www.alvestrand.no/objectid/top.html
    
    .. seealso::
       Source - https://www.itu.int/rec/T-REC-X.690-201508-I/en
    """

    class TypeTag(Enum):
        end_of_content = 0
        boolean = 1
        integer = 2
        bit_string = 3
        octet_string = 4
        null_value = 5
        object_id = 6
        object_descriptor = 7
        external = 8
        real = 9
        enumerated = 10
        embedded_pdv = 11
        utf8string = 12
        relative_oid = 13
        sequence_10 = 16
        printable_string = 19
        ia5string = 22
        sequence_30 = 48
        set = 49
    SEQ_FIELDS = ["type_tag", "len", "body"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['type_tag']['start'] = self._io.pos()
        self.type_tag = KaitaiStream.resolve_enum(self._root.TypeTag, self._io.read_u1())
        self._debug['type_tag']['end'] = self._io.pos()
        self._debug['len']['start'] = self._io.pos()
        self.len = self._root.LenEncoded(self._io, self, self._root)
        self.len._read()
        self._debug['len']['end'] = self._io.pos()
        self._debug['body']['start'] = self._io.pos()
        _on = self.type_tag
        if _on == self._root.TypeTag.printable_string:
            self._raw_body = self._io.read_bytes(self.len.result)
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = self._root.BodyPrintableString(io, self, self._root)
            self.body._read()
        elif _on == self._root.TypeTag.sequence_10:
            self._raw_body = self._io.read_bytes(self.len.result)
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = self._root.BodySequence(io, self, self._root)
            self.body._read()
        elif _on == self._root.TypeTag.set:
            self._raw_body = self._io.read_bytes(self.len.result)
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = self._root.BodySequence(io, self, self._root)
            self.body._read()
        elif _on == self._root.TypeTag.sequence_30:
            self._raw_body = self._io.read_bytes(self.len.result)
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = self._root.BodySequence(io, self, self._root)
            self.body._read()
        elif _on == self._root.TypeTag.utf8string:
            self._raw_body = self._io.read_bytes(self.len.result)
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = self._root.BodyUtf8string(io, self, self._root)
            self.body._read()
        elif _on == self._root.TypeTag.object_id:
            self._raw_body = self._io.read_bytes(self.len.result)
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = self._root.BodyObjectId(io, self, self._root)
            self.body._read()
        else:
            self.body = self._io.read_bytes(self.len.result)
        self._debug['body']['end'] = self._io.pos()

    class BodySequence(KaitaiStruct):
        SEQ_FIELDS = ["entries"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['entries']['start'] = self._io.pos()
            self.entries = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['entries']:
                    self._debug['entries']['arr'] = []
                self._debug['entries']['arr'].append({'start': self._io.pos()})
                _t_entries = Asn1Der(self._io)
                _t_entries._read()
                self.entries.append(_t_entries)
                self._debug['entries']['arr'][len(self.entries) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['entries']['end'] = self._io.pos()


    class BodyUtf8string(KaitaiStruct):
        SEQ_FIELDS = ["str"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['str']['start'] = self._io.pos()
            self.str = (self._io.read_bytes_full()).decode(u"UTF-8")
            self._debug['str']['end'] = self._io.pos()


    class BodyObjectId(KaitaiStruct):
        """
        .. seealso::
           Source - https://docs.microsoft.com/en-us/windows/desktop/SecCertEnroll/about-object-identifier
        """
        SEQ_FIELDS = ["first_and_second", "rest"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['first_and_second']['start'] = self._io.pos()
            self.first_and_second = self._io.read_u1()
            self._debug['first_and_second']['end'] = self._io.pos()
            self._debug['rest']['start'] = self._io.pos()
            self.rest = self._io.read_bytes_full()
            self._debug['rest']['end'] = self._io.pos()

        @property
        def first(self):
            if hasattr(self, '_m_first'):
                return self._m_first if hasattr(self, '_m_first') else None

            self._m_first = self.first_and_second // 40
            return self._m_first if hasattr(self, '_m_first') else None

        @property
        def second(self):
            if hasattr(self, '_m_second'):
                return self._m_second if hasattr(self, '_m_second') else None

            self._m_second = (self.first_and_second % 40)
            return self._m_second if hasattr(self, '_m_second') else None


    class LenEncoded(KaitaiStruct):
        SEQ_FIELDS = ["b1", "int2", "int1"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['b1']['start'] = self._io.pos()
            self.b1 = self._io.read_u1()
            self._debug['b1']['end'] = self._io.pos()
            if self.b1 == 130:
                self._debug['int2']['start'] = self._io.pos()
                self.int2 = self._io.read_u2be()
                self._debug['int2']['end'] = self._io.pos()

            if self.b1 == 129:
                self._debug['int1']['start'] = self._io.pos()
                self.int1 = self._io.read_u1()
                self._debug['int1']['end'] = self._io.pos()


        @property
        def result(self):
            if hasattr(self, '_m_result'):
                return self._m_result if hasattr(self, '_m_result') else None

            self._m_result = (self.int1 if self.b1 == 129 else (self.int2 if self.b1 == 130 else self.b1))
            return self._m_result if hasattr(self, '_m_result') else None


    class BodyPrintableString(KaitaiStruct):
        SEQ_FIELDS = ["str"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['str']['start'] = self._io.pos()
            self.str = (self._io.read_bytes_full()).decode(u"ASCII")
            self._debug['str']['end'] = self._io.pos()



