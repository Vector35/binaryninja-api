from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class TlsClientHello(KaitaiStruct):
    SEQ_FIELDS = ["version", "random", "session_id", "cipher_suites", "compression_methods", "extensions"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['version']['start'] = self._io.pos()
        self.version = self._root.Version(self._io, self, self._root)
        self.version._read()
        self._debug['version']['end'] = self._io.pos()
        self._debug['random']['start'] = self._io.pos()
        self.random = self._root.Random(self._io, self, self._root)
        self.random._read()
        self._debug['random']['end'] = self._io.pos()
        self._debug['session_id']['start'] = self._io.pos()
        self.session_id = self._root.SessionId(self._io, self, self._root)
        self.session_id._read()
        self._debug['session_id']['end'] = self._io.pos()
        self._debug['cipher_suites']['start'] = self._io.pos()
        self.cipher_suites = self._root.CipherSuites(self._io, self, self._root)
        self.cipher_suites._read()
        self._debug['cipher_suites']['end'] = self._io.pos()
        self._debug['compression_methods']['start'] = self._io.pos()
        self.compression_methods = self._root.CompressionMethods(self._io, self, self._root)
        self.compression_methods._read()
        self._debug['compression_methods']['end'] = self._io.pos()
        if self._io.is_eof() == False:
            self._debug['extensions']['start'] = self._io.pos()
            self.extensions = self._root.Extensions(self._io, self, self._root)
            self.extensions._read()
            self._debug['extensions']['end'] = self._io.pos()


    class ServerName(KaitaiStruct):
        SEQ_FIELDS = ["name_type", "length", "host_name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name_type']['start'] = self._io.pos()
            self.name_type = self._io.read_u1()
            self._debug['name_type']['end'] = self._io.pos()
            self._debug['length']['start'] = self._io.pos()
            self.length = self._io.read_u2be()
            self._debug['length']['end'] = self._io.pos()
            self._debug['host_name']['start'] = self._io.pos()
            self.host_name = self._io.read_bytes(self.length)
            self._debug['host_name']['end'] = self._io.pos()


    class Random(KaitaiStruct):
        SEQ_FIELDS = ["gmt_unix_time", "random"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['gmt_unix_time']['start'] = self._io.pos()
            self.gmt_unix_time = self._io.read_u4be()
            self._debug['gmt_unix_time']['end'] = self._io.pos()
            self._debug['random']['start'] = self._io.pos()
            self.random = self._io.read_bytes(28)
            self._debug['random']['end'] = self._io.pos()


    class SessionId(KaitaiStruct):
        SEQ_FIELDS = ["len", "sid"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u1()
            self._debug['len']['end'] = self._io.pos()
            self._debug['sid']['start'] = self._io.pos()
            self.sid = self._io.read_bytes(self.len)
            self._debug['sid']['end'] = self._io.pos()


    class Sni(KaitaiStruct):
        SEQ_FIELDS = ["list_length", "server_names"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['list_length']['start'] = self._io.pos()
            self.list_length = self._io.read_u2be()
            self._debug['list_length']['end'] = self._io.pos()
            self._debug['server_names']['start'] = self._io.pos()
            self.server_names = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['server_names']:
                    self._debug['server_names']['arr'] = []
                self._debug['server_names']['arr'].append({'start': self._io.pos()})
                _t_server_names = self._root.ServerName(self._io, self, self._root)
                _t_server_names._read()
                self.server_names.append(_t_server_names)
                self._debug['server_names']['arr'][len(self.server_names) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['server_names']['end'] = self._io.pos()


    class CipherSuites(KaitaiStruct):
        SEQ_FIELDS = ["len", "cipher_suites"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u2be()
            self._debug['len']['end'] = self._io.pos()
            self._debug['cipher_suites']['start'] = self._io.pos()
            self.cipher_suites = [None] * (self.len // 2)
            for i in range(self.len // 2):
                if not 'arr' in self._debug['cipher_suites']:
                    self._debug['cipher_suites']['arr'] = []
                self._debug['cipher_suites']['arr'].append({'start': self._io.pos()})
                self.cipher_suites[i] = self._io.read_u2be()
                self._debug['cipher_suites']['arr'][i]['end'] = self._io.pos()

            self._debug['cipher_suites']['end'] = self._io.pos()


    class CompressionMethods(KaitaiStruct):
        SEQ_FIELDS = ["len", "compression_methods"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u1()
            self._debug['len']['end'] = self._io.pos()
            self._debug['compression_methods']['start'] = self._io.pos()
            self.compression_methods = self._io.read_bytes(self.len)
            self._debug['compression_methods']['end'] = self._io.pos()


    class Alpn(KaitaiStruct):
        SEQ_FIELDS = ["ext_len", "alpn_protocols"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ext_len']['start'] = self._io.pos()
            self.ext_len = self._io.read_u2be()
            self._debug['ext_len']['end'] = self._io.pos()
            self._debug['alpn_protocols']['start'] = self._io.pos()
            self.alpn_protocols = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['alpn_protocols']:
                    self._debug['alpn_protocols']['arr'] = []
                self._debug['alpn_protocols']['arr'].append({'start': self._io.pos()})
                _t_alpn_protocols = self._root.Protocol(self._io, self, self._root)
                _t_alpn_protocols._read()
                self.alpn_protocols.append(_t_alpn_protocols)
                self._debug['alpn_protocols']['arr'][len(self.alpn_protocols) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['alpn_protocols']['end'] = self._io.pos()


    class Extensions(KaitaiStruct):
        SEQ_FIELDS = ["len", "extensions"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u2be()
            self._debug['len']['end'] = self._io.pos()
            self._debug['extensions']['start'] = self._io.pos()
            self.extensions = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['extensions']:
                    self._debug['extensions']['arr'] = []
                self._debug['extensions']['arr'].append({'start': self._io.pos()})
                _t_extensions = self._root.Extension(self._io, self, self._root)
                _t_extensions._read()
                self.extensions.append(_t_extensions)
                self._debug['extensions']['arr'][len(self.extensions) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['extensions']['end'] = self._io.pos()


    class Version(KaitaiStruct):
        SEQ_FIELDS = ["major", "minor"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['major']['start'] = self._io.pos()
            self.major = self._io.read_u1()
            self._debug['major']['end'] = self._io.pos()
            self._debug['minor']['start'] = self._io.pos()
            self.minor = self._io.read_u1()
            self._debug['minor']['end'] = self._io.pos()


    class Protocol(KaitaiStruct):
        SEQ_FIELDS = ["strlen", "name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['strlen']['start'] = self._io.pos()
            self.strlen = self._io.read_u1()
            self._debug['strlen']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = self._io.read_bytes(self.strlen)
            self._debug['name']['end'] = self._io.pos()


    class Extension(KaitaiStruct):
        SEQ_FIELDS = ["type", "len", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['type']['start'] = self._io.pos()
            self.type = self._io.read_u2be()
            self._debug['type']['end'] = self._io.pos()
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u2be()
            self._debug['len']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.type
            if _on == 0:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Sni(io, self, self._root)
                self.body._read()
            elif _on == 16:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Alpn(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes(self.len)
            self._debug['body']['end'] = self._io.pos()



