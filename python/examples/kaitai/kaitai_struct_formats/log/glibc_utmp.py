from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class GlibcUtmp(KaitaiStruct):

    class EntryType(Enum):
        empty = 0
        run_lvl = 1
        boot_time = 2
        new_time = 3
        old_time = 4
        init_process = 5
        login_process = 6
        user_process = 7
        dead_process = 8
        accounting = 9
    SEQ_FIELDS = ["records"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['records']['start'] = self._io.pos()
        self._raw_records = []
        self.records = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['records']:
                self._debug['records']['arr'] = []
            self._debug['records']['arr'].append({'start': self._io.pos()})
            self._raw_records.append(self._io.read_bytes(384))
            io = KaitaiStream(BytesIO(self._raw_records[-1]))
            _t_records = self._root.Record(io, self, self._root)
            _t_records._read()
            self.records.append(_t_records)
            self._debug['records']['arr'][len(self.records) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['records']['end'] = self._io.pos()

    class Record(KaitaiStruct):
        SEQ_FIELDS = ["ut_type", "pid", "line", "id", "user", "host", "exit", "session", "tv", "addr_v6", "reserved"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ut_type']['start'] = self._io.pos()
            self.ut_type = KaitaiStream.resolve_enum(self._root.EntryType, self._io.read_s4le())
            self._debug['ut_type']['end'] = self._io.pos()
            self._debug['pid']['start'] = self._io.pos()
            self.pid = self._io.read_u4le()
            self._debug['pid']['end'] = self._io.pos()
            self._debug['line']['start'] = self._io.pos()
            self.line = (self._io.read_bytes(32)).decode(u"UTF-8")
            self._debug['line']['end'] = self._io.pos()
            self._debug['id']['start'] = self._io.pos()
            self.id = (self._io.read_bytes(4)).decode(u"UTF-8")
            self._debug['id']['end'] = self._io.pos()
            self._debug['user']['start'] = self._io.pos()
            self.user = (self._io.read_bytes(32)).decode(u"UTF-8")
            self._debug['user']['end'] = self._io.pos()
            self._debug['host']['start'] = self._io.pos()
            self.host = (self._io.read_bytes(256)).decode(u"UTF-8")
            self._debug['host']['end'] = self._io.pos()
            self._debug['exit']['start'] = self._io.pos()
            self.exit = self._io.read_u4le()
            self._debug['exit']['end'] = self._io.pos()
            self._debug['session']['start'] = self._io.pos()
            self.session = self._io.read_s4le()
            self._debug['session']['end'] = self._io.pos()
            self._debug['tv']['start'] = self._io.pos()
            self.tv = self._root.Timeval(self._io, self, self._root)
            self.tv._read()
            self._debug['tv']['end'] = self._io.pos()
            self._debug['addr_v6']['start'] = self._io.pos()
            self.addr_v6 = self._io.read_bytes(16)
            self._debug['addr_v6']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bytes(20)
            self._debug['reserved']['end'] = self._io.pos()


    class Timeval(KaitaiStruct):
        SEQ_FIELDS = ["sec", "usec"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['sec']['start'] = self._io.pos()
            self.sec = self._io.read_s4le()
            self._debug['sec']['end'] = self._io.pos()
            self._debug['usec']['start'] = self._io.pos()
            self.usec = self._io.read_s4le()
            self._debug['usec']['end'] = self._io.pos()



