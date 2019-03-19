# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class AixUtmp(KaitaiStruct):
    """This spec can be used to parse utmp, wtmp and other similar as created by IBM AIX.
    
    .. seealso::
       Source - https://www.ibm.com/support/knowledgecenter/en/ssw_aix_71/com.ibm.aix.files/utmp.h.htm
    """

    class EntryType(Enum):
        empty = 0
        run_lvl = 1
        boot_time = 2
        old_time = 3
        new_time = 4
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
        self.records = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['records']:
                self._debug['records']['arr'] = []
            self._debug['records']['arr'].append({'start': self._io.pos()})
            _t_records = self._root.Record(self._io, self, self._root)
            _t_records._read()
            self.records.append(_t_records)
            self._debug['records']['arr'][len(self.records) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['records']['end'] = self._io.pos()

    class Record(KaitaiStruct):
        SEQ_FIELDS = ["user", "inittab_id", "device", "pid", "type", "timestamp", "exit_status", "hostname", "dbl_word_pad", "reserved_a", "reserved_v"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['user']['start'] = self._io.pos()
            self.user = (self._io.read_bytes(256)).decode(u"ascii")
            self._debug['user']['end'] = self._io.pos()
            self._debug['inittab_id']['start'] = self._io.pos()
            self.inittab_id = (self._io.read_bytes(14)).decode(u"ascii")
            self._debug['inittab_id']['end'] = self._io.pos()
            self._debug['device']['start'] = self._io.pos()
            self.device = (self._io.read_bytes(64)).decode(u"ascii")
            self._debug['device']['end'] = self._io.pos()
            self._debug['pid']['start'] = self._io.pos()
            self.pid = self._io.read_u8be()
            self._debug['pid']['end'] = self._io.pos()
            self._debug['type']['start'] = self._io.pos()
            self.type = KaitaiStream.resolve_enum(self._root.EntryType, self._io.read_s2be())
            self._debug['type']['end'] = self._io.pos()
            self._debug['timestamp']['start'] = self._io.pos()
            self.timestamp = self._io.read_s8be()
            self._debug['timestamp']['end'] = self._io.pos()
            self._debug['exit_status']['start'] = self._io.pos()
            self.exit_status = self._root.ExitStatus(self._io, self, self._root)
            self.exit_status._read()
            self._debug['exit_status']['end'] = self._io.pos()
            self._debug['hostname']['start'] = self._io.pos()
            self.hostname = (self._io.read_bytes(256)).decode(u"ascii")
            self._debug['hostname']['end'] = self._io.pos()
            self._debug['dbl_word_pad']['start'] = self._io.pos()
            self.dbl_word_pad = self._io.read_s4be()
            self._debug['dbl_word_pad']['end'] = self._io.pos()
            self._debug['reserved_a']['start'] = self._io.pos()
            self.reserved_a = self._io.read_bytes(8)
            self._debug['reserved_a']['end'] = self._io.pos()
            self._debug['reserved_v']['start'] = self._io.pos()
            self.reserved_v = self._io.read_bytes(24)
            self._debug['reserved_v']['end'] = self._io.pos()


    class ExitStatus(KaitaiStruct):
        SEQ_FIELDS = ["termination_code", "exit_code"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['termination_code']['start'] = self._io.pos()
            self.termination_code = self._io.read_s2be()
            self._debug['termination_code']['end'] = self._io.pos()
            self._debug['exit_code']['start'] = self._io.pos()
            self.exit_code = self._io.read_s2be()
            self._debug['exit_code']['end'] = self._io.pos()



