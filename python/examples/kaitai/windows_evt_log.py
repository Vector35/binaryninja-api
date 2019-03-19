# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections
from enum import Enum


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class WindowsEvtLog(KaitaiStruct):
    """EVT files are Windows Event Log files written by older Windows
    operating systems (2000, XP, 2003). They are used as binary log
    files by several major Windows subsystems and
    applications. Typically, several of them can be found in
    `%WINDIR%\system32\config` directory:
    
    * Application = `AppEvent.evt`
    * System = `SysEvent.evt`
    * Security = `SecEvent.evt`
    
    Alternatively, one can export any system event log as distinct .evt
    file using relevant option in Event Viewer application.
    
    A Windows application can submit an entry into these logs using
    [ReportEvent](https://msdn.microsoft.com/en-us/library/aa363679(v=vs.85).aspx)
    function of Windows API.
    
    Internally, EVT files consist of a fixed-size header and event
    records. There are several usage scenarios (non-wrapping vs wrapping
    log files) which result in slightly different organization of
    records.
    
    .. seealso::
       Source - https://msdn.microsoft.com/en-us/library/bb309026(v=vs.85).aspx
    """
    SEQ_FIELDS = ["header", "records"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self.header = self._root.Header(self._io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()
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

    class Header(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/bb309024(v=vs.85).aspx
        """
        SEQ_FIELDS = ["len_header", "magic", "version_major", "version_minor", "ofs_start", "ofs_end", "cur_rec_idx", "oldest_rec_idx", "len_file_max", "flags", "retention", "len_header_2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_header']['start'] = self._io.pos()
            self.len_header = self._io.read_u4le()
            self._debug['len_header']['end'] = self._io.pos()
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x4C\x66\x4C\x65")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['version_major']['start'] = self._io.pos()
            self.version_major = self._io.read_u4le()
            self._debug['version_major']['end'] = self._io.pos()
            self._debug['version_minor']['start'] = self._io.pos()
            self.version_minor = self._io.read_u4le()
            self._debug['version_minor']['end'] = self._io.pos()
            self._debug['ofs_start']['start'] = self._io.pos()
            self.ofs_start = self._io.read_u4le()
            self._debug['ofs_start']['end'] = self._io.pos()
            self._debug['ofs_end']['start'] = self._io.pos()
            self.ofs_end = self._io.read_u4le()
            self._debug['ofs_end']['end'] = self._io.pos()
            self._debug['cur_rec_idx']['start'] = self._io.pos()
            self.cur_rec_idx = self._io.read_u4le()
            self._debug['cur_rec_idx']['end'] = self._io.pos()
            self._debug['oldest_rec_idx']['start'] = self._io.pos()
            self.oldest_rec_idx = self._io.read_u4le()
            self._debug['oldest_rec_idx']['end'] = self._io.pos()
            self._debug['len_file_max']['start'] = self._io.pos()
            self.len_file_max = self._io.read_u4le()
            self._debug['len_file_max']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._root.Header.Flags(self._io, self, self._root)
            self.flags._read()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['retention']['start'] = self._io.pos()
            self.retention = self._io.read_u4le()
            self._debug['retention']['end'] = self._io.pos()
            self._debug['len_header_2']['start'] = self._io.pos()
            self.len_header_2 = self._io.read_u4le()
            self._debug['len_header_2']['end'] = self._io.pos()

        class Flags(KaitaiStruct):
            SEQ_FIELDS = ["reserved", "archive", "log_full", "wrap", "dirty"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)

            def _read(self):
                self._debug['reserved']['start'] = self._io.pos()
                self.reserved = self._io.read_bits_int(28)
                self._debug['reserved']['end'] = self._io.pos()
                self._debug['archive']['start'] = self._io.pos()
                self.archive = self._io.read_bits_int(1) != 0
                self._debug['archive']['end'] = self._io.pos()
                self._debug['log_full']['start'] = self._io.pos()
                self.log_full = self._io.read_bits_int(1) != 0
                self._debug['log_full']['end'] = self._io.pos()
                self._debug['wrap']['start'] = self._io.pos()
                self.wrap = self._io.read_bits_int(1) != 0
                self._debug['wrap']['end'] = self._io.pos()
                self._debug['dirty']['start'] = self._io.pos()
                self.dirty = self._io.read_bits_int(1) != 0
                self._debug['dirty']['end'] = self._io.pos()



    class Record(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/windows/desktop/aa363646(v=vs.85).aspx
        """
        SEQ_FIELDS = ["len_record", "type", "body", "len_record2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_record']['start'] = self._io.pos()
            self.len_record = self._io.read_u4le()
            self._debug['len_record']['end'] = self._io.pos()
            self._debug['type']['start'] = self._io.pos()
            self.type = self._io.read_u4le()
            self._debug['type']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.type
            if _on == 1699505740:
                self._raw_body = self._io.read_bytes((self.len_record - 12))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.RecordBody(io, self, self._root)
                self.body._read()
            elif _on == 286331153:
                self._raw_body = self._io.read_bytes((self.len_record - 12))
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.CursorRecordBody(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes((self.len_record - 12))
            self._debug['body']['end'] = self._io.pos()
            self._debug['len_record2']['start'] = self._io.pos()
            self.len_record2 = self._io.read_u4le()
            self._debug['len_record2']['end'] = self._io.pos()


    class RecordBody(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/windows/desktop/aa363646(v=vs.85).aspx
        """

        class EventTypes(Enum):
            error = 1
            audit_failure = 2
            audit_success = 3
            info = 4
            warning = 5
        SEQ_FIELDS = ["idx", "time_generated", "time_written", "event_id", "event_type", "num_strings", "event_category", "reserved", "ofs_strings", "len_user_sid", "ofs_user_sid", "len_data", "ofs_data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['idx']['start'] = self._io.pos()
            self.idx = self._io.read_u4le()
            self._debug['idx']['end'] = self._io.pos()
            self._debug['time_generated']['start'] = self._io.pos()
            self.time_generated = self._io.read_u4le()
            self._debug['time_generated']['end'] = self._io.pos()
            self._debug['time_written']['start'] = self._io.pos()
            self.time_written = self._io.read_u4le()
            self._debug['time_written']['end'] = self._io.pos()
            self._debug['event_id']['start'] = self._io.pos()
            self.event_id = self._io.read_u4le()
            self._debug['event_id']['end'] = self._io.pos()
            self._debug['event_type']['start'] = self._io.pos()
            self.event_type = KaitaiStream.resolve_enum(self._root.RecordBody.EventTypes, self._io.read_u2le())
            self._debug['event_type']['end'] = self._io.pos()
            self._debug['num_strings']['start'] = self._io.pos()
            self.num_strings = self._io.read_u2le()
            self._debug['num_strings']['end'] = self._io.pos()
            self._debug['event_category']['start'] = self._io.pos()
            self.event_category = self._io.read_u2le()
            self._debug['event_category']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bytes(6)
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['ofs_strings']['start'] = self._io.pos()
            self.ofs_strings = self._io.read_u4le()
            self._debug['ofs_strings']['end'] = self._io.pos()
            self._debug['len_user_sid']['start'] = self._io.pos()
            self.len_user_sid = self._io.read_u4le()
            self._debug['len_user_sid']['end'] = self._io.pos()
            self._debug['ofs_user_sid']['start'] = self._io.pos()
            self.ofs_user_sid = self._io.read_u4le()
            self._debug['ofs_user_sid']['end'] = self._io.pos()
            self._debug['len_data']['start'] = self._io.pos()
            self.len_data = self._io.read_u4le()
            self._debug['len_data']['end'] = self._io.pos()
            self._debug['ofs_data']['start'] = self._io.pos()
            self.ofs_data = self._io.read_u4le()
            self._debug['ofs_data']['end'] = self._io.pos()

        @property
        def user_sid(self):
            if hasattr(self, '_m_user_sid'):
                return self._m_user_sid if hasattr(self, '_m_user_sid') else None

            _pos = self._io.pos()
            self._io.seek((self.ofs_user_sid - 8))
            self._debug['_m_user_sid']['start'] = self._io.pos()
            self._m_user_sid = self._io.read_bytes(self.len_user_sid)
            self._debug['_m_user_sid']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_user_sid if hasattr(self, '_m_user_sid') else None

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data if hasattr(self, '_m_data') else None

            _pos = self._io.pos()
            self._io.seek((self.ofs_data - 8))
            self._debug['_m_data']['start'] = self._io.pos()
            self._m_data = self._io.read_bytes(self.len_data)
            self._debug['_m_data']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_data if hasattr(self, '_m_data') else None


    class CursorRecordBody(KaitaiStruct):
        """
        .. seealso::
           Source - http://www.forensicswiki.org/wiki/Windows_Event_Log_(EVT)#Cursor_Record
        """
        SEQ_FIELDS = ["magic", "ofs_first_record", "ofs_next_record", "idx_next_record", "idx_first_record"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x22\x22\x22\x22\x33\x33\x33\x33\x44\x44\x44\x44")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['ofs_first_record']['start'] = self._io.pos()
            self.ofs_first_record = self._io.read_u4le()
            self._debug['ofs_first_record']['end'] = self._io.pos()
            self._debug['ofs_next_record']['start'] = self._io.pos()
            self.ofs_next_record = self._io.read_u4le()
            self._debug['ofs_next_record']['end'] = self._io.pos()
            self._debug['idx_next_record']['start'] = self._io.pos()
            self.idx_next_record = self._io.read_u4le()
            self._debug['idx_next_record']['end'] = self._io.pos()
            self._debug['idx_first_record']['start'] = self._io.pos()
            self.idx_first_record = self._io.read_u4le()
            self._debug['idx_first_record']['end'] = self._io.pos()



