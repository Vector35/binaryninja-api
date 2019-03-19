# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class SystemdJournal(KaitaiStruct):
    """systemd, a popular user-space system/service management suite on Linux,
    offers logging functionality, storing incoming logs in a binary journal
    format.
    
    On live Linux system running systemd, these journals are typically located at:
    
    * /run/log/journal/machine-id/*.journal (volatile, lost after reboot)
    * /var/log/journal/machine-id/*.journal (persistent, but disabled by default on Debian / Ubuntu)
    
    .. seealso::
       Source - https://www.freedesktop.org/wiki/Software/systemd/journal-files/
    """

    class State(Enum):
        offline = 0
        online = 1
        archived = 2
    SEQ_FIELDS = ["header", "objects"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['header']['start'] = self._io.pos()
        self._raw_header = self._io.read_bytes(self.len_header)
        io = KaitaiStream(BytesIO(self._raw_header))
        self.header = self._root.Header(io, self, self._root)
        self.header._read()
        self._debug['header']['end'] = self._io.pos()
        self._debug['objects']['start'] = self._io.pos()
        self.objects = [None] * (self.header.num_objects)
        for i in range(self.header.num_objects):
            if not 'arr' in self._debug['objects']:
                self._debug['objects']['arr'] = []
            self._debug['objects']['arr'].append({'start': self._io.pos()})
            _t_objects = self._root.JournalObject(self._io, self, self._root)
            _t_objects._read()
            self.objects[i] = _t_objects
            self._debug['objects']['arr'][i]['end'] = self._io.pos()

        self._debug['objects']['end'] = self._io.pos()

    class Header(KaitaiStruct):
        SEQ_FIELDS = ["signature", "compatible_flags", "incompatible_flags", "state", "reserved", "file_id", "machine_id", "boot_id", "seqnum_id", "len_header", "len_arena", "ofs_data_hash_table", "len_data_hash_table", "ofs_field_hash_table", "len_field_hash_table", "ofs_tail_object", "num_objects", "num_entries", "tail_entry_seqnum", "head_entry_seqnum", "ofs_entry_array", "head_entry_realtime", "tail_entry_realtime", "tail_entry_monotonic", "num_data", "num_fields", "num_tags", "num_entry_arrays"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['signature']['start'] = self._io.pos()
            self.signature = self._io.ensure_fixed_contents(b"\x4C\x50\x4B\x53\x48\x48\x52\x48")
            self._debug['signature']['end'] = self._io.pos()
            self._debug['compatible_flags']['start'] = self._io.pos()
            self.compatible_flags = self._io.read_u4le()
            self._debug['compatible_flags']['end'] = self._io.pos()
            self._debug['incompatible_flags']['start'] = self._io.pos()
            self.incompatible_flags = self._io.read_u4le()
            self._debug['incompatible_flags']['end'] = self._io.pos()
            self._debug['state']['start'] = self._io.pos()
            self.state = KaitaiStream.resolve_enum(self._root.State, self._io.read_u1())
            self._debug['state']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bytes(7)
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['file_id']['start'] = self._io.pos()
            self.file_id = self._io.read_bytes(16)
            self._debug['file_id']['end'] = self._io.pos()
            self._debug['machine_id']['start'] = self._io.pos()
            self.machine_id = self._io.read_bytes(16)
            self._debug['machine_id']['end'] = self._io.pos()
            self._debug['boot_id']['start'] = self._io.pos()
            self.boot_id = self._io.read_bytes(16)
            self._debug['boot_id']['end'] = self._io.pos()
            self._debug['seqnum_id']['start'] = self._io.pos()
            self.seqnum_id = self._io.read_bytes(16)
            self._debug['seqnum_id']['end'] = self._io.pos()
            self._debug['len_header']['start'] = self._io.pos()
            self.len_header = self._io.read_u8le()
            self._debug['len_header']['end'] = self._io.pos()
            self._debug['len_arena']['start'] = self._io.pos()
            self.len_arena = self._io.read_u8le()
            self._debug['len_arena']['end'] = self._io.pos()
            self._debug['ofs_data_hash_table']['start'] = self._io.pos()
            self.ofs_data_hash_table = self._io.read_u8le()
            self._debug['ofs_data_hash_table']['end'] = self._io.pos()
            self._debug['len_data_hash_table']['start'] = self._io.pos()
            self.len_data_hash_table = self._io.read_u8le()
            self._debug['len_data_hash_table']['end'] = self._io.pos()
            self._debug['ofs_field_hash_table']['start'] = self._io.pos()
            self.ofs_field_hash_table = self._io.read_u8le()
            self._debug['ofs_field_hash_table']['end'] = self._io.pos()
            self._debug['len_field_hash_table']['start'] = self._io.pos()
            self.len_field_hash_table = self._io.read_u8le()
            self._debug['len_field_hash_table']['end'] = self._io.pos()
            self._debug['ofs_tail_object']['start'] = self._io.pos()
            self.ofs_tail_object = self._io.read_u8le()
            self._debug['ofs_tail_object']['end'] = self._io.pos()
            self._debug['num_objects']['start'] = self._io.pos()
            self.num_objects = self._io.read_u8le()
            self._debug['num_objects']['end'] = self._io.pos()
            self._debug['num_entries']['start'] = self._io.pos()
            self.num_entries = self._io.read_u8le()
            self._debug['num_entries']['end'] = self._io.pos()
            self._debug['tail_entry_seqnum']['start'] = self._io.pos()
            self.tail_entry_seqnum = self._io.read_u8le()
            self._debug['tail_entry_seqnum']['end'] = self._io.pos()
            self._debug['head_entry_seqnum']['start'] = self._io.pos()
            self.head_entry_seqnum = self._io.read_u8le()
            self._debug['head_entry_seqnum']['end'] = self._io.pos()
            self._debug['ofs_entry_array']['start'] = self._io.pos()
            self.ofs_entry_array = self._io.read_u8le()
            self._debug['ofs_entry_array']['end'] = self._io.pos()
            self._debug['head_entry_realtime']['start'] = self._io.pos()
            self.head_entry_realtime = self._io.read_u8le()
            self._debug['head_entry_realtime']['end'] = self._io.pos()
            self._debug['tail_entry_realtime']['start'] = self._io.pos()
            self.tail_entry_realtime = self._io.read_u8le()
            self._debug['tail_entry_realtime']['end'] = self._io.pos()
            self._debug['tail_entry_monotonic']['start'] = self._io.pos()
            self.tail_entry_monotonic = self._io.read_u8le()
            self._debug['tail_entry_monotonic']['end'] = self._io.pos()
            if not (self._io.is_eof()):
                self._debug['num_data']['start'] = self._io.pos()
                self.num_data = self._io.read_u8le()
                self._debug['num_data']['end'] = self._io.pos()

            if not (self._io.is_eof()):
                self._debug['num_fields']['start'] = self._io.pos()
                self.num_fields = self._io.read_u8le()
                self._debug['num_fields']['end'] = self._io.pos()

            if not (self._io.is_eof()):
                self._debug['num_tags']['start'] = self._io.pos()
                self.num_tags = self._io.read_u8le()
                self._debug['num_tags']['end'] = self._io.pos()

            if not (self._io.is_eof()):
                self._debug['num_entry_arrays']['start'] = self._io.pos()
                self.num_entry_arrays = self._io.read_u8le()
                self._debug['num_entry_arrays']['end'] = self._io.pos()



    class JournalObject(KaitaiStruct):
        """
        .. seealso::
           Source - https://www.freedesktop.org/wiki/Software/systemd/journal-files/#objects
        """

        class ObjectTypes(Enum):
            unused = 0
            data = 1
            field = 2
            entry = 3
            data_hash_table = 4
            field_hash_table = 5
            entry_array = 6
            tag = 7
        SEQ_FIELDS = ["padding", "object_type", "flags", "reserved", "len_object", "payload"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['padding']['start'] = self._io.pos()
            self.padding = self._io.read_bytes(((8 - self._io.pos()) % 8))
            self._debug['padding']['end'] = self._io.pos()
            self._debug['object_type']['start'] = self._io.pos()
            self.object_type = KaitaiStream.resolve_enum(self._root.JournalObject.ObjectTypes, self._io.read_u1())
            self._debug['object_type']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u1()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bytes(6)
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['len_object']['start'] = self._io.pos()
            self.len_object = self._io.read_u8le()
            self._debug['len_object']['end'] = self._io.pos()
            self._debug['payload']['start'] = self._io.pos()
            _on = self.object_type
            if _on == self._root.JournalObject.ObjectTypes.data:
                self._raw_payload = self._io.read_bytes((self.len_object - 16))
                io = KaitaiStream(BytesIO(self._raw_payload))
                self.payload = self._root.DataObject(io, self, self._root)
                self.payload._read()
            else:
                self.payload = self._io.read_bytes((self.len_object - 16))
            self._debug['payload']['end'] = self._io.pos()


    class DataObject(KaitaiStruct):
        """Data objects are designed to carry log payload, typically in
        form of a "key=value" string in `payload` attribute.
        
        .. seealso::
           Source - https://www.freedesktop.org/wiki/Software/systemd/journal-files/#dataobjects
        """
        SEQ_FIELDS = ["hash", "ofs_next_hash", "ofs_head_field", "ofs_entry", "ofs_entry_array", "num_entries", "payload"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['hash']['start'] = self._io.pos()
            self.hash = self._io.read_u8le()
            self._debug['hash']['end'] = self._io.pos()
            self._debug['ofs_next_hash']['start'] = self._io.pos()
            self.ofs_next_hash = self._io.read_u8le()
            self._debug['ofs_next_hash']['end'] = self._io.pos()
            self._debug['ofs_head_field']['start'] = self._io.pos()
            self.ofs_head_field = self._io.read_u8le()
            self._debug['ofs_head_field']['end'] = self._io.pos()
            self._debug['ofs_entry']['start'] = self._io.pos()
            self.ofs_entry = self._io.read_u8le()
            self._debug['ofs_entry']['end'] = self._io.pos()
            self._debug['ofs_entry_array']['start'] = self._io.pos()
            self.ofs_entry_array = self._io.read_u8le()
            self._debug['ofs_entry_array']['end'] = self._io.pos()
            self._debug['num_entries']['start'] = self._io.pos()
            self.num_entries = self._io.read_u8le()
            self._debug['num_entries']['end'] = self._io.pos()
            self._debug['payload']['start'] = self._io.pos()
            self.payload = self._io.read_bytes_full()
            self._debug['payload']['end'] = self._io.pos()

        @property
        def next_hash(self):
            if hasattr(self, '_m_next_hash'):
                return self._m_next_hash if hasattr(self, '_m_next_hash') else None

            if self.ofs_next_hash != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.ofs_next_hash)
                self._debug['_m_next_hash']['start'] = io.pos()
                self._m_next_hash = self._root.JournalObject(io, self, self._root)
                self._m_next_hash._read()
                self._debug['_m_next_hash']['end'] = io.pos()
                io.seek(_pos)

            return self._m_next_hash if hasattr(self, '_m_next_hash') else None

        @property
        def head_field(self):
            if hasattr(self, '_m_head_field'):
                return self._m_head_field if hasattr(self, '_m_head_field') else None

            if self.ofs_head_field != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.ofs_head_field)
                self._debug['_m_head_field']['start'] = io.pos()
                self._m_head_field = self._root.JournalObject(io, self, self._root)
                self._m_head_field._read()
                self._debug['_m_head_field']['end'] = io.pos()
                io.seek(_pos)

            return self._m_head_field if hasattr(self, '_m_head_field') else None

        @property
        def entry(self):
            if hasattr(self, '_m_entry'):
                return self._m_entry if hasattr(self, '_m_entry') else None

            if self.ofs_entry != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.ofs_entry)
                self._debug['_m_entry']['start'] = io.pos()
                self._m_entry = self._root.JournalObject(io, self, self._root)
                self._m_entry._read()
                self._debug['_m_entry']['end'] = io.pos()
                io.seek(_pos)

            return self._m_entry if hasattr(self, '_m_entry') else None

        @property
        def entry_array(self):
            if hasattr(self, '_m_entry_array'):
                return self._m_entry_array if hasattr(self, '_m_entry_array') else None

            if self.ofs_entry_array != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.ofs_entry_array)
                self._debug['_m_entry_array']['start'] = io.pos()
                self._m_entry_array = self._root.JournalObject(io, self, self._root)
                self._m_entry_array._read()
                self._debug['_m_entry_array']['end'] = io.pos()
                io.seek(_pos)

            return self._m_entry_array if hasattr(self, '_m_entry_array') else None


    @property
    def len_header(self):
        """Header length is used to set substream size, as it thus required
        prior to declaration of header.
        """
        if hasattr(self, '_m_len_header'):
            return self._m_len_header if hasattr(self, '_m_len_header') else None

        _pos = self._io.pos()
        self._io.seek(88)
        self._debug['_m_len_header']['start'] = self._io.pos()
        self._m_len_header = self._io.read_u8le()
        self._debug['_m_len_header']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_len_header if hasattr(self, '_m_len_header') else None

    @property
    def data_hash_table(self):
        if hasattr(self, '_m_data_hash_table'):
            return self._m_data_hash_table if hasattr(self, '_m_data_hash_table') else None

        _pos = self._io.pos()
        self._io.seek(self.header.ofs_data_hash_table)
        self._debug['_m_data_hash_table']['start'] = self._io.pos()
        self._m_data_hash_table = self._io.read_bytes(self.header.len_data_hash_table)
        self._debug['_m_data_hash_table']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_data_hash_table if hasattr(self, '_m_data_hash_table') else None

    @property
    def field_hash_table(self):
        if hasattr(self, '_m_field_hash_table'):
            return self._m_field_hash_table if hasattr(self, '_m_field_hash_table') else None

        _pos = self._io.pos()
        self._io.seek(self.header.ofs_field_hash_table)
        self._debug['_m_field_hash_table']['start'] = self._io.pos()
        self._m_field_hash_table = self._io.read_bytes(self.header.len_field_hash_table)
        self._debug['_m_field_hash_table']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_field_hash_table if hasattr(self, '_m_field_hash_table') else None


