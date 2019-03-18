from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class ApmPartitionTable(KaitaiStruct):
    """
    .. seealso::
       Specification taken from https://en.wikipedia.org/wiki/Apple_Partition_Map
    """
    SEQ_FIELDS = []
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        pass

    class PartitionEntry(KaitaiStruct):
        SEQ_FIELDS = ["magic", "reserved_1", "number_of_partitions", "partition_start", "partition_size", "partition_name", "partition_type", "data_start", "data_size", "partition_status", "boot_code_start", "boot_code_size", "boot_loader_address", "reserved_2", "boot_code_entry", "reserved_3", "boot_code_cksum", "processor_type"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x50\x4D")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['reserved_1']['start'] = self._io.pos()
            self.reserved_1 = self._io.read_bytes(2)
            self._debug['reserved_1']['end'] = self._io.pos()
            self._debug['number_of_partitions']['start'] = self._io.pos()
            self.number_of_partitions = self._io.read_u4be()
            self._debug['number_of_partitions']['end'] = self._io.pos()
            self._debug['partition_start']['start'] = self._io.pos()
            self.partition_start = self._io.read_u4be()
            self._debug['partition_start']['end'] = self._io.pos()
            self._debug['partition_size']['start'] = self._io.pos()
            self.partition_size = self._io.read_u4be()
            self._debug['partition_size']['end'] = self._io.pos()
            self._debug['partition_name']['start'] = self._io.pos()
            self.partition_name = (KaitaiStream.bytes_terminate(self._io.read_bytes(32), 0, False)).decode(u"ascii")
            self._debug['partition_name']['end'] = self._io.pos()
            self._debug['partition_type']['start'] = self._io.pos()
            self.partition_type = (KaitaiStream.bytes_terminate(self._io.read_bytes(32), 0, False)).decode(u"ascii")
            self._debug['partition_type']['end'] = self._io.pos()
            self._debug['data_start']['start'] = self._io.pos()
            self.data_start = self._io.read_u4be()
            self._debug['data_start']['end'] = self._io.pos()
            self._debug['data_size']['start'] = self._io.pos()
            self.data_size = self._io.read_u4be()
            self._debug['data_size']['end'] = self._io.pos()
            self._debug['partition_status']['start'] = self._io.pos()
            self.partition_status = self._io.read_u4be()
            self._debug['partition_status']['end'] = self._io.pos()
            self._debug['boot_code_start']['start'] = self._io.pos()
            self.boot_code_start = self._io.read_u4be()
            self._debug['boot_code_start']['end'] = self._io.pos()
            self._debug['boot_code_size']['start'] = self._io.pos()
            self.boot_code_size = self._io.read_u4be()
            self._debug['boot_code_size']['end'] = self._io.pos()
            self._debug['boot_loader_address']['start'] = self._io.pos()
            self.boot_loader_address = self._io.read_u4be()
            self._debug['boot_loader_address']['end'] = self._io.pos()
            self._debug['reserved_2']['start'] = self._io.pos()
            self.reserved_2 = self._io.read_bytes(4)
            self._debug['reserved_2']['end'] = self._io.pos()
            self._debug['boot_code_entry']['start'] = self._io.pos()
            self.boot_code_entry = self._io.read_u4be()
            self._debug['boot_code_entry']['end'] = self._io.pos()
            self._debug['reserved_3']['start'] = self._io.pos()
            self.reserved_3 = self._io.read_bytes(4)
            self._debug['reserved_3']['end'] = self._io.pos()
            self._debug['boot_code_cksum']['start'] = self._io.pos()
            self.boot_code_cksum = self._io.read_u4be()
            self._debug['boot_code_cksum']['end'] = self._io.pos()
            self._debug['processor_type']['start'] = self._io.pos()
            self.processor_type = (KaitaiStream.bytes_terminate(self._io.read_bytes(16), 0, False)).decode(u"ascii")
            self._debug['processor_type']['end'] = self._io.pos()

        @property
        def partition(self):
            if hasattr(self, '_m_partition'):
                return self._m_partition if hasattr(self, '_m_partition') else None

            if (self.partition_status & 1) != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek((self.partition_start * self._root.sector_size))
                self._debug['_m_partition']['start'] = io.pos()
                self._m_partition = io.read_bytes((self.partition_size * self._root.sector_size))
                self._debug['_m_partition']['end'] = io.pos()
                io.seek(_pos)

            return self._m_partition if hasattr(self, '_m_partition') else None

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data if hasattr(self, '_m_data') else None

            io = self._root._io
            _pos = io.pos()
            io.seek((self.data_start * self._root.sector_size))
            self._debug['_m_data']['start'] = io.pos()
            self._m_data = io.read_bytes((self.data_size * self._root.sector_size))
            self._debug['_m_data']['end'] = io.pos()
            io.seek(_pos)
            return self._m_data if hasattr(self, '_m_data') else None

        @property
        def boot_code(self):
            if hasattr(self, '_m_boot_code'):
                return self._m_boot_code if hasattr(self, '_m_boot_code') else None

            io = self._root._io
            _pos = io.pos()
            io.seek((self.boot_code_start * self._root.sector_size))
            self._debug['_m_boot_code']['start'] = io.pos()
            self._m_boot_code = io.read_bytes(self.boot_code_size)
            self._debug['_m_boot_code']['end'] = io.pos()
            io.seek(_pos)
            return self._m_boot_code if hasattr(self, '_m_boot_code') else None


    @property
    def sector_size(self):
        """0x200 (512) bytes for disks, 0x1000 (4096) bytes is not supported by APM
        0x800 (2048) bytes for CDROM
        """
        if hasattr(self, '_m_sector_size'):
            return self._m_sector_size if hasattr(self, '_m_sector_size') else None

        self._m_sector_size = 512
        return self._m_sector_size if hasattr(self, '_m_sector_size') else None

    @property
    def partition_lookup(self):
        """Every partition entry contains the number of partition entries.
        We parse the first entry, to know how many to parse, including the first one.
        No logic is given what to do if other entries have a different number.
        """
        if hasattr(self, '_m_partition_lookup'):
            return self._m_partition_lookup if hasattr(self, '_m_partition_lookup') else None

        io = self._root._io
        _pos = io.pos()
        io.seek(self._root.sector_size)
        self._debug['_m_partition_lookup']['start'] = io.pos()
        self._raw__m_partition_lookup = io.read_bytes(self.sector_size)
        io = KaitaiStream(BytesIO(self._raw__m_partition_lookup))
        self._m_partition_lookup = self._root.PartitionEntry(io, self, self._root)
        self._m_partition_lookup._read()
        self._debug['_m_partition_lookup']['end'] = io.pos()
        io.seek(_pos)
        return self._m_partition_lookup if hasattr(self, '_m_partition_lookup') else None

    @property
    def partition_entries(self):
        if hasattr(self, '_m_partition_entries'):
            return self._m_partition_entries if hasattr(self, '_m_partition_entries') else None

        io = self._root._io
        _pos = io.pos()
        io.seek(self._root.sector_size)
        self._debug['_m_partition_entries']['start'] = io.pos()
        self._raw__m_partition_entries = [None] * (self._root.partition_lookup.number_of_partitions)
        self._m_partition_entries = [None] * (self._root.partition_lookup.number_of_partitions)
        for i in range(self._root.partition_lookup.number_of_partitions):
            if not 'arr' in self._debug['_m_partition_entries']:
                self._debug['_m_partition_entries']['arr'] = []
            self._debug['_m_partition_entries']['arr'].append({'start': io.pos()})
            self._raw__m_partition_entries[i] = io.read_bytes(self.sector_size)
            io = KaitaiStream(BytesIO(self._raw__m_partition_entries[i]))
            _t__m_partition_entries = self._root.PartitionEntry(io, self, self._root)
            _t__m_partition_entries._read()
            self._m_partition_entries[i] = _t__m_partition_entries
            self._debug['_m_partition_entries']['arr'][i]['end'] = io.pos()

        self._debug['_m_partition_entries']['end'] = io.pos()
        io.seek(_pos)
        return self._m_partition_entries if hasattr(self, '_m_partition_entries') else None


