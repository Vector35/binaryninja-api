from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class MbrPartitionTable(KaitaiStruct):
    """MBR (Master Boot Record) partition table is a traditional way of
    MS-DOS to partition larger hard disc drives into distinct
    partitions.
    
    This table is stored in the end of the boot sector (first sector) of
    the drive, after the bootstrap code. Original DOS 2.0 specification
    allowed only 4 partitions per disc, but DOS 3.2 introduced concept
    of "extended partitions", which work as nested extra "boot records"
    which are pointed to by original ("primary") partitions in MBR.
    """
    SEQ_FIELDS = ["bootstrap_code", "partitions", "boot_signature"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['bootstrap_code']['start'] = self._io.pos()
        self.bootstrap_code = self._io.read_bytes(446)
        self._debug['bootstrap_code']['end'] = self._io.pos()
        self._debug['partitions']['start'] = self._io.pos()
        self.partitions = [None] * (4)
        for i in range(4):
            if not 'arr' in self._debug['partitions']:
                self._debug['partitions']['arr'] = []
            self._debug['partitions']['arr'].append({'start': self._io.pos()})
            _t_partitions = self._root.PartitionEntry(self._io, self, self._root)
            _t_partitions._read()
            self.partitions[i] = _t_partitions
            self._debug['partitions']['arr'][i]['end'] = self._io.pos()

        self._debug['partitions']['end'] = self._io.pos()
        self._debug['boot_signature']['start'] = self._io.pos()
        self.boot_signature = self._io.ensure_fixed_contents(b"\x55\xAA")
        self._debug['boot_signature']['end'] = self._io.pos()

    class PartitionEntry(KaitaiStruct):
        SEQ_FIELDS = ["status", "chs_start", "partition_type", "chs_end", "lba_start", "num_sectors"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['status']['start'] = self._io.pos()
            self.status = self._io.read_u1()
            self._debug['status']['end'] = self._io.pos()
            self._debug['chs_start']['start'] = self._io.pos()
            self.chs_start = self._root.Chs(self._io, self, self._root)
            self.chs_start._read()
            self._debug['chs_start']['end'] = self._io.pos()
            self._debug['partition_type']['start'] = self._io.pos()
            self.partition_type = self._io.read_u1()
            self._debug['partition_type']['end'] = self._io.pos()
            self._debug['chs_end']['start'] = self._io.pos()
            self.chs_end = self._root.Chs(self._io, self, self._root)
            self.chs_end._read()
            self._debug['chs_end']['end'] = self._io.pos()
            self._debug['lba_start']['start'] = self._io.pos()
            self.lba_start = self._io.read_u4le()
            self._debug['lba_start']['end'] = self._io.pos()
            self._debug['num_sectors']['start'] = self._io.pos()
            self.num_sectors = self._io.read_u4le()
            self._debug['num_sectors']['end'] = self._io.pos()


    class Chs(KaitaiStruct):
        SEQ_FIELDS = ["head", "b2", "b3"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['head']['start'] = self._io.pos()
            self.head = self._io.read_u1()
            self._debug['head']['end'] = self._io.pos()
            self._debug['b2']['start'] = self._io.pos()
            self.b2 = self._io.read_u1()
            self._debug['b2']['end'] = self._io.pos()
            self._debug['b3']['start'] = self._io.pos()
            self.b3 = self._io.read_u1()
            self._debug['b3']['end'] = self._io.pos()

        @property
        def sector(self):
            if hasattr(self, '_m_sector'):
                return self._m_sector if hasattr(self, '_m_sector') else None

            self._m_sector = (self.b2 & 63)
            return self._m_sector if hasattr(self, '_m_sector') else None

        @property
        def cylinder(self):
            if hasattr(self, '_m_cylinder'):
                return self._m_cylinder if hasattr(self, '_m_cylinder') else None

            self._m_cylinder = (self.b3 + ((self.b2 & 192) << 2))
            return self._m_cylinder if hasattr(self, '_m_cylinder') else None



