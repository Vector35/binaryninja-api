from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ....kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Specpr(KaitaiStruct):
    """Specpr records are fixed format, 1536 bytes/record. Record number
    counting starts at 0. Binary data are in IEEE format real numbers
    and non-byte swapped integers (compatiible with all Sun
    Microsystems, and Hewlett Packard workstations (Intel and some DEC
    machines are byte swapped relative to Suns and HPs). Each record may
    contain different information according to the following scheme.
    
    You can get some library of spectra from
    ftp://ftpext.cr.usgs.gov/pub/cr/co/denver/speclab/pub/spectral.library/splib06.library/
    """

    class RecordType(Enum):
        data_initial = 0
        text_initial = 1
        data_continuation = 2
        text_continuation = 3
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

    class DataInitial(KaitaiStruct):
        SEQ_FIELDS = ["ids", "iscta", "isctb", "jdatea", "jdateb", "istb", "isra", "isdec", "itchan", "irmas", "revs", "iband", "irwav", "irespt", "irecno", "itpntr", "ihist", "mhist", "nruns", "siangl", "seangl", "sphase", "iwtrns", "itimch", "xnrm", "scatim", "timint", "tempd", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ids']['start'] = self._io.pos()
            self.ids = self._root.Identifiers(self._io, self, self._root)
            self.ids._read()
            self._debug['ids']['end'] = self._io.pos()
            self._debug['iscta']['start'] = self._io.pos()
            self.iscta = self._root.CoarseTimestamp(self._io, self, self._root)
            self.iscta._read()
            self._debug['iscta']['end'] = self._io.pos()
            self._debug['isctb']['start'] = self._io.pos()
            self.isctb = self._root.CoarseTimestamp(self._io, self, self._root)
            self.isctb._read()
            self._debug['isctb']['end'] = self._io.pos()
            self._debug['jdatea']['start'] = self._io.pos()
            self.jdatea = self._io.read_s4be()
            self._debug['jdatea']['end'] = self._io.pos()
            self._debug['jdateb']['start'] = self._io.pos()
            self.jdateb = self._io.read_s4be()
            self._debug['jdateb']['end'] = self._io.pos()
            self._debug['istb']['start'] = self._io.pos()
            self.istb = self._root.CoarseTimestamp(self._io, self, self._root)
            self.istb._read()
            self._debug['istb']['end'] = self._io.pos()
            self._debug['isra']['start'] = self._io.pos()
            self.isra = self._io.read_s4be()
            self._debug['isra']['end'] = self._io.pos()
            self._debug['isdec']['start'] = self._io.pos()
            self.isdec = self._io.read_s4be()
            self._debug['isdec']['end'] = self._io.pos()
            self._debug['itchan']['start'] = self._io.pos()
            self.itchan = self._io.read_s4be()
            self._debug['itchan']['end'] = self._io.pos()
            self._debug['irmas']['start'] = self._io.pos()
            self.irmas = self._io.read_s4be()
            self._debug['irmas']['end'] = self._io.pos()
            self._debug['revs']['start'] = self._io.pos()
            self.revs = self._io.read_s4be()
            self._debug['revs']['end'] = self._io.pos()
            self._debug['iband']['start'] = self._io.pos()
            self.iband = [None] * (2)
            for i in range(2):
                if not 'arr' in self._debug['iband']:
                    self._debug['iband']['arr'] = []
                self._debug['iband']['arr'].append({'start': self._io.pos()})
                self.iband[i] = self._io.read_s4be()
                self._debug['iband']['arr'][i]['end'] = self._io.pos()

            self._debug['iband']['end'] = self._io.pos()
            self._debug['irwav']['start'] = self._io.pos()
            self.irwav = self._io.read_s4be()
            self._debug['irwav']['end'] = self._io.pos()
            self._debug['irespt']['start'] = self._io.pos()
            self.irespt = self._io.read_s4be()
            self._debug['irespt']['end'] = self._io.pos()
            self._debug['irecno']['start'] = self._io.pos()
            self.irecno = self._io.read_s4be()
            self._debug['irecno']['end'] = self._io.pos()
            self._debug['itpntr']['start'] = self._io.pos()
            self.itpntr = self._io.read_s4be()
            self._debug['itpntr']['end'] = self._io.pos()
            self._debug['ihist']['start'] = self._io.pos()
            self.ihist = (KaitaiStream.bytes_strip_right(self._io.read_bytes(60), 32)).decode(u"ascii")
            self._debug['ihist']['end'] = self._io.pos()
            self._debug['mhist']['start'] = self._io.pos()
            self.mhist = [None] * (4)
            for i in range(4):
                if not 'arr' in self._debug['mhist']:
                    self._debug['mhist']['arr'] = []
                self._debug['mhist']['arr'].append({'start': self._io.pos()})
                self.mhist[i] = (self._io.read_bytes(74)).decode(u"ascii")
                self._debug['mhist']['arr'][i]['end'] = self._io.pos()

            self._debug['mhist']['end'] = self._io.pos()
            self._debug['nruns']['start'] = self._io.pos()
            self.nruns = self._io.read_s4be()
            self._debug['nruns']['end'] = self._io.pos()
            self._debug['siangl']['start'] = self._io.pos()
            self.siangl = self._root.IllumAngle(self._io, self, self._root)
            self.siangl._read()
            self._debug['siangl']['end'] = self._io.pos()
            self._debug['seangl']['start'] = self._io.pos()
            self.seangl = self._root.IllumAngle(self._io, self, self._root)
            self.seangl._read()
            self._debug['seangl']['end'] = self._io.pos()
            self._debug['sphase']['start'] = self._io.pos()
            self.sphase = self._io.read_s4be()
            self._debug['sphase']['end'] = self._io.pos()
            self._debug['iwtrns']['start'] = self._io.pos()
            self.iwtrns = self._io.read_s4be()
            self._debug['iwtrns']['end'] = self._io.pos()
            self._debug['itimch']['start'] = self._io.pos()
            self.itimch = self._io.read_s4be()
            self._debug['itimch']['end'] = self._io.pos()
            self._debug['xnrm']['start'] = self._io.pos()
            self.xnrm = self._io.read_f4be()
            self._debug['xnrm']['end'] = self._io.pos()
            self._debug['scatim']['start'] = self._io.pos()
            self.scatim = self._io.read_f4be()
            self._debug['scatim']['end'] = self._io.pos()
            self._debug['timint']['start'] = self._io.pos()
            self.timint = self._io.read_f4be()
            self._debug['timint']['end'] = self._io.pos()
            self._debug['tempd']['start'] = self._io.pos()
            self.tempd = self._io.read_f4be()
            self._debug['tempd']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            self.data = [None] * (256)
            for i in range(256):
                if not 'arr' in self._debug['data']:
                    self._debug['data']['arr'] = []
                self._debug['data']['arr'].append({'start': self._io.pos()})
                self.data[i] = self._io.read_f4be()
                self._debug['data']['arr'][i]['end'] = self._io.pos()

            self._debug['data']['end'] = self._io.pos()

        @property
        def phase_angle_arcsec(self):
            """The phase angle between iangl and eangl in seconds."""
            if hasattr(self, '_m_phase_angle_arcsec'):
                return self._m_phase_angle_arcsec if hasattr(self, '_m_phase_angle_arcsec') else None

            self._m_phase_angle_arcsec = (self.sphase / 1500)
            return self._m_phase_angle_arcsec if hasattr(self, '_m_phase_angle_arcsec') else None


    class CoarseTimestamp(KaitaiStruct):
        SEQ_FIELDS = ["scaled_seconds"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['scaled_seconds']['start'] = self._io.pos()
            self.scaled_seconds = self._io.read_s4be()
            self._debug['scaled_seconds']['end'] = self._io.pos()

        @property
        def seconds(self):
            if hasattr(self, '_m_seconds'):
                return self._m_seconds if hasattr(self, '_m_seconds') else None

            self._m_seconds = (self.scaled_seconds * 24000)
            return self._m_seconds if hasattr(self, '_m_seconds') else None


    class Icflag(KaitaiStruct):
        """it is big endian."""
        SEQ_FIELDS = ["reserved", "isctb_type", "iscta_type", "coordinate_mode", "errors", "text", "continuation"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_bits_int(26)
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['isctb_type']['start'] = self._io.pos()
            self.isctb_type = self._io.read_bits_int(1) != 0
            self._debug['isctb_type']['end'] = self._io.pos()
            self._debug['iscta_type']['start'] = self._io.pos()
            self.iscta_type = self._io.read_bits_int(1) != 0
            self._debug['iscta_type']['end'] = self._io.pos()
            self._debug['coordinate_mode']['start'] = self._io.pos()
            self.coordinate_mode = self._io.read_bits_int(1) != 0
            self._debug['coordinate_mode']['end'] = self._io.pos()
            self._debug['errors']['start'] = self._io.pos()
            self.errors = self._io.read_bits_int(1) != 0
            self._debug['errors']['end'] = self._io.pos()
            self._debug['text']['start'] = self._io.pos()
            self.text = self._io.read_bits_int(1) != 0
            self._debug['text']['end'] = self._io.pos()
            self._debug['continuation']['start'] = self._io.pos()
            self.continuation = self._io.read_bits_int(1) != 0
            self._debug['continuation']['end'] = self._io.pos()

        @property
        def type(self):
            if hasattr(self, '_m_type'):
                return self._m_type if hasattr(self, '_m_type') else None

            self._m_type = KaitaiStream.resolve_enum(self._root.RecordType, ((int(self.text) * 1) + (int(self.continuation) * 2)))
            return self._m_type if hasattr(self, '_m_type') else None


    class DataContinuation(KaitaiStruct):
        SEQ_FIELDS = ["cdata"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['cdata']['start'] = self._io.pos()
            self.cdata = [None] * (383)
            for i in range(383):
                if not 'arr' in self._debug['cdata']:
                    self._debug['cdata']['arr'] = []
                self._debug['cdata']['arr'].append({'start': self._io.pos()})
                self.cdata[i] = self._io.read_f4be()
                self._debug['cdata']['arr'][i]['end'] = self._io.pos()

            self._debug['cdata']['end'] = self._io.pos()


    class Identifiers(KaitaiStruct):
        SEQ_FIELDS = ["ititle", "usernm"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ititle']['start'] = self._io.pos()
            self.ititle = (KaitaiStream.bytes_strip_right(self._io.read_bytes(40), 32)).decode(u"ascii")
            self._debug['ititle']['end'] = self._io.pos()
            self._debug['usernm']['start'] = self._io.pos()
            self.usernm = (self._io.read_bytes(8)).decode(u"ascii")
            self._debug['usernm']['end'] = self._io.pos()


    class IllumAngle(KaitaiStruct):
        SEQ_FIELDS = ["angl"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['angl']['start'] = self._io.pos()
            self.angl = self._io.read_s4be()
            self._debug['angl']['end'] = self._io.pos()

        @property
        def seconds_total(self):
            if hasattr(self, '_m_seconds_total'):
                return self._m_seconds_total if hasattr(self, '_m_seconds_total') else None

            self._m_seconds_total = self.angl // 6000
            return self._m_seconds_total if hasattr(self, '_m_seconds_total') else None

        @property
        def minutes_total(self):
            if hasattr(self, '_m_minutes_total'):
                return self._m_minutes_total if hasattr(self, '_m_minutes_total') else None

            self._m_minutes_total = self.seconds_total // 60
            return self._m_minutes_total if hasattr(self, '_m_minutes_total') else None

        @property
        def degrees_total(self):
            if hasattr(self, '_m_degrees_total'):
                return self._m_degrees_total if hasattr(self, '_m_degrees_total') else None

            self._m_degrees_total = self.minutes_total // 60
            return self._m_degrees_total if hasattr(self, '_m_degrees_total') else None


    class TextInitial(KaitaiStruct):
        SEQ_FIELDS = ["ids", "itxtpt", "itxtch", "itext"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['ids']['start'] = self._io.pos()
            self.ids = self._root.Identifiers(self._io, self, self._root)
            self.ids._read()
            self._debug['ids']['end'] = self._io.pos()
            self._debug['itxtpt']['start'] = self._io.pos()
            self.itxtpt = self._io.read_u4be()
            self._debug['itxtpt']['end'] = self._io.pos()
            self._debug['itxtch']['start'] = self._io.pos()
            self.itxtch = self._io.read_s4be()
            self._debug['itxtch']['end'] = self._io.pos()
            self._debug['itext']['start'] = self._io.pos()
            self.itext = (self._io.read_bytes(1476)).decode(u"ascii")
            self._debug['itext']['end'] = self._io.pos()


    class Record(KaitaiStruct):
        SEQ_FIELDS = ["icflag", "content"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['icflag']['start'] = self._io.pos()
            self.icflag = self._root.Icflag(self._io, self, self._root)
            self.icflag._read()
            self._debug['icflag']['end'] = self._io.pos()
            self._debug['content']['start'] = self._io.pos()
            _on = self.icflag.type
            if _on == self._root.RecordType.data_initial:
                self._raw_content = self._io.read_bytes((1536 - 4))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.DataInitial(io, self, self._root)
                self.content._read()
            elif _on == self._root.RecordType.data_continuation:
                self._raw_content = self._io.read_bytes((1536 - 4))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.DataContinuation(io, self, self._root)
                self.content._read()
            elif _on == self._root.RecordType.text_continuation:
                self._raw_content = self._io.read_bytes((1536 - 4))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.TextContinuation(io, self, self._root)
                self.content._read()
            elif _on == self._root.RecordType.text_initial:
                self._raw_content = self._io.read_bytes((1536 - 4))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.TextInitial(io, self, self._root)
                self.content._read()
            else:
                self.content = self._io.read_bytes((1536 - 4))
            self._debug['content']['end'] = self._io.pos()


    class TextContinuation(KaitaiStruct):
        SEQ_FIELDS = ["tdata"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['tdata']['start'] = self._io.pos()
            self.tdata = (self._io.read_bytes(1532)).decode(u"ascii")
            self._debug['tdata']['end'] = self._io.pos()



