from __future__ import absolute_import
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from ...kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class QuicktimeMov(KaitaiStruct):
    """
    .. seealso::
       Source - https://developer.apple.com/library/content/documentation/QuickTime/QTFF/QTFFChap1/qtff1.html#//apple_ref/doc/uid/TP40000939-CH203-BBCGDDDF
    """

    class AtomType(Enum):
        xtra = 1484026465
        dinf = 1684631142
        dref = 1685218662
        edts = 1701082227
        elst = 1701606260
        free = 1718773093
        ftyp = 1718909296
        hdlr = 1751411826
        iods = 1768907891
        mdat = 1835295092
        mdhd = 1835296868
        mdia = 1835297121
        meta = 1835365473
        minf = 1835626086
        moof = 1836019558
        moov = 1836019574
        mvhd = 1836476516
        smhd = 1936549988
        stbl = 1937007212
        stco = 1937007471
        stsc = 1937011555
        stsd = 1937011556
        stsz = 1937011578
        stts = 1937011827
        tkhd = 1953196132
        traf = 1953653094
        trak = 1953653099
        tref = 1953654118
        udta = 1969517665
        vmhd = 1986881636

    class Brand(Enum):
        x_3g2a = 862401121
        x_3ge6 = 862414134
        x_3ge9 = 862414137
        x_3gf9 = 862414393
        x_3gg6 = 862414646
        x_3gg9 = 862414649
        x_3gh9 = 862414905
        x_3gm9 = 862416185
        x_3gp4 = 862416948
        x_3gp5 = 862416949
        x_3gp6 = 862416950
        x_3gp7 = 862416951
        x_3gp8 = 862416952
        x_3gp9 = 862416953
        x_3gr6 = 862417462
        x_3gr9 = 862417465
        x_3gs6 = 862417718
        x_3gs9 = 862417721
        x_3gt9 = 862417977
        arri = 1095914057
        caep = 1128351056
        cdes = 1128555891
        j2p0 = 1244811312
        j2p1 = 1244811313
        lcag = 1279476039
        m4a = 1295270176
        m4b = 1295270432
        m4p = 1295274016
        m4v = 1295275552
        mfsm = 1296454477
        mgsv = 1296520022
        mppi = 1297109065
        msnv = 1297305174
        ross = 1380930387
        seau = 1397047637
        sebk = 1397047883
        xavc = 1480676931
        avc1 = 1635148593
        bbxm = 1650620525
        caqv = 1667330422
        ccff = 1667458662
        da0a = 1684090977
        da0b = 1684090978
        da1a = 1684091233
        da1b = 1684091234
        da2a = 1684091489
        da2b = 1684091490
        da3a = 1684091745
        da3b = 1684091746
        dash = 1684108136
        dby1 = 1684175153
        dmb1 = 1684890161
        dsms = 1685286259
        dv1a = 1685467489
        dv1b = 1685467490
        dv2a = 1685467745
        dv2b = 1685467746
        dv3a = 1685468001
        dv3b = 1685468002
        dvr1 = 1685484081
        dvt1 = 1685484593
        dxo = 1685614368
        emsg = 1701671783
        ifrm = 1768321645
        isc2 = 1769169714
        iso2 = 1769172786
        iso3 = 1769172787
        iso4 = 1769172788
        iso5 = 1769172789
        iso6 = 1769172790
        isom = 1769172845
        jp2 = 1785737760
        jpm = 1785752864
        jpsi = 1785754473
        jpx = 1785755680
        jpxb = 1785755746
        lmsg = 1819112295
        mj2s = 1835676275
        mjp2 = 1835692082
        mp21 = 1836069425
        mp41 = 1836069937
        mp42 = 1836069938
        mp71 = 1836070705
        msdh = 1836278888
        msix = 1836280184
        niko = 1852402543
        odcf = 1868850022
        opf2 = 1869637170
        opx2 = 1869641778
        pana = 1885433441
        piff = 1885955686
        pnvi = 1886287465
        qt = 1903435808
        risx = 1919513464
        sdv = 1935963680
        senv = 1936027254
        sims = 1936289139
        sisx = 1936290680
        ssss = 1936946035
        uvvu = 1970697845
    SEQ_FIELDS = ["atoms"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['atoms']['start'] = self._io.pos()
        self.atoms = self._root.AtomList(self._io, self, self._root)
        self.atoms._read()
        self._debug['atoms']['end'] = self._io.pos()

    class MvhdBody(KaitaiStruct):
        """
        .. seealso::
           Source - https://developer.apple.com/library/content/documentation/QuickTime/QTFF/QTFFChap2/qtff2.html#//apple_ref/doc/uid/TP40000939-CH204-BBCGFGJG
        """
        SEQ_FIELDS = ["version", "flags", "creation_time", "modification_time", "time_scale", "duration", "preferred_rate", "preferred_volume", "reserved1", "matrix", "preview_time", "preview_duration", "poster_time", "selection_time", "selection_duration", "current_time", "next_track_id"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u1()
            self._debug['version']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_bytes(3)
            self._debug['flags']['end'] = self._io.pos()
            self._debug['creation_time']['start'] = self._io.pos()
            self.creation_time = self._io.read_u4be()
            self._debug['creation_time']['end'] = self._io.pos()
            self._debug['modification_time']['start'] = self._io.pos()
            self.modification_time = self._io.read_u4be()
            self._debug['modification_time']['end'] = self._io.pos()
            self._debug['time_scale']['start'] = self._io.pos()
            self.time_scale = self._io.read_u4be()
            self._debug['time_scale']['end'] = self._io.pos()
            self._debug['duration']['start'] = self._io.pos()
            self.duration = self._io.read_u4be()
            self._debug['duration']['end'] = self._io.pos()
            self._debug['preferred_rate']['start'] = self._io.pos()
            self.preferred_rate = self._root.Fixed32(self._io, self, self._root)
            self.preferred_rate._read()
            self._debug['preferred_rate']['end'] = self._io.pos()
            self._debug['preferred_volume']['start'] = self._io.pos()
            self.preferred_volume = self._root.Fixed16(self._io, self, self._root)
            self.preferred_volume._read()
            self._debug['preferred_volume']['end'] = self._io.pos()
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bytes(10)
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['matrix']['start'] = self._io.pos()
            self.matrix = self._io.read_bytes(36)
            self._debug['matrix']['end'] = self._io.pos()
            self._debug['preview_time']['start'] = self._io.pos()
            self.preview_time = self._io.read_u4be()
            self._debug['preview_time']['end'] = self._io.pos()
            self._debug['preview_duration']['start'] = self._io.pos()
            self.preview_duration = self._io.read_u4be()
            self._debug['preview_duration']['end'] = self._io.pos()
            self._debug['poster_time']['start'] = self._io.pos()
            self.poster_time = self._io.read_u4be()
            self._debug['poster_time']['end'] = self._io.pos()
            self._debug['selection_time']['start'] = self._io.pos()
            self.selection_time = self._io.read_u4be()
            self._debug['selection_time']['end'] = self._io.pos()
            self._debug['selection_duration']['start'] = self._io.pos()
            self.selection_duration = self._io.read_u4be()
            self._debug['selection_duration']['end'] = self._io.pos()
            self._debug['current_time']['start'] = self._io.pos()
            self.current_time = self._io.read_u4be()
            self._debug['current_time']['end'] = self._io.pos()
            self._debug['next_track_id']['start'] = self._io.pos()
            self.next_track_id = self._io.read_u4be()
            self._debug['next_track_id']['end'] = self._io.pos()


    class FtypBody(KaitaiStruct):
        """
        .. seealso::
           Source - https://developer.apple.com/library/content/documentation/QuickTime/QTFF/QTFFChap1/qtff1.html#//apple_ref/doc/uid/TP40000939-CH203-CJBCBIFF
        """
        SEQ_FIELDS = ["major_brand", "minor_version", "compatible_brands"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['major_brand']['start'] = self._io.pos()
            self.major_brand = KaitaiStream.resolve_enum(self._root.Brand, self._io.read_u4be())
            self._debug['major_brand']['end'] = self._io.pos()
            self._debug['minor_version']['start'] = self._io.pos()
            self.minor_version = self._io.read_bytes(4)
            self._debug['minor_version']['end'] = self._io.pos()
            self._debug['compatible_brands']['start'] = self._io.pos()
            self.compatible_brands = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['compatible_brands']:
                    self._debug['compatible_brands']['arr'] = []
                self._debug['compatible_brands']['arr'].append({'start': self._io.pos()})
                self.compatible_brands.append(KaitaiStream.resolve_enum(self._root.Brand, self._io.read_u4be()))
                self._debug['compatible_brands']['arr'][len(self.compatible_brands) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['compatible_brands']['end'] = self._io.pos()


    class Fixed32(KaitaiStruct):
        """Fixed-point 32-bit number."""
        SEQ_FIELDS = ["int_part", "frac_part"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['int_part']['start'] = self._io.pos()
            self.int_part = self._io.read_s2be()
            self._debug['int_part']['end'] = self._io.pos()
            self._debug['frac_part']['start'] = self._io.pos()
            self.frac_part = self._io.read_u2be()
            self._debug['frac_part']['end'] = self._io.pos()


    class Fixed16(KaitaiStruct):
        """Fixed-point 16-bit number."""
        SEQ_FIELDS = ["int_part", "frac_part"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['int_part']['start'] = self._io.pos()
            self.int_part = self._io.read_s1()
            self._debug['int_part']['end'] = self._io.pos()
            self._debug['frac_part']['start'] = self._io.pos()
            self.frac_part = self._io.read_u1()
            self._debug['frac_part']['end'] = self._io.pos()


    class Atom(KaitaiStruct):
        SEQ_FIELDS = ["len32", "atom_type", "len64", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len32']['start'] = self._io.pos()
            self.len32 = self._io.read_u4be()
            self._debug['len32']['end'] = self._io.pos()
            self._debug['atom_type']['start'] = self._io.pos()
            self.atom_type = KaitaiStream.resolve_enum(self._root.AtomType, self._io.read_u4be())
            self._debug['atom_type']['end'] = self._io.pos()
            if self.len32 == 1:
                self._debug['len64']['start'] = self._io.pos()
                self.len64 = self._io.read_u8be()
                self._debug['len64']['end'] = self._io.pos()

            self._debug['body']['start'] = self._io.pos()
            _on = self.atom_type
            if _on == self._root.AtomType.moof:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.AtomList(io, self, self._root)
                self.body._read()
            elif _on == self._root.AtomType.tkhd:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.TkhdBody(io, self, self._root)
                self.body._read()
            elif _on == self._root.AtomType.stbl:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.AtomList(io, self, self._root)
                self.body._read()
            elif _on == self._root.AtomType.traf:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.AtomList(io, self, self._root)
                self.body._read()
            elif _on == self._root.AtomType.minf:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.AtomList(io, self, self._root)
                self.body._read()
            elif _on == self._root.AtomType.trak:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.AtomList(io, self, self._root)
                self.body._read()
            elif _on == self._root.AtomType.moov:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.AtomList(io, self, self._root)
                self.body._read()
            elif _on == self._root.AtomType.mdia:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.AtomList(io, self, self._root)
                self.body._read()
            elif _on == self._root.AtomType.dinf:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.AtomList(io, self, self._root)
                self.body._read()
            elif _on == self._root.AtomType.mvhd:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.MvhdBody(io, self, self._root)
                self.body._read()
            elif _on == self._root.AtomType.ftyp:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.FtypBody(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes(self.len)
            self._debug['body']['end'] = self._io.pos()

        @property
        def len(self):
            if hasattr(self, '_m_len'):
                return self._m_len if hasattr(self, '_m_len') else None

            self._m_len = ((self._io.size() - 8) if self.len32 == 0 else ((self.len64 - 16) if self.len32 == 1 else (self.len32 - 8)))
            return self._m_len if hasattr(self, '_m_len') else None


    class TkhdBody(KaitaiStruct):
        """
        .. seealso::
           Source - https://developer.apple.com/library/content/documentation/QuickTime/QTFF/QTFFChap2/qtff2.html#//apple_ref/doc/uid/TP40000939-CH204-25550
        """
        SEQ_FIELDS = ["version", "flags", "creation_time", "modification_time", "track_id", "reserved1", "duration", "reserved2", "layer", "alternative_group", "volume", "reserved3", "matrix", "width", "height"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u1()
            self._debug['version']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_bytes(3)
            self._debug['flags']['end'] = self._io.pos()
            self._debug['creation_time']['start'] = self._io.pos()
            self.creation_time = self._io.read_u4be()
            self._debug['creation_time']['end'] = self._io.pos()
            self._debug['modification_time']['start'] = self._io.pos()
            self.modification_time = self._io.read_u4be()
            self._debug['modification_time']['end'] = self._io.pos()
            self._debug['track_id']['start'] = self._io.pos()
            self.track_id = self._io.read_u4be()
            self._debug['track_id']['end'] = self._io.pos()
            self._debug['reserved1']['start'] = self._io.pos()
            self.reserved1 = self._io.read_bytes(4)
            self._debug['reserved1']['end'] = self._io.pos()
            self._debug['duration']['start'] = self._io.pos()
            self.duration = self._io.read_u4be()
            self._debug['duration']['end'] = self._io.pos()
            self._debug['reserved2']['start'] = self._io.pos()
            self.reserved2 = self._io.read_bytes(8)
            self._debug['reserved2']['end'] = self._io.pos()
            self._debug['layer']['start'] = self._io.pos()
            self.layer = self._io.read_u2be()
            self._debug['layer']['end'] = self._io.pos()
            self._debug['alternative_group']['start'] = self._io.pos()
            self.alternative_group = self._io.read_u2be()
            self._debug['alternative_group']['end'] = self._io.pos()
            self._debug['volume']['start'] = self._io.pos()
            self.volume = self._io.read_u2be()
            self._debug['volume']['end'] = self._io.pos()
            self._debug['reserved3']['start'] = self._io.pos()
            self.reserved3 = self._io.read_u2be()
            self._debug['reserved3']['end'] = self._io.pos()
            self._debug['matrix']['start'] = self._io.pos()
            self.matrix = self._io.read_bytes(36)
            self._debug['matrix']['end'] = self._io.pos()
            self._debug['width']['start'] = self._io.pos()
            self.width = self._root.Fixed32(self._io, self, self._root)
            self.width._read()
            self._debug['width']['end'] = self._io.pos()
            self._debug['height']['start'] = self._io.pos()
            self.height = self._root.Fixed32(self._io, self, self._root)
            self.height._read()
            self._debug['height']['end'] = self._io.pos()


    class AtomList(KaitaiStruct):
        SEQ_FIELDS = ["items"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['items']['start'] = self._io.pos()
            self.items = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['items']:
                    self._debug['items']['arr'] = []
                self._debug['items']['arr'].append({'start': self._io.pos()})
                _t_items = self._root.Atom(self._io, self, self._root)
                _t_items._read()
                self.items.append(_t_items)
                self._debug['items']['arr'][len(self.items) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['items']['end'] = self._io.pos()



