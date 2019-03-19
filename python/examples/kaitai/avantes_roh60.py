# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class AvantesRoh60(KaitaiStruct):
    """Avantes USB spectrometers are supplied with a Windows binary which 
    generates one ROH and one RCM file when the user clicks "Save
    experiment". In the version of 6.0, the ROH file contains a header 
    of 22 four-byte floats, then the spectrum as a float array and a 
    footer of 3 floats. The first and last pixel numbers are specified in the 
    header and determine the (length+1) of the spectral data. In the tested 
    files, the length is (2032-211-1)=1820 pixels, but Kaitai determines this 
    automatically anyway.
    
    The wavelength calibration is stored as a polynomial with coefficients
    of 'wlintercept', 'wlx1', ... 'wlx4', the argument of which is the
    (pixel number + 1), as found out by comparing with the original 
    Avantes converted data files. There is no intensity calibration saved,
    but it is recommended to do it in your program - the CCD in the spectrometer 
    is so uneven that one should prepare exact pixel-to-pixel calibration curves 
    to get reasonable spectral results.
    
    The rest of the header floats is not known to the author. Note that the 
    newer version of Avantes software has a different format, see also
    https://kr.mathworks.com/examples/matlab/community/20341-reading-spectra-from-avantes-binary-files-demonstration
    
    The RCM file contains the user-specified comment, so it may be useful
    for automatic conversion of data. You may wish to divide the spectra by 
    the integration time before comparing them.
    
    Written and tested by Filip Dominec, 2017-2018
    """
    SEQ_FIELDS = ["unknown1", "wlintercept", "wlx1", "wlx2", "wlx3", "wlx4", "unknown2", "ipixfirst", "ipixlast", "unknown3", "spectrum", "integration_ms", "averaging", "pixel_smoothing"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['unknown1']['start'] = self._io.pos()
        self.unknown1 = self._io.read_f4le()
        self._debug['unknown1']['end'] = self._io.pos()
        self._debug['wlintercept']['start'] = self._io.pos()
        self.wlintercept = self._io.read_f4le()
        self._debug['wlintercept']['end'] = self._io.pos()
        self._debug['wlx1']['start'] = self._io.pos()
        self.wlx1 = self._io.read_f4le()
        self._debug['wlx1']['end'] = self._io.pos()
        self._debug['wlx2']['start'] = self._io.pos()
        self.wlx2 = self._io.read_f4le()
        self._debug['wlx2']['end'] = self._io.pos()
        self._debug['wlx3']['start'] = self._io.pos()
        self.wlx3 = self._io.read_f4le()
        self._debug['wlx3']['end'] = self._io.pos()
        self._debug['wlx4']['start'] = self._io.pos()
        self.wlx4 = self._io.read_f4le()
        self._debug['wlx4']['end'] = self._io.pos()
        self._debug['unknown2']['start'] = self._io.pos()
        self.unknown2 = [None] * (9)
        for i in range(9):
            if not 'arr' in self._debug['unknown2']:
                self._debug['unknown2']['arr'] = []
            self._debug['unknown2']['arr'].append({'start': self._io.pos()})
            self.unknown2[i] = self._io.read_f4le()
            self._debug['unknown2']['arr'][i]['end'] = self._io.pos()

        self._debug['unknown2']['end'] = self._io.pos()
        self._debug['ipixfirst']['start'] = self._io.pos()
        self.ipixfirst = self._io.read_f4le()
        self._debug['ipixfirst']['end'] = self._io.pos()
        self._debug['ipixlast']['start'] = self._io.pos()
        self.ipixlast = self._io.read_f4le()
        self._debug['ipixlast']['end'] = self._io.pos()
        self._debug['unknown3']['start'] = self._io.pos()
        self.unknown3 = [None] * (4)
        for i in range(4):
            if not 'arr' in self._debug['unknown3']:
                self._debug['unknown3']['arr'] = []
            self._debug['unknown3']['arr'].append({'start': self._io.pos()})
            self.unknown3[i] = self._io.read_f4le()
            self._debug['unknown3']['arr'][i]['end'] = self._io.pos()

        self._debug['unknown3']['end'] = self._io.pos()
        self._debug['spectrum']['start'] = self._io.pos()
        self.spectrum = [None] * (((int(self.ipixlast) - int(self.ipixfirst)) - 1))
        for i in range(((int(self.ipixlast) - int(self.ipixfirst)) - 1)):
            if not 'arr' in self._debug['spectrum']:
                self._debug['spectrum']['arr'] = []
            self._debug['spectrum']['arr'].append({'start': self._io.pos()})
            self.spectrum[i] = self._io.read_f4le()
            self._debug['spectrum']['arr'][i]['end'] = self._io.pos()

        self._debug['spectrum']['end'] = self._io.pos()
        self._debug['integration_ms']['start'] = self._io.pos()
        self.integration_ms = self._io.read_f4le()
        self._debug['integration_ms']['end'] = self._io.pos()
        self._debug['averaging']['start'] = self._io.pos()
        self.averaging = self._io.read_f4le()
        self._debug['averaging']['end'] = self._io.pos()
        self._debug['pixel_smoothing']['start'] = self._io.pos()
        self.pixel_smoothing = self._io.read_f4le()
        self._debug['pixel_smoothing']['end'] = self._io.pos()


