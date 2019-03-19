# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class GettextMo(KaitaiStruct):
    """[GNU gettext](https://www.gnu.org/software/gettext/) is a popular
    solution in free/open source software world to do i18n/l10n of
    software, by providing translated strings that will substitute
    strings in original language (typically, English).
    
    gettext .mo is a binary database format which stores these string
    translation pairs in an efficient binary format, ready to be used by
    gettext-enabled software. .mo format is a result of compilation of
    text-based .po files using
    [msgfmt](https://www.gnu.org/software/gettext/manual/html_node/msgfmt-Invocation.html#msgfmt-Invocation)
    utility. The reverse conversion (.mo -> .po) is also possible using
    [msgunfmt](https://www.gnu.org/software/gettext/manual/html_node/msgunfmt-Invocation.html#msgunfmt-Invocation)
    decompiler utility.
    
    .. seealso::
       Source - https://gitlab.com/worr/libintl
    """
    SEQ_FIELDS = ["signature", "mo"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['signature']['start'] = self._io.pos()
        self.signature = self._io.read_bytes(4)
        self._debug['signature']['end'] = self._io.pos()
        self._debug['mo']['start'] = self._io.pos()
        self.mo = self._root.Mo(self._io, self, self._root)
        self.mo._read()
        self._debug['mo']['end'] = self._io.pos()

    class HashLookupIteration(KaitaiStruct):
        SEQ_FIELDS = []
        def __init__(self, idx, collision_step, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.idx = idx
            self.collision_step = collision_step
            self._debug = collections.defaultdict(dict)

        def _read(self):
            pass

        @property
        def original(self):
            if hasattr(self, '_m_original'):
                return self._m_original if hasattr(self, '_m_original') else None

            self._m_original = self._root.mo.originals[self.idx].str
            return self._m_original if hasattr(self, '_m_original') else None

        @property
        def translation(self):
            if hasattr(self, '_m_translation'):
                return self._m_translation if hasattr(self, '_m_translation') else None

            self._m_translation = self._root.mo.translations[self.idx].str
            return self._m_translation if hasattr(self, '_m_translation') else None

        @property
        def next_idx(self):
            if hasattr(self, '_m_next_idx'):
                return self._m_next_idx if hasattr(self, '_m_next_idx') else None

            self._m_next_idx = ((self.idx + self.collision_step) - (self._root.mo.num_hashtable_items if self.idx >= (self._root.mo.num_hashtable_items - self.collision_step) else 0))
            return self._m_next_idx if hasattr(self, '_m_next_idx') else None

        @property
        def next(self):
            if hasattr(self, '_m_next'):
                return self._m_next if hasattr(self, '_m_next') else None

            _pos = self._io.pos()
            self._io.seek(0)
            self._debug['_m_next']['start'] = self._io.pos()
            self._m_next = self._root.HashLookupIteration(self._root.mo.hashtable_items[self.next_idx].val, self.collision_step, self._io, self, self._root)
            self._m_next._read()
            self._debug['_m_next']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_next if hasattr(self, '_m_next') else None


    class LookupIteration(KaitaiStruct):
        SEQ_FIELDS = []
        def __init__(self, current, query, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.current = current
            self.query = query
            self._debug = collections.defaultdict(dict)

        def _read(self):
            pass

        @property
        def found(self):
            if hasattr(self, '_m_found'):
                return self._m_found if hasattr(self, '_m_found') else None

            self._m_found = self.query == self.current.original
            return self._m_found if hasattr(self, '_m_found') else None

        @property
        def next(self):
            if hasattr(self, '_m_next'):
                return self._m_next if hasattr(self, '_m_next') else None

            if not (self.found):
                _pos = self._io.pos()
                self._io.seek(0)
                self._debug['_m_next']['start'] = self._io.pos()
                self._m_next = self._root.LookupIteration(self.current.next, self.query, self._io, self, self._root)
                self._m_next._read()
                self._debug['_m_next']['end'] = self._io.pos()
                self._io.seek(_pos)

            return self._m_next if hasattr(self, '_m_next') else None


    class HashtableLookup(KaitaiStruct):
        """def lookup(s:str, t:gettext_mo.GettextMo):
          try:
            l=gettext_mo.GettextMo.HashtableLookup(s, string_hash(s), t._io, _parent=t, _root=t)
            e=l.entry
            while(not e.found):
              e=e.next
            return e.current
          except:
            raise Exception("Not found "+s+" in the hashtable!")
        
        lookup(t.mo.originals[145].str, t)
        
        .. seealso::
           Source - https://gitlab.com/worr/libintl/raw/master/src/lib/libintl/gettext.c
        """
        SEQ_FIELDS = []
        def __init__(self, query, hash, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.query = query
            self.hash = hash
            self._debug = collections.defaultdict(dict)

        def _read(self):
            pass

        @property
        def collision_step(self):
            if hasattr(self, '_m_collision_step'):
                return self._m_collision_step if hasattr(self, '_m_collision_step') else None

            self._m_collision_step = ((self.hash % (self._root.mo.num_hashtable_items - 2)) + 1)
            return self._m_collision_step if hasattr(self, '_m_collision_step') else None

        @property
        def idx(self):
            if hasattr(self, '_m_idx'):
                return self._m_idx if hasattr(self, '_m_idx') else None

            self._m_idx = (self.hash % self._root.mo.num_hashtable_items)
            return self._m_idx if hasattr(self, '_m_idx') else None

        @property
        def hash_lookup_iteration(self):
            if hasattr(self, '_m_hash_lookup_iteration'):
                return self._m_hash_lookup_iteration if hasattr(self, '_m_hash_lookup_iteration') else None

            _pos = self._io.pos()
            self._io.seek(0)
            self._debug['_m_hash_lookup_iteration']['start'] = self._io.pos()
            self._m_hash_lookup_iteration = self._root.HashLookupIteration(self._root.mo.hashtable_items[self.idx].val, self.collision_step, self._io, self, self._root)
            self._m_hash_lookup_iteration._read()
            self._debug['_m_hash_lookup_iteration']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_hash_lookup_iteration if hasattr(self, '_m_hash_lookup_iteration') else None

        @property
        def entry(self):
            if hasattr(self, '_m_entry'):
                return self._m_entry if hasattr(self, '_m_entry') else None

            _pos = self._io.pos()
            self._io.seek(0)
            self._debug['_m_entry']['start'] = self._io.pos()
            self._m_entry = self._root.LookupIteration(self.hash_lookup_iteration, self.query, self._io, self, self._root)
            self._m_entry._read()
            self._debug['_m_entry']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_entry if hasattr(self, '_m_entry') else None


    class Mo(KaitaiStruct):
        SEQ_FIELDS = ["version", "num_translations", "ofs_originals", "ofs_translations", "num_hashtable_items", "ofs_hashtable_items"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            _on = self._root.signature
            if _on == b"\xDE\x12\x04\x95":
                self._is_le = True
            elif _on == b"\x95\x04\x12\xDE":
                self._is_le = False

            if self._is_le == True:
                self._read_le()
            elif self._is_le == False:
                self._read_be()
            else:
                raise Exception("Unable to decide endianness")

        def _read_le(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._root.Mo.Version(self._io, self, self._root, self._is_le)
            self.version._read()
            self._debug['version']['end'] = self._io.pos()
            self._debug['num_translations']['start'] = self._io.pos()
            self.num_translations = self._io.read_u4le()
            self._debug['num_translations']['end'] = self._io.pos()
            self._debug['ofs_originals']['start'] = self._io.pos()
            self.ofs_originals = self._io.read_u4le()
            self._debug['ofs_originals']['end'] = self._io.pos()
            self._debug['ofs_translations']['start'] = self._io.pos()
            self.ofs_translations = self._io.read_u4le()
            self._debug['ofs_translations']['end'] = self._io.pos()
            self._debug['num_hashtable_items']['start'] = self._io.pos()
            self.num_hashtable_items = self._io.read_u4le()
            self._debug['num_hashtable_items']['end'] = self._io.pos()
            self._debug['ofs_hashtable_items']['start'] = self._io.pos()
            self.ofs_hashtable_items = self._io.read_u4le()
            self._debug['ofs_hashtable_items']['end'] = self._io.pos()

        def _read_be(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._root.Mo.Version(self._io, self, self._root, self._is_le)
            self.version._read()
            self._debug['version']['end'] = self._io.pos()
            self._debug['num_translations']['start'] = self._io.pos()
            self.num_translations = self._io.read_u4be()
            self._debug['num_translations']['end'] = self._io.pos()
            self._debug['ofs_originals']['start'] = self._io.pos()
            self.ofs_originals = self._io.read_u4be()
            self._debug['ofs_originals']['end'] = self._io.pos()
            self._debug['ofs_translations']['start'] = self._io.pos()
            self.ofs_translations = self._io.read_u4be()
            self._debug['ofs_translations']['end'] = self._io.pos()
            self._debug['num_hashtable_items']['start'] = self._io.pos()
            self.num_hashtable_items = self._io.read_u4be()
            self._debug['num_hashtable_items']['end'] = self._io.pos()
            self._debug['ofs_hashtable_items']['start'] = self._io.pos()
            self.ofs_hashtable_items = self._io.read_u4be()
            self._debug['ofs_hashtable_items']['end'] = self._io.pos()

        class Version(KaitaiStruct):
            SEQ_FIELDS = ["version_raw"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['version_raw']['start'] = self._io.pos()
                self.version_raw = self._io.read_u4le()
                self._debug['version_raw']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['version_raw']['start'] = self._io.pos()
                self.version_raw = self._io.read_u4be()
                self._debug['version_raw']['end'] = self._io.pos()

            @property
            def major(self):
                if hasattr(self, '_m_major'):
                    return self._m_major if hasattr(self, '_m_major') else None

                self._m_major = (self.version_raw >> 16)
                return self._m_major if hasattr(self, '_m_major') else None

            @property
            def minor(self):
                if hasattr(self, '_m_minor'):
                    return self._m_minor if hasattr(self, '_m_minor') else None

                self._m_minor = (self.version_raw & 65535)
                return self._m_minor if hasattr(self, '_m_minor') else None


        class HashtableItem(KaitaiStruct):
            SEQ_FIELDS = ["raw_val"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['raw_val']['start'] = self._io.pos()
                self.raw_val = self._io.read_u4le()
                self._debug['raw_val']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['raw_val']['start'] = self._io.pos()
                self.raw_val = self._io.read_u4be()
                self._debug['raw_val']['end'] = self._io.pos()

            @property
            def mask(self):
                if hasattr(self, '_m_mask'):
                    return self._m_mask if hasattr(self, '_m_mask') else None

                self._m_mask = 2147483648
                return self._m_mask if hasattr(self, '_m_mask') else None

            @property
            def val_1(self):
                if hasattr(self, '_m_val_1'):
                    return self._m_val_1 if hasattr(self, '_m_val_1') else None

                if self.raw_val != 0:
                    self._m_val_1 = (self.raw_val - 1)

                return self._m_val_1 if hasattr(self, '_m_val_1') else None

            @property
            def is_system_dependent(self):
                if hasattr(self, '_m_is_system_dependent'):
                    return self._m_is_system_dependent if hasattr(self, '_m_is_system_dependent') else None

                if self.raw_val != 0:
                    self._m_is_system_dependent = (self.val_1 & self.mask) == 1

                return self._m_is_system_dependent if hasattr(self, '_m_is_system_dependent') else None

            @property
            def val(self):
                if hasattr(self, '_m_val'):
                    return self._m_val if hasattr(self, '_m_val') else None

                if self.raw_val != 0:
                    self._m_val = (self.val_1 & ~(self.mask))

                return self._m_val if hasattr(self, '_m_val') else None


        class Descriptor(KaitaiStruct):
            SEQ_FIELDS = ["len_str", "ofs_str"]
            def __init__(self, _io, _parent=None, _root=None, _is_le=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._is_le = _is_le
                self._debug = collections.defaultdict(dict)

            def _read(self):

                if self._is_le == True:
                    self._read_le()
                elif self._is_le == False:
                    self._read_be()
                else:
                    raise Exception("Unable to decide endianness")

            def _read_le(self):
                self._debug['len_str']['start'] = self._io.pos()
                self.len_str = self._io.read_u4le()
                self._debug['len_str']['end'] = self._io.pos()
                self._debug['ofs_str']['start'] = self._io.pos()
                self.ofs_str = self._io.read_u4le()
                self._debug['ofs_str']['end'] = self._io.pos()

            def _read_be(self):
                self._debug['len_str']['start'] = self._io.pos()
                self.len_str = self._io.read_u4be()
                self._debug['len_str']['end'] = self._io.pos()
                self._debug['ofs_str']['start'] = self._io.pos()
                self.ofs_str = self._io.read_u4be()
                self._debug['ofs_str']['end'] = self._io.pos()

            @property
            def str(self):
                if hasattr(self, '_m_str'):
                    return self._m_str if hasattr(self, '_m_str') else None

                io = self._root._io
                _pos = io.pos()
                io.seek(self.ofs_str)
                self._debug['_m_str']['start'] = io.pos()
                if self._is_le:
                    self._m_str = (KaitaiStream.bytes_terminate(io.read_bytes(self.len_str), 0, False)).decode(u"UTF-8")
                else:
                    self._m_str = (KaitaiStream.bytes_terminate(io.read_bytes(self.len_str), 0, False)).decode(u"UTF-8")
                self._debug['_m_str']['end'] = io.pos()
                io.seek(_pos)
                return self._m_str if hasattr(self, '_m_str') else None


        @property
        def originals(self):
            if hasattr(self, '_m_originals'):
                return self._m_originals if hasattr(self, '_m_originals') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.ofs_originals)
            self._debug['_m_originals']['start'] = io.pos()
            if self._is_le:
                self._m_originals = [None] * (self.num_translations)
                for i in range(self.num_translations):
                    if not 'arr' in self._debug['_m_originals']:
                        self._debug['_m_originals']['arr'] = []
                    self._debug['_m_originals']['arr'].append({'start': io.pos()})
                    _t__m_originals = self._root.Mo.Descriptor(io, self, self._root, self._is_le)
                    _t__m_originals._read()
                    self._m_originals[i] = _t__m_originals
                    self._debug['_m_originals']['arr'][i]['end'] = io.pos()

            else:
                self._m_originals = [None] * (self.num_translations)
                for i in range(self.num_translations):
                    if not 'arr' in self._debug['_m_originals']:
                        self._debug['_m_originals']['arr'] = []
                    self._debug['_m_originals']['arr'].append({'start': io.pos()})
                    _t__m_originals = self._root.Mo.Descriptor(io, self, self._root, self._is_le)
                    _t__m_originals._read()
                    self._m_originals[i] = _t__m_originals
                    self._debug['_m_originals']['arr'][i]['end'] = io.pos()

            self._debug['_m_originals']['end'] = io.pos()
            io.seek(_pos)
            return self._m_originals if hasattr(self, '_m_originals') else None

        @property
        def translations(self):
            if hasattr(self, '_m_translations'):
                return self._m_translations if hasattr(self, '_m_translations') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.ofs_translations)
            self._debug['_m_translations']['start'] = io.pos()
            if self._is_le:
                self._m_translations = [None] * (self.num_translations)
                for i in range(self.num_translations):
                    if not 'arr' in self._debug['_m_translations']:
                        self._debug['_m_translations']['arr'] = []
                    self._debug['_m_translations']['arr'].append({'start': io.pos()})
                    _t__m_translations = self._root.Mo.Descriptor(io, self, self._root, self._is_le)
                    _t__m_translations._read()
                    self._m_translations[i] = _t__m_translations
                    self._debug['_m_translations']['arr'][i]['end'] = io.pos()

            else:
                self._m_translations = [None] * (self.num_translations)
                for i in range(self.num_translations):
                    if not 'arr' in self._debug['_m_translations']:
                        self._debug['_m_translations']['arr'] = []
                    self._debug['_m_translations']['arr'].append({'start': io.pos()})
                    _t__m_translations = self._root.Mo.Descriptor(io, self, self._root, self._is_le)
                    _t__m_translations._read()
                    self._m_translations[i] = _t__m_translations
                    self._debug['_m_translations']['arr'][i]['end'] = io.pos()

            self._debug['_m_translations']['end'] = io.pos()
            io.seek(_pos)
            return self._m_translations if hasattr(self, '_m_translations') else None

        @property
        def hashtable_items(self):
            if hasattr(self, '_m_hashtable_items'):
                return self._m_hashtable_items if hasattr(self, '_m_hashtable_items') else None

            if self.ofs_hashtable_items != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.ofs_hashtable_items)
                self._debug['_m_hashtable_items']['start'] = io.pos()
                if self._is_le:
                    self._m_hashtable_items = [None] * (self.num_hashtable_items)
                    for i in range(self.num_hashtable_items):
                        if not 'arr' in self._debug['_m_hashtable_items']:
                            self._debug['_m_hashtable_items']['arr'] = []
                        self._debug['_m_hashtable_items']['arr'].append({'start': io.pos()})
                        _t__m_hashtable_items = self._root.Mo.HashtableItem(io, self, self._root, self._is_le)
                        _t__m_hashtable_items._read()
                        self._m_hashtable_items[i] = _t__m_hashtable_items
                        self._debug['_m_hashtable_items']['arr'][i]['end'] = io.pos()

                else:
                    self._m_hashtable_items = [None] * (self.num_hashtable_items)
                    for i in range(self.num_hashtable_items):
                        if not 'arr' in self._debug['_m_hashtable_items']:
                            self._debug['_m_hashtable_items']['arr'] = []
                        self._debug['_m_hashtable_items']['arr'].append({'start': io.pos()})
                        _t__m_hashtable_items = self._root.Mo.HashtableItem(io, self, self._root, self._is_le)
                        _t__m_hashtable_items._read()
                        self._m_hashtable_items[i] = _t__m_hashtable_items
                        self._debug['_m_hashtable_items']['arr'][i]['end'] = io.pos()

                self._debug['_m_hashtable_items']['end'] = io.pos()
                io.seek(_pos)

            return self._m_hashtable_items if hasattr(self, '_m_hashtable_items') else None



