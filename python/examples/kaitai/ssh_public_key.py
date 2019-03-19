# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class SshPublicKey(KaitaiStruct):
    """SSH public keys are encoded in a special binary format, typically represented
    to end users as either one-liner OpenSSH format or multi-line PEM format
    (commerical SSH). Text wrapper carries extra information about user who
    created the key, comment, etc, but the inner binary is always base64-encoded
    and follows the same internal format.
    
    This format spec deals with this internal binary format (called "blob" in
    openssh sources) only. Buffer is expected to be raw binary and not base64-d.
    Implementation closely follows code in OpenSSH.
    
    .. seealso::
       Source - https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L1970
    """
    SEQ_FIELDS = ["key_name", "body"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['key_name']['start'] = self._io.pos()
        self.key_name = self._root.Cstring(self._io, self, self._root)
        self.key_name._read()
        self._debug['key_name']['end'] = self._io.pos()
        self._debug['body']['start'] = self._io.pos()
        _on = self.key_name.value
        if _on == u"ssh-rsa":
            self.body = self._root.KeyRsa(self._io, self, self._root)
            self.body._read()
        elif _on == u"ecdsa-sha2-nistp256":
            self.body = self._root.KeyEcdsa(self._io, self, self._root)
            self.body._read()
        elif _on == u"ssh-ed25519":
            self.body = self._root.KeyEd25519(self._io, self, self._root)
            self.body._read()
        elif _on == u"ssh-dss":
            self.body = self._root.KeyDsa(self._io, self, self._root)
            self.body._read()
        self._debug['body']['end'] = self._io.pos()

    class KeyRsa(KaitaiStruct):
        """
        .. seealso::
           Source - https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L2011-L2028
        """
        SEQ_FIELDS = ["rsa_e", "rsa_n"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['rsa_e']['start'] = self._io.pos()
            self.rsa_e = self._root.Bignum2(self._io, self, self._root)
            self.rsa_e._read()
            self._debug['rsa_e']['end'] = self._io.pos()
            self._debug['rsa_n']['start'] = self._io.pos()
            self.rsa_n = self._root.Bignum2(self._io, self, self._root)
            self.rsa_n._read()
            self._debug['rsa_n']['end'] = self._io.pos()

        @property
        def key_length(self):
            """Key length in bits."""
            if hasattr(self, '_m_key_length'):
                return self._m_key_length if hasattr(self, '_m_key_length') else None

            self._m_key_length = self.rsa_n.length_in_bits
            return self._m_key_length if hasattr(self, '_m_key_length') else None


    class KeyEd25519(KaitaiStruct):
        """
        .. seealso::
           Source - https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L2111-L2124
        """
        SEQ_FIELDS = ["len_pk", "pk"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_pk']['start'] = self._io.pos()
            self.len_pk = self._io.read_u4be()
            self._debug['len_pk']['end'] = self._io.pos()
            self._debug['pk']['start'] = self._io.pos()
            self.pk = self._io.read_bytes(self.len_pk)
            self._debug['pk']['end'] = self._io.pos()


    class KeyEcdsa(KaitaiStruct):
        """
        .. seealso::
           Source - https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L2060-L2103
        """
        SEQ_FIELDS = ["curve_name", "ec"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['curve_name']['start'] = self._io.pos()
            self.curve_name = self._root.Cstring(self._io, self, self._root)
            self.curve_name._read()
            self._debug['curve_name']['end'] = self._io.pos()
            self._debug['ec']['start'] = self._io.pos()
            self.ec = self._root.EllipticCurve(self._io, self, self._root)
            self.ec._read()
            self._debug['ec']['end'] = self._io.pos()


    class Cstring(KaitaiStruct):
        """A integer-prefixed string designed to be read using `sshbuf_get_cstring`
        and written by `sshbuf_put_cstring` routines in ssh sources. Name is an
        obscure misnomer, as typically "C string" means a null-terminated string.
        
        .. seealso::
           Source - https://github.com/openssh/openssh-portable/blob/master/sshbuf-getput-basic.c#L181
        """
        SEQ_FIELDS = ["len", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u4be()
            self._debug['len']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = (self._io.read_bytes(self.len)).decode(u"ASCII")
            self._debug['value']['end'] = self._io.pos()


    class KeyDsa(KaitaiStruct):
        """
        .. seealso::
           Source - https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L2036-L2051
        """
        SEQ_FIELDS = ["dsa_p", "dsa_q", "dsa_g", "dsa_pub_key"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['dsa_p']['start'] = self._io.pos()
            self.dsa_p = self._root.Bignum2(self._io, self, self._root)
            self.dsa_p._read()
            self._debug['dsa_p']['end'] = self._io.pos()
            self._debug['dsa_q']['start'] = self._io.pos()
            self.dsa_q = self._root.Bignum2(self._io, self, self._root)
            self.dsa_q._read()
            self._debug['dsa_q']['end'] = self._io.pos()
            self._debug['dsa_g']['start'] = self._io.pos()
            self.dsa_g = self._root.Bignum2(self._io, self, self._root)
            self.dsa_g._read()
            self._debug['dsa_g']['end'] = self._io.pos()
            self._debug['dsa_pub_key']['start'] = self._io.pos()
            self.dsa_pub_key = self._root.Bignum2(self._io, self, self._root)
            self.dsa_pub_key._read()
            self._debug['dsa_pub_key']['end'] = self._io.pos()


    class EllipticCurve(KaitaiStruct):
        """Elliptic curve dump format used by ssh. In OpenSSH code, the following
        routines are used to read/write it:
        
        * sshbuf_get_ec
        * get_ec
        
        .. seealso::
           Source - https://github.com/openssh/openssh-portable/blob/master/sshbuf-getput-crypto.c#L90
           https://github.com/openssh/openssh-portable/blob/master/sshbuf-getput-crypto.c#L76
        """
        SEQ_FIELDS = ["len", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u4be()
            self._debug['len']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            self.body = self._io.read_bytes(self.len)
            self._debug['body']['end'] = self._io.pos()


    class Bignum2(KaitaiStruct):
        """Big integers serialization format used by ssh, v2. In the code, the following
        routines are used to read/write it:
        
        * sshbuf_get_bignum2
        * sshbuf_get_bignum2_bytes_direct
        * sshbuf_put_bignum2
        * sshbuf_get_bignum2_bytes_direct
        
        .. seealso::
           Source - https://github.com/openssh/openssh-portable/blob/master/sshbuf-getput-crypto.c#L35
           https://github.com/openssh/openssh-portable/blob/master/sshbuf-getput-basic.c#L431
        """
        SEQ_FIELDS = ["len", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._io.read_u4be()
            self._debug['len']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            self.body = self._io.read_bytes(self.len)
            self._debug['body']['end'] = self._io.pos()

        @property
        def length_in_bits(self):
            """Length of big integer in bits. In OpenSSH sources, this corresponds to
            `BN_num_bits` function.
            """
            if hasattr(self, '_m_length_in_bits'):
                return self._m_length_in_bits if hasattr(self, '_m_length_in_bits') else None

            self._m_length_in_bits = ((self.len - 1) * 8)
            return self._m_length_in_bits if hasattr(self, '_m_length_in_bits') else None



