# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class OpenpgpMessage(KaitaiStruct):
    """The OpenPGP Message Format is a format to store encryption and signature keys for emails.
    
    .. seealso::
       Source - https://tools.ietf.org/html/rfc4880
    """

    class PublicKeyAlgorithms(Enum):
        rsa_encrypt_or_sign_hac = 1
        rsa_encrypt_only_hac = 2
        rsa_sign_only_hac = 3
        elgamal_encrypt_only_elgamal_hac = 16
        dsa_digital_signature_algorithm_fips_hac = 17
        reserved_for_elliptic_curve = 18
        reserved_for_ecdsa = 19
        reserved_formerly_elgamal_encrypt_or_sign_ = 20
        reserved_for_diffie_hellman_x_as_defined_for_ietf_s_mime = 21
        private_experimental_algorithm_00 = 100
        private_experimental_algorithm_01 = 101
        private_experimental_algorithm_02 = 102
        private_experimental_algorithm_03 = 103
        private_experimental_algorithm_04 = 104
        private_experimental_algorithm_05 = 105
        private_experimental_algorithm_06 = 106
        private_experimental_algorithm_07 = 107
        private_experimental_algorithm_08 = 108
        private_experimental_algorithm_09 = 109
        private_experimental_algorithm_10 = 110

    class ServerFlags(Enum):
        no_modify = 128

    class KeyFlags(Enum):
        this_key_may_be_used_to_certify_other_keys = 1
        this_key_may_be_used_to_sign_data = 2
        this_key_may_be_used_to_encrypt_communications = 4
        this_key_may_be_used_to_encrypt_storage = 8
        the_private_component_of_this_key_may_have_been_split_by_a_secret_sharing_mechanism = 16
        this_key_may_be_used_for_authentication = 32
        the_private_component_of_this_key_may_be_in_the_possession_of_more_than_one_person = 128

    class CompressionAlgorithms(Enum):
        uncompressed = 0
        zib = 1
        zlib = 2
        bzip = 3
        private_experimental_algorithm_00 = 100
        private_experimental_algorithm_01 = 101
        private_experimental_algorithm_02 = 102
        private_experimental_algorithm_03 = 103
        private_experimental_algorithm_04 = 104
        private_experimental_algorithm_05 = 105
        private_experimental_algorithm_06 = 106
        private_experimental_algorithm_07 = 107
        private_experimental_algorithm_08 = 108
        private_experimental_algorithm_09 = 109
        private_experimental_algorithm_10 = 110

    class PacketTags(Enum):
        reserved_a_packet_tag_must_not_have_this_value = 0
        public_key_encrypted_session_key_packet = 1
        signature_packet = 2
        symmetric_key_encrypted_session_key_packet = 3
        one_pass_signature_packet = 4
        secret_key_packet = 5
        public_key_packet = 6
        secret_subkey_packet = 7
        compressed_data_packet = 8
        symmetrically_encrypted_data_packet = 9
        marker_packet = 10
        literal_data_packet = 11
        trust_packet = 12
        user_id_packet = 13
        public_subkey_packet = 14
        user_attribute_packet = 17
        sym_encrypted_and_integrity_protected_data_packet = 18
        modification_detection_code_packet = 19
        private_or_experimental_values_0 = 60
        private_or_experimental_values_1 = 61
        private_or_experimental_values_2 = 62
        private_or_experimental_values_3 = 63

    class RevocationCodes(Enum):
        no_reason_specified_key_revocations_or_cert_revocations = 0
        key_is_superseded_key_revocations = 1
        key_material_has_been_compromised_key_revocations = 2
        key_is_retired_and_no_longer_used_key_revocations = 3
        user_id_information_is_no_longer_valid_cert_revocations = 32
        private_use_1 = 100
        private_use_2 = 101
        private_use_3 = 102
        private_use_4 = 103
        private_use_11 = 110

    class HashAlgorithms(Enum):
        md5 = 1
        sha1 = 2
        ripemd160 = 3
        reserved_4 = 4
        reserved_5 = 5
        reserved_6 = 6
        reserved_7 = 7
        sha256 = 8
        sha384 = 9
        sha512 = 10
        sha224 = 11
        private_experimental_algorithm_00 = 100
        private_experimental_algorithm_01 = 101
        private_experimental_algorithm_02 = 102
        private_experimental_algorithm_03 = 103
        private_experimental_algorithm_04 = 104
        private_experimental_algorithm_05 = 105
        private_experimental_algorithm_06 = 106
        private_experimental_algorithm_07 = 107
        private_experimental_algorithm_08 = 108
        private_experimental_algorithm_09 = 109
        private_experimental_algorithm_10 = 110

    class SymmetricKeyAlgorithm(Enum):
        plain = 0
        idea = 1
        triple_des = 2
        cast5 = 3
        blowfisch = 4
        reserved_5 = 5
        reserved_6 = 6
        aes_128 = 7
        aes_192 = 8
        aes_256 = 9
        twofish_256 = 10
        private_experimental_algorithm_00 = 100
        private_experimental_algorithm_01 = 101
        private_experimental_algorithm_02 = 102
        private_experimental_algorithm_03 = 103
        private_experimental_algorithm_04 = 104
        private_experimental_algorithm_05 = 105
        private_experimental_algorithm_06 = 106
        private_experimental_algorithm_07 = 107
        private_experimental_algorithm_08 = 108
        private_experimental_algorithm_09 = 109
        private_experimental_algorithm_10 = 110

    class SubpacketTypes(Enum):
        reserved0 = 0
        reserved1 = 1
        signature_creation_time = 2
        signature_expiration_time = 3
        exportable_certification = 4
        trust_signature = 5
        regular_expression = 6
        revocable = 7
        reserved8 = 8
        key_expiration_time = 9
        placeholder_for_backward_compatibility = 10
        preferred_symmetric_algorithms = 11
        revocation_key = 12
        reserved13 = 13
        reserved14 = 14
        reserved15 = 15
        issuer = 16
        reserved17 = 17
        reserved18 = 18
        reserved19 = 19
        notation_data = 20
        preferred_hash_algorithms = 21
        preferred_compression_algorithms = 22
        key_server_preferences = 23
        preferred_key_server = 24
        primary_user_id = 25
        policy_uri = 26
        key_flags = 27
        signers_user_id = 28
        reason_for_revocation = 29
        features = 30
        signature_target = 31
        embedded_signature = 32
    SEQ_FIELDS = ["packets"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['packets']['start'] = self._io.pos()
        self.packets = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['packets']:
                self._debug['packets']['arr'] = []
            self._debug['packets']['arr'].append({'start': self._io.pos()})
            _t_packets = self._root.Packet(self._io, self, self._root)
            _t_packets._read()
            self.packets.append(_t_packets)
            self._debug['packets']['arr'][len(self.packets) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['packets']['end'] = self._io.pos()

    class PreferredHashAlgorithms(KaitaiStruct):
        SEQ_FIELDS = ["algorithm"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['algorithm']['start'] = self._io.pos()
            self.algorithm = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['algorithm']:
                    self._debug['algorithm']['arr'] = []
                self._debug['algorithm']['arr'].append({'start': self._io.pos()})
                self.algorithm.append(KaitaiStream.resolve_enum(self._root.HashAlgorithms, self._io.read_u1()))
                self._debug['algorithm']['arr'][len(self.algorithm) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['algorithm']['end'] = self._io.pos()


    class PreferredCompressionAlgorithms(KaitaiStruct):
        SEQ_FIELDS = ["algorithm"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['algorithm']['start'] = self._io.pos()
            self.algorithm = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['algorithm']:
                    self._debug['algorithm']['arr'] = []
                self._debug['algorithm']['arr'].append({'start': self._io.pos()})
                self.algorithm.append(KaitaiStream.resolve_enum(self._root.CompressionAlgorithms, self._io.read_u1()))
                self._debug['algorithm']['arr'][len(self.algorithm) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['algorithm']['end'] = self._io.pos()


    class SignersUserId(KaitaiStruct):
        SEQ_FIELDS = ["user_id"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['user_id']['start'] = self._io.pos()
            self.user_id = (self._io.read_bytes_full()).decode(u"UTF-8")
            self._debug['user_id']['end'] = self._io.pos()


    class SecretKeyPacket(KaitaiStruct):
        SEQ_FIELDS = ["public_key", "string_to_key", "symmetric_encryption_algorithm", "secret_key"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['public_key']['start'] = self._io.pos()
            self.public_key = self._root.PublicKeyPacket(self._io, self, self._root)
            self.public_key._read()
            self._debug['public_key']['end'] = self._io.pos()
            self._debug['string_to_key']['start'] = self._io.pos()
            self.string_to_key = self._io.read_u1()
            self._debug['string_to_key']['end'] = self._io.pos()
            if self.string_to_key >= 254:
                self._debug['symmetric_encryption_algorithm']['start'] = self._io.pos()
                self.symmetric_encryption_algorithm = KaitaiStream.resolve_enum(self._root.SymmetricKeyAlgorithm, self._io.read_u1())
                self._debug['symmetric_encryption_algorithm']['end'] = self._io.pos()

            self._debug['secret_key']['start'] = self._io.pos()
            self.secret_key = self._io.read_bytes_full()
            self._debug['secret_key']['end'] = self._io.pos()


    class KeyServerPreferences(KaitaiStruct):
        SEQ_FIELDS = ["flag"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['flag']['start'] = self._io.pos()
            self.flag = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['flag']:
                    self._debug['flag']['arr'] = []
                self._debug['flag']['arr'].append({'start': self._io.pos()})
                self.flag.append(KaitaiStream.resolve_enum(self._root.ServerFlags, self._io.read_u1()))
                self._debug['flag']['arr'][len(self.flag) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['flag']['end'] = self._io.pos()


    class RegularExpression(KaitaiStruct):
        SEQ_FIELDS = ["regex"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['regex']['start'] = self._io.pos()
            self.regex = (self._io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")
            self._debug['regex']['end'] = self._io.pos()


    class Subpackets(KaitaiStruct):
        SEQ_FIELDS = ["subpacketss"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['subpacketss']['start'] = self._io.pos()
            self.subpacketss = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['subpacketss']:
                    self._debug['subpacketss']['arr'] = []
                self._debug['subpacketss']['arr'].append({'start': self._io.pos()})
                _t_subpacketss = self._root.Subpacket(self._io, self, self._root)
                _t_subpacketss._read()
                self.subpacketss.append(_t_subpacketss)
                self._debug['subpacketss']['arr'][len(self.subpacketss) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['subpacketss']['end'] = self._io.pos()


    class RevocationKey(KaitaiStruct):
        SEQ_FIELDS = ["class_", "public_key_algorithm", "fingerprint"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['class_']['start'] = self._io.pos()
            self.class_ = self._io.read_u1()
            self._debug['class_']['end'] = self._io.pos()
            self._debug['public_key_algorithm']['start'] = self._io.pos()
            self.public_key_algorithm = KaitaiStream.resolve_enum(self._root.PublicKeyAlgorithms, self._io.read_u1())
            self._debug['public_key_algorithm']['end'] = self._io.pos()
            self._debug['fingerprint']['start'] = self._io.pos()
            self.fingerprint = self._io.read_bytes(20)
            self._debug['fingerprint']['end'] = self._io.pos()


    class UserIdPacket(KaitaiStruct):
        SEQ_FIELDS = ["user_id"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['user_id']['start'] = self._io.pos()
            self.user_id = (self._io.read_bytes_full()).decode(u"UTF-8")
            self._debug['user_id']['end'] = self._io.pos()


    class PolicyUri(KaitaiStruct):
        SEQ_FIELDS = ["uri"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['uri']['start'] = self._io.pos()
            self.uri = (self._io.read_bytes_full()).decode(u"UTF-8")
            self._debug['uri']['end'] = self._io.pos()


    class SignatureTarget(KaitaiStruct):
        SEQ_FIELDS = ["public_key_algorithm", "hash_algorithm", "hash"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['public_key_algorithm']['start'] = self._io.pos()
            self.public_key_algorithm = KaitaiStream.resolve_enum(self._root.PublicKeyAlgorithms, self._io.read_u1())
            self._debug['public_key_algorithm']['end'] = self._io.pos()
            self._debug['hash_algorithm']['start'] = self._io.pos()
            self.hash_algorithm = KaitaiStream.resolve_enum(self._root.HashAlgorithms, self._io.read_u1())
            self._debug['hash_algorithm']['end'] = self._io.pos()
            self._debug['hash']['start'] = self._io.pos()
            self.hash = self._io.read_bytes_full()
            self._debug['hash']['end'] = self._io.pos()


    class KeyFlags(KaitaiStruct):
        SEQ_FIELDS = ["flag"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['flag']['start'] = self._io.pos()
            self.flag = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['flag']:
                    self._debug['flag']['arr'] = []
                self._debug['flag']['arr'].append({'start': self._io.pos()})
                self.flag.append(KaitaiStream.resolve_enum(self._root.KeyFlags, self._io.read_u1()))
                self._debug['flag']['arr'][len(self.flag) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['flag']['end'] = self._io.pos()


    class Features(KaitaiStruct):
        SEQ_FIELDS = ["flags"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_bytes_full()
            self._debug['flags']['end'] = self._io.pos()


    class PrimaryUserId(KaitaiStruct):
        SEQ_FIELDS = ["user_id"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['user_id']['start'] = self._io.pos()
            self.user_id = self._io.read_u1()
            self._debug['user_id']['end'] = self._io.pos()


    class Subpacket(KaitaiStruct):
        SEQ_FIELDS = ["len", "subpacket_type", "content"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            self.len = self._root.LenSubpacket(self._io, self, self._root)
            self.len._read()
            self._debug['len']['end'] = self._io.pos()
            self._debug['subpacket_type']['start'] = self._io.pos()
            self.subpacket_type = KaitaiStream.resolve_enum(self._root.SubpacketTypes, self._io.read_u1())
            self._debug['subpacket_type']['end'] = self._io.pos()
            self._debug['content']['start'] = self._io.pos()
            _on = self.subpacket_type
            if _on == self._root.SubpacketTypes.preferred_key_server:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.PreferredKeyServer(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.issuer:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.Issuer(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.revocable:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.Revocable(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.signature_target:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.SignatureTarget(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.regular_expression:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.RegularExpression(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.exportable_certification:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.ExportableCertification(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.reason_for_revocation:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.ReasonForRevocation(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.key_server_preferences:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.KeyServerPreferences(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.signature_creation_time:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.SignatureCreationTime(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.preferred_hash_algorithms:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.PreferredHashAlgorithms(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.trust_signature:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.TrustSignature(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.key_expiration_time:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.KeyExpirationTime(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.key_flags:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.KeyFlags(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.signature_expiration_time:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.SignatureExpirationTime(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.features:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.Features(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.signers_user_id:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.SignersUserId(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.notation_data:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.NotationData(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.revocation_key:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.RevocationKey(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.preferred_compression_algorithms:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.PreferredCompressionAlgorithms(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.policy_uri:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.PolicyUri(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.primary_user_id:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.PrimaryUserId(io, self, self._root)
                self.content._read()
            elif _on == self._root.SubpacketTypes.embedded_signature:
                self._raw_content = self._io.read_bytes((self.len.len - 1))
                io = KaitaiStream(BytesIO(self._raw_content))
                self.content = self._root.EmbeddedSignature(io, self, self._root)
                self.content._read()
            else:
                self.content = self._io.read_bytes((self.len.len - 1))
            self._debug['content']['end'] = self._io.pos()


    class OldPacket(KaitaiStruct):
        SEQ_FIELDS = ["len", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len']['start'] = self._io.pos()
            _on = self._parent.len_type
            if _on == 0:
                self.len = self._io.read_u1()
            elif _on == 1:
                self.len = self._io.read_u2be()
            elif _on == 2:
                self.len = self._io.read_u4be()
            self._debug['len']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self._parent.packet_type_old
            if _on == self._root.PacketTags.public_key_packet:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.PublicKeyPacket(io, self, self._root)
                self.body._read()
            elif _on == self._root.PacketTags.public_subkey_packet:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.PublicKeyPacket(io, self, self._root)
                self.body._read()
            elif _on == self._root.PacketTags.user_id_packet:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.UserIdPacket(io, self, self._root)
                self.body._read()
            elif _on == self._root.PacketTags.signature_packet:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SignaturePacket(io, self, self._root)
                self.body._read()
            elif _on == self._root.PacketTags.secret_subkey_packet:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.PublicKeyPacket(io, self, self._root)
                self.body._read()
            elif _on == self._root.PacketTags.secret_key_packet:
                self._raw_body = self._io.read_bytes(self.len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SecretKeyPacket(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes(self.len)
            self._debug['body']['end'] = self._io.pos()


    class Issuer(KaitaiStruct):
        SEQ_FIELDS = ["keyid"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['keyid']['start'] = self._io.pos()
            self.keyid = self._io.read_u8be()
            self._debug['keyid']['end'] = self._io.pos()


    class ExportableCertification(KaitaiStruct):
        SEQ_FIELDS = ["exportable"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['exportable']['start'] = self._io.pos()
            self.exportable = self._io.read_u1()
            self._debug['exportable']['end'] = self._io.pos()


    class SignatureExpirationTime(KaitaiStruct):
        SEQ_FIELDS = ["time"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['time']['start'] = self._io.pos()
            self.time = self._io.read_u4be()
            self._debug['time']['end'] = self._io.pos()


    class SignatureCreationTime(KaitaiStruct):
        SEQ_FIELDS = ["time"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['time']['start'] = self._io.pos()
            self.time = self._io.read_u4be()
            self._debug['time']['end'] = self._io.pos()


    class SignaturePacket(KaitaiStruct):
        SEQ_FIELDS = ["version", "signature_type", "public_key_algorithm", "hash_algorithm", "len_hashed_subpacket", "hashed_subpackets", "len_unhashed_subpacket", "unhashed_subpackets", "left_signed_hash", "rsa_n", "signature"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u1()
            self._debug['version']['end'] = self._io.pos()
            self._debug['signature_type']['start'] = self._io.pos()
            self.signature_type = self._io.read_u1()
            self._debug['signature_type']['end'] = self._io.pos()
            self._debug['public_key_algorithm']['start'] = self._io.pos()
            self.public_key_algorithm = KaitaiStream.resolve_enum(self._root.PublicKeyAlgorithms, self._io.read_u1())
            self._debug['public_key_algorithm']['end'] = self._io.pos()
            self._debug['hash_algorithm']['start'] = self._io.pos()
            self.hash_algorithm = KaitaiStream.resolve_enum(self._root.HashAlgorithms, self._io.read_u1())
            self._debug['hash_algorithm']['end'] = self._io.pos()
            self._debug['len_hashed_subpacket']['start'] = self._io.pos()
            self.len_hashed_subpacket = self._io.read_u2be()
            self._debug['len_hashed_subpacket']['end'] = self._io.pos()
            self._debug['hashed_subpackets']['start'] = self._io.pos()
            self._raw_hashed_subpackets = self._io.read_bytes(self.len_hashed_subpacket)
            io = KaitaiStream(BytesIO(self._raw_hashed_subpackets))
            self.hashed_subpackets = self._root.Subpackets(io, self, self._root)
            self.hashed_subpackets._read()
            self._debug['hashed_subpackets']['end'] = self._io.pos()
            self._debug['len_unhashed_subpacket']['start'] = self._io.pos()
            self.len_unhashed_subpacket = self._io.read_u2be()
            self._debug['len_unhashed_subpacket']['end'] = self._io.pos()
            self._debug['unhashed_subpackets']['start'] = self._io.pos()
            self._raw_unhashed_subpackets = self._io.read_bytes(self.len_unhashed_subpacket)
            io = KaitaiStream(BytesIO(self._raw_unhashed_subpackets))
            self.unhashed_subpackets = self._root.Subpackets(io, self, self._root)
            self.unhashed_subpackets._read()
            self._debug['unhashed_subpackets']['end'] = self._io.pos()
            self._debug['left_signed_hash']['start'] = self._io.pos()
            self.left_signed_hash = self._io.read_u2be()
            self._debug['left_signed_hash']['end'] = self._io.pos()
            self._debug['rsa_n']['start'] = self._io.pos()
            self.rsa_n = self._io.read_u2be()
            self._debug['rsa_n']['end'] = self._io.pos()
            self._debug['signature']['start'] = self._io.pos()
            self.signature = self._io.read_bytes_full()
            self._debug['signature']['end'] = self._io.pos()


    class Revocable(KaitaiStruct):
        SEQ_FIELDS = ["revocable"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['revocable']['start'] = self._io.pos()
            self.revocable = self._io.read_u1()
            self._debug['revocable']['end'] = self._io.pos()


    class EmbeddedSignature(KaitaiStruct):
        SEQ_FIELDS = ["signature_packet"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['signature_packet']['start'] = self._io.pos()
            self.signature_packet = self._root.SignaturePacket(self._io, self, self._root)
            self.signature_packet._read()
            self._debug['signature_packet']['end'] = self._io.pos()


    class PreferredKeyServer(KaitaiStruct):
        SEQ_FIELDS = ["uri"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['uri']['start'] = self._io.pos()
            self.uri = (self._io.read_bytes_full()).decode(u"UTF-8")
            self._debug['uri']['end'] = self._io.pos()


    class ReasonForRevocation(KaitaiStruct):
        SEQ_FIELDS = ["revocation_code", "reason"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['revocation_code']['start'] = self._io.pos()
            self.revocation_code = KaitaiStream.resolve_enum(self._root.RevocationCodes, self._io.read_u1())
            self._debug['revocation_code']['end'] = self._io.pos()
            self._debug['reason']['start'] = self._io.pos()
            self.reason = (self._io.read_bytes_full()).decode(u"UTF-8")
            self._debug['reason']['end'] = self._io.pos()


    class LenSubpacket(KaitaiStruct):
        SEQ_FIELDS = ["first_octet", "second_octet", "scalar"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['first_octet']['start'] = self._io.pos()
            self.first_octet = self._io.read_u1()
            self._debug['first_octet']['end'] = self._io.pos()
            if  ((self.first_octet >= 192) and (self.first_octet < 255)) :
                self._debug['second_octet']['start'] = self._io.pos()
                self.second_octet = self._io.read_u1()
                self._debug['second_octet']['end'] = self._io.pos()

            if self.first_octet == 255:
                self._debug['scalar']['start'] = self._io.pos()
                self.scalar = self._io.read_u4be()
                self._debug['scalar']['end'] = self._io.pos()


        @property
        def len(self):
            if hasattr(self, '_m_len'):
                return self._m_len if hasattr(self, '_m_len') else None

            self._m_len = (self.first_octet if self.first_octet < 192 else (((((self.first_octet - 192) << 8) + self.second_octet) + 192) if  ((self.first_octet >= 192) and (self.first_octet < 255))  else self.scalar))
            return self._m_len if hasattr(self, '_m_len') else None


    class NotationData(KaitaiStruct):
        SEQ_FIELDS = ["flags", "len_name", "len_value", "name", "value"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_bytes(4)
            self._debug['flags']['end'] = self._io.pos()
            self._debug['len_name']['start'] = self._io.pos()
            self.len_name = self._io.read_u2be()
            self._debug['len_name']['end'] = self._io.pos()
            self._debug['len_value']['start'] = self._io.pos()
            self.len_value = self._io.read_u2be()
            self._debug['len_value']['end'] = self._io.pos()
            self._debug['name']['start'] = self._io.pos()
            self.name = self._io.read_bytes(self.len_name)
            self._debug['name']['end'] = self._io.pos()
            self._debug['value']['start'] = self._io.pos()
            self.value = self._io.read_bytes(self.len_value)
            self._debug['value']['end'] = self._io.pos()


    class PublicKeyPacket(KaitaiStruct):
        SEQ_FIELDS = ["version", "timestamp", "public_key_algorithm", "len_alg", "rsa_n", "padding", "rsa_e"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u1()
            self._debug['version']['end'] = self._io.pos()
            self._debug['timestamp']['start'] = self._io.pos()
            self.timestamp = self._io.read_u4be()
            self._debug['timestamp']['end'] = self._io.pos()
            self._debug['public_key_algorithm']['start'] = self._io.pos()
            self.public_key_algorithm = KaitaiStream.resolve_enum(self._root.PublicKeyAlgorithms, self._io.read_u1())
            self._debug['public_key_algorithm']['end'] = self._io.pos()
            self._debug['len_alg']['start'] = self._io.pos()
            self.len_alg = self._io.read_u2be()
            self._debug['len_alg']['end'] = self._io.pos()
            self._debug['rsa_n']['start'] = self._io.pos()
            self.rsa_n = self._io.read_bytes(self.len_alg // 8)
            self._debug['rsa_n']['end'] = self._io.pos()
            self._debug['padding']['start'] = self._io.pos()
            self.padding = self._io.read_u2be()
            self._debug['padding']['end'] = self._io.pos()
            self._debug['rsa_e']['start'] = self._io.pos()
            self.rsa_e = self._io.read_bytes(3)
            self._debug['rsa_e']['end'] = self._io.pos()


    class KeyExpirationTime(KaitaiStruct):
        SEQ_FIELDS = ["time"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['time']['start'] = self._io.pos()
            self.time = self._io.read_u4be()
            self._debug['time']['end'] = self._io.pos()


    class Packet(KaitaiStruct):
        SEQ_FIELDS = ["one", "new_packet_format", "packet_type_new", "packet_type_old", "len_type", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['one']['start'] = self._io.pos()
            self.one = self._io.read_bits_int(1) != 0
            self._debug['one']['end'] = self._io.pos()
            self._debug['new_packet_format']['start'] = self._io.pos()
            self.new_packet_format = self._io.read_bits_int(1) != 0
            self._debug['new_packet_format']['end'] = self._io.pos()
            if self.new_packet_format:
                self._debug['packet_type_new']['start'] = self._io.pos()
                self.packet_type_new = KaitaiStream.resolve_enum(self._root.PacketTags, self._io.read_bits_int(6))
                self._debug['packet_type_new']['end'] = self._io.pos()

            if not (self.new_packet_format):
                self._debug['packet_type_old']['start'] = self._io.pos()
                self.packet_type_old = KaitaiStream.resolve_enum(self._root.PacketTags, self._io.read_bits_int(4))
                self._debug['packet_type_old']['end'] = self._io.pos()

            if not (self.new_packet_format):
                self._debug['len_type']['start'] = self._io.pos()
                self.len_type = self._io.read_bits_int(2)
                self._debug['len_type']['end'] = self._io.pos()

            self._io.align_to_byte()
            self._debug['body']['start'] = self._io.pos()
            _on = self.new_packet_format
            if _on == False:
                self.body = self._root.OldPacket(self._io, self, self._root)
                self.body._read()
            self._debug['body']['end'] = self._io.pos()


    class TrustSignature(KaitaiStruct):
        SEQ_FIELDS = ["level", "amount"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['level']['start'] = self._io.pos()
            self.level = self._io.read_u1()
            self._debug['level']['end'] = self._io.pos()
            self._debug['amount']['start'] = self._io.pos()
            self.amount = self._io.read_u1()
            self._debug['amount']['end'] = self._io.pos()



