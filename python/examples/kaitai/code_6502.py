# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Code6502(KaitaiStruct):
    """This spec can be used to disassemble raw stream of 6502 CPU machine
    code into individual operations. Each operation includes an opcode
    and, optionally, an argument. Register arguments are part of the
    `opcode` enum.
    """

    class Opcode(Enum):
        brk_impl = 0
        ora_x_ind = 1
        ora_zpg = 5
        asl_zpg = 6
        php_impl = 8
        ora_imm = 9
        asl_a = 10
        ora_abs = 13
        asl_abs = 14
        bpl_rel = 16
        ora_ind_y = 17
        ora_zpg_x = 21
        asl_zpg_x = 22
        clc_impl = 24
        ora_abs_y = 25
        ora_abs_x = 29
        asl_abs_x = 30
        jsr_abs = 32
        and_x_ind = 33
        bit_zpg = 36
        and_zpg = 37
        rol_zpg = 38
        plp_impl = 40
        and_imm = 41
        rol_a = 42
        bit_abs = 44
        and_abs = 45
        rol_abs = 46
        bmi_rel = 48
        and_ind_y = 49
        and_zpg_x = 53
        rol_zpg_x = 54
        sec_impl = 56
        and_abs_y = 57
        and_abs_x = 61
        rol_abs_x = 62
        rti_impl = 64
        eor_x_ind = 65
        eor_zpg = 69
        lsr_zpg = 70
        pha_impl = 72
        eor_imm = 73
        lsr_a = 74
        jmp_abs = 76
        eor_abs = 77
        lsr_abs = 78
        bvc_rel = 80
        eor_ind_y = 81
        eor_zpg_x = 85
        lsr_zpg_x = 86
        cli_impl = 88
        eor_abs_y = 89
        eor_abs_x = 93
        lsr_abs_x = 94
        rts_impl = 96
        adc_x_ind = 97
        adc_zpg = 101
        ror_zpg = 102
        pla_impl = 104
        adc_imm = 105
        ror_a = 106
        jmp_ind = 108
        adc_abs = 109
        ror_abs = 110
        bvs_rel = 112
        adc_ind_y = 113
        adc_zpg_x = 117
        ror_zpg_x = 118
        sei_impl = 120
        adc_abs_y = 121
        adc_abs_x = 125
        ror_abs_x = 126
        sta_x_ind = 129
        sty_zpg = 132
        sta_zpg = 133
        stx_zpg = 134
        dey_impl = 136
        txa_impl = 138
        sty_abs = 140
        sta_abs = 141
        stx_abs = 142
        bcc_rel = 144
        sta_ind_y = 145
        sty_zpg_x = 148
        sta_zpg_x = 149
        stx_zpg_y = 150
        tya_impl = 152
        sta_abs_y = 153
        txs_impl = 154
        sta_abs_x = 157
        ldy_imm = 160
        lda_x_ind = 161
        ldx_imm = 162
        ldy_zpg = 164
        lda_zpg = 165
        ldx_zpg = 166
        tay_impl = 168
        lda_imm = 169
        tax_impl = 170
        ldy_abs = 172
        lda_abs = 173
        ldx_abs = 174
        bcs_rel = 176
        lda_ind_y = 177
        ldy_zpg_x = 180
        lda_zpg_x = 181
        ldx_zpg_y = 182
        clv_impl = 184
        lda_abs_y = 185
        tsx_impl = 186
        ldy_abs_x = 188
        lda_abs_x = 189
        ldx_abs_y = 190
        cpy_imm = 192
        cmp_x_ind = 193
        cpy_zpg = 196
        cmp_zpg = 197
        dec_zpg = 198
        iny_impl = 200
        cmp_imm = 201
        dex_impl = 202
        cpy_abs = 204
        cmp_abs = 205
        dec_abs = 206
        bne_rel = 208
        cmp_ind_y = 209
        cmp_zpg_x = 213
        dec_zpg_x = 214
        cld_impl = 216
        cmp_abs_y = 217
        cmp_abs_x = 221
        dec_abs_x = 222
        cpx_imm = 224
        sbc_x_ind = 225
        cpx_zpg = 228
        sbc_zpg = 229
        inc_zpg = 230
        inx_impl = 232
        sbc_imm = 233
        nop_impl = 234
        cpx_abs = 236
        sbc_abs = 237
        inc_abs = 238
        beq_rel = 240
        sbc_ind_y = 241
        sbc_zpg_x = 245
        inc_zpg_x = 246
        sed_impl = 248
        sbc_abs_y = 249
        sbc_abs_x = 253
        inc_abs_x = 254
    SEQ_FIELDS = ["operations"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['operations']['start'] = self._io.pos()
        self.operations = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['operations']:
                self._debug['operations']['arr'] = []
            self._debug['operations']['arr'].append({'start': self._io.pos()})
            _t_operations = self._root.Operation(self._io, self, self._root)
            _t_operations._read()
            self.operations.append(_t_operations)
            self._debug['operations']['arr'][len(self.operations) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['operations']['end'] = self._io.pos()

    class Operation(KaitaiStruct):
        SEQ_FIELDS = ["code", "args"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = KaitaiStream.resolve_enum(self._root.Opcode, self._io.read_u1())
            self._debug['code']['end'] = self._io.pos()
            self._debug['args']['start'] = self._io.pos()
            _on = self.code
            if _on == self._root.Opcode.bcc_rel:
                self.args = self._io.read_s1()
            elif _on == self._root.Opcode.ora_ind_y:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.lda_ind_y:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.cpx_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.sta_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.sta_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.bcs_rel:
                self.args = self._io.read_s1()
            elif _on == self._root.Opcode.ldy_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.lsr_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.and_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.adc_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.sta_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.bne_rel:
                self.args = self._io.read_s1()
            elif _on == self._root.Opcode.lda_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.adc_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.lsr_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.adc_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.sta_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.cpx_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.jmp_ind:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.adc_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.eor_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.eor_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.sta_x_ind:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.sbc_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.cpy_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.ldx_abs_y:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.adc_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.bpl_rel:
                self.args = self._io.read_s1()
            elif _on == self._root.Opcode.ora_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.ror_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.adc_ind_y:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.eor_ind_y:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.lda_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.bit_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.rol_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.sty_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.jsr_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.eor_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.eor_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.lda_abs_y:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.lda_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.bmi_rel:
                self.args = self._io.read_s1()
            elif _on == self._root.Opcode.sty_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.adc_x_ind:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.rol_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.stx_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.asl_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.lsr_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.ora_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.adc_abs_y:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.ldy_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.cmp_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.lda_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.bvs_rel:
                self.args = self._io.read_s1()
            elif _on == self._root.Opcode.lda_x_ind:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.cmp_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.inc_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.asl_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.and_abs_y:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.ldx_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.and_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.cpx_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.dec_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.ror_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.ldx_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.dec_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.sbc_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.cmp_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.ror_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.inc_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.and_x_ind:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.sbc_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.asl_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.eor_x_ind:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.ora_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.ldy_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.sbc_x_ind:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.asl_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.sbc_abs_y:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.rol_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.lsr_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.stx_zpg_y:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.ora_abs_y:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.eor_abs_y:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.bit_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.ldx_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.ldy_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.jmp_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.beq_rel:
                self.args = self._io.read_s1()
            elif _on == self._root.Opcode.dec_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.and_ind_y:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.and_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.cmp_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.eor_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.sbc_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.cmp_abs_y:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.sbc_ind_y:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.cmp_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.stx_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.sty_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.cpy_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.dec_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.ror_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.sta_abs_y:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.inc_abs_x:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.lda_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.cmp_ind_y:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.cpy_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.ldx_zpg_y:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.sbc_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.ora_x_ind:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.rol_zpg_x:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.ora_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.sta_ind_y:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.and_abs:
                self.args = self._io.read_u2le()
            elif _on == self._root.Opcode.and_imm:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.cmp_x_ind:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.ldy_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.inc_zpg:
                self.args = self._io.read_u1()
            elif _on == self._root.Opcode.bvc_rel:
                self.args = self._io.read_s1()
            elif _on == self._root.Opcode.ora_zpg:
                self.args = self._io.read_u1()
            self._debug['args']['end'] = self._io.pos()



