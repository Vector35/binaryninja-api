#!/usr/bin/env python3

# These are not real registers and should be excluded from the intrinsic types
XED_INVALID_OPERAND_REGISTERS = {
    'XED_REG_INVALID',
    'XED_REG_MSRS',
    'XED_REG_STACKPUSH',
    'XED_REG_STACKPOP',
    'XED_REG_ERROR',
    'XED_REG_LAST',
}

class TypeCacher():

    def __init__(self, name):
        self.cached_types = []
        self.name = name
    
    def get_cached_type_str(self, type_str):
        try:
            cached_type_str = 'X86CommonArchitecture::cached_%s_types[%d]' % (self.name, self.cached_types.index(type_str))
        except:
            self.cached_types.append(type_str)
            cached_type_str = 'X86CommonArchitecture::cached_%s_types[%d]' % (self.name, len(self.cached_types) - 1)

        return cached_type_str
    
    def dump_to_file(self, decl_path):
        with open(decl_path, 'w') as output:
            output.write('// Generated file, please do not edit directly\n\n')
            type_id_str = self.cached_types[0].split(' ')[0]
            n = len(self.cached_types)
            output.write(f'X86CommonArchitecture::cached_{self.name}_types = new {type_id_str}[{n}];\n')
            for idx, cached_type in enumerate(self.cached_types):
                output.write(f'X86CommonArchitecture::cached_{self.name}_types[{idx}] = {cached_type};\n')

class CodeGenerator():
    
    def __init__(self, path, vector_element_name, enclose_element_with, name, rw):
        self.file = open(path, 'w')
        self.write_header()
        self.vector_element_name = vector_element_name
        self.enclose_element_with = enclose_element_with
        self.rw = rw
        self.name = name
        self.type_cacher = TypeCacher(name)
        # if you do not exclude these, when you run code like `Architecture['x86_64']`,
        # if will create integer of size 576
        self.excluded_intrinsics = [
            'INTRINSIC_XED_IFORM_XSAVE_MEMmxsave',
            'INTRINSIC_XED_IFORM_XSAVE64_MEMmxsave',
            'INTRINSIC_XED_IFORM_XSAVEOPT_MEMmxsave',
            'INTRINSIC_XED_IFORM_XSAVEOPT64_MEMmxsave',
            'INTRINSIC_XED_IFORM_XSAVES_MEMmxsave',
            'INTRINSIC_XED_IFORM_XSAVES64_MEMmxsave',
            'INTRINSIC_XED_IFORM_XSAVEC_MEMmxsave',
            'INTRINSIC_XED_IFORM_XSAVEC64_MEMmxsave',
            'INTRINSIC_XED_IFORM_XRSTOR_MEMmxsave',
            'INTRINSIC_XED_IFORM_XRSTOR64_MEMmxsave',
            'INTRINSIC_XED_IFORM_XRSTORS_MEMmxsave',
            'INTRINSIC_XED_IFORM_XRSTORS64_MEMmxsave',
        ]

    def clean_up(self):
        self.file.close()

    def write_header(self):
        self.file.write('// Generated file, please do not edit directly\n\n')

    def generate_intrinsic(self, ins):

        if ins.iform in self.excluded_intrinsics:
            return

        s = 'case %s:' % ins.iform
        s += '\n\treturn '
        return_str = 'vector<%s> ' % self.vector_element_name
        return_str += '{ '
        for operand in ins.operands:
            if not self.rw in operand.rw:
                continue

            op_str = operand.generate_str()

            if self.enclose_element_with == '':
                return_str += '%s, ' % op_str
            else:
                return_str += '%s(%s), ' % (self.enclose_element_with, op_str)

        if return_str.endswith(', '):
            return_str = return_str[:-2]

        return_str += ' }'
        return_str = self.type_cacher.get_cached_type_str(return_str)
        s += return_str
        s += ';\n'
        self.file.write(s)
    
    def dump_cached_types(self):
        self.type_cacher.dump_to_file(f'../x86_intrinsic_cached_{self.name}_types.include')

class Intrinsic():
    def __init__(self):
        self.iform = ''
        self.operands = []
        self.vl = None

    def reset(self):
        self.iform = ''
        self.operands = []
        self.vl = None
   
    def set_iform(self, iform):
        self.iform = iform

    def set_VL(self, vl):
        self.vl = vl

    def add_operand(self, operand):
        if operand.oc2 == 'vv':
            if self.vl is None:
                print('cannot determine number of elements')
                # more info goes here
            else:
                operand.oc2 = self.vl
        elif operand.oc2 in XED_INVALID_OPERAND_REGISTERS:
            # These are not real registers
            return

        operand.parse()
        self.operands.append(operand)

class Operand():
    
    def __init__(self, xtype, rw, oc2):
        self.xtype = xtype
        self.rw = rw
        self.oc2 = oc2
    
    def parse(self):
        # from build/obj/dgen/all-element-types.txt
        #         #XTYPE       TYPE   BITS-PER-ELEM
        # #
        # var      VARIABLE    0  # instruction must set NELEM and  ELEMENT_SIZE
        # struct     STRUCT    0  # many elements of different widths
        # int           INT    0  # one element, all the bits, width varies
        # uint         UINT    0  # one element, all the bits, width varies
        # #
        # i1            INT    1
        # i8            INT    8
        # i16           INT   16
        # i32           INT   32
        # i64           INT   64
        # u8           UINT    8
        # u16          UINT   16
        # u32          UINT   32
        # u64          UINT   64
        # u128         UINT  128
        # u256         UINT  256
        # f32        SINGLE   32
        # f64        DOUBLE   64
        # f80    LONGDOUBLE   80
        # b80       LONGBCD   80

        self.signed = (self.xtype[0] == 'i')

        if self.xtype[0] == 'f':
            self.type = 'float'
        elif self.xtype == 'i1':
            self.type = 'boolean'
        else:
            self.type = 'int'

        # thse lengths are obtained from A.2.2  Codes for Operand Type
        # of the Intel Dev Manual Volume 2
        # See comment inside for varying sizes
        size_mapping = {
            'f80': 80,
            'mem32real': 32,
            'mem64real': 64,
            'mem80real': 80,
            'm32real': 32,
            'm32int': 32,
            'm64real': 64,
            'm64int': 32,
            'm80real': 80,
            'mskw': 1,
            'mem14': 14 * 8,
            'mem28': 28 * 8,
            'mem16': 16 * 8,
            'mem94': 94 * 8,
            'mem108': 108 * 8,
            'mem32int': 32,
            'mem16int': 16,
            "mem80dec": 80,
            'b': 8,
            'w': 16,
            'd': 32,
            'q': 64,
            'u64': 64,
            'dq': 128,
            'qq': 256,
            'zd': 512,
            'zu8': 512,
            'zi8': 512,
            'zi16': 512,
            'zu16': 512,
            'zuf64': 512,
            'zuf32': 512,
            'zf32': 512,
            'zf64': 512,
            'zi64': 512,
            'zu64': 512,
            'zu128': 512,
            'zi32': 512,
            'zu32': 512,
            'VL512': 512,
            'VL256': 256,
            'VL128': 128,
            'ss': 128,
            'sd': 128,
            'ps': 128,
            'pd': 128,
            'zbf16': 16,
            's': 80,
            's64': 64,
            'a16': 16,
            'a32': 32,
            'xud': 128,
            'xuq': 128,

            # The specifiers below actually map to variable sizes, e.g., v can be 
            # "Word, doubleword or quadword (in 64-bit mode), depending on operand-size attribute".
            # However, instructions that contain such operands are mostly covered by explicit liftings,
            # for example, add, sub, and mov, etc. So they do not mess up the types
            # Excpetions are lzcnt, tzcnt, popcnt, and crc32,
            # which have to be further splitted into various finer-grained intrinsics
            'v': 32,
            'z': 32,
            'y': 64,

            # below specifiers are not found in the list, their size are determined manually
            'spw': 32,
            'spw8': 32,
            'spw2': 32,
            'spw3': 32,
            'spw5': 32,
            'wrd': 16,
            'bnd32': 32,
            'bnd64': 64,
            'p': 64,
            'p2': 64,
            'mfpxenv': 512 * 8,
            'mxsave': 576 * 8,
            'mprefetch': 64,
            'pmmsz16': 14 * 8,
            'pmmsz32': 24 * 8,

            'rFLAGS': 64,
            'eFLAGS': 32,
            'GPR64_R': 64,
            'GPR64_B': 64,
            'GPRv_R': 64,
            'GPRv_B': 64,
            'GPR32_R': 32,
            'GPR32_B': 32,
            'GPR16_R': 16,
            'GPR16_B': 16,
            'GPR8_R': 8,
            'GPR8_B': 8,
            'GPRy_B': 64,
            'GPRz_B': 64,
            'GPRz_R': 64,
            'GPR8_SB': 64,
            'A_GPR_R': 64,
            'A_GPR_B': 64,
            'GPRv_SB': 64,
            'BND_R': 64,
            'BND_B': 64,
            'OeAX': 16,
            'OrAX': 16,
            'OrBX': 16,
            'OrCX': 16,
            'OrDX': 16,
            'OrBP': 16,
            'OrSP': 16,
            'ArAX': 16,
            'ArBX': 16,
            'ArCX': 16,
            'ArDI': 16,
            'ArSI': 16,
            'ArBP': 16,
            'FINAL_SSEG0': 16,
            'FINAL_SSEG1': 16,
            'FINAL_DSEG': 16,
            'FINAL_DSEG0': 16,
            'FINAL_DSEG1': 16,
            'FINAL_ESEG': 16,
            'FINAL_ESEG1': 16,
            'SEG': 16,
            'SEG_MOV': 16,
            'SrSP': 64,
            'rIP': 64,
            'CR_R': 32,
            'DR_R': 32,
            'XED_REG_AL': 8,
            'XED_REG_AH': 8,
            'XED_REG_BL': 8,
            'XED_REG_BH': 8,
            'XED_REG_CL': 8,
            'XED_REG_DL': 8,

            'XED_REG_AX': 16,
            'XED_REG_BX': 16,
            'XED_REG_CX': 16,
            'XED_REG_DX': 16,
            'XED_REG_BP': 16,
            'XED_REG_SP': 16,
            'XED_REG_SI': 16,
            'XED_REG_DI': 16,
            'XED_REG_SS': 16,
            'XED_REG_DS': 16,
            'XED_REG_ES': 16,
            'XED_REG_IP': 16,
            'XED_REG_FS': 16,
            'XED_REG_GS': 16,
            'XED_REG_CS': 16,

            'XED_REG_EAX': 32,
            'XED_REG_EBX': 32,
            'XED_REG_ECX': 32,
            'XED_REG_EDX': 32,
            'XED_REG_EIP': 32,
            'XED_REG_ESP': 32,
            'XED_REG_EBP': 32,
            'XED_REG_ESI': 32,
            'XED_REG_EDI': 32,

            'XED_REG_RAX': 64,
            'XED_REG_RBX': 64,
            'XED_REG_RCX': 64,
            'XED_REG_RDX': 64,
            'XED_REG_RIP': 64,
            'XED_REG_RSP': 64,
            'XED_REG_RBP': 64,
            'XED_REG_RSI': 64,
            'XED_REG_RDI': 64,
            'XED_REG_R11': 64,

            'XED_REG_X87STATUS': 16,
            'XED_REG_X87CONTROL': 16,
            'XED_REG_X87TAG': 16,
            'XED_REG_X87PUSH': 64,
            'XED_REG_X87POP': 64,
            'XED_REG_X87POP2': 64,

            'XED_REG_CR0': 64,
            'XED_REG_XCR0': 64,
            'XED_REG_MXCSR': 32,

            'XED_REG_GDTR': 48,
            'XED_REG_LDTR': 48,
            'XED_REG_IDTR': 48,

            'XED_REG_TR': 64,
            'XED_REG_TSC': 64,
            'XED_REG_TSCAUX': 64,
            'XED_REG_MSRS': 64,
        }

        # if '_' in self.oc2:
        #     self.oc2 = self.oc2.split('_')[0]

        try:
            self.width = size_mapping[self.oc2]
        except:
            print('I do not know the width of oc2: %s' % self.oc2)
            self.width = 8
  
        if self.xtype == 'struct' or self.xtype == 'INVALID':
            self.element_size = self.width
        elif self.xtype == 'int':
            self.element_size = 32
        elif self.xtype == 'uint':
            self.element_size = 32
        elif self.xtype == 'bf16':
            self.element_size = 16
        elif self.xtype == '2bf16':
            self.element_size = 32
        elif self.xtype == '2f16':
            self.element_size = 32
        elif self.xtype == '2i16':
            self.element_size = 32
        elif self.xtype == '2u16':
            self.element_size = 32
        elif self.xtype == '4i8':
            self.element_size = 32
        elif self.xtype == '4u8':
            self.element_size = 32
        else:
            size_str = self.xtype[1:]
            self.element_size = int(size_str)
        
        self.element_size_byte = int((self.element_size + 7) / 8)

        n = int((self.width + 7) / 8) / self.element_size_byte
        n = int(n)

        if n < 1:
            n = 1

        self.n_element = n

    def generate_str(self):
        array = False
        if self.element_size > 1:
            array = True
        
        inner_str = ''
        if self.type == 'float':
            inner_str = 'Type::FloatType(%d)' % self.element_size_byte
        elif self.type == 'int':
            signed_str = 'true' if self.signed else 'false'
            inner_str = 'Type::IntegerType(%d, %s)' % (self.element_size_byte, signed_str)
        else:
            inner_str = 'Type::BoolType()'
        
        if self.n_element > 1:
            s = 'Type::ArrayType(%s, %d)' % (inner_str, self.n_element)
        else:
            s = inner_str

        return s

def main():
    intrinsic_input = CodeGenerator('../x86_intrinsic_input_type.include', 'NameAndType', 'NameAndType', 'input', 'r')
    intrinsic_output = CodeGenerator('../x86_intrinsic_output_type.include', 'Confidence<Ref<Type>>', '', 'output', 'w')
    with open('iform-type-dump.txt', 'r') as f:
        ins = Intrinsic()
        for line in f:
            if line.strip() == '':
                intrinsic_input.generate_intrinsic(ins)
                intrinsic_output.generate_intrinsic(ins)
                ins.reset()
                continue

            if line.startswith('INTRINSIC_XED_IFORM_'):
                ins.set_iform(line.strip())
            elif line.startswith('VL'):
                ins.set_VL(line.strip())
            elif line.startswith('\t'):
                fields = line.strip().split('\t')
                op = Operand(fields[0], fields[1], fields[2])
                ins.add_operand(op)
            else:
                print('unexpected line! I do not know what to do with it')
                print(line)

    intrinsic_input.dump_cached_types()
    intrinsic_output.dump_cached_types()

    intrinsic_input.clean_up()
    intrinsic_output.clean_up()

if __name__ == '__main__':
    main()
