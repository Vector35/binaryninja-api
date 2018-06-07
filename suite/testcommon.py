import tempfile
import pickle
import os
import zipfile
import inspect
import binaryninja as binja
from binaryninja.binaryview import BinaryViewType, BinaryView
from binaryninja.filemetadata import FileMetadata
import subprocess
import traceback
import types


def get_file_list(test_store):
    all_files = []
    for root, dir, files in os.walk(test_store):
        for file in files:
            all_files.append(os.path.join(root, file))

    return all_files


class Builder(object):
    def __init__(self, test_store):
        self.test_store = test_store
        self.examples_dir = os.path.join(self.test_store, "..", "..", "..", "python", "examples")

    def methods(self):
        methodnames = []
        for methodname, method in inspect.getmembers(self, predicate=inspect.ismethod):
            if methodname.startswith("test_"):
                methodnames.append(methodname)
        return methodnames

    def unpackage_file(self, file):
        if not os.path.exists(file):
            with zipfile.ZipFile(file + ".zip", "r") as zf:
                zf.extractall()
        assert os.path.exists(file)


class BinaryViewTestBuilder(Builder):
    """ The BinaryViewTestBuilder is for test that are verified against a binary.
        The tests are first run on your dev machine to base line then run again
        on the build machine to verify they are correct.

         - Function that are tests should start with 'test_'
         - Function doc string used as 'on error' message
         - Should return: list of strings
    """
    def __init__(self, filename, test_store):
        self.filename = filename
        self.bv = BinaryViewType.get_view_of_file(filename)
        if self.bv is None:
            print("%s is not an executable format" % filename)
            return

    def test_available_types(self):
        """Available types don't match"""
        return [x.name for x in BinaryView(FileMetadata()).open(self.filename).available_view_types]

    def test_function_starts(self):
        """Function starts list doesnt match"""
        return [hex(x.start) for x in self.bv.functions]

    def test_function_symbol_names(self):
        """Function.symbol.name list doesnt match"""
        return [x.symbol.name + ' ' + str(x.symbol.type) + ' ' + hex(x.symbol.address) for x in self.bv.functions]

    def test_function_can_return(self):
        """Function.can_return list doesnt match"""
        return [x.symbol.name + ' ' + str(x.symbol.type) + ' ' + hex(x.symbol.address) + ' ' + str(bool(x.can_return)) for x in self.bv.functions]

    def test_function_basic_blocks(self):
        """Function basic_block list doesnt match (start, end, has_undetermined_outgoing_edges)"""
        bblist = []
        for func in self.bv.functions:
            for bb in func.basic_blocks:
                bblist.append(hex(bb.start) + ' ' + hex(bb.end) + ' ' + str(bb.has_undetermined_outgoing_edges))
        return bblist

    def test_function_low_il_basic_blocks(self):
        """"Function low_il_basic_block list doesnt match"""
        ilbblist = []
        for func in self.bv.functions:
            for bb in func.low_level_il.basic_blocks:
                ilbblist.append(hex(bb.start) + ' ' + hex(bb.end) + ' ' + str(len(bb.outgoing_edges)))
        return ilbblist
    
    def test_function_med_il_basic_blocks(self):
        """"Function med_il_basic_block list doesn't match"""
        ilbblist = []
        for func in self.bv.functions:
            for bb in func.medium_level_il.basic_blocks:
                ilbblist.append(hex(bb.start) + ' ' + hex(bb.end) + ' ' + str(len(bb.outgoing_edges)))
        return ilbblist

    def test_symbols(self):
        """"Symbols list doesn't match"""
        return [str(i) for i in sorted(self.bv.symbols)]

    def test_strings(self):
        """Strings list doesn't match"""
        return [str(x.value) + ' ' + str(x.type) + ' ' + str(hex(x.start)) for x in self.bv.strings]


    def test_low_il_instructions(self):
        """LLIL instructions produced different output"""
        retinfo = []
        for func in self.bv.functions:
            for bb in func.low_level_il.basic_blocks:
                for ins in bb:
                    retinfo.append(str(ins.medium_level_il))
                    retinfo.append(str(ins.mapped_medium_level_il))
                    retinfo.append(str(ins.value))
                    retinfo.append(str(ins.possible_values))
                    retinfo.append(str(ins.prefix_operands))
                    retinfo.append(str(ins.postfix_operands))
                    retinfo.append(str(ins.ssa_form))
                    retinfo.append(str(ins.non_ssa_form))

        return retinfo

    
    def test_low_il_ssa(self):
        """LLIL ssa produced different output"""
        retinfo = []
        reg_list = [binja.SSARegister(i,1) for i in self.bv.arch.regs]
        flag_list = [binja.SSAFlag(i,1) for i in self.bv.arch.flags]
        for func in self.bv.functions:
            func = func.low_level_il
            for reg in reg_list:
                retinfo.append(str(func.get_ssa_reg_definition(reg)))
                retinfo.append(str(func.get_ssa_reg_uses(reg)))
                retinfo.append(str(func.get_ssa_reg_value(reg)))
            for flag in flag_list:
                retinfo.append(str(func.get_ssa_flag_uses(flag)))
                retinfo.append(str(func.get_ssa_flag_value(flag)))
            for bb in func.basic_blocks:
                for ins in bb:
                    tempind = func.get_non_ssa_instruction_index(ins.instr_index)
                    retinfo.append(str(tempind))
                    retinfo.append(str(func.get_ssa_instruction_index(tempind)))
                    retinfo.append(str(func.get_medium_level_il_instruction_index(ins.instr_index)))
                    retinfo.append(str(func.get_mapped_medium_level_il_instruction_index(ins.instr_index)))

        return retinfo


    def test_med_il_instructions(self):
        """MLIL instructions produced different output"""
        retinfo = []
        for func in self.bv.functions:
            for bb in func.medium_level_il.basic_blocks:
                for ins in bb:
                    retinfo.append(str(ins.expr_type))
                    retinfo.append(str(ins.low_level_il))
                    retinfo.append(str(ins.value))
                    retinfo.append(str(ins.possible_values))
                    retinfo.append(str(ins.branch_dependence))
                    retinfo.append(str(sorted([str(i) for i in ins.prefix_operands])))
                    retinfo.append(str(sorted([str(i) for i in ins.postfix_operands])))
                    retinfo.append(str(ins.ssa_form))
                    retinfo.append(str(ins.non_ssa_form))

        return retinfo

    

    def test_med_il_vars(self):
        """"Function med_il_vars doesn't match"""
        varlist = []
        for func in self.bv.functions:
            func = func.medium_level_il
            for bb in func.basic_blocks:
                for instruction in bb:
                    instruction = instruction.ssa_form
                    for var in (instruction.vars_read + instruction.vars_written):
                        #varlist.append((func.get_var_uses(var), func.get_var_definitions(var)))
                        if hasattr(var, "var"):
                            varlist.append(str(func.get_ssa_var_definition(var)) + ' ' + \
                                str(func.get_ssa_var_uses(var)) + ' ' + \
                                str(func.get_ssa_var_value(var)) + ' ' + \
                                str(instruction.get_ssa_var_possible_values(var)) + ' ' + \
                                str(instruction.get_ssa_var_version))
        return varlist

    def test_function_stack(self):
        """Function stack produced different output"""
        funcinfo = []
        for func in self.bv.functions:
            func.stack_adjustment = func.stack_adjustment
            func.reg_stack_adjustments = func.reg_stack_adjustments
            func.create_user_stack_var(0, binja.Type.int(4), "testuservar")
            func.create_auto_stack_var(4, binja.Type.int(4), "testautovar")

            temp = []
            for i in func.stack_layout:
                temp.append(str(i))
            funcinfo.append(str(temp))

            funcinfo.append(str(func.get_stack_contents_at(func.start + 0x10, 0, 0x10)))
            funcinfo.append(str(func.get_stack_contents_after(func.start + 0x10, 0, 0x10)))
            funcinfo.append(str(func.get_stack_var_at_frame_offset(0, 0)))
            func.delete_user_stack_var(0)
            func.delete_auto_stack_var(0)

        return funcinfo

    def test_function_llil(self):
        """Function LLIL produced different output"""
        retinfo = []

        for func in self.bv.functions:
            for llilbb in func.llil_basic_blocks:
                retinfo.append(str(llilbb))
            for llilins in func.llil_instructions:
                retinfo.append(str(llilins))
            
            for mlilbb in func.mlil_basic_blocks:
                retinfo.append(str(mlilbb))
            for mlilins in func.mlil_instructions:
                retinfo.append(str(mlilins))

            for ins in func.instructions:
                retinfo.append(str(ins))

        return retinfo


    def test_functions_attributes(self):
        """"Function attributes don't match"""
        funcinfo = []
        for func in self.bv.functions:
            func.comment = "testcomment " + func.name
            func.name = func.name
            func.can_return = func.can_return
            func.function_type = func.function_type
            func.return_type = func.return_type
            func.return_regs = func.return_regs
            func.calling_convention = func.calling_convention
            func.parameter_vars = func.parameter_vars
            func.has_variable_arguments = func.has_variable_arguments
            func.analysis_skipped = func.analysis_skipped
            func.clobbered_regs = func.clobbered_regs
            func.set_user_instr_highlight(func.start, binja.highlight.HighlightColor(red=0xff, blue=0xff, green=0))
            func.set_auto_instr_highlight(func.start, binja.highlight.HighlightColor(red=0xff, blue=0xfe, green=0))
            
            funcinfo.append(str([str(i) for i in func.vars]))
            funcinfo.append(str(func.indirect_branches))
            funcinfo.append(str(func.session_data))
            funcinfo.append(len(func.analysis_performance_info))
            funcinfo.append(str(func.clobbered_regs))
            funcinfo.append(str(func.explicitly_defined_type))
            funcinfo.append(str(func.needs_update))
            funcinfo.append(len(func.lifted_il))
            funcinfo.append(str(func.global_pointer_value))
            funcinfo.append(str(func.comment))
            funcinfo.append(str(func.too_large))
            funcinfo.append(str(func.analysis_skipped))
            funcinfo.append(str(func.get_low_level_il_at(func.start)))
            funcinfo.append(str(func.get_low_level_il_exits_at(func.start+0x100)))
            funcinfo.append(str(func.get_regs_read_by(func.start)))
            funcinfo.append(str(func.get_regs_written_by(func.start)))
            funcinfo.append(str(func.get_stack_vars_referenced_by(func.start)))
            funcinfo.append(str(func.get_constants_referenced_by(func.start)))
            funcinfo.append(str(func.get_lifted_il_at(func.start)))
            funcinfo.append(str(func.get_flags_read_by_lifted_il_instruction(0)))
            funcinfo.append(str(func.get_flags_written_by_lifted_il_instruction(0)))
            funcinfo.append(str(func.create_graph()))
            funcinfo.append(str(func.get_indirect_branches_at(func.start+0x10)))
            funcinfo.append(str(func.get_block_annotations(func.start)))
            funcinfo.append(str(func.get_basic_block_at(func.start)))
            funcinfo.append(str(func.get_instr_highlight(func.start)))
            funcinfo.append(str(func.get_type_tokens()))


        return funcinfo

    def test_BinaryView(self):
        """BinaryView produced different results"""
        retinfo = []

        retinfo += [str(i[1]) for i in self.bv.types.items()]
        retinfo.append(str(self.bv.segments))
        retinfo.append(str(self.bv.sections))
        retinfo.append(str(self.bv.allocated_ranges))
        retinfo.append(str(self.bv.session_data))
        for var in self.bv.data_vars:
            retinfo.append(str(var))
        retinfo.append(str(self.bv.entry_function))
        for i in self.bv:
            retinfo.append(str(i))
        retinfo.append(hex(self.bv.entry_point))
        retinfo.append(hex(self.bv.start))
        retinfo.append("length: " + hex(len(self.bv)))
        return retinfo




class TestBuilder(Builder):
    """ The TestBuilder is for tests that need to be checked against
        stored oracle data that isn't from a binary. These test are
        generated on your local machine then run again on the build
        machine to verify correctness.

         - Function that are tests should start with 'test_'
         - Function doc string used as 'on error' message
         - Should return: list of strings
    """

    def test_BinaryViewType_list(self):
        """BinaryViewType list doesnt match"""
        return [x.name for x in binja.BinaryViewType.list]

    def test_Architecture_list(self):
        """Architecture list doesnt match"""
        return [x.name for x in binja.Architecture.list]

    def test_Assemble(self):
        """unexpected assemble result"""
        result = []
        # success cases
        result.append(binja.Architecture["x86"].assemble("xor eax, eax"))
        result.append(binja.Architecture["x86_64"].assemble("xor rax, rax"))
        result.append(binja.Architecture["mips32"].assemble("move $ra, $zero"))
        result.append(binja.Architecture["mipsel32"].assemble("move $ra, $zero"))
        result.append(binja.Architecture["armv7"].assemble("str r2, [sp,  #-0x4]!"))
        result.append(binja.Architecture["aarch64"].assemble("mov x0, x0"))
        result.append(binja.Architecture["thumb2"].assemble("ldr r4, [r4]"))
        result.append(binja.Architecture["thumb2eb"].assemble("ldr r4, [r4]"))
        # fail cases
        result.append(binja.Architecture["x86"].assemble("thisisnotaninstruction"))
        result.append(binja.Architecture["x86_64"].assemble("thisisnotaninstruction"))
        result.append(binja.Architecture["mips32"].assemble("thisisnotaninstruction"))
        result.append(binja.Architecture["mipsel32"].assemble("thisisnotaninstruction"))
        result.append(binja.Architecture["armv7"].assemble("thisisnotaninstruction"))
        result.append(binja.Architecture["aarch64"].assemble("thisisnotaninstruction"))
        result.append(binja.Architecture["thumb2"].assemble("thisisnotaninstruction"))
        result.append(binja.Architecture["thumb2eb"].assemble("thisisnotaninstruction"))
        return result

    def test_Architecture(self):
        """Architecture failure"""
        if not os.path.exists(os.path.join(os.path.expanduser("~"), '.binaryninja', 'plugins', 'nes.py')):
            return

        retinfo = []
        file_name = os.path.join(self.test_store, "..", "pwnadventurez.nes")
        bv = binja.BinaryViewType["NES Bank 0"].open(file_name)
        
        retinfo.append(str([str(i) for i in bv.platform.arch.calling_conventions]))
        retinfo.append(str(bv.platform.arch.full_width_regs))

        reg = binja.RegisterValue()
        retinfo.append(str(reg.entry_value(bv.platform.arch, 'x')))
        retinfo.append(str(reg.constant(0xfe)))
        retinfo.append(str(reg.constant_ptr(0xcafebabe)))
        retinfo.append(str(reg.stack_frame_offset(0x10)))
        retinfo.append(str(reg.imported_address(0xdeadbeef)))
        retinfo.append(str(reg.return_address()))

        bv.update_analysis_and_wait()
        for func in bv.functions:
            for bb in func.low_level_il.basic_blocks:
                for ins in bb:
                    retinfo.append(str(bv.platform.arch.get_instruction_info(0x10, ins.address)))
                    retinfo.append(str(bv.platform.arch.get_instruction_text(0x10, ins.address)))
                    retinfo.append(str(ins))
        return retinfo



    def test_Function(self):
        """Function produced different result"""
        inttype = binja.Type.int(4)
        testfunction = binja.Type.function(inttype, [inttype, inttype, inttype])
        return [str(testfunction.parameters), str(testfunction.pointer(binja.Architecture["x86"], testfunction))]

    def test_Struct(self):
        """Struct produced different result"""
        inttype = binja.Type.int(4)
        struct = binja.Structure()
        struct.a = 1
        struct.insert(0, inttype)
        struct.append(inttype)
        struct.replace(0, inttype)
        struct.remove(1)
        retinfo = [str(i) for i in struct.members]
        retinfo += [struct.width]
        struct.width = 16
        retinfo += [struct.width]
        retinfo += [struct.alignment]
        struct.alignment = 8
        retinfo += [struct.alignment]
        retinfo += [struct.packed]
        struct.packed = 1
        retinfo += [struct.packed]
        retinfo += [struct.type]
        retinfo = [str(i) for i in retinfo]
        return retinfo

    def test_Enumeration(self):
        """Enumeration produced different result"""
        inttype = binja.Type.int(4)
        enum = binja.Enumeration()
        enum.a = 1
        enum.append("a", 1)
        enum.append("b", 2)
        enum.replace(0, "a", 2)
        enum.remove(0)
        retinfo = [str(enum)]
        retinfo += [str((enum == enum) and not (enum != enum))]
        return retinfo

    def test_Types(self):
        """Types produced different result"""

        file_name = os.path.join(self.test_store, "helloworld")
        bv = binja.BinaryViewType.get_view_of_file(file_name)
        
        preprocessed = binja.preprocess_source("""
        #ifdef nonexistant
        int foo = 1;
        long long foo1 = 1;
        #else
        int bar = 2;
        long long bar1 = 2;
        #endif
        """)
        source = '\n'.join([i.decode('charmap') for i in preprocessed[0].split(b'\n') if not b'#line' in i and len(i) > 0])
        typelist = bv.platform.parse_types_from_source(source)
        inttype = binja.Type.int(4)

        tokens = inttype.get_tokens() + inttype.get_tokens_before_name() +  inttype.get_tokens_after_name()
        namedtype = binja.NamedTypeReference()

        retinfo = [[str(i) for i in typelist.variables.popitem()][::-1] for i in range(len(typelist.variables))]
        retinfo += [str(namedtype)]
        
        equalcheck = (inttype == inttype) and not (inttype != inttype)
        retinfo += [str(equalcheck)]
        return retinfo


    def test_Plugin_bin_info(self):
        """print_syscalls plugin produced different result"""

        file_name = os.path.join(self.test_store, "helloworld")
        self.unpackage_file(file_name)
        result = subprocess.Popen(["python", os.path.join(self.examples_dir, "bin_info.py"), file_name], stdout=subprocess.PIPE).communicate()[0]
        # normalize line endings and path sep
        return [result.replace(b"\\", b"/").replace(b"\r\n", b"\n")]

    def test_linear_disassembly(self):
        """linear_disassembly produced different result"""
        file = os.path.join(self.test_store, "helloworld")
        self.unpackage_file(file)
        bv = binja.BinaryViewType['ELF'].open(file)
        settings = binja.DisassemblySettings()
        disass = bv.linear_disassembly
        res = []
        for i in disass:
            res.append(str(i))
        #return res

    def test_partial_register_dataflow(self):
        """partial_register_dataflow produced different results"""

        file_name = os.path.join(self.test_store, "partial_register_dataflow")
        self.unpackage_file(file_name)
        result = []
        try:
            reg_list = ['ch', 'cl', 'ah', 'edi', 'al', 'cx', 'ebp', 'ax', 'edx', 'ebx', 'esp', 'esi', 'dl', 'dh', 'di', 'bl', 'bh', 'eax', 'dx', 'bx', 'ecx', 'sp', 'si']
            bv = binja.BinaryViewType.get_view_of_file(file_name)
            for func in bv.functions:
                llil = func.low_level_il
                for i in range(0, llil.__len__()-1):
                    result.append(["LLIL:" + str(i).replace('L', '') + ":" + x + ":" + str(llil[i].get_reg_value(x)).replace('L', '') for x in reg_list])
                    result.append(["LLIL:" + str(i).replace('L', '') + ":" + x + ":" + str(llil[i].get_possible_reg_values(x)).replace('L', '') for x in reg_list])
                    result.append(["LLIL:" + str(i).replace('L', '') + ":" + x + ":" + str(llil[i].get_reg_value_after(x)).replace('L', '') for x in reg_list])
                    result.append(["LLIL:" + str(i).replace('L', '') + ":" + x + ":" + str(llil[i].get_possible_reg_values_after(x)).replace('L', '') for x in reg_list])
            bv.file.close()
            del bv
        finally:
            os.unlink(file_name)

        return result


    def test_low_il_stack(self):
        """LLIL stack produced different output"""
        file_name = os.path.join(self.test_store, "ls")
        self.unpackage_file(file_name)
        bv = binja.BinaryViewType.get_view_of_file(file_name)
        reg_list = ['ch', 'cl', 'ah', 'edi', 'al', 'cx', 'ebp', 'ax', 'edx', 'ebx', 'esp', 'esi', 'dl', 'dh', 'di', 'bl', 'bh', 'eax', 'dx', 'bx', 'ecx', 'sp', 'si']
        flag_list = ['c', 'p', 'a', 'z', 's', 'o']
        retinfo = []
        for func in bv.functions:
            for bb in func.low_level_il.basic_blocks:
                for ins in bb:
                    retinfo.append(str(ins.get_stack_contents(0,1)))
                    retinfo.append(str(ins.get_stack_contents_after(0,1)))
                    retinfo.append(str(ins.get_possible_stack_contents(0,1)))
                    retinfo.append(str(ins.get_possible_stack_contents_after(0,1)))


                    for flag in flag_list:
                        retinfo.append(str(ins.get_flag_value(flag)))
                        retinfo.append(str(ins.get_flag_value_after(flag)))
                        retinfo.append(str(ins.get_possible_flag_values(flag)))
                        retinfo.append(str(ins.get_possible_flag_values_after(flag)))

        os.unlink(file_name)

        return retinfo

    def test_med_il_stack(self):
        """MLIL stack produced different output"""
        file_name = os.path.join(self.test_store, "ls")
        self.unpackage_file(file_name)
        bv = binja.BinaryViewType.get_view_of_file(file_name)
        reg_list = ['ch', 'cl', 'ah', 'edi', 'al', 'cx', 'ebp', 'ax', 'edx', 'ebx', 'esp', 'esi', 'dl', 'dh', 'di', 'bl', 'bh', 'eax', 'dx', 'bx', 'ecx', 'sp', 'si']
        flag_list = ['c', 'p', 'a', 'z', 's', 'o']
        retinfo = []
        for func in bv.functions:
            for bb in func.medium_level_il.basic_blocks:
                for ins in bb:
                    retinfo.append(str(ins.get_var_for_stack_location(0)))
                    retinfo.append(str(ins.get_stack_contents(0, 0x10)))
                    retinfo.append(str(ins.get_stack_contents_after(0, 0x10)))
                    retinfo.append(str(ins.get_possible_stack_contents(0, 0x10)))
                    retinfo.append(str(ins.get_possible_stack_contents_after(0, 0x10)))
                    
                    for reg in reg_list:
                        retinfo.append(str(ins.get_var_for_reg(reg)))
                        retinfo.append(str(ins.get_reg_value(reg)))
                        retinfo.append(str(ins.get_reg_value_after(reg)))
                        retinfo.append(str(ins.get_possible_reg_values(reg)))
                        retinfo.append(str(ins.get_possible_reg_values_after(reg)))


                    for flag in flag_list:
                        retinfo.append(str(ins.get_flag_value(flag)))
                        retinfo.append(str(ins.get_flag_value_after(flag)))
                        retinfo.append(str(ins.get_possible_flag_values(flag)))
                        retinfo.append(str(ins.get_possible_flag_values_after(flag)))

        os.unlink(file_name)

        return retinfo


    def test_events(self):
        """Event failure"""
        file_name = os.path.join(self.test_store, "helloworld")
        self.unpackage_file(file_name)
        bv = binja.BinaryViewType['ELF'].open(file_name)

        results = []
        

        def simple_complete(self):
            results.append("analysis complete")

        evt = binja.AnalysisCompletionEvent(bv, simple_complete)

        class NotifyTest(binja.BinaryDataNotification):

            def data_written(self, view, offset, length):
                def data_written_complete(self):
                    results.append("data written {0} {1}".format(offset, length))
                evt = binja.AnalysisCompletionEvent(bv, data_written_complete)

            def data_inserted(self, view, offset, length):
                def data_inserted_complete(self):
                    results.append("data inserted {0} {1}".format(offset, length))
                evt = binja.AnalysisCompletionEvent(bv, data_inserted_complete)

            def data_removed(self, view, offset, length):
                def data_removed_complete(self):
                    results.append("data removed {0} {1}".format(offset, length))
                evt = binja.AnalysisCompletionEvent(bv, data_removed_complete)

            def function_added(self, view, func):
                def function_added_complete(self):
                    results.append("function added {0}".format(func.name))
                evt = binja.AnalysisCompletionEvent(bv, function_added_complete)

            def function_removed(self, view, func):
                def function_removed_complete(self):
                    results.append("function removed {0}".format(func.name))
                evt = binja.AnalysisCompletionEvent(bv, function_removed_complete)

            def function_updated(self, view, func):
                def function_updated_complete(self):
                    results.append("function updated {0}".format(func.name))
                evt = binja.AnalysisCompletionEvent(bv, function_updated_complete)

            def function_update_requested(self, view, func):
                def function_update_requested_complete(self):
                    results.append("function update requested {0}".format(func.name))
                evt = binja.AnalysisCompletionEvent(bv, function_update_requested_complete)

            def data_var_added(self, view, var):
                def data_var_added_complete(self):
                    results.append("data var added {0}".format(var.name))
                evt = binja.AnalysisCompletionEvent(bv, data_var_added_complete)

            def data_var_removed(self, view, var):
                def data_var_removed_complete(self):
                    results.append("data var removed {0}".format(var.name))
                evt = binja.AnalysisCompletionEvent(bv, data_var_removed_complete)

            def data_var_updated(self, view, var):
                def data_var_updated_complete(self):
                    results.append("data var updated {0}".format(var.name))
                evt = binja.AnalysisCompletionEvent(bv, data_var_updated_complete)

            def string_found(self, view, string_type, offset, length):
                def string_found_complete(self):
                    results.append("string found {0} {1}".format(offset, length))
                evt = binja.AnalysisCompletionEvent(bv, string_found_complete)

            def string_removed(self, view, string_type, offset, length):
                def string_removed_complete(self):
                    results.append("string removed {0} {1}".format(offset, length))
                evt = binja.AnalysisCompletionEvent(bv, string_removed_complete)

            def type_defined(self, view, name, type):
                def type_defined_complete(self):
                    results.append("type defined {0} {1}".format(name))
                evt = binja.AnalysisCompletionEvent(bv, type_defined_complete)

            def type_undefined(self, view, name, type):
                def type_undefined_complete(self):
                    results.append("type undefined {0} {1}".format(name))
                evt = binja.AnalysisCompletionEvent(bv, type_undefined_complete)


        test = NotifyTest()
        bv.register_notification(test)
        sacrificial_addr = 0x84fc


        type, name = bv.parse_type_string("int foo")
        type_id = type.generate_auto_type_id("source", name)
        bv.define_type(type_id, name, type)
        bv.undefine_type(type_id)

        bv.insert(sacrificial_addr, "AAAA")
        bv.define_data_var(sacrificial_addr, binja.types.Type.int(4))

        bv.write(sacrificial_addr, "BBBB")

        bv.add_function(sacrificial_addr)
        bv.remove_function(bv.get_function_at(sacrificial_addr))

        bv.undefine_data_var(sacrificial_addr)
        bv.remove(sacrificial_addr, 4)

        bv.update_analysis_and_wait()
 
        bv.unregister_notification(test)

        return str(sorted(results))

    def unpackage(self, fileName):
        testname = None
        with zipfile.ZipFile(fileName, "r") as zf:
            testname = zf.namelist()[0]
            zf.extractall()

        if not os.path.exists(testname + ".pkl"):
            return None, None
        binary_oracle = pickle.load(open(testname + ".pkl", "rb"))
        return binary_oracle.oracle_test_data, testname

    def cleanup_package(self, fileName):
        if fileName.endswith(".zip"):
            os.unlink(fileName[:-4])


class VerifyBuilder(Builder):
    """ The VerifyBuilder is for tests that verify
        Binary Ninja against expected output.

         - Function that are tests should start with 'test_'
         - Function doc string used as 'on error' message
         - Should return: boolean
    """
    def __init__(self, test_store):
        super(VerifyBuilder, self).__init__(test_store)

    def get_functions(self, bv):
        return [x.start for x in bv.functions]

    def get_comments(self, bv):
        return bv.functions[0].comments

    def test_verify_BNDB_round_trip(self):
        """Binary Ninja Database output doesn't match its input"""
        # This will test Binja's ability to save and restore databases
        # By:
        #  - Creating a binary view
        #  - Make modification that impact the database
        #  - Record those modification
        #  - Save the database
        #  - Restore the datbase
        #  - Validate that the modifications are present
        file = os.path.join(self.test_store, "helloworld")
        self.unpackage_file(file)
        try:
            bv = binja.BinaryViewType['ELF'].open(file)
            bv.update_analysis_and_wait()
            # Make some modifications to the binary view

            # Add a comment
            bv.functions[0].set_comment(bv.functions[0].start, "Function start")
            # Add a new function
            bv.add_function(bv.functions[0].start + 4)
            temp_name = next(tempfile._get_candidate_names()) + ".bndb"

            comments = self.get_comments(bv)
            functions = self.get_functions(bv)
            bv.create_database(temp_name)
            bv.file.close()
            del bv
        finally:
            os.unlink(file)

        try:
            bv = binja.FileMetadata(temp_name).open_existing_database(temp_name).get_view_of_type('ELF')
            bv.update_analysis_and_wait()
            bndb_functions = self.get_functions(bv)
            bndb_comments = self.get_comments(bv)
            # force windows to close the handle to the bndb that we want to delete
            bv.file.close()
            del bv
            return [str(functions == bndb_functions and comments == bndb_comments)]
        finally:
            os.unlink(temp_name)

