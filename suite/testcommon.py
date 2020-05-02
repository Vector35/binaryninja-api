import tempfile
import pickle
import os
import sys
import zipfile
import inspect
import binaryninja as binja
from binaryninja.binaryview import BinaryViewType, BinaryView
from binaryninja.filemetadata import FileMetadata
from binaryninja.datarender import DataRenderer
from binaryninja.function import InstructionTextToken, DisassemblyTextLine
from binaryninja.enums import InstructionTextTokenType
import subprocess
import re


# Dear people from the future: If you're adding tests or debuging an
#  issue where python2 and python3 are producing different output
#  for the same function and it's a issue of `longs`, run the output
#  through this function.  If it's a unicode/bytes issue, fix it in
#  api/python/
def fixOutput(outputList):
    # Apply regular expression to detect python2 longs
    splitList = []
    for elem in outputList:
        if isinstance(elem, str):
            splitList.append(re.split(r"((?<=[\[ ])0x[\da-f]+L|[\d]+L)", elem))
        else:
            splitList.append(elem)

    # Resolve application of regular expression
    result = []
    for elem in splitList:
        if isinstance(elem, list):
            newElem = []
            for item in elem:
                if len(item) > 1 and item[-1] == 'L':
                    newElem.append(item[:-1])
                else:
                    newElem.append(item)
            result.append(''.join(newElem))
        else:
            result.append(elem)
    return result


# Alright so this one is here for Binja functions that output <in set([blah, blah, blah])>
def fixSet(string):
    # Apply regular expression
    splitList = (re.split(r"((?<=<in set\(\[).*(?=\]\)>))", string))
    if len(splitList) > 1:
        return splitList[0] + ', '.join(sorted(splitList[1].split(', '))) + splitList[2]
    else:
        return string


def get_file_list(test_store_rel):
    test_store = os.path.join(os.path.dirname(__file__), test_store_rel)
    all_files = []
    for root, dir, files in os.walk(test_store):
        for file in files:
            all_files.append(os.path.join(root, file))
    return all_files

def remove_low_confidence(type_string):
    low_confidence_types = ["int32_t", "void"]
    for lct in low_confidence_types:
        type_string = type_string.replace(lct + " ", '')  # done to resolve confidence ties
    return type_string

class Builder(object):
    def __init__(self, test_store):
        self.test_store = test_store
        # binja.log.log_to_stdout(binja.LogLevel.DebugLog)  # Uncomment for more info

    def methods(self):
        methodnames = []
        for methodname, method in inspect.getmembers(self, predicate=inspect.ismethod):
            if methodname.startswith("test_"):
                methodnames.append(methodname)
        return methodnames

    def unpackage_file(self, filename):
        path = os.path.join(os.path.dirname(__file__), self.test_store, filename)
        if not os.path.exists(path):
            with zipfile.ZipFile(path + ".zip", "r") as zf:
                zf.extractall(path = os.path.dirname(__file__))
        assert os.path.exists(path)
        return os.path.relpath(path)

    def delete_package(self, filename):
        path = os.path.join(os.path.dirname(__file__), self.test_store, filename)
        os.unlink(path)

class BinaryViewTestBuilder(Builder):
    """ The BinaryViewTestBuilder is for test that are verified against a binary.
        The tests are first run on your dev machine to base line then run again
        on the build machine to verify they are correct.

         - Function that are tests should start with 'test_'
         - Function doc string used as 'on error' message
         - Should return: list of strings
    """
    def __init__(self, filename, imageBase=None):
        self.filename = os.path.join(os.path.dirname(__file__), filename)
        if imageBase is None:
            self.bv = BinaryViewType.get_view_of_file(self.filename)
        else:
            self.bv = BinaryViewType.get_view_of_file_with_options(self.filename, options={'loader.imageBase' : imageBase})
        if self.bv is None:
            print("%s is not an executable format" % filename)
            return

    def test_available_types(self):
        """Available types don't match"""
        return ["Available Type: " + x.name for x in BinaryView(FileMetadata()).open(self.filename).available_view_types]

    def test_function_starts(self):
        """Function starts list doesnt match"""
        result = []
        for x in self.bv.functions:
            result.append("Function start: " + hex(x.start))
        return fixOutput(result)

    def test_function_symbol_names(self):
        """Function.symbol.name list doesnt match"""
        result = []
        for x in self.bv.functions:
            result.append("Symbol: " + x.symbol.name + ' ' + str(x.symbol.type) + ' ' + hex(x.symbol.address) + ' ' + str(x.symbol.namespace))
        return fixOutput(result)

    def test_function_can_return(self):
        """Function.can_return list doesnt match"""
        result = []
        for x in self.bv.functions:
            result.append("function name: " + x.symbol.name + ' type: ' + str(x.symbol.type) + ' address: ' + hex(x.symbol.address) + ' can_return: ' + str(bool(x.can_return)))
        return fixOutput(result)

    def test_function_basic_blocks(self):
        """Function basic_block list doesnt match (start, end, has_undetermined_outgoing_edges)"""
        bblist = []
        for func in self.bv.functions:
            for bb in func.basic_blocks:
                bblist.append("basic block {} start: ".format(str(bb)) + hex(bb.start) + ' end: ' + hex(bb.end) + ' undetermined outgoing edges: ' + str(bb.has_undetermined_outgoing_edges) + ' incoming edges: ' + str(bb.incoming_edges) + ' outgoing edges: ' + str(bb.outgoing_edges))
                for anno in func.get_block_annotations(bb.start):
                    bblist.append("basic block {} function annotation: ".format(str(bb)) + str(anno))
                bblist.append("basic block {} test get self: ".format(str(bb)) + str(func.get_basic_block_at(bb.start)))
        return fixOutput(bblist)

    def test_function_low_il_basic_blocks(self):
        """Function low_il_basic_block list doesnt match"""
        ilbblist = []
        for func in self.bv.functions:
            for bb in func.low_level_il.basic_blocks:
                ilbblist.append("LLIL basic block {} start: ".format(str(bb)) + hex(bb.start) + ' end: ' + hex(bb.end) + ' outgoing edges: ' + str(len(bb.outgoing_edges)))
        return fixOutput(ilbblist)

    def test_function_med_il_basic_blocks(self):
        """Function med_il_basic_block list doesn't match"""
        ilbblist = []
        for func in self.bv.functions:
            for bb in func.mlil.basic_blocks:
                ilbblist.append("MLIL basic block {} start: ".format(str(bb)) + hex(bb.start) + ' end: ' + hex(bb.end) + ' outgoing_edges: ' + str(len(bb.outgoing_edges)))
        return fixOutput(ilbblist)

    def test_symbols(self):
        """Symbols list doesn't match"""
        return ["Symbol: " + str(i) for i in sorted(self.bv.symbols)]

    def test_symbol_namespaces(self):
        """Symbol namespaces don't match"""
        return self.bv.namespaces

    def test_internal_external_namespaces(self):
        """Symbol namespaces don't match"""
        return [BinaryView.internal_namespace(), BinaryView.external_namespace()]

    def test_strings(self):
        """Strings list doesn't match"""
        return fixOutput(["String: " + str(x.value) + ' type: ' + str(x.type) + ' at: ' + hex(x.start) for x in self.bv.strings])

    def test_low_il_instructions(self):
        """LLIL instructions produced different output"""
        retinfo = []
        for func in self.bv.functions:
            for bb in func.low_level_il.basic_blocks:
                for ins in bb:
                    retinfo.append("Function: {:x} Instruction: {:x} MLIL: {}".format(func.start, ins.address, str(ins.medium_level_il)))
                    retinfo.append("Function: {:x} Instruction: {:x} Mapped MLIL: {}".format(func.start, ins.address, str(ins.mapped_medium_level_il)))
                    retinfo.append("Function: {:x} Instruction: {:x} Value: {}".format(func.start, ins.address, str(ins.value)))
                    retinfo.append("Function: {:x} Instruction: {:x} Possible Values: {}".format(func.start, ins.address, str(ins.possible_values)))

                    prefixList = []
                    for i in ins.prefix_operands:
                        if isinstance(i, dict):
                            contents = []
                            for j in sorted(i.keys()):
                                contents.append((j, i[j]))
                            prefixList.append(str(contents))
                        else:
                            prefixList.append(i)
                    retinfo.append("Function: {:x} Instruction: {:x} Prefix operands: {}".format(func.start, ins.address, str(prefixList)))

                    postfixList = []
                    for i in ins.postfix_operands:
                        if isinstance(i, dict):
                            contents = []
                            for j in sorted(i.keys()):
                                contents.append((j, i[j]))
                            postfixList.append(str(contents))
                        else:
                            postfixList.append(i)
                    retinfo.append("Function: {:x} Instruction: {:x} Postfix operands: {}".format(func.start, ins.address, str(postfixList)))

                    retinfo.append("Function: {:x} Instruction: {:x} SSA form: {}".format(func.start, ins.address, str(ins.ssa_form)))
                    retinfo.append("Function: {:x} Instruction: {:x} Non-SSA form: {}".format(func.start, ins.address, str(ins.non_ssa_form)))
        return fixOutput(retinfo)

    def test_low_il_ssa(self):
        """LLIL ssa produced different output"""
        retinfo = []
        for func in self.bv.functions:
            func = func.low_level_il
            for reg_name in self.bv.arch.regs:
                reg = binja.SSARegister(reg_name, 1)
                retinfo.append("Function: {:x} Reg {} SSA definition: {}".format(func.source_function.start, reg_name, str(getattr(func.get_ssa_reg_definition(reg), 'instr_index', None))))
                retinfo.append("Function: {:x} Reg {} SSA uses: {}".format(func.source_function.start, reg_name, str(list(map(lambda instr: instr.instr_index, func.get_ssa_reg_uses(reg))))))
                retinfo.append("Function: {:x} Reg {} SSA value: {}".format(func.source_function.start, reg_name, str(func.get_ssa_reg_value(reg))))
            for flag_name in self.bv.arch.flags:
                flag = binja.SSAFlag(flag_name, 1)
                retinfo.append("Function: {:x} Flag {} SSA uses: {}".format(func.source_function.start, flag_name, str(list(map(lambda instr: instr.instr_index, func.get_ssa_flag_uses(flag))))))
                retinfo.append("Function: {:x} Flag {} SSA value: {}".format(func.source_function.start, flag_name, str(func.get_ssa_flag_value(flag))))
            for bb in func.basic_blocks:
                for ins in bb:
                    tempind = func.get_non_ssa_instruction_index(ins.instr_index)
                    retinfo.append("Function: {:x} Instruction: {:x} Non-SSA instruction index: {}".format(func.source_function.start, ins.address, str(tempind)))
                    retinfo.append("Function: {:x} Instruction: {:x} SSA instruction index: {}".format(func.source_function.start, ins.address, str(func.get_ssa_instruction_index(tempind))))
                    retinfo.append("Function: {:x} Instruction: {:x} MLIL instruction index: {}".format(func.source_function.start, ins.address, str(func.get_medium_level_il_instruction_index(ins.instr_index))))
                    retinfo.append("Function: {:x} Instruction: {:x} Mapped MLIL instruction index: {}".format(func.source_function.start, ins.address, str(func.get_mapped_medium_level_il_instruction_index(ins.instr_index))))
        return fixOutput(retinfo)

    def test_med_il_instructions(self):
        """MLIL instructions produced different output"""
        retinfo = []
        for func in self.bv.functions:
            for bb in func.mlil.basic_blocks:
                for ins in bb:
                    retinfo.append("Function: {:x} Instruction: {:x} Expression type:  {}".format(func.start, ins.address, str(ins.expr_type)))
                    retinfo.append("Function: {:x} Instruction: {:x} LLIL:  {}".format(func.start, ins.address, str(ins.low_level_il)))
                    retinfo.append("Function: {:x} Instruction: {:x} Value:  {}".format(func.start, ins.address, str(ins.value)))
                    retinfo.append("Function: {:x} Instruction: {:x} Possible values:  {}".format(func.start, ins.address, str(ins.possible_values)))
                    retinfo.append("Function: {:x} Instruction: {:x} Branch dependence:  {}".format(func.start, ins.address, str(sorted(ins.branch_dependence.items()))))

                    prefixList = []
                    for i in ins.prefix_operands:
                        if isinstance(i, float) and 'e' in str(i):
                            prefixList.append(str(round(i, 21)))
                        elif isinstance(i, float):
                            prefixList.append(str(round(i, 11)))
                        elif isinstance(i, dict):
                            contents = []
                            for j in sorted(i.keys()):
                                contents.append((j, i[j]))
                            prefixList.append(str(contents))
                        else:
                            prefixList.append(str(i))
                    retinfo.append("Function: {:x} Instruction: {:x} Prefix operands:  {}".format(func.start, ins.address, str(sorted(prefixList))))
                    postfixList = []
                    for i in ins.postfix_operands:
                        if isinstance(i, float) and 'e' in str(i):
                            postfixList.append(str(round(i, 21)))
                        elif isinstance(i, float):
                            postfixList.append(str(round(i, 11)))
                        elif isinstance(i, dict):
                            contents = []
                            for j in sorted(i.keys()):
                                contents.append((j, i[j]))
                            postfixList.append(str(contents))
                        else:
                            postfixList.append(str(i))

                    retinfo.append("Function: {:x} Instruction: {:x} Postfix operands:  {}".format(func.start, ins.address, str(sorted(postfixList))))
                    retinfo.append("Function: {:x} Instruction: {:x} SSA form:  {}".format(func.start, ins.address, str(ins.ssa_form)))
                    retinfo.append("Function: {:x} Instruction: {:x} Non-SSA form: {}".format(func.start, ins.address, str(ins.non_ssa_form)))
        return fixOutput(retinfo)

    def test_med_il_vars(self):
        """Function med_il_vars doesn't match"""
        varlist = []
        for func in self.bv.functions:
            func = func.mlil
            for bb in func.basic_blocks:
                for instruction in bb:
                    instruction = instruction.ssa_form
                    for var in (instruction.vars_read + instruction.vars_written):
                        if hasattr(var, "var"):
                            varlist.append("Function: {:x} Instruction {:x} SSA var definition: {}".format (func.source_function.start, instruction.address, str(getattr(func.get_ssa_var_definition(var), 'instr_index', None))))
                            varlist.append("Function: {:x} Instruction {:x} SSA var uses:  {}".format (func.source_function.start, instruction.address, str(list(map(lambda instr: instr.instr_index, func.get_ssa_var_uses(var))))))
                            varlist.append("Function: {:x} Instruction {:x} SSA var value: {}".format (func.source_function.start, instruction.address, str(func.get_ssa_var_value(var))))
                            varlist.append("Function: {:x} Instruction {:x} SSA var possible values: {}".format (func.source_function.start, instruction.address, fixSet(str(instruction.get_ssa_var_possible_values(var)))))
                            varlist.append("Function: {:x} Instruction {:x} SSA var version: {}".format (func.source_function.start, instruction.address, str(instruction.get_ssa_var_version)))
        return fixOutput(varlist)

    def test_function_stack(self):
        """Function stack produced different output"""
        funcinfo = []
        for func in self.bv.functions:
            func.stack_adjustment = func.stack_adjustment
            func.reg_stack_adjustments = func.reg_stack_adjustments
            func.create_user_stack_var(0, binja.Type.int(4), "testuservar")
            func.create_auto_stack_var(4, binja.Type.int(4), "testautovar")

            sl = func.stack_layout
            for i in range(len(sl)):
                funcinfo.append("Function: {:x} Stack position {}: ".format(func.start, i) + str(sl[i]))

            funcinfo.append("Function: {:x} Stack content sample: {}".format(func.start, str(func.get_stack_contents_at(func.start + 0x10, 0, 0x10))))
            funcinfo.append("Function: {:x} Stack content range sample: {}".format(func.start, str(func.get_stack_contents_after(func.start + 0x10, 0, 0x10))))
            funcinfo.append("Function: {:x} Sample stack var: {}".format(func.start, str(func.get_stack_var_at_frame_offset(0, 0))))
            func.delete_user_stack_var(0)
            func.delete_auto_stack_var(0)
        return funcinfo

    def test_function_llil(self):
        """Function LLIL produced different output"""
        retinfo = []
        for func in self.bv.functions:
            for llilbb in func.llil_basic_blocks:
                retinfo.append("Function: {:x} LLIL basic block: {}".format(func.start, str(llilbb)))
            for llilins in func.llil_instructions:
                retinfo.append("Function: {:x} Instruction: {:x} LLIL instruction: {}".format(func.start, llilins.address, str(llilins)))
            for mlilbb in func.mlil_basic_blocks:
                retinfo.append("Function: {:x} MLIL basic block: {}".format(func.start, str(mlilbb)))
            for mlilins in func.mlil_instructions:
                retinfo.append("Function: {:x} Instruction: {:x} MLIL instruction: {}".format(func.start, mlilins.address, str(mlilins)))
            for ins in func.instructions:
                retinfo.append("Function: {:x} Instruction: {}: ".format(func.start, hex(ins[1]), ''.join([str(i) for i in ins[0]])))
        return fixOutput(retinfo)

    def test_functions_attributes(self):
        """Function attributes don't match"""
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

            for var in func.vars:
                funcinfo.append("Function {} var: ".format(func.name) + str(var))

            for branch in func.indirect_branches:
                funcinfo.append("Function {} indirect branch: ".format(func.name) + str(branch))
            funcinfo.append("Function {} session data: ".format(func.name) + str(func.session_data))
            funcinfo.append("Function {} analysis perf length: ".format(func.name) + str(len(func.analysis_performance_info)))
            for cr in func.clobbered_regs:
                funcinfo.append("Function {} clobbered reg: ".format(func.name) + str(cr))
            funcinfo.append("Function {} explicitly defined type: ".format(func.name) + str(func.explicitly_defined_type))
            funcinfo.append("Function {} needs update: ".format(func.name) + str(func.needs_update))
            funcinfo.append("Function {} global pointer value: ".format(func.name) + str(func.global_pointer_value))
            funcinfo.append("Function {} comment: ".format(func.name) + str(func.comment))
            funcinfo.append("Function {} too large: ".format(func.name) + str(func.too_large))
            funcinfo.append("Function {} analysis skipped: ".format(func.name) + str(func.analysis_skipped))
            funcinfo.append("Function {} first ins LLIL: ".format(func.name) + str(func.get_low_level_il_at(func.start)))
            funcinfo.append("Function {} LLIL exit test: ".format(func.name) + str(func.get_low_level_il_exits_at(func.start+0x100)))
            funcinfo.append("Function {} regs read test: ".format(func.name) + str(func.get_regs_read_by(func.start)))
            funcinfo.append("Function {} regs written test: ".format(func.name) + str(func.get_regs_written_by(func.start)))
            funcinfo.append("Function {} stack var test: ".format(func.name) + str(func.get_stack_vars_referenced_by(func.start)))
            funcinfo.append("Function {} constant reference test: ".format(func.name) + str(func.get_constants_referenced_by(func.start)))
            funcinfo.append("Function {} first ins lifted IL: ".format(func.name) + str(func.get_lifted_il_at(func.start)))
            funcinfo.append("Function {} flags read by lifted IL ins: ".format(func.name) + str(func.get_flags_read_by_lifted_il_instruction(0)))
            funcinfo.append("Function {} flags written by lifted IL ins: ".format(func.name) + str(func.get_flags_written_by_lifted_il_instruction(0)))
            funcinfo.append("Function {} create graph: ".format(func.name) + str(func.create_graph()))
            funcinfo.append("Function {} indirect branches test: ".format(func.name) + str(func.get_indirect_branches_at(func.start+0x10)))
            funcinfo.append("Function {} test instr highlight: ".format(func.name) + str(func.get_instr_highlight(func.start)))
            for token in func.get_type_tokens():
                token = str(token)
                token = remove_low_confidence(token)
                funcinfo.append("Function {} type token: ".format(func.name) + str(token))
        return fixOutput(funcinfo)

    def test_BinaryView(self):
        """BinaryView produced different results"""
        retinfo = []

        for type in self.bv.types.items():
            retinfo.append("BV Type: " + str(type))
        for segment in sorted([str(i) for i in self.bv.segments]):
            retinfo.append("BV segment: " + str(segment))
        for section in sorted(self.bv.sections):
            retinfo.append("BV section: " + str(section))
        for allrange in self.bv.allocated_ranges:
            retinfo.append("BV allocated range: " + str(allrange))
        retinfo.append("Session Data: " + str(self.bv.session_data))
        for var in map(hex, sorted(self.bv.data_vars.keys())):
            retinfo.append("BV data var: " + var)
        retinfo.append("BV Entry function: " + repr(self.bv.entry_function))
        for i in self.bv:
            retinfo.append("BV function: " + repr(i))
        retinfo.append("BV entry point: " + hex(self.bv.entry_point))
        retinfo.append("BV start: " + hex(self.bv.start))
        retinfo.append("BV length: " + hex(len(self.bv)))

        return fixOutput(retinfo)


    def test_dominators(self):
        """Dominators don't match oracle"""
        retinfo = []
        for func in self.bv.functions:
            for bb in func:
                for dom in sorted(bb.dominators, key=lambda x: x.start):
                    retinfo.append("Dominator: %x of %x" % (dom.start, bb.start))
                for pdom in sorted(bb.post_dominators, key=lambda x: x.start):
                    retinfo.append("PostDominator: %x of %x" % (pdom.start, bb.start))
        return fixOutput(retinfo)

class TestBuilder(Builder):
    """ The TestBuilder is for tests that need to be checked against a
        stored oracle data that isn't from a binary. These test are
        generated on your local machine then run again on the build
        machine to verify correctness.

         - Function that are tests should start with 'test_'
         - Function doc string used as 'on error' message
         - Should return: list of strings
    """

    def test_BinaryViewType_list(self):
        """BinaryViewType list doesnt match"""
        return ["BinaryViewType: " + x.name for x in binja.BinaryViewType.list]

    def test_Architecture_list(self):
        """Architecture list doesnt match"""
        return ["Arch name: " + x.name for x in binja.Architecture.list]

    def test_Assemble(self):
        """unexpected assemble result"""
        result = []
        # success cases

        strResult = binja.Architecture["x86"].assemble("xor eax, eax")
        if sys.version_info.major == 3 and not strResult[0] is None:
            result.append("x86 assembly: " + "'" + str(strResult)[2:-1] + "'")
        else:
            result.append("x86 assembly: " + repr(str(strResult)))
        strResult = binja.Architecture["x86_64"].assemble("xor rax, rax")
        if sys.version_info.major == 3 and not strResult[0] is None:
            result.append("x86_64 assembly: " + "'" + str(strResult)[2:-1] + "'")
        else:
            result.append("x86_64 assembly: " + repr(str(strResult)))
        strResult = binja.Architecture["mips32"].assemble("move $ra, $zero")
        if sys.version_info.major == 3 and not strResult[0] is None:
            result.append("mips32 assembly: " + "'" + str(strResult)[2:-1] + "'")
        else:
            result.append("mips32 assembly: " + repr(str(strResult)))
        strResult = binja.Architecture["mipsel32"].assemble("move $ra, $zero")
        if sys.version_info.major == 3 and not strResult[0] is None:
            result.append("mipsel32 assembly: " + "'" + str(strResult)[2:-1] + "'")
        else:
            result.append("mipsel32 assembly: " + repr(str(strResult)))
        strResult = binja.Architecture["armv7"].assemble("str r2, [sp,  #-0x4]!")
        if sys.version_info.major == 3 and not strResult[0] is None:
            result.append("armv7 assembly: " + "'" + str(strResult)[2:-1] + "'")
        else:
            result.append("armv7 assembly: " + repr(str(strResult)))
        strResult = binja.Architecture["aarch64"].assemble("mov x0, x0")
        if sys.version_info.major == 3 and not strResult[0] is None:
            result.append("aarch64 assembly: " + "'" + str(strResult)[2:-1] + "'")
        else:
            result.append("aarch64 assembly: " + repr(str(strResult)))
        strResult = binja.Architecture["thumb2"].assemble("ldr r4, [r4]")
        if sys.version_info.major == 3 and not strResult[0] is None:
            result.append("thumb2 assembly: " + "'" + str(strResult)[2:-1] + "'")
        else:
            result.append("thumb2 assembly: " + repr(str(strResult)))
        strResult = binja.Architecture["thumb2eb"].assemble("ldr r4, [r4]")
        if sys.version_info.major == 3 and not strResult[0] is None:
            result.append("thumb2eb assembly: " + "'" + str(strResult)[2:-1] + "'")
        else:
            result.append("thumb2eb assembly: " + repr(str(strResult)))

        # fail cases
        try:
            strResult = binja.Architecture["x86"].assemble("thisisnotaninstruction")
        except ValueError:
            result.append("Assemble Failed As Expected; 'thisisnotaninstruction' is not an instruction on 'x86'")
        try:
            strResult = binja.Architecture["x86_64"].assemble("thisisnotaninstruction")
        except ValueError:
            result.append("Assemble Failed As Expected; 'thisisnotaninstruction' is not an instruction on 'x86_64'")
        try:
            strResult = binja.Architecture["mips32"].assemble("thisisnotaninstruction")
        except ValueError:
            result.append("Assemble Failed As Expected; 'thisisnotaninstruction' is not an instruction on 'mips32'")
        try:
            strResult = binja.Architecture["mipsel32"].assemble("thisisnotaninstruction")
        except ValueError:
            result.append("Assemble Failed As Expected; 'thisisnotaninstruction' is not an instruction on 'mipsel32'")
        try:
            strResult = binja.Architecture["armv7"].assemble("thisisnotaninstruction")
        except ValueError:
            result.append("Assemble Failed As Expected; 'thisisnotaninstruction' is not an instruction on 'armv7'")
        try:
            strResult = binja.Architecture["aarch64"].assemble("thisisnotaninstruction")
        except ValueError:
            result.append("Assemble Failed As Expected; 'thisisnotaninstruction' is not an instruction on 'aarch64'")
        try:
            strResult = binja.Architecture["thumb2"].assemble("thisisnotaninstruction")
        except ValueError:
            result.append("Assemble Failed As Expected; 'thisisnotaninstruction' is not an instruction on 'thumb2'")
        try:
            strResult = binja.Architecture["thumb2eb"].assemble("thisisnotaninstruction")
        except ValueError:
            result.append("Assemble Failed As Expected; 'thisisnotaninstruction' is not an instruction on 'thumb2eb'")
        return result

    def test_Architecture(self):
        """Architecture failure"""
        if not os.path.exists(os.path.join(os.path.expanduser("~"), '.binaryninja', 'plugins', 'nes.py')):
            return [""]

        retinfo = []
        file_name = os.path.join(self.test_store, "..", "pwnadventurez.nes")
        bv = binja.BinaryViewType["NES Bank 0"].open(file_name)

        for i in bv.platform.arch.calling_conventions:
            retinfo.append("Custom arch calling convention: " + str(i))
        for i in bv.platform.arch.full_width_regs:
            retinfo.append("Custom arch full width reg: " + str(i))

        reg = binja.RegisterValue()
        retinfo.append("Reg entry value: " + str(reg.entry_value(bv.platform.arch, 'x')))
        retinfo.append("Reg constant: " + str(reg.constant(0xfe)))
        retinfo.append("Reg constant pointer: " + str(reg.constant_ptr(0xcafebabe)))
        retinfo.append("Reg stack frame offset: " + str(reg.stack_frame_offset(0x10)))
        retinfo.append("Reg imported address: " + str(reg.imported_address(0xdeadbeef)))
        retinfo.append("Reg return address: " + str(reg.return_address()))

        bv.update_analysis_and_wait()
        for func in bv.functions:
            for bb in func.low_level_il.basic_blocks:
                for ins in bb:
                    retinfo.append("Instruction info: " + str(bv.platform.arch.get_instruction_info(0x10, ins.address)))
                    retinfo.append("Instruction test: " + str(bv.platform.arch.get_instruction_text(0x10, ins.address)))
                    retinfo.append("Instruction: " + str(ins))
        return retinfo

    def test_Function(self):
        """Function produced different result"""
        inttype = binja.Type.int(4)
        testfunction = binja.Type.function(inttype, [inttype, inttype, inttype])
        return ["Test_function params: " + str(testfunction.parameters), "Test_function pointer: " + str(testfunction.pointer(binja.Architecture["x86"], testfunction))]

    def test_Struct(self):
        """Struct produced different result"""
        retinfo = []
        inttype = binja.Type.int(4)
        struct = binja.Structure()
        struct.a = 1
        struct.insert(0, inttype)
        struct.append(inttype)
        struct.replace(0, inttype)
        struct.remove(1)
        for i in struct.members:
            retinfo.append("Struct member: " + str(i))
        retinfo.append("Struct width: " + str(struct.width))
        struct.width = 16
        retinfo.append("Struct width after adjustment: " + str(struct.width))
        retinfo.append("Struct alignment: " + str(struct.alignment))
        struct.alignment = 8
        retinfo.append("Struct alignment after adjustment: " + str(struct.alignment))
        retinfo.append("Struct packed: " + str(struct.packed))
        struct.packed = 1
        retinfo.append("Struct packed after adjustment: " + str(struct.packed))
        retinfo.append("Struct type: " + str(struct.type))
        retinfo.append(str((struct == struct) and not (struct != struct)))
        return retinfo

    def test_Enumeration(self):
        """Enumeration produced different result"""
        retinfo = []
        inttype = binja.Type.int(4)
        enum = binja.Enumeration()
        enum.a = 1
        enum.append("a", 1)
        enum.append("b", 2)
        enum.replace(0, "a", 2)
        enum.remove(0)
        retinfo.append(str(enum))
        retinfo.append(str((enum == enum) and not (enum != enum)))
        return retinfo

    def test_Types(self):
        """Types produced different result"""
        file_name = self.unpackage_file("helloworld")
        try:
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

            retinfo = []
            for i in range(len(typelist.variables)):
                for j in typelist.variables.popitem():
                    retinfo.append("Type: " + str(j))
            retinfo.append("Named Type: " + str(namedtype))

            retinfo.append("Type equality: " + str((inttype == inttype) and not (inttype != inttype)))
            return retinfo
        finally:
            self.delete_package("helloworld")

    def test_Plugin_bin_info(self):
        """print_syscalls plugin produced different result"""
        file_name = self.unpackage_file("helloworld")
        try:
            bin_info_path = os.path.join(os.path.dirname(__file__), '..', 'python', 'examples', 'bin_info.py')
            if sys.platform == "linux" or sys.platform == "linux2":
                python_bin = "python2"
            else:
                python_bin = "python"
            result = subprocess.Popen([python_bin, bin_info_path, file_name], stdout=subprocess.PIPE).communicate()[0]
            # normalize line endings and path sep
            return [line for line in result.replace(b"\\", b"/").replace(b"\r\n", b"\n").decode("charmap").split("\n")]
        finally:
            self.delete_package("helloworld")

    def test_linear_disassembly(self):
        """linear_disassembly produced different result"""
        file_name = self.unpackage_file("helloworld")
        try:
            bv = binja.BinaryViewType['ELF'].open(file_name)
            disass = bv.linear_disassembly
            retinfo = []
            for i in disass:
                i = str(i)
                i = remove_low_confidence(i)
                retinfo.append(i)
            return retinfo
        finally:
            self.delete_package("helloworld")

    def test_data_renderer(self):
        """data renderer produced different result"""
        file_name = self.unpackage_file("helloworld")
        class ElfHeaderDataRenderer(DataRenderer):
            def __init__(self):
                DataRenderer.__init__(self)
            def perform_is_valid_for_data(self, ctxt, view, addr, type, context):
                return DataRenderer.is_type_of_struct_name(type, "Elf64_Header", context)
            def perform_get_lines_for_data(self, ctxt, view, addr, type, prefix, width, context):
                prefix.append(InstructionTextToken(InstructionTextTokenType.TextToken, "I'm in ur Elf64_Header"))
                return [DisassemblyTextLine(prefix, addr)]
            def __del__(self):
                pass
        try:
            bv = binja.BinaryViewType['ELF'].open(file_name)
            ElfHeaderDataRenderer().register_type_specific()
            disass = bv.linear_disassembly
            retinfo = []
            for i in disass:
                i = str(i)
                i = remove_low_confidence(i)
                retinfo.append(i)
            return retinfo
        finally:
            self.delete_package("helloworld")

    #  def test_partial_register_dataflow(self):
    #      """partial_register_dataflow produced different results"""
    #      file_name = self.unpackage_file("partial_register_dataflow")
    #      result = []
    #      reg_list = ['ch', 'cl', 'ah', 'edi', 'al', 'cx', 'ebp', 'ax', 'edx', 'ebx', 'esp', 'esi', 'dl', 'dh', 'di', 'bl', 'bh', 'eax', 'dx', 'bx', 'ecx', 'sp', 'si']
    #      bv = binja.BinaryViewType.get_view_of_file(file_name)
    #      for func in bv.functions:
    #          llil = func.low_level_il
    #          for i in range(0, llil.__len__()-1):
    #              for x in reg_list:
    #                  result.append("LLIL:" + str(i).replace('L', '') + ":" + x + ":" + str(llil[i].get_reg_value(x)).replace('L', ''))
    #                  result.append("LLIL:" + str(i).replace('L', '') + ":" + x + ":" + str(llil[i].get_possible_reg_values(x)).replace('L', ''))
    #                  result.append("LLIL:" + str(i).replace('L', '') + ":" + x + ":" + str(llil[i].get_reg_value_after(x)).replace('L', ''))
    #                  result.append("LLIL:" + str(i).replace('L', '') + ":" + x + ":" + str(llil[i].get_possible_reg_values_after(x)).replace('L', ''))
    #      bv.file.close()
    #      del bv
    #      return result


    def test_low_il_stack(self):
        """LLIL stack produced different output"""
        file_name = self.unpackage_file("jumptable_reordered")
        try:
            bv = binja.BinaryViewType.get_view_of_file(file_name)
            reg_list = ['ch', 'cl', 'ah', 'edi', 'al', 'cx', 'ebp', 'ax', 'edx', 'ebx', 'esp', 'esi', 'dl', 'dh', 'di', 'bl', 'bh', 'eax', 'dx', 'bx', 'ecx', 'sp', 'si']
            flag_list = ['c', 'p', 'a', 'z', 's', 'o']
            retinfo = []
            for func in bv.functions:
                for bb in func.low_level_il.basic_blocks:
                    for ins in bb:
                        retinfo.append("LLIL first stack element: " + str(ins.get_stack_contents(0,1)))
                        retinfo.append("LLIL second stack element: " + str(ins.get_stack_contents_after(0,1)))
                        retinfo.append("LLIL possible first stack element: " + str(ins.get_possible_stack_contents(0,1)))
                        retinfo.append("LLIL possible second stack element: " + str(ins.get_possible_stack_contents_after(0,1)))
                        for flag in flag_list:
                            retinfo.append("LLIL flag {} value at: ".format(flag, hex(ins.address)) + str(ins.get_flag_value(flag)))
                            retinfo.append("LLIL flag {} value after {}: ".format(flag, hex(ins.address)) + str(ins.get_flag_value_after(flag)))
                            retinfo.append("LLIL flag {} possible value at {}: ".format(flag, hex(ins.address)) + str(ins.get_possible_flag_values(flag)))
                            retinfo.append("LLIL flag {} possible value after {}: ".format(flag, hex(ins.address)) + str(ins.get_possible_flag_values_after(flag)))
            return fixOutput(retinfo)
        finally:
            self.delete_package("jumptable_reordered")

    def test_med_il_stack(self):
        """MLIL stack produced different output"""
        file_name = self.unpackage_file("jumptable_reordered")
        try:
            bv = binja.BinaryViewType.get_view_of_file(file_name)
            reg_list = ['ch', 'cl', 'ah', 'edi', 'al', 'cx', 'ebp', 'ax', 'edx', 'ebx', 'esp', 'esi', 'dl', 'dh', 'di', 'bl', 'bh', 'eax', 'dx', 'bx', 'ecx', 'sp', 'si']
            flag_list = ['c', 'p', 'a', 'z', 's', 'o']
            retinfo = []
            for func in bv.functions:
                for bb in func.mlil.basic_blocks:
                    for ins in bb:
                        retinfo.append("MLIL stack begin var: " + str(ins.get_var_for_stack_location(0)))
                        retinfo.append("MLIL first stack element: " + str(ins.get_stack_contents(0, 1)))
                        retinfo.append("MLIL second stack element: " + str(ins.get_stack_contents_after(0, 1)))
                        retinfo.append("MLIL possible first stack element: " + str(ins.get_possible_stack_contents(0, 1)))
                        retinfo.append("MLIL possible second stack element: " + str(ins.get_possible_stack_contents_after(0, 1)))

                        for reg in reg_list:
                            retinfo.append("MLIL reg {} var at {}: ".format(reg, hex(ins.address)) + str(ins.get_var_for_reg(reg)))
                            retinfo.append("MLIL reg {} value at {}: ".format(reg, hex(ins.address)) + str(ins.get_reg_value(reg)))
                            retinfo.append("MLIL reg {} value after {}: ".format(reg, hex(ins.address)) + str(ins.get_reg_value_after(reg)))
                            retinfo.append("MLIL reg {} possible value at {}: ".format(reg, hex(ins.address)) + fixSet(str(ins.get_possible_reg_values(reg))))
                            retinfo.append("MLIL reg {} possible value after {}: ".format(reg, hex(ins.address)) + fixSet(str(ins.get_possible_reg_values_after(reg))))

                        for flag in flag_list:
                            retinfo.append("MLIL flag {} value at: ".format(flag, hex(ins.address)) + str(ins.get_flag_value(flag)))
                            retinfo.append("MLIL flag {} value after {}: ".format(flag, hex(ins.address)) + str(ins.get_flag_value_after(flag)))
                            retinfo.append("MLIL flag {} possible value at {}: ".format(flag, hex(ins.address)) + fixSet(str(ins.get_possible_flag_values(flag))))
                            retinfo.append("MLIL flag {} possible value after {}: ".format(flag, hex(ins.address)) + fixSet(str(ins.get_possible_flag_values(flag))))
            return fixOutput(retinfo)
        finally:
            self.delete_package("jumptable_reordered")

    def test_events(self):
        """Event failure"""
        file_name = self.unpackage_file("helloworld")
        try:
            bv = binja.BinaryViewType['ELF'].open(file_name)
            bv.update_analysis_and_wait()

            results = []

            def simple_complete(self):
                results.append("analysis complete")
            evt = binja.AnalysisCompletionEvent(bv, simple_complete)

            class NotifyTest(binja.BinaryDataNotification):
                def data_written(self, view, offset, length):
                    results.append("data written: offset {0} length {1}".format(hex(offset), hex(length)))

                def data_inserted(self, view, offset, length):
                    results.append("data inserted: offset {0} length {1}".format(hex(offset), hex(length)))

                def data_removed(self, view, offset, length):
                    results.append("data removed: offset {0} length {1}".format(hex(offset), hex(length)))

                def function_added(self, view, func):
                    results.append("function added: {0}".format(func.name))

                def function_removed(self, view, func):
                    results.append("function removed: {0}".format(func.name))

                def data_var_added(self, view, var):
                    results.append("data var added: {0}".format(hex(var.address)))

                def data_var_removed(self, view, var):
                    results.append("data var removed: {0}".format(hex(var.address)))

                def string_found(self, view, string_type, offset, length):
                    results.append("string found: offset {0} length {1}".format(hex(offset), hex(length)))

                def string_removed(self, view, string_type, offset, length):
                    results.append("string removed: offset {0} length {1}".format(hex(offset), hex(length)))

                def type_defined(self, view, name, type):
                    results.append("type defined: {0}".format(name))

                def type_undefined(self, view, name, type):
                    results.append("type undefined: {0}".format(name))

            test = NotifyTest()
            bv.register_notification(test)
            sacrificial_addr = 0x84fc

            type, name = bv.parse_type_string("int foo")
            type_id = type.generate_auto_type_id("source", name)

            bv.define_type(type_id, name, type)
            bv.undefine_type(type_id)

            bv.update_analysis_and_wait()

            bv.insert(sacrificial_addr, b"AAAA")
            bv.update_analysis_and_wait()

            bv.define_data_var(sacrificial_addr, binja.types.Type.int(4))
            bv.update_analysis_and_wait()

            bv.write(sacrificial_addr, b"BBBB")
            bv.update_analysis_and_wait()

            bv.add_function(sacrificial_addr)
            bv.update_analysis_and_wait()

            bv.remove_function(bv.get_function_at(sacrificial_addr))
            bv.update_analysis_and_wait()

            bv.undefine_data_var(sacrificial_addr)
            bv.update_analysis_and_wait()

            bv.remove(sacrificial_addr, 4)
            bv.update_analysis_and_wait()

            bv.unregister_notification(test)

            return fixOutput(sorted(results))
        finally:
            self.delete_package("helloworld")


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

    def test_expression_parse(self):
        file_name = self.unpackage_file("helloworld")
        try:
            bv = binja.BinaryViewType.get_view_of_file(file_name)
            assert bv.parse_expression("1 + 1") == 2
            assert bv.parse_expression("-1 + 1") == 0
            assert bv.parse_expression("1 - 1") == 0
            assert bv.parse_expression("1 + -1") == 0
            assert bv.parse_expression("[0x8000]") == 0x464c457f
            assert bv.parse_expression("[0x8000]b") == 0
            assert bv.parse_expression("[0x8000].b") == 0x7f
            assert bv.parse_expression("[0x8000].w") == 0x457f
            assert bv.parse_expression("[0x8000].d") == 0x464c457f
            assert bv.parse_expression("[0x8000].q") == 0x10101464c457f
            assert bv.parse_expression("$here + 1", 12345) == 12345 + 1
            assert bv.parse_expression("_start") == 0x830c
            assert bv.parse_expression("_start + 4") == 0x8310
            return True
        finally:
            self.delete_package("helloworld")

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
        file_name = self.unpackage_file("helloworld")
        try:
            bv = binja.BinaryViewType['ELF'].open(file_name)
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

            bv = binja.FileMetadata(temp_name).open_existing_database(temp_name).get_view_of_type('ELF')
            bv.update_analysis_and_wait()
            bndb_functions = self.get_functions(bv)
            bndb_comments = self.get_comments(bv)
            # force windows to close the handle to the bndb that we want to delete
            bv.file.close()
            del bv
            os.unlink(temp_name)
            return [str(functions == bndb_functions and comments == bndb_comments)]
        finally:
            self.delete_package("helloworld")

    def test_verify_persistent_undo(self):
        file_name = self.unpackage_file("helloworld")
        try:
            temp_name = next(tempfile._get_candidate_names()) + ".bndb"

            bv = binja.BinaryViewType['ELF'].open(file_name)
            bv.update_analysis_and_wait()

            bv.begin_undo_actions()
            bv.functions[0].set_comment(bv.functions[0].start, "Function start")
            bv.functions[0].set_comment(bv.functions[0].start, "Function start!")
            bv.commit_undo_actions()

            bv.begin_undo_actions()
            bv.add_function(bv.functions[0].start + 4)
            bv.commit_undo_actions()

            comments = self.get_comments(bv)
            functions = self.get_functions(bv)

            bv.create_database(temp_name)
            bv.file.close()
            del bv

            bv = binja.FileMetadata(temp_name).open_existing_database(temp_name).get_view_of_type('ELF')
            bv.update_analysis_and_wait()

            bv.undo()
            bv.undo()

            bndb_functions = self.get_functions(bv)
            bndb_comments = self.get_comments(bv)

            bv.file.close()
            del bv
            os.unlink(temp_name)

            return functions == bndb_functions and comments == bndb_comments
        finally:
            self.delete_package("helloworld")

    def test_verify_clean_save(self):
        file_name = self.unpackage_file("helloworld")
        try:
            temp_name = next(tempfile._get_candidate_names()) + ".bndb"

            bv = binja.BinaryViewType['ELF'].open(file_name)
            bv.update_analysis_and_wait()

            bv.begin_undo_actions()
            bv.functions[0].set_comment(bv.functions[0].start, "This is a secret comment")
            bv.commit_undo_actions()

            bv.begin_undo_actions()
            bv.functions[0].set_comment(bv.functions[0].start, "Function start!")
            bv.commit_undo_actions()

            bv.create_database(temp_name, clean=True)
            bv.file.close()
            del bv

            bv = binja.FileMetadata(temp_name).open_existing_database(temp_name).get_view_of_type('ELF')
            bv.update_analysis_and_wait()

            bv.undo()

            comment = bv.functions[0].get_comment_at(bv.functions[0].start)

            bv.file.close()
            del bv
            os.unlink(temp_name)

            return comment == "Function start!"
        finally:
            self.delete_package("helloworld")

    def test_memory_leaks(self):
        """Detected memory leaks during analysis"""
        # This test will attempt to detect object leaks during headless analysis
        file_name = self.unpackage_file("helloworld")
        try:
            # Open the binary once and let any persistent structures be created (typically types)
            bv = binja.BinaryViewType['ELF'].open(file_name)
            bv.update_analysis_and_wait()
            # Hold on to a graph reference while tearing down the binary view. This will keep a reference
            # in the core. If we directly free the view, the teardown will happen in a worker thread and
            # we will not be able to get a reliable object count. By keeping a reference in a different
            # object in the core, the teardown will occur immediately upon freeing the other object.
            graph = bv.functions[0].create_graph()
            bv.file.close()
            del bv
            import gc
            gc.collect()
            del graph
            gc.collect()

            initial_object_counts = binja.get_memory_usage_info()

            # Analyze the binary again
            bv = binja.BinaryViewType['ELF'].open(file_name)
            bv.update_analysis_and_wait()
            graph = bv.functions[0].create_graph()
            bv.file.close()
            del bv
            gc.collect()
            del graph
            gc.collect()

            # Capture final object count
            final_object_counts = binja.get_memory_usage_info()

            # Check for leaks
            ok = True
            for i in initial_object_counts.keys():
                if final_object_counts[i] > initial_object_counts[i]:
                    ok = False
            return ok
        finally:
            self.delete_package("helloworld")
