import tempfile
import os
import sys
import zipfile
import inspect
from platform import system
import binaryninja as binja
from binaryninja.binaryview import BinaryViewType, BinaryView
from binaryninja.filemetadata import FileMetadata
from binaryninja.datarender import DataRenderer
from binaryninja.function import InstructionTextToken, DisassemblyTextLine
from binaryninja.enums import InstructionTextTokenType, FindFlag,\
    FunctionGraphType, NamedTypeReferenceClass, ReferenceType
from binaryninja.types import (Type, BoolWithConfidence, EnumerationBuilder, NamedTypeReferenceBuilder,
    IntegerBuilder, CharBuilder, FloatBuilder, WideCharBuilder, PointerBuilder, ArrayBuilder, FunctionBuilder, StructureBuilder,
    EnumerationBuilder, NamedTypeReferenceBuilder)
import subprocess
import re


# Alright so this one is here for Binja functions that output <in set([blah, blah, blah])>
def fixSet(string):
    # Apply regular expression
    splitList = (re.split(r"((?<=<in set\(\[).*(?=\]\)>))", string))
    if len(splitList) > 1:
        return splitList[0] + ', '.join(sorted(splitList[1].split(', '))) + splitList[2]
    else:
        return string


def fixStrRepr(string):
    # Python 2 and Python 3 represent Unicode character reprs differently
    return string.replace(b"\xe2\x80\xa6".decode("utf8"), "\\xe2\\x80\\xa6")

def get_file_list(test_store_rel):
    test_store = os.path.join(os.path.dirname(__file__), test_store_rel)
    all_files = []
    for root, _, files in os.walk(test_store):
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
        for methodname, _ in inspect.getmembers(self, predicate=inspect.ismethod):
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
    def __init__(self, filename, options=None):
        self.filename = os.path.join(os.path.dirname(__file__), filename)
        if options:
            _bv = BinaryViewType.get_view_of_file_with_options(self.filename, options=options)
        else:
            _bv = BinaryViewType.get_view_of_file(self.filename)
        assert _bv is not None, f"{filename} is not an executable format"
        self.bv = _bv

    @classmethod
    def get_root_directory(cls):
        return os.path.dirname(__file__)

    def test_available_types(self):
        """Available types don't match"""
        bv = BinaryView(FileMetadata()).open(self.filename)
        assert bv is not None
        return ["Available Type: " + x.name for x in bv.available_view_types]

    def test_function_starts(self):
        """Function starts list doesn't match"""
        result = []
        for x in self.bv.functions:
            result.append("Function start: " + hex(x.start))
        return result

    def test_function_symbol_names(self):
        """Function.symbol.name list doesnt' match"""
        result = []
        for x in self.bv.functions:
            result.append("Symbol: " + x.symbol.name + ' ' + str(x.symbol.type) + ' ' + hex(x.symbol.address) + ' ' + str(x.symbol.namespace))
        return result

    def test_function_can_return(self):
        """Function.can_return list doesn't match"""
        result = []
        for x in self.bv.functions:
            result.append("function name: " + x.symbol.name + ' type: ' + str(x.symbol.type) + ' address: ' + hex(x.symbol.address) + ' can_return: ' + str(bool(x.can_return)))
        return result

    def test_function_basic_blocks(self):
        """Function basic_block list doesn't match (start, end, has_undetermined_outgoing_edges)"""
        bblist = []
        for func in self.bv.functions:
            for bb in func.basic_blocks:
                bblist.append(f"basic block {bb} start: {bb.start:#x} end: {bb.end:#x} undetermined outgoing edges: {bb.has_undetermined_outgoing_edges} incoming edges: {bb.incoming_edges} outgoing edges: {bb.outgoing_edges}")
                for anno in func.get_block_annotations(bb.start):
                    bblist.append(f"basic block {bb} function annotation: {anno}")
                bblist.append(f"basic block {bb} test get self: {func.get_basic_block_at(bb.start)}")
        return bblist

    def test_function_low_il_basic_blocks(self):
        """Function low_il_basic_block list doesn't match"""
        ilbblist = []
        for func in self.bv.functions:
            for bb in func.low_level_il.basic_blocks:
                ilbblist.append("LLIL basic block {} start: ".format(str(bb)) + hex(bb.start) + ' end: ' + hex(bb.end) + ' outgoing edges: ' + str(len(bb.outgoing_edges)))
        return ilbblist

    def test_function_med_il_basic_blocks(self):
        """Function med_il_basic_block list doesn't match"""
        ilbblist = []
        for func in self.bv.functions:
            for bb in func.mlil.basic_blocks:
                ilbblist.append("MLIL basic block {} start: ".format(str(bb)) + hex(bb.start) + ' end: ' + hex(bb.end) + ' outgoing_edges: ' + str(len(bb.outgoing_edges)))
        return ilbblist

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
        return ["String: " + str(x.value) + ' type: ' + str(x.type) + ' at: ' + hex(x.start) for x in self.bv.strings]

    def test_low_il_instructions(self):
        """LLIL instructions produced different output"""
        retinfo = []
        for func in self.bv.functions:
            for bb in func.low_level_il.basic_blocks:
                for ins in bb:
                    retinfo.append("Function: {:x} Instruction: {:x} ADDR->LiftedILS: {}".format(func.start, ins.address, str(sorted(list(map(str, func.get_lifted_ils_at(ins.address)))))))
                    retinfo.append("Function: {:x} Instruction: {:x} ADDR->LLILS: {}".format(func.start, ins.address, str(sorted(list(map(str, func.get_llils_at(ins.address)))))))
                    retinfo.append("Function: {:x} Instruction: {:x} LLIL->MLIL: {}".format(func.start, ins.address, str(ins.mlil)))
                    retinfo.append("Function: {:x} Instruction: {:x} LLIL->MLILS: {}".format(func.start, ins.address, str(sorted(list(map(str, ins.mlils))))))
                    retinfo.append("Function: {:x} Instruction: {:x} LLIL->HLIL: {}".format(func.start, ins.address, str(ins.hlil)))
                    retinfo.append("Function: {:x} Instruction: {:x} LLIL->HLILS: {}".format(func.start, ins.address, str(sorted(list(map(str, ins.hlils))))))
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
                    retinfo.append("Function: {:x} Instruction: {:x} Prefix operands: {}".format(func.start, ins.address, fixStrRepr(str(prefixList))))

                    postfixList = []
                    for i in ins.postfix_operands:
                        if isinstance(i, dict):
                            contents = []
                            for j in sorted(i.keys()):
                                contents.append((j, i[j]))
                            postfixList.append(str(contents))
                        else:
                            postfixList.append(i)
                    retinfo.append("Function: {:x} Instruction: {:x} Postfix operands: {}".format(func.start, ins.address, fixStrRepr(str(postfixList))))

                    retinfo.append("Function: {:x} Instruction: {:x} SSA form: {}".format(func.start, ins.address, str(ins.ssa_form)))
                    retinfo.append("Function: {:x} Instruction: {:x} Non-SSA form: {}".format(func.start, ins.address, str(ins.non_ssa_form)))
        return retinfo

    def test_low_il_ssa(self):
        """LLIL ssa produced different output"""
        retinfo = []
        for func in self.bv.functions:
            func = func.low_level_il
            arch = self.bv.arch
            assert arch is not None, "Architecture is None"
            source_function = func.source_function
            assert source_function is not None, "source_function is None"
            for reg_name in sorted(arch.regs):
                reg = binja.SSARegister(reg_name, 1)
                retinfo.append("Function: {:x} Reg {} SSA definition: {}".format(source_function.start, reg_name, str(getattr(func.get_ssa_reg_definition(reg), 'instr_index', None))))
                retinfo.append("Function: {:x} Reg {} SSA uses: {}".format(source_function.start, reg_name, str(list(map(lambda instr: instr.instr_index, func.get_ssa_reg_uses(reg))))))
                retinfo.append("Function: {:x} Reg {} SSA value: {}".format(source_function.start, reg_name, str(func.get_ssa_reg_value(reg))))
            for flag_name in sorted(arch.flags):
                flag = binja.SSAFlag(flag_name, 1)
                retinfo.append("Function: {:x} Flag {} SSA uses: {}".format(source_function.start, flag_name, str(list(map(lambda instr: instr.instr_index, func.get_ssa_flag_uses(flag))))))
                retinfo.append("Function: {:x} Flag {} SSA value: {}".format(source_function.start, flag_name, str(func.get_ssa_flag_value(flag))))
            for bb in func.basic_blocks:
                for ins in bb:
                    tempind = func.get_non_ssa_instruction_index(ins.instr_index)
                    retinfo.append("Function: {:x} Instruction: {:x} Non-SSA instruction index: {}".format(source_function.start, ins.address, str(tempind)))
                    retinfo.append("Function: {:x} Instruction: {:x} SSA instruction index: {}".format(source_function.start, ins.address, str(func.get_ssa_instruction_index(tempind))))
                    retinfo.append("Function: {:x} Instruction: {:x} MLIL instruction index: {}".format(source_function.start, ins.address, str(func.get_medium_level_il_instruction_index(ins.instr_index))))
                    retinfo.append("Function: {:x} Instruction: {:x} Mapped MLIL instruction index: {}".format(source_function.start, ins.address, str(func.get_mapped_medium_level_il_instruction_index(ins.instr_index))))
                    retinfo.append("Function: {:x} Instruction: {:x} LLIL_SSA->MLIL: {}".format(source_function.start, ins.address, str(ins.mlil)))
                    retinfo.append("Function: {:x} Instruction: {:x} LLIL_SSA->MLILS: {}".format(source_function.start, ins.address, str(sorted(list(map(str, ins.mlils))))))
                    retinfo.append("Function: {:x} Instruction: {:x} LLIL_SSA->HLIL: {}".format(source_function.start, ins.address, str(ins.hlil)))
                    retinfo.append("Function: {:x} Instruction: {:x} LLIL_SSA->HLILS: {}".format(source_function.start, ins.address, str(sorted(list(map(str, ins.hlils))))))
        return retinfo

    def test_med_il_instructions(self):
        """MLIL instructions produced different output"""
        retinfo = []
        for func in self.bv.functions:
            for bb in func.mlil.basic_blocks:
                for ins in bb:
                    retinfo.append("Function: {:x} Instruction: {:x} Expression type:  {}".format(func.start, ins.address, str(ins.expr_type)))
                    retinfo.append("Function: {:x} Instruction: {:x} MLIL->LLIL:  {}".format(func.start, ins.address, str(ins.llil)))
                    retinfo.append("Function: {:x} Instruction: {:x} MLIL->LLILS:  {}".format(func.start, ins.address, str(sorted(list(map(str, ins.llils))))))
                    retinfo.append("Function: {:x} Instruction: {:x} MLIL->HLIL:  {}".format(func.start, ins.address, str(ins.hlil)))
                    retinfo.append("Function: {:x} Instruction: {:x} MLIL->HLILS:  {}".format(func.start, ins.address, str(sorted(list(map(str, ins.hlils))))))
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
                    retinfo.append("Function: {:x} Instruction: {:x} Prefix operands:  {}".format(func.start, ins.address, fixStrRepr(str(sorted(prefixList)))))
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

                    retinfo.append("Function: {:x} Instruction: {:x} Postfix operands:  {}".format(func.start, ins.address, fixStrRepr(str(sorted(postfixList)))))
                    retinfo.append("Function: {:x} Instruction: {:x} SSA form:  {}".format(func.start, ins.address, str(ins.ssa_form)))
                    retinfo.append("Function: {:x} Instruction: {:x} Non-SSA form: {}".format(func.start, ins.address, str(ins.non_ssa_form)))
        return retinfo

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
                            varlist.append(f"Function: {func.source_function.start:x} Instruction {instruction.address:x} SSA var definition: {getattr(func.get_ssa_var_definition(var), 'instr_index', None)}")
                            varlist.append(f"Function: {func.source_function.start:x} Instruction {instruction.address:x} SSA var uses:  {list(map(lambda instr: instr.instr_index, func.get_ssa_var_uses(var)))}")
                            varlist.append(f"Function: {func.source_function.start:x} Instruction {instruction.address:x} SSA var value: {func.get_ssa_var_value(var)}")
                            varlist.append(f"Function: {func.source_function.start:x} Instruction {instruction.address:x} SSA var possible values: {fixSet(str(instruction.get_ssa_var_possible_values(var)))}")
                            varlist.append(f"Function: {func.source_function.start:x} Instruction {instruction.address:x} SSA var version: {instruction.get_ssa_var_version(var.var)}")
        return varlist

    def test_function_stack(self):
        """Function stack produced different output"""
        funcinfo = []
        for func in self.bv.functions:
            for i, var in enumerate(func.stack_layout):
                funcinfo.append(f"Function: {func.start:x} Stack position {i}: {var}")

            funcinfo.append(f"Function: {func.start:x} Stack adjustment: {func.stack_adjustment.value}")
            funcinfo.append(f"Function: {func.start:x} Register stack adjustment: {[v.value for v in func.reg_stack_adjustments.values()]}")

            func.stack_adjustment = func.stack_adjustment
            func.reg_stack_adjustments = func.reg_stack_adjustments
            func.create_user_stack_var(0, binja.Type.int(4), "testuservar")
            # The following test has been commented as it leads to non-deterministic test results
            # This is likely due to an extra update coming along afterward and removing sometimes
            # This test would need to be conducted in an analysis pass to be consistent and accurate
            # func.create_auto_stack_var(4, binja.Type.int(4), "testautovar")



            funcinfo.append(f"Function: {func.start:x} Stack content sample: {func.get_stack_contents_at(func.start + 0x10, 0, 0x10)}")
            funcinfo.append(f"Function: {func.start:x} Stack content range sample: {func.get_stack_contents_after(func.start + 0x10, 0, 0x10)}")
            funcinfo.append(f"Function: {func.start:x} Sample stack var: {func.get_stack_var_at_frame_offset(0, 0)}")
            func.delete_user_stack_var(0)
            func.delete_auto_stack_var(0)
        return funcinfo

    def test_function_llil(self):
        """Function LLIL produced different output"""
        retinfo = []
        for func in self.bv.functions:
            for llil_bb in func.llil_basic_blocks:
                retinfo.append(f"Function: {func.start:x} LLIL basic block: {llil_bb}")
            for llil_ins in func.llil.instructions:
                retinfo.append(f"Function: {func.start:x} Instruction: {llil_ins.address:x} LLIL instruction: {llil_ins}")
            for mlil_bb in func.mlil_basic_blocks:
                retinfo.append(f"Function: {func.start:x} MLIL basic block: {mlil_bb}")
            for mlil_ins in func.mlil.instructions:
                retinfo.append(f"Function: {func.start:x} Instruction: {mlil_ins.address:x} MLIL instruction: {mlil_ins}")
            for hlil_ins in func.hlil.instructions:
                retinfo.append(f"Function: {func.start:x} Instruction: {hlil_ins.address:x} HLIL instruction: {hlil_ins}")
            for ins in func.instructions:
                retinfo.append(f"Function: {func.start:x} Instruction: {ins[1]:#x}: {''.join([str(i) for i in ins[0]])}")
        return retinfo

    def test_function_hlil(self):
        """Function HLIL produced different output"""
        retinfo = []
        for func in self.bv.functions:
            if func.hlil is None or func.hlil.root is None:
                continue
            for line in func.hlil.root.lines:
                retinfo.append(f"Function: {func.start:x} HLIL line: {line}")
            for hlilins in func.hlil.instructions:
                retinfo.append(f"Function: {func.start:x} Instruction: {hlilins.address:x} HLIL->LLIL instruction: {str(hlilins.llil)}")
                retinfo.append(f"Function: {func.start:x} Instruction: {hlilins.address:x} HLIL->MLIL instruction: {str(hlilins.mlil)}")
                retinfo.append(f"Function: {func.start:x} Instruction: {hlilins.address:x} HLIL->MLILS instruction: {str(sorted(list(map(str, hlilins.mlils))))}")
        return retinfo

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

            for (arch, addr, tag) in func.address_tags:
                funcinfo.append("Function {} tag at ({}, {:x}): ".format(func.name, arch.name, addr) + str(tag))
            for tag in func.function_tags:
                funcinfo.append("Function {} tag: ".format(func.name) + str(tag))

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
        return funcinfo

    def test_BinaryView(self):
        """BinaryView produced different results"""
        retinfo = []

        for type in sorted([str(i) for i in self.bv.types.items()]):
            retinfo.append(f"BV Type: {type}")
        for segment in sorted([str(i) for i in self.bv.segments]):
            retinfo.append(f"BV segment: {segment}")
        for section in sorted(self.bv.sections):
            retinfo.append(f"BV section: {section}")
        for allrange in self.bv.allocated_ranges:
            retinfo.append(f"BV allocated range: {allrange}")
        retinfo.append(f"Session Data: {self.bv.session_data}")
        for (addr, tag) in self.bv.data_tags:
            retinfo.append(f"BV tag: {addr:x} {repr(tag)}")
        for tag_type in self.bv.tag_types:
            retinfo.append(f"BV tag type: {repr(tag_type)}")
        vars = self.bv.data_vars
        for addr in sorted(vars.keys()):
            retinfo.append(f"BV data var: {vars[addr]}")
        retinfo.append(f"BV Entry function: {repr(self.bv.entry_function)}")
        for i in self.bv:
            retinfo.append(f"BV function: {repr(i)}")
        retinfo.append(f"BV entry point: {self.bv.entry_point:#x}")
        retinfo.append(f"BV start: {self.bv.start:#x}")
        retinfo.append(f"BV length: {len(self.bv):#x}")

        return retinfo

    def test_dominators(self):
        """Dominators don't match oracle"""
        retinfo = []
        for func in self.bv.functions:
            for bb in func:
                for dom in sorted(bb.dominators, key=lambda x: x.start):
                    retinfo.append("Dominator: %x of %x" % (dom.start, bb.start))
                for pdom in sorted(bb.post_dominators, key=lambda x: x.start):
                    retinfo.append("PostDominator: %x of %x" % (pdom.start, bb.start))
        return retinfo

    def test_liveness(self):
        """Liveness results don't match oracle"""
        retinfo1 = []
        retinfo2 = []
        for hlil in self.bv.hlil_functions():
            vars = hlil.vars
            hlil_ssa = hlil.ssa_form
            ssa_vars = hlil_ssa.ssa_vars
            name = hlil.source_function.name
            for instr_index in range(0, len(hlil)):
                for var in vars:
                    retinfo1.append(f"{name}-hlil@{instr_index}: {hlil.is_var_live_at(var, binja.highlevelil.InstructionIndex(instr_index))}")
            for instr_index in range(0, len(hlil_ssa)):
                for var in ssa_vars:
                    retinfo2.append(f"{name}-hlil-ssa@{instr_index}: {hlil_ssa.is_ssa_var_live_at(var, binja.highlevelil.InstructionIndex(instr_index))}")

        return retinfo1 + retinfo2


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
        """BinaryViewType list doesn't match"""
        return ["BinaryViewType: " + x.name for x in binja.BinaryViewType]

    def test_deprecated_BinaryViewType(self):
        """deprecated BinaryViewType list doesn't match"""
        file_name = self.unpackage_file("fat_macho_9arch.bndb")
        if not os.path.exists(file_name):
            return [""]

        view_types = []
        with binja.filemetadata.FileMetadata().open_existing_database(file_name, None) as bv:
            for view_type in bv.available_view_types:
                if view_type.is_deprecated:
                    view_types.append('BinaryViewType: %s (deprecated)' % view_type.name)
                else:
                    view_types.append('BinaryViewType: %s' % view_type.name)

        self.delete_package("fat_macho_9arch.bndb")
        return view_types

    def test_Architecture_list(self):
        """Architecture list doesn't match"""
        return ["Arch name: " + arch.name for arch in binja.Architecture]

    def test_Assemble(self):
        """unexpected assemble result"""
        result = []

        # success cases
        result.append(f"x86 assembly: {binja.Architecture['x86'].assemble('xor eax, eax')}")
        result.append(f"x86_64 assembly: {binja.Architecture['x86_64'].assemble('xor rax, rax')}")
        result.append(f"mips32 assembly: {binja.Architecture['mips32'].assemble('move $ra, $zero')}")
        result.append(f"armv7 assembly: {binja.Architecture['armv7'].assemble('str r2, [sp,  #-0x4]!')}")
        result.append(f"aarch64 assembly: {binja.Architecture['aarch64'].assemble('mov x0, x0')}")
        result.append(f"thumb2 assembly: {binja.Architecture['thumb2'].assemble('ldr r4, [r4]')}")
        result.append(f"thumb2eb assembly: {binja.Architecture['thumb2eb'].assemble('ldr r4, [r4]')}")

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
        file_name = os.path.join(os.path.dirname(__file__), self.test_store, "..", "pwnadventurez.nes")
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

    def test_Simplifier(self):
        """Template Simplification"""
        result = [binja.demangle.simplify_name_to_string(s) for s in [
            # Minimal exhaustive examples of simplifier (these are replicated in testcommon)
            "std::basic_string<T, std::char_traits<T>, std::allocator<T> >",
            "std::vector<T, std::allocator<T> >",
            "std::vector<T, std::allocator<T>, std::lessthan<T> >",
            "std::deque<T, std::allocator<T> >",
            "std::forward_list<T, std::allocator<T> >",
            "std::list<T, std::allocator<T> >",
            "std::stack<T, std::deque<T> >",
            "std::queue<T, std::deque<T> >",
            "std::set<T, std::less<T>, std::allocator<T> >",
            "std::multiset<T, std::less<T>, std::allocator<T> >",
            "std::map<T1, T2, std::less<T1>, std::allocator<std::pair<const T1, T2> > >",
            "std::multimap<T1, T2, std::less<T1>, std::allocator<std::pair<const T1, T2> > >",
            "std::unordered_set<T, std::hash<T>, std::equal_to<T>, std::allocator<T> >",
            "std::unordered_multiset<T, std::hash<T>, std::equal_to<T>, std::allocator<T> >",
            "std::unordered_map<T1, T2, std::hash<T1>, std::equal_to<T1>, std::allocator<std::pair<const T1, T2> > >",
            "std::unordered_multimap<T1, T2, std::hash<T1>, std::equal_to<T1>, std::allocator<std::pair<const T1, T2> > >",

            "std::basic_stringbuf<char, std::char_traits<char>, std::allocator<char> >",
            "std::basic_istringstream<char, std::char_traits<char>, std::allocator<char> >",
            "std::basic_ostringstream<char, std::char_traits<char>, std::allocator<char> >",
            "std::basic_stringstream<char, std::char_traits<char>, std::allocator<char> >",
            "std::basic_stringbuf<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t> >",
            "std::basic_istringstream<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t> >",
            "std::basic_ostringstream<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t> >",
            "std::basic_stringstream<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t> >",
            "std::basic_stringbuf<T, std::char_traits<T>, std::allocator<T> >",
            "std::basic_istringstream<T, std::char_traits<T>, std::allocator<T> >",
            "std::basic_ostringstream<T, std::char_traits<T>, std::allocator<T> >",
            "std::basic_stringstream<T, std::char_traits<T>, std::allocator<T> >",

            "std::basic_ios<char, std::char_traits<char> >",
            "std::basic_streambuf<char, std::char_traits<char> >",
            "std::basic_istream<char, std::char_traits<char> >",
            "std::basic_ostream<char, std::char_traits<char> >",
            "std::basic_iostream<char, std::char_traits<char> >",
            "std::basic_filebuf<char, std::char_traits<char> >",
            "std::basic_ifstream<char, std::char_traits<char> >",
            "std::basic_ofstream<char, std::char_traits<char> >",
            "std::basic_fstream<char, std::char_traits<char> >",
            "std::basic_ios<wchar_t, std::char_traits<wchar_t> >",
            "std::basic_streambuf<wchar_t, std::char_traits<wchar_t> >",
            "std::basic_istream<wchar_t, std::char_traits<wchar_t> >",
            "std::basic_ostream<wchar_t, std::char_traits<wchar_t> >",
            "std::basic_iostream<wchar_t, std::char_traits<wchar_t> >",
            "std::basic_filebuf<wchar_t, std::char_traits<wchar_t> >",
            "std::basic_ifstream<wchar_t, std::char_traits<wchar_t> >",
            "std::basic_ofstream<wchar_t, std::char_traits<wchar_t> >",
            "std::basic_fstream<wchar_t, std::char_traits<wchar_t> >",
            "std::basic_ios<T, std::char_traits<T> >",
            "std::basic_streambuf<T, std::char_traits<T> >",
            "std::basic_istream<T, std::char_traits<T> >",
            "std::basic_ostream<T, std::char_traits<T> >",
            "std::basic_iostream<T, std::char_traits<T> >",
            "std::basic_filebuf<T, std::char_traits<T> >",
            "std::basic_ifstream<T, std::char_traits<T> >",
            "std::basic_ofstream<T, std::char_traits<T> >",
            "std::basic_fstream<T, std::char_traits<T> >",

            # The following simplifiers should probably be done as typedefs some where as they can appear both
            # as the simplified and unsimplified name in the type libraries and in mangled names
            # "std::fpos<__mbstate_t>",
            # "std::_Ios_Iostate",
            # "std::_Ios_Seekdir",
            # "std::_Ios_Openmode",
            # "std::_Ios_Fmtflags",

            # The following 5 entries are the simplified versions of the above so we don't have to re-generate
            # unit test results.
            "std::streampos",
            "std::ios_base::iostate",
            "std::ios_base::seekdir",
            "std::ios_base::openmode",
            "std::ios_base::fmtflags",

            "std::foo<T, std::char_traits<T> >",
            "std::bar<T, std::char_traits<T> >::bar",
            "std::foo<T, std::char_traits<T> >::~foo",
            "std::foo<T, std::char_traits<T> >::bar",

            "std::foo<bleh::T, std::char_traits<bleh::T> >",
            "std::bar<bleh::T, std::char_traits<bleh::T> >::bar",
            "std::foo<bleh::T, std::char_traits<bleh::T> >::~foo",
            "std::foo<bleh::T, std::char_traits<bleh::T> >::bar",

            "std::foo<foo::bleh::T, std::char_traits<foo::bleh::T> >",
            "std::bar<foo::bleh::T, std::char_traits<foo::bleh::T> >::bar",
            "std::foo<foo::bleh::T, std::char_traits<foo::bleh::T> >::~foo",
            "std::foo<foo::bleh::T, std::char_traits<foo::bleh::T> >::bar",

            # More complex examples:
            "AddRequiredUIPluginDependency(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)",
            "std::vector<std::vector<BinaryNinja::InstructionTextToken, std::allocator<BinaryNinja::InstructionTextToken> >, std::allocator<std::vector<BinaryNinja::InstructionTextToken, std::allocator<BinaryNinja::InstructionTextToken> > > >::_M_check_len(uint64_t, char const*) const",
            "std::vector<std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::array<uint32_t, 5ul> >, std::allocator<std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::array<uint32_t, 5ul> > > >::_M_default_append(uint64_t)",
            "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string",
            "std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string",
        ]]

        # Test all the APIs
        qName = binja.types.QualifiedName(["std", "__cxx11", "basic_string<T, std::char_traits<T>, std::allocator<T> >"])
        result.append(binja.demangle.simplify_name_to_string(qName))
        result.append(str(binja.demangle.simplify_name_to_qualified_name(qName)))
        result.append(str(binja.demangle.simplify_name_to_qualified_name(str(qName))))
        result.append(str(binja.demangle.simplify_name_to_qualified_name(str(qName), False).name))
        result.append("::".join(binja.demangle_gnu3(binja.Architecture['x86_64'], "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm", False)[1]))
        result.append("::".join(binja.demangle_gnu3(binja.Architecture['x86_64'], "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm", True)[1]))

        return result

    def test_Struct(self):
        """Struct produced different result"""
        retinfo = []
        inttype = binja.Type.int(4)
        struct = binja.TypeBuilder.structure()
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
        struct.packed = True
        retinfo.append("Struct packed after adjustment: " + str(struct.packed))
        retinfo.append("Struct type: " + str(struct.type))
        assert struct == struct, "Structs are not equal"
        assert not (struct != struct), "Structs are not not not equal"
        retinfo.append("False") # TODO Remove when regenerating this
        return retinfo

    def test_Enumeration(self):
        """Enumeration produced different result"""
        retinfo = []
        enum = binja.TypeBuilder.enumeration()
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
            with binja.BinaryViewType.get_view_of_file(file_name) as bv:

                preprocessed = binja.preprocess_source("""
                #ifdef nonexistant
                int foo = 1;
                long long foo1 = 1;
                #else
                int bar = 2;
                long long bar1 = 2;
                #endif
                """)
                source = '\n'.join([i for i in preprocessed[0].split('\n') if not '#line' in i and len(i) > 0])
                typelist = bv.platform.parse_types_from_source(source)
                inttype = binja.Type.int(4)

                namedtype = binja.NamedTypeReferenceBuilder.create()
                tokens = inttype.get_tokens() + inttype.get_tokens_before_name() +  inttype.get_tokens_after_name()
                retinfo = []
                for i in range(len(typelist.variables)):
                    for j in typelist.variables.popitem():
                        retinfo.append("Type: " + str(j))
                retinfo.append("Named Type: " + str(namedtype))

                retinfo.append("Type equality: " + str((inttype == inttype) and not (inttype != inttype)))
                return retinfo
        finally:
            self.delete_package("helloworld")

    def test_TypeBuilders_and_Types(self):
        """Test TypeBuilders"""
        file_name = self.unpackage_file("helloworld")
        try:
            with binja.open_view(file_name) as bv:
                with binja.StructureBuilder.builder(bv, 'Foo') as s:
                    s.packed = True
                    s.append(Type.int(2))
                    s.append(Type.int(4))
                    s.append(Type.void())
                    s.append(Type.bool())
                    s.append(Type.char())
                    s.append(Type.char("char_alt_name"))
                    s.append(Type.float(2, "half"))
                    s.append(Type.float(4) )
                    s.append(Type.float(8))
                    s.append(Type.float(16))
                    s.append(Type.wide_char(4, "wchar32_t"))
                    s.append(Type.structure_type(binja.StructureBuilder.create([Type.int(1)])))
                    s.append(Type.named_type(NamedTypeReferenceBuilder.create(NamedTypeReferenceClass.UnknownNamedTypeClass, "id", "name")))
                    s.append(Type.named_type_from_type_and_id("id2", ["qualified", "name"]))
                    s.append(Type.generate_named_type_reference("guid", [b"byte", b"name"]))
                    s.append(Type.enumeration_type(bv.arch, EnumerationBuilder.create([("Member1", 1)])))
                    try:
                        Type.pointer(None, None) # test the failure case
                    except ValueError:
                        pass
                    s.append(Type.pointer_of_width(8, Type.int(4), BoolWithConfidence(True, 255), BoolWithConfidence(False, 255), ReferenceType.RValueReferenceType))
                    s.append(Type.array(Type.int(4), 4))
                    s.append(Type.structure([(Type.int(4), "field1")]))
                    s.append(Type.enumeration(bv.arch, [binja.types.EnumerationMember("Mem-1", 1), binja.types.EnumerationMember("Mem-2")]))
                    s.append(Type.enumeration(bv.arch, [binja.types.EnumerationMember("Mem2-1", 1), binja.types.EnumerationMember("Mem2-2")], 2))
                    s.append(Type.enumeration(bv.arch, [binja.types.EnumerationMember("Mem3-1", 1), binja.types.EnumerationMember("Mem3-2")], 2, True))
                    s.append(Type.enumeration(bv.arch, None))
                    tid = Type.generate_auto_demangled_type_id("auto_demangled_tid")
                    tid_source = Type.get_auto_demangled_type_id_source()
                    s.append(Type.named_type_reference(NamedTypeReferenceClass.UnknownNamedTypeClass, "Someothername", tid, 4, 4, True, True))
                    try:
                        Type.int(4).name
                        assert False, "trying to access name of integer succeeded when it shouldn't have"
                    except NotImplementedError:
                        pass

                    members = s.members
                    const = s.const
                    volatile = s.volatile
                s = bv.types['Foo']
                assert members == s.members
                assert const == s.const
                assert volatile == s.volatile
            return [str(s.members)]
        finally:
            self.delete_package("helloworld")

    def test_Plugin_bin_info(self):
        """print_syscalls plugin produced different result"""
        file_name = self.unpackage_file("helloworld")
        try:
            bin_info_path = os.path.join(os.path.dirname(__file__), '..', 'python', 'examples', 'bin_info.py')
            if sys.platform == "win32":
                python_bin = ["py", "-3"]
            else:
                python_bin = ["python3"]
            result = subprocess.Popen(python_bin + [bin_info_path, file_name], stdout=subprocess.PIPE).communicate()[0]
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
            with binja.BinaryViewType.get_view_of_file(file_name) as bv:
                # reg_list = ['ch', 'cl', 'ah', 'edi', 'al', 'cx', 'ebp', 'ax', 'edx', 'ebx', 'esp', 'esi', 'dl', 'dh', 'di', 'bl', 'bh', 'eax', 'dx', 'bx', 'ecx', 'sp', 'si']
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
                                retinfo.append("LLIL flag {} value at {}: {}".format(flag, hex(ins.address), str(ins.get_flag_value(flag))))
                                retinfo.append("LLIL flag {} value after {}: {}".format(flag, hex(ins.address), str(ins.get_flag_value_after(flag))))
                                retinfo.append("LLIL flag {} possible value at {}: {}".format(flag, hex(ins.address), str(ins.get_possible_flag_values(flag))))
                                retinfo.append("LLIL flag {} possible value after {}: {}".format(flag, hex(ins.address), str(ins.get_possible_flag_values_after(flag))))
                return retinfo
        finally:
            self.delete_package("jumptable_reordered")

    def test_med_il_stack(self):
        """MLIL stack produced different output"""
        file_name = self.unpackage_file("jumptable_reordered")
        try:
            with binja.BinaryViewType.get_view_of_file(file_name) as bv:
                reg_list = ['ch', 'cl', 'ah', 'edi', 'al', 'cx', 'ebp', 'ax', 'edx', 'ebx', 'esp', 'esi', 'dl', 'dh', 'di', 'bl', 'bh', 'eax', 'dx', 'bx', 'ecx', 'sp', 'si']
                flag_list = ['c', 'p', 'a', 'z', 's', 'o']
                retinfo = []
                for func in bv.functions:
                    for bb in func.mlil.basic_blocks:
                        for ins in bb:
                            retinfo.append(f"MLIL stack begin var: {ins.get_var_for_stack_location(0)}")
                            retinfo.append(f"MLIL first stack element: {ins.get_stack_contents(0, 1)}")
                            retinfo.append(f"MLIL second stack element: {ins.get_stack_contents_after(0, 1)}")
                            retinfo.append(f"MLIL possible first stack element: {ins.get_possible_stack_contents(0, 1)}")
                            retinfo.append(f"MLIL possible second stack element: {ins.get_possible_stack_contents_after(0, 1)}")

                            for reg in reg_list:
                                retinfo.append(f"MLIL reg {reg} var at {ins.address:#x}: {ins.get_var_for_reg(reg)}")
                                retinfo.append(f"MLIL reg {reg} value at {ins.address:#x}: {ins.get_reg_value(reg)}")
                                retinfo.append(f"MLIL reg {reg} value after {ins.address:#x}: {ins.get_reg_value_after(reg)}")
                                retinfo.append(f"MLIL reg {reg} possible value at {ins.address:#x}: {ins.get_possible_reg_values(reg)}")
                                retinfo.append(f"MLIL reg {reg} possible value after {ins.address:#x}: {ins.get_possible_reg_values_after(reg)}")

                            for flag in flag_list:
                                retinfo.append("MLIL flag {} value at {}: {}".format(flag, hex(ins.address), str(ins.get_flag_value(flag))))
                                retinfo.append("MLIL flag {} value after {}: {}".format(flag, hex(ins.address), str(ins.get_flag_value_after(flag))))
                                retinfo.append("MLIL flag {} possible value at {}: {}".format(flag, hex(ins.address), fixSet(str(ins.get_possible_flag_values(flag)))))
                                retinfo.append("MLIL flag {} possible value after {}: {}".format(flag, hex(ins.address), fixSet(str(ins.get_possible_flag_values(flag)))))
                return retinfo
        finally:
            self.delete_package("jumptable_reordered")

    def test_events(self):
        """Event failure"""
        file_name = self.unpackage_file("helloworld")
        try:
            with binja.BinaryViewType['ELF'].get_view_of_file(file_name) as bv:

                bv.update_analysis_and_wait()
                results = []

                def simple_complete(self):
                    results.append("analysis complete")
                _ = binja.AnalysisCompletionEvent(bv, simple_complete)

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

                    def type_ref_changed(self, view, name, type):
                        results.append("type reference changed: {0}".format(name))

                    def type_field_ref_changed(self, view, name, offset):
                        results.append("type field reference changed: {0}, offset {1}".format(name, hex(offset)))

                test = NotifyTest()
                bv.register_notification(test)
                sacrificial_addr = 0x84fc

                type, name = bv.parse_type_string("int foo")
                type_id = Type.generate_auto_type_id("source", name)

                bv.define_type(type_id, name, type)
                bv.undefine_type(type_id)

                bv.update_analysis_and_wait()

                bv.insert(sacrificial_addr, b"AAAA")
                bv.update_analysis_and_wait()

                bv.define_data_var(sacrificial_addr, binja.types.Type.int(4))
                bv.update_analysis_and_wait()

                bv.define_data_var(sacrificial_addr + 4, "int")
                bv.update_analysis_and_wait()

                bv.write(sacrificial_addr, b"BBBB")
                bv.update_analysis_and_wait()

                bv.add_function(sacrificial_addr)
                bv.update_analysis_and_wait()

                bv.remove_function(bv.get_function_at(sacrificial_addr))
                bv.update_analysis_and_wait()

                bv.undefine_data_var(sacrificial_addr)
                bv.update_analysis_and_wait()

                bv.undefine_data_var(sacrificial_addr + 4)
                bv.update_analysis_and_wait()

                bv.remove(sacrificial_addr, 4)
                bv.update_analysis_and_wait()

                type, _ = bv.parse_type_string("struct { uint64_t bar; }")
                bv.define_user_type('foo', type)
                bv.define_user_type('bar', "struct { uint64_t bas; }")
                func = bv.get_function_at(0x8440)
                func.return_type = binja.Type.named_type_from_type('foo', type)
                bv.update_analysis_and_wait()

                bv.unregister_notification(test)

                return sorted(results)
        finally:
            self.delete_package("helloworld")

    def test_type_xref(self):
        """Type xref failure"""

        def dump_type_xref_info(type_name, code_refs, data_refs, type_refs, offset = None):
            retinfo = []
            if offset is None:
                for ref in code_refs:
                    retinfo.append('type {} is referenced by code {}'.format(type_name, ref))
                for ref in data_refs:
                    retinfo.append('type {} is referenced by data {}'.format(type_name, ref))
                for ref in type_refs:
                    retinfo.append('type {} is referenced by type {}'.format(type_name, ref))
            else:
                for ref in code_refs:
                    retinfo.append('type field {}, offset {} is referenced by code {}'.format(type_name, hex(offset), ref))
                for ref in data_refs:
                    retinfo.append('type field {}, offset {} is referenced by data {}'.format(type_name, hex(offset), ref))
                for ref in type_refs:
                    retinfo.append('type field {}, offset {} is referenced by type {}'.format(type_name, hex(offset), ref))

            return retinfo

        retinfo = []
        file_name = self.unpackage_file("type_xref.bndb")
        if not os.path.exists(file_name):
            return retinfo

        with BinaryViewType.get_view_of_file(file_name) as bv:
            if bv is None:
                return retinfo

            types = bv.types
            test_types = ['A', 'B', 'C', 'D', 'E', 'F']
            for test_type in test_types:
                code_refs = bv.get_code_refs_for_type(test_type)
                data_refs = bv.get_data_refs_for_type(test_type)
                type_refs = bv.get_type_refs_for_type(test_type)
                retinfo.extend(dump_type_xref_info(test_type, code_refs, data_refs, type_refs))

                t = types[test_type]
                if not t:
                    continue

                for member in t.members:
                    offset = member.offset
                    code_refs = bv.get_code_refs_for_type_field(test_type, offset)
                    data_refs = bv.get_data_refs_for_type_field(test_type, offset)
                    type_refs = bv.get_type_refs_for_type_field(test_type, offset)
                    retinfo.extend(dump_type_xref_info(test_type, code_refs, data_refs, type_refs, offset))

        self.delete_package("type_xref.bndb")
        return sorted(retinfo)

    def test_variable_xref(self):
        """Variable xref failure"""

        def dump_var_xref_info(var, var_refs):
            retinfo = []
            for ref in var_refs:
                retinfo.append('var {} is referenced at {}'.format(repr(var), repr(ref)))
            return retinfo

        retinfo = []
        file_name = self.unpackage_file("type_xref.bndb")
        if not os.path.exists(file_name):
            return retinfo

        with BinaryViewType.get_view_of_file(file_name) as bv:
            if bv is None:
                return retinfo

            func = bv.get_function_at(0x1169)
            for var in func.vars:
                mlil_refs = func.get_mlil_var_refs(var)
                retinfo.extend(dump_var_xref_info(var, mlil_refs))
                hlil_refs = func.get_hlil_var_refs(var)
                retinfo.extend(dump_var_xref_info(var, hlil_refs))

            mlil_range_var_refs = func.get_mlil_var_refs_from(0x1175, 0x8c)
            for ref in mlil_range_var_refs:
                retinfo.append(f"var {ref.var} is referenced at {ref.src}")

            hlil_range_var_refs = func.get_hlil_var_refs_from(0x1175, 0x8c)
            for ref in hlil_range_var_refs:
                retinfo.append(f"var {ref.var} is referenced at {ref.src}")

        self.delete_package("type_xref.bndb")
        return sorted(retinfo)

    # INSANE HACK AHEAD
    # The name `test_all_search` is VERY special here. It reorders this test to
    # before the binary tests. This is EXTREMELY important to the speed of the
    # unit tests on Linux. No one knows why. There be dragons here.
    def test_all_search(self):
        """Search"""
        retinfo = []
        file_name = self.unpackage_file("type_xref.bndb")
        if not os.path.exists(file_name):
            return retinfo

        with BinaryViewType.get_view_of_file(file_name) as bv:
            if bv is None:
                return retinfo

            for addr, match in bv.find_all_data(bv.start, bv.end, b'\xc3'):
                retinfo.append('byte 0xc3 is found at address 0x%lx with DataBuffer %s' %
                    (addr, match.escape()))

            for addr, match, line in bv.find_all_text(bv.start, bv.end, 'test'):
                retinfo.append('text "test" is found at address 0x%lx with string %s \
                    line %s' % (addr, match, line))

            for addr, line in bv.find_all_constant(bv.start, bv.end, 0x58):
                retinfo.append('constant 0x58 is found at address 0x%lx with line %s' %\
                    (addr, line))

            def data_callback(addr, match):
                retinfo.append('match found at address: 0x%lx with DataBuffer %s' % (addr, match.escape()))

            bv.find_all_data(bv.start, bv.end, b'\xc3', FindFlag.FindCaseSensitive, None,
                data_callback)

            def string_callback(addr, match, line):
                retinfo.append('match found at address: 0x%lx with string %s, line %s' %\
                    (addr, match, line))

            bv.find_all_text(bv.start, bv.end, 'test', None, FindFlag.FindCaseSensitive,
                FunctionGraphType.NormalFunctionGraph, None, string_callback)

            def constant_callback(addr, line):
                retinfo.append('match found at address: 0x%lx with constant 0x58, line %s'\
                    % (addr, line))

            bv.find_all_constant(bv.start, bv.end, 0x58, None,\
                FunctionGraphType.NormalFunctionGraph, None, constant_callback)

        self.delete_package("type_xref.bndb")
        return sorted(retinfo)

    def test_auto_create_struct(self):
        """Automatically create a structure"""
        retinfo = []
        file_name = self.unpackage_file("auto_create_members.bndb")
        if not os.path.exists(file_name):
            return retinfo

        with BinaryViewType.get_view_of_file(file_name) as bv:
            if bv is None:
                return retinfo

            test_types = ['struct_1', 'struct_2', 'struct_3']
            for test_type in test_types:
                offsets = bv.get_all_fields_referenced(test_type)
                for offset in offsets:
                    retinfo.append(f'type {test_type}, offset {offset:#x} is referenced')

                refs = bv.get_all_sizes_referenced(test_type)
                for offset in refs:
                    sizes = refs[offset]
                    for size in sizes:
                        retinfo.append(f'type {test_type}, offset {offset:#x} is referenced of size {size:#x}')

                refs = bv.get_all_types_referenced(test_type)
                for offset in refs:
                    types = refs[offset]
                    for refType in types:
                        retinfo.append(f'type {test_type}, offset {offset:#x} is referenced of type {refType}')

                struct = bv.create_structure_from_offset_access(test_type)
                for member in struct.members:
                    retinfo.append(f'type {test_type}, member: {member}')

        self.delete_package("auto_create_members.bndb")
        return sorted(retinfo)

    def test_hlil_arrays(self):
        """HLIL array resolution failure"""

        retinfo = []
        file_name = self.unpackage_file("array_test.bndb")
        if not os.path.exists(file_name):
            return retinfo

        with BinaryViewType.get_view_of_file(file_name) as bv:
            if bv is None:
                return retinfo

            for func in bv.functions:
                for line in func.hlil.root.lines:
                    retinfo.append(f"Function: {func.start:x} HLIL line: {line}")
                for hlilins in func.hlil.instructions:
                    retinfo.append(f"Function: {func.start:x} Instruction: {hlilins.address:x} HLIL->LLIL instruction: {hlilins.llil}")
                    retinfo.append(f"Function: {func.start:x} Instruction: {hlilins.address:x} HLIL->MLIL instruction: {hlilins.mlil}")
                    retinfo.append(f"Function: {func.start:x} Instruction: {hlilins.address:x} HLIL->MLILS instruction: {sorted(list(map(str, hlilins.mlils)))}")

        self.delete_package("array_test.bndb")
        return sorted(retinfo)

    def test_x87_uniqueness(self):
        """
        Verify fix for fmul: that different assembly strings do not disassemble the same
        Vector35/arch-x86#29
        """
        pairs = [
            ("x86", "fadd st0, st1",  "fadd st1, st0"),
            ("x86", "fsub st0, st1",  "fsub st1, st0"),
            ("x86", "fsubr st0, st1", "fsubr st1, st0"),
            ("x86", "fmul st0, st1",  "fmul st1, st0"),
            ("x86", "fdiv st0, st1",  "fdiv st1, st0"),
            ("x86", "fdivr st0, st1", "fdivr st1, st0"),
        ]
        for (arch, asm1, asm2) in pairs:
            a = binja.Architecture[arch]
            code1 = a.assemble(asm1)
            code2 = a.assemble(asm2)
            text1 = ''.join(str(t) for t in a.get_instruction_text(code1, 0)[0])
            text2 = ''.join(str(t) for t in a.get_instruction_text(code2, 0)[0])
            assert code1 != code2
            assert text1 != text2, f"{asm1} and {asm2} are different but both disassemble to {text1}"


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
        return next(bv.functions).comments

    def test_possiblevalueset_parse(self):
        """ Failed to parse PossibleValueSet from string"""
        file_name = self.unpackage_file("helloworld")
        try:
            with binja.open_view(file_name) as bv:
                # ConstantValue
                lhs = bv.parse_possiblevalueset("0", binja.RegisterValueType.ConstantValue)
                rhs = binja.PossibleValueSet.constant(0)
                assert lhs == rhs
                lhs = bv.parse_possiblevalueset("$here + 2", binja.RegisterValueType.ConstantValue, 0x2000)
                rhs = binja.PossibleValueSet.constant(0x2000 + 2)
                assert lhs == rhs
                # ConstantPointerValue
                lhs = bv.parse_possiblevalueset("0x8000", binja.RegisterValueType.ConstantPointerValue)
                rhs = binja.PossibleValueSet.constant_ptr(0x8000)
                assert lhs == rhs
                # StackFrameOffset
                lhs = bv.parse_possiblevalueset("16", binja.RegisterValueType.StackFrameOffset)
                rhs = binja.PossibleValueSet.stack_frame_offset(0x16)
                assert lhs == rhs
                # SignedRangeValue
                lhs = bv.parse_possiblevalueset("-10:0:2", binja.RegisterValueType.SignedRangeValue)
                rhs = binja.PossibleValueSet.signed_range_value([binja.ValueRange(-0x10, 0, 2)])
                assert lhs == rhs
                lhs = bv.parse_possiblevalueset("-10:0:2,2:5:1", binja.RegisterValueType.SignedRangeValue)
                rhs = binja.PossibleValueSet.signed_range_value([binja.ValueRange(-0x10, 0, 2), binja.ValueRange(2, 5, 1)])
                assert lhs == rhs
                # UnsignedRangeValue
                lhs = bv.parse_possiblevalueset("1:10:1", binja.RegisterValueType.UnsignedRangeValue)
                rhs = binja.PossibleValueSet.unsigned_range_value([binja.ValueRange(1, 0x10, 1)])
                assert lhs == rhs
                lhs = bv.parse_possiblevalueset("1:10:1, 2:20:2", binja.RegisterValueType.UnsignedRangeValue)
                rhs = binja.PossibleValueSet.unsigned_range_value([binja.ValueRange(1, 0x10, 1), binja.ValueRange(2, 0x20, 2)])
                assert lhs == rhs
                # InSetOfValues
                lhs = bv.parse_possiblevalueset("1,2,3,3,4", binja.RegisterValueType.InSetOfValues)
                rhs = binja.PossibleValueSet.in_set_of_values([1,2,3,4])
                assert lhs == rhs
                # NotInSetOfValues
                lhs = bv.parse_possiblevalueset("1,2,3,4,4", binja.RegisterValueType.NotInSetOfValues)
                rhs = binja.PossibleValueSet.not_in_set_of_values([1,2,3,4])
                assert lhs == rhs
                # UndeterminedValue
                lhs = bv.parse_possiblevalueset("", binja.RegisterValueType.UndeterminedValue)
                rhs = binja.PossibleValueSet.undetermined()
                assert lhs == rhs
            return True
        finally:
            self.delete_package("helloworld")

    def test_expression_parse(self):
        file_name = self.unpackage_file("helloworld")
        try:
            with binja.BinaryViewType.get_view_of_file(file_name) as bv:
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

    def test_get_il_vars(self):
        file_name = self.unpackage_file("helloworld")
        try:
            with binja.BinaryViewType.get_view_of_file(file_name) as bv:
                main_func = bv.get_functions_by_name("main")[0]
                value = sorted(list(map(lambda v: str(v), main_func.vars)))
                oracle = ['__saved_r11', 'arg_0', 'argc', 'argv', 'envp', 'r0', 'r3', 'var_10', 'var_4', 'var_c']
                assert value == oracle, f"test result from 'main_func.vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.lifted_il.vars)))
                oracle = []
                assert value == oracle, f"test result from 'main_func.lifted_il.vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.lifted_il.ssa_vars)))
                oracle = []
                assert value == oracle, f"test result from 'main_func.lifted_il.ssa_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.llil.vars)))
                oracle = ['lr', 'r0', 'r1', 'r11', 'r12', 'r2', 'r3', 'sp', 'temp0']
                assert value == oracle, f"test result from 'main_func.llil.vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.llil.ssa_vars)))
                oracle = ['<ssa lr version 0>', '<ssa lr version 1>', '<ssa lr version 2>', '<ssa lr version 3>', '<ssa r0 version 0>', '<ssa r0 version 1>', '<ssa r0 version 2>', '<ssa r0 version 3>', '<ssa r0 version 4>', '<ssa r0 version 5>', '<ssa r0 version 6>', '<ssa r1 version 0>', '<ssa r1 version 1>', '<ssa r1 version 2>', '<ssa r1 version 3>', '<ssa r11 version 0>', '<ssa r11 version 1>', '<ssa r11 version 2>', '<ssa r12 version 1>', '<ssa r12 version 2>', '<ssa r12 version 3>', '<ssa r2 version 1>', '<ssa r2 version 2>', '<ssa r2 version 3>', '<ssa r3 version 1>', '<ssa r3 version 2>', '<ssa r3 version 3>', '<ssa r3 version 4>', '<ssa r3 version 5>', '<ssa sp version 0>', '<ssa sp version 1>', '<ssa sp version 2>', '<ssa sp version 3>', '<ssa sp version 4>', '<ssa sp version 5>', '<ssa sp version 6>', '<ssa temp0 version 1>']
                assert value == oracle, f"test result from 'main_func.llil.ssa_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.llil.ssa_form.vars)))
                oracle = ['lr', 'r0', 'r1', 'r11', 'r12', 'r2', 'r3', 'sp', 'temp0']
                assert value == oracle, f"test result from 'main_func.llil.ssa_form.vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.llil.ssa_form.ssa_registers)))
                oracle = ['<ssa lr version 0>', '<ssa lr version 1>', '<ssa lr version 2>', '<ssa lr version 3>', '<ssa r0 version 0>', '<ssa r0 version 1>', '<ssa r0 version 2>', '<ssa r0 version 3>', '<ssa r0 version 4>', '<ssa r0 version 5>', '<ssa r0 version 6>', '<ssa r1 version 0>', '<ssa r1 version 1>', '<ssa r1 version 2>', '<ssa r1 version 3>', '<ssa r11 version 0>', '<ssa r11 version 1>', '<ssa r11 version 2>', '<ssa r12 version 1>', '<ssa r12 version 2>', '<ssa r12 version 3>', '<ssa r2 version 1>', '<ssa r2 version 2>', '<ssa r2 version 3>', '<ssa r3 version 1>', '<ssa r3 version 2>', '<ssa r3 version 3>', '<ssa r3 version 4>', '<ssa r3 version 5>', '<ssa sp version 0>', '<ssa sp version 1>', '<ssa sp version 2>', '<ssa sp version 3>', '<ssa sp version 4>', '<ssa sp version 5>', '<ssa sp version 6>', '<ssa temp0 version 1>']
                assert value == oracle, f"test result from 'main_func.llil.ssa_form.ssa_registers' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.llil.ssa_form.ssa_register_stacks)))
                oracle = []
                assert value == oracle, f"test result from 'main_func.llil.ssa_form.ssa_register_stacks' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.llil.ssa_form.ssa_flags)))
                oracle = []
                assert value == oracle, f"test result from 'main_func.llil.ssa_form.ssa_flags' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.llil.mapped_medium_level_il.vars)))
                oracle = ['__saved_r11', 'argc', 'argv', 'envp', 'lr', 'r11', 'r12', 'r3', 'sp', 'temp0', 'var_10', 'var_4', 'var_c']
                assert value == oracle, f"test result from 'main_func.llil.mapped_medium_level_il.vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.llil.mapped_medium_level_il.ssa_vars)))
                oracle = ['<ssa __saved_r11 version 1>', '<ssa argc version 0>', '<ssa argc version 1>', '<ssa argc version 2>', '<ssa argc version 3>', '<ssa argc version 4>', '<ssa argc version 5>', '<ssa argc version 6>', '<ssa argv version 0>', '<ssa argv version 1>', '<ssa argv version 2>', '<ssa argv version 3>', '<ssa envp version 1>', '<ssa envp version 2>', '<ssa envp version 3>', '<ssa lr version 0>', '<ssa lr version 1>', '<ssa lr version 2>', '<ssa lr version 3>', '<ssa r11 version 0>', '<ssa r11 version 1>', '<ssa r11 version 2>', '<ssa r12 version 1>', '<ssa r12 version 2>', '<ssa r12 version 3>', '<ssa r3 version 1>', '<ssa r3 version 2>', '<ssa r3 version 3>', '<ssa r3 version 4>', '<ssa r3 version 5>', '<ssa sp version 1>', '<ssa sp version 2>', '<ssa sp version 3>', '<ssa sp version 4>', '<ssa sp version 5>', '<ssa sp version 6>', '<ssa temp0 version 1>', '<ssa var_10 version 1>', '<ssa var_4 version 1>', '<ssa var_c version 1>']
                assert value == oracle, f"test result from 'main_func.llil.mapped_medium_level_il.ssa_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.llil.mapped_medium_level_il.ssa_form.vars)))
                oracle = ['__saved_r11', 'argc', 'argv', 'envp', 'lr', 'r11', 'r12', 'r3', 'sp', 'temp0', 'var_10', 'var_4', 'var_c']
                assert value == oracle, f"test result from 'main_func.llil.mapped_medium_level_il.ssa_form.vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.llil.mapped_medium_level_il.ssa_form.ssa_vars)))
                oracle = ['<ssa __saved_r11 version 1>', '<ssa argc version 0>', '<ssa argc version 1>', '<ssa argc version 2>', '<ssa argc version 3>', '<ssa argc version 4>', '<ssa argc version 5>', '<ssa argc version 6>', '<ssa argv version 0>', '<ssa argv version 1>', '<ssa argv version 2>', '<ssa argv version 3>', '<ssa envp version 1>', '<ssa envp version 2>', '<ssa envp version 3>', '<ssa lr version 0>', '<ssa lr version 1>', '<ssa lr version 2>', '<ssa lr version 3>', '<ssa r11 version 0>', '<ssa r11 version 1>', '<ssa r11 version 2>', '<ssa r12 version 1>', '<ssa r12 version 2>', '<ssa r12 version 3>', '<ssa r3 version 1>', '<ssa r3 version 2>', '<ssa r3 version 3>', '<ssa r3 version 4>', '<ssa r3 version 5>', '<ssa sp version 1>', '<ssa sp version 2>', '<ssa sp version 3>', '<ssa sp version 4>', '<ssa sp version 5>', '<ssa sp version 6>', '<ssa temp0 version 1>', '<ssa var_10 version 1>', '<ssa var_4 version 1>', '<ssa var_c version 1>']
                assert value == oracle, f"test result from 'main_func.llil.mapped_medium_level_il.ssa_form.ssa_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.mlil.vars)))
                oracle = ['argc', 'argv', 'r0', 'r3', 'var_10', 'var_c']
                assert value == oracle, f"test result from 'main_func.mlil.vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.mlil.ssa_vars)))
                oracle = ['<ssa argc version 0>', '<ssa argv version 0>', '<ssa r0 version 1>', '<ssa r3 version 1>', '<ssa var_10 version 1>', '<ssa var_c version 1>']
                assert value == oracle, f"test result from 'main_func.mlil.ssa_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.mlil.ssa_form.vars)))
                oracle = ['argc', 'argv', 'r0', 'r3', 'var_10', 'var_c']
                assert value == oracle, f"test result from 'main_func.mlil.ssa_form.vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.mlil.ssa_form.ssa_vars)))
                oracle = ['<ssa argc version 0>', '<ssa argv version 0>', '<ssa r0 version 1>', '<ssa r3 version 1>', '<ssa var_10 version 1>', '<ssa var_c version 1>']
                assert value == oracle, f"test result from 'main_func.mlil.ssa_form.ssa_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.hlil.vars)))
                oracle = ['argc', 'argv', 'var_10']
                assert value == oracle, f"test result from 'main_func.hlil.vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.hlil.ssa_vars)))
                oracle = ['<ssa argc version 0>', '<ssa argv version 0>', '<ssa var_10 version 1>']
                assert value == oracle, f"test result from 'main_func.hlil.ssa_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.hlil.ssa_form.vars)))
                oracle = ['argc', 'argv', 'var_10']
                assert value == oracle, f"test result from 'main_func.hlil.ssa_form.vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), main_func.hlil.ssa_form.ssa_vars)))
                oracle = ['<ssa argc version 0>', '<ssa argv version 0>', '<ssa var_10 version 1>']
                assert value == oracle, f"test result from 'main_func.hlil.ssa_form.ssa_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"

                start_func = bv.get_functions_by_name("_start")[0]
                value = sorted(list(map(lambda v: str(v), start_func.mlil.aliased_vars)))
                oracle = ['arg_4']
                assert value == oracle, f"test result from 'start_func.mlil.aliased_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), start_func.mlil.ssa_form.aliased_vars)))
                oracle = ['arg_4']
                assert value == oracle, f"test result from 'start_func.mlil.ssa_form.aliased_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), start_func.hlil.aliased_vars)))
                oracle = ['arg_4']
                assert value == oracle, f"test result from 'start_func.hlil.aliased_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"
                value = sorted(list(map(lambda v: str(v), start_func.hlil.ssa_form.aliased_vars)))
                oracle = ['arg_4']
                assert value == oracle, f"test result from 'start_func.hlil.ssa_form.aliased_vars' = \n\t{value}\nwhich is != to oracle: \n\t{oracle}"

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
            with binja.BinaryViewType['ELF'].get_view_of_file(file_name) as bv:
                bv.update_analysis_and_wait()
                # Make some modifications to the binary view

                # Add a comment
                f = next(bv.functions)
                f.set_comment(f.start, "Function start")
                # Add a new function
                bv.add_function(f.start + 4)
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

            with binja.BinaryViewType['ELF'].get_view_of_file(file_name) as bv:

                bv.update_analysis_and_wait()

                bv.begin_undo_actions()
                f = next(bv.functions)
                f.set_comment(f.start, "Function start")
                bv.commit_undo_actions()

                bv.update_analysis_and_wait()
                comments = self.get_comments(bv)
                functions = self.get_functions(bv)

                bv.begin_undo_actions()
                f.set_comment(f.start, "Function start!")
                bv.commit_undo_actions()

                bv.begin_undo_actions()
                bv.create_user_function(bv.start)
                bv.commit_undo_actions()

                bv.update_analysis_and_wait()
                bv.create_database(temp_name)

            with binja.FileMetadata(temp_name).open_existing_database(temp_name).get_view_of_type('ELF') as bv:

                bv.update_analysis_and_wait()

                bv.undo()
                bv.undo()

                bndb_functions = self.get_functions(bv)
                bndb_comments = self.get_comments(bv)

            os.unlink(temp_name)
            return functions == bndb_functions and comments == bndb_comments

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
            graph = next(bv.functions).create_graph()
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
            graph = next(bv.functions).create_graph()
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

    def test_univeral_loader(self):
        """Universal Mach-O Loader Tests"""
        file_name = self.unpackage_file("fat_macho_9arch")
        save_setting_value = binja.Settings().get_string_list("files.universal.architecturePreference")
        binja.Settings().reset("files.universal.architecturePreference")
        try:
            # test with default arch preference
            with binja.BinaryViewType.get_view_of_file(file_name) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "x86")
                assert(bv.start == 0x1000)
                load_setting_keys = bv.get_load_settings("Mach-O")
                assert(load_setting_keys is not None)
                assert(len(bv.get_load_settings("Mach-O").keys()) == 1)
                assert(bv.get_load_settings("Mach-O").get_integer("loader.macho.universalImageOffset") == 0x1000)

                # save temp bndb for round trip testing
                f = next(bv.functions)
                f.set_comment(f.start, "Function start")
                comments = self.get_comments(bv)
                functions = self.get_functions(bv)
                temp_name = next(tempfile._get_candidate_names()) + ".bndb"
                bv.create_database(temp_name)

            # test get_view_of_file open path
            binja.Settings().reset("files.universal.architecturePreference")
            with BinaryViewType.get_view_of_file(temp_name) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "x86")
                assert(bv.start == 0x1000)
                bndb_functions = self.get_functions(bv)
                bndb_comments = self.get_comments(bv)
                assert([str(functions == bndb_functions and comments == bndb_comments)])

            # test get_view_of_file_with_options open path
            binja.Settings().reset("files.universal.architecturePreference")
            with BinaryViewType.get_view_of_file_with_options(temp_name) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "x86")
                assert(bv.start == 0x1000)
                bndb_functions = self.get_functions(bv)
                bndb_comments = self.get_comments(bv)
                assert([str(functions == bndb_functions and comments == bndb_comments)])

            # test get_view_of_file open path (modified architecture preference)
            binja.Settings().set_string_list("files.universal.architecturePreference", ["arm64"])
            with BinaryViewType.get_view_of_file(temp_name) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "x86")
                assert(bv.start == 0x1000)
                bndb_functions = self.get_functions(bv)
                bndb_comments = self.get_comments(bv)
                assert([str(functions == bndb_functions and comments == bndb_comments)])

            # test get_view_of_file_with_options open path (modified architecture preference)
            binja.Settings().set_string_list("files.universal.architecturePreference", ["x86_64", "arm64"])
            with BinaryViewType.get_view_of_file_with_options(temp_name) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "x86")
                assert(bv.start == 0x1000)
                bndb_functions = self.get_functions(bv)
                bndb_comments = self.get_comments(bv)
                assert([str(functions == bndb_functions and comments == bndb_comments)])
            os.unlink(temp_name)

            # test with overridden arch preference
            binja.Settings().set_string_list("files.universal.architecturePreference", ["arm64"])
            with binja.BinaryViewType.get_view_of_file(file_name) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "aarch64")
                assert(bv.start == 0x100000000)
                load_setting_keys = bv.get_load_settings("Mach-O")
                assert(load_setting_keys is not None)
                assert(len(bv.get_load_settings("Mach-O").keys()) == 1)
                assert(bv.get_load_settings("Mach-O").get_integer("loader.macho.universalImageOffset") == 0x4c000)

                # save temp bndb for round trip testing
                f = next(bv.functions)
                f.set_comment(f.start, "Function start")
                comments = self.get_comments(bv)
                functions = self.get_functions(bv)
                temp_name = next(tempfile._get_candidate_names()) + ".bndb"
                bv.create_database(temp_name)

            # test get_view_of_file open path
            binja.Settings().reset("files.universal.architecturePreference")
            with BinaryViewType.get_view_of_file(temp_name) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "aarch64")
                assert(bv.start == 0x100000000)
                bndb_functions = self.get_functions(bv)
                bndb_comments = self.get_comments(bv)
                assert([str(functions == bndb_functions and comments == bndb_comments)])

            # test get_view_of_file_with_options open path
            binja.Settings().reset("files.universal.architecturePreference")
            with BinaryViewType.get_view_of_file_with_options(temp_name) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "aarch64")
                assert(bv.start == 0x100000000)
                bndb_functions = self.get_functions(bv)
                bndb_comments = self.get_comments(bv)
                assert([str(functions == bndb_functions and comments == bndb_comments)])

            # test get_view_of_file open path (modified architecture preference)
            binja.Settings().set_string_list("files.universal.architecturePreference", ["x86"])
            with BinaryViewType.get_view_of_file(temp_name) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "aarch64")
                assert(bv.start == 0x100000000)
                bndb_functions = self.get_functions(bv)
                bndb_comments = self.get_comments(bv)
                assert([str(functions == bndb_functions and comments == bndb_comments)])

            # test get_view_of_file_with_options open path (modified architecture preference)
            binja.Settings().set_string_list("files.universal.architecturePreference", ["x86_64", "arm64"])
            with BinaryViewType.get_view_of_file_with_options(temp_name) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "aarch64")
                assert(bv.start == 0x100000000)
                bndb_functions = self.get_functions(bv)
                bndb_comments = self.get_comments(bv)
                assert([str(functions == bndb_functions and comments == bndb_comments)])
                bv.file.close()
            os.unlink(temp_name)


            binja.Settings().set_string_list("files.universal.architecturePreference", ["x86_64", "arm64"])
            with binja.BinaryViewType.get_view_of_file_with_options(file_name, options={'loader.imageBase': 0xfffffff0000}) as bv:
                assert(bv.view_type == "Mach-O")
                assert(bv.arch.name == "x86_64")
                assert(bv.start == 0xfffffff0000)
                load_setting_keys = bv.get_load_settings("Mach-O")
                assert(load_setting_keys is not None)
                assert(len(bv.get_load_settings("Mach-O").keys()) == 8)
                assert(bv.get_load_settings("Mach-O").get_integer("loader.macho.universalImageOffset") == 0x8000)

                binja.Settings().set_string_list("files.universal.architecturePreference", save_setting_value)
                return True

        finally:
            binja.Settings().set_string_list("files.universal.architecturePreference", save_setting_value)
            self.delete_package("fat_macho_9arch")

    def test_user_informed_dataflow(self):
        """User-informed dataflow tests"""
        file_name = self.unpackage_file("helloworld")
        try:
            with binja.open_view(file_name) as bv:
                func = bv.get_function_at(0x00008440)

                ins_idx = func.mlil.get_instruction_start(0x845c)
                ins = func.mlil[ins_idx]
                assert(ins.operation == binja.MediumLevelILOperation.MLIL_IF)
                assert(len(ins.vars_read) == 1)
                var = ins.vars_read[0]
                defs = func.mlil.get_var_definitions(var)
                assert(len(defs) == 1)
                def_site = defs[0].address

                # Set variable value to 0
                bv.begin_undo_actions()
                func.set_user_var_value(var, def_site, binja.PossibleValueSet.constant(0))
                bv.commit_undo_actions()
                bv.update_analysis_and_wait()

                ins_idx = func.mlil.get_instruction_start(0x845c)
                ins = func.mlil[ins_idx]
                assert(ins.operation == binja.MediumLevelILOperation.MLIL_IF)
                # test if condition value is updated to true
                assert(ins.condition.value == True)
                # test if register value is updated to 0
                assert(ins.get_reg_value_after('r3') == 0)
                # test if branch is eliminated in hlil
                for hlil_ins in func.hlil.instructions:
                    assert(hlil_ins.operation != binja.HighLevelILOperation.HLIL_IF)

                # test undo action
                bv.undo()
                bv.update_analysis_and_wait()
                ins_idx = func.mlil.get_instruction_start(0x845c)
                ins = func.mlil[ins_idx]
                assert(ins.operation == binja.MediumLevelILOperation.MLIL_IF)
                # test if condition value is updated to undetermined
                assert(ins.condition.value.type == binja.RegisterValueType.UndeterminedValue)
                # test if register value is updated to undetermined
                assert(ins.get_reg_value_after('r3').type == binja.RegisterValueType.EntryValue)
                # test if branch is restored in hlil
                found = False
                for hlil_ins in func.hlil.instructions:
                    if hlil_ins.operation == binja.HighLevelILOperation.HLIL_IF:
                        found = True
                assert(found)

                # test redo action
                bv.redo()
                bv.update_analysis_and_wait()
                ins_idx = func.mlil.get_instruction_start(0x845c)
                ins = func.mlil[ins_idx]
                assert(ins.operation == binja.MediumLevelILOperation.MLIL_IF)
                # test if condition value is updated to true
                assert(ins.condition.value == True)
                # test if register value is updated to 0
                assert(ins.get_reg_value_after('r3') == 0)
                # test if branch is eliminated in hlil
                for hlil_ins in func.hlil.instructions:
                    assert(hlil_ins.operation != binja.HighLevelILOperation.HLIL_IF)

                # test bndb round trip
                temp_name = next(tempfile._get_candidate_names()) + ".bndb"
                bv.create_database(temp_name)

            with binja.open_view(temp_name) as bv:
                func = bv.get_function_at(0x00008440)

                ins_idx = func.mlil.get_instruction_start(0x845c)
                ins = func.mlil[ins_idx]
                assert(ins.operation == binja.MediumLevelILOperation.MLIL_IF)
                # test if condition value is updated to true
                assert(ins.condition.value == True)
                # test if register value is updated to 0
                assert(ins.get_reg_value_after('r3') == 0)
                # test if branch is eliminated in hlil
                for hlil_ins in func.hlil.instructions:
                    assert(hlil_ins.operation != binja.HighLevelILOperation.HLIL_IF)

                # test undo after round trip
                bv.undo()
                bv.update_analysis_and_wait()
                ins_idx = func.mlil.get_instruction_start(0x845c)
                ins = func.mlil[ins_idx]
                assert(ins.operation == binja.MediumLevelILOperation.MLIL_IF)
                # test if condition value is updated to undetermined
                assert(ins.condition.value.type == binja.RegisterValueType.UndeterminedValue)
                # test if register value is updated to undetermined
                assert(ins.get_reg_value_after('r3').type == binja.RegisterValueType.EntryValue)
                # test if branch is restored in hlil
                found = False
                for hlil_ins in func.hlil.instructions:
                    if hlil_ins.operation == binja.HighLevelILOperation.HLIL_IF:
                        found = True
                assert(found)

            os.unlink(temp_name)
            return True

        finally:
            self.delete_package("helloworld")

    def test_possiblevalueset_ser_and_deser(self):
        """PossibleValueSet serialization and deserialization"""
        def test_helper(value):
            file_name = self.unpackage_file("helloworld")
            try:
                with binja.open_view(file_name) as bv:
                    func = bv.get_function_at(0x00008440)

                    ins_idx = func.mlil.get_instruction_start(0x845c)
                    ins = func.mlil[ins_idx]

                    var = ins.vars_read[0]
                    defs = func.mlil.get_var_definitions(var)
                    def_site = defs[0].address

                    func.set_user_var_value(var, def_site, value)
                    bv.update_analysis_and_wait()

                    def_ins_idx = func.mlil.get_instruction_start(def_site)
                    def_ins = func.mlil[def_ins_idx]

                    assert(def_ins.get_possible_reg_values_after('r3') == value)

                    temp_name = next(tempfile._get_candidate_names()) + ".bndb"
                    bv.create_database(temp_name)

                with binja.open_view(temp_name) as bv:
                    func = bv.get_function_at(0x00008440)

                    ins_idx = func.mlil.get_instruction_start(0x845c)
                    ins = func.mlil[ins_idx]

                    def_ins_idx = func.mlil.get_instruction_start(def_site)
                    def_ins = func.mlil[def_ins_idx]

                    assert(def_ins.get_possible_reg_values_after('r3') == value)

                os.unlink(temp_name)
                return True

            finally:
                self.delete_package("helloworld")

        assert(test_helper(binja.PossibleValueSet.constant(0)))
        assert(test_helper(binja.PossibleValueSet.constant_ptr(0x8000)))
        assert(test_helper(binja.PossibleValueSet.unsigned_range_value([binja.ValueRange(1, 10, 2)])))
        # assert(test_helper(binja.PossibleValueSet.signed_range_value([binja.ValueRange(-10, 0, 2)])))
        assert(test_helper(binja.PossibleValueSet.in_set_of_values([1,2,3,4])))
        assert(test_helper(binja.PossibleValueSet.not_in_set_of_values([1,2,3,4])))
        return True

    def test_binaryview_callbacks(self):
        """BinaryView finalized callback and analysis completion callback"""
        file_name = self.unpackage_file("helloworld")

        # Currently, there is no way to unregister a BinaryView event callback.
        # This boolean tells the callback function whether it should run or just return
        callback_should_run = True

        def bv_finalized_callback(bv):
            if callback_should_run:
                bv.store_metadata('finalized', 'yes')

        def bv_finalized_callback_2(bv):
            if callback_should_run:
                bv.store_metadata('finalized_2', 'yes')

        def bv_analysis_completion_callback(bv):
            if callback_should_run:
                bv.store_metadata('analysis_completion', 'yes')

        BinaryViewType.add_binaryview_finalized_event(bv_finalized_callback)
        BinaryViewType.add_binaryview_finalized_event(bv_finalized_callback_2)
        BinaryViewType.add_binaryview_initial_analysis_completion_event(bv_analysis_completion_callback)

        try:
            with binja.open_view(file_name) as bv:
                finalized = bv.query_metadata('finalized') == 'yes'
                finalized_2 = bv.query_metadata('finalized_2') == 'yes'
                analysis_completion = bv.query_metadata('analysis_completion') == 'yes'
                return finalized and finalized_2 and analysis_completion

        finally:
            self.delete_package("helloworld")
            callback_should_run = False

    def test_load_old_database(self):
        """Load a database produced by Binary Ninja v1.2.1921"""
        file_name = self.unpackage_file("binja_v1.2.1921_bin_ls.bndb")
        if not os.path.exists(file_name):
            return False

        binja.Settings().set_bool("analysis.database.suppressReanalysis", True)
        ret = None
        with BinaryViewType.get_view_of_file_with_options(file_name) as bv:
            if bv is None:
                ret = False
            if bv.file.snapshot_data_applied_without_error:
                ret = True

        binja.Settings().reset("analysis.database.suppressReanalysis")
        self.delete_package("binja_v1.2.1921_bin_ls.bndb")
        return ret

    def test_struct_type_leakage(self):
        """
        Define a structure, then assign a variable to it. There should only be NTRs (and not dereffed types) in func.vars
        See: #2428
        """
        file_name = self.unpackage_file("basic_struct")

        ret = True
        try:
            with binja.open_view(file_name) as bv:
                # struct A { uint64_t a; uint64_t b; };
                with binja.StructureBuilder.builder(bv, "A") as s:
                    s.width = 0x10
                    s.append(binja.Type.int(8, False), "a")
                    s.append(binja.Type.int(8, False), "b")

                # Find main and the var it sets to malloc(0x10)
                func = [f for f in bv.functions if f.name == '_main'][0]
                for v in func.vars:
                    d = func.mlil.get_var_definitions(v)
                    if len(d) == 0:
                        continue

                    if d[0].operation == binja.MediumLevelILOperation.MLIL_CALL:
                        var = v

                # Change var type to struct A*
                vt = binja.Type.pointer(bv.arch, binja.Type.named_type_from_registered_type(bv, 'A'))
                func.create_user_var(var, vt, 'test')
                bv.update_analysis_and_wait()

                for v in func.vars:
                    if isinstance(v.type, binja.types.PointerType):
                        if isinstance(v.type.target, binja.types.StructureType):
                            ret = False
                            print(f"Found ptr to raw structure: {v.type} {v}")
        finally:
            self.delete_package("basic_struct")

        return ret

    def test_old_tags(self):
        """
        New builds use string-based ids for tags, whereas older builds used integers. Make sure the old builds still work
        """

        file_name = self.unpackage_file("old_tags.bndb")
        assert file_name is not None
        ret = True
        try:
            binja.Settings().set_bool("analysis.database.suppressReanalysis", True)
            with BinaryViewType.get_view_of_file_with_options(file_name) as bv:
                if bv is None:
                    ret = False
                    raise Exception("File load error")
                if not bv.file.snapshot_data_applied_without_error:
                    ret = False
                    raise Exception("Snapshot apply error")

                # Make sure the tags exist and are where we expect them
                _start = bv.get_function_at(bv.start + 0x1060)
                assert _start is not None
                sub_1012 = bv.get_function_at(bv.start + 0x1012)

                assert len(bv.get_data_tags_at(bv.start + 0x6030)) == 1
                assert bv.get_data_tags_at(bv.start + 0x6030)[0].type.name == 'Bookmarks'
                assert bv.get_data_tags_at(bv.start + 0x6030)[0].data == '2'
                assert bv.get_data_tags_at(bv.start + 0x6030)[0].id == '7'

                assert len(bv.get_data_tags_at(bv.start + 0x6040)) == 2
                assert bv.get_data_tags_at(bv.start + 0x6040)[0].type.name == 'Crashes'
                assert bv.get_data_tags_at(bv.start + 0x6040)[0].data == 'New Tag'
                assert bv.get_data_tags_at(bv.start + 0x6040)[0].id == '8'
                assert bv.get_data_tags_at(bv.start + 0x6040)[1].type.name == 'Library'
                assert bv.get_data_tags_at(bv.start + 0x6040)[1].data == 'New Tag'
                assert bv.get_data_tags_at(bv.start + 0x6040)[1].id == '9'

                function_tags = list(_start.function_tags)
                assert len(function_tags) == 1
                assert function_tags[0].type.name == 'Library'
                assert function_tags[0].data == 'New Tag'
                assert function_tags[0].id == '1'

                function_tags = list(sub_1012.function_tags)
                assert len(function_tags) == 2
                assert function_tags[0].type.name == 'Library'
                assert function_tags[0].data == 'New Tag'
                assert function_tags[0].id == '3'
                assert function_tags[1].type.name == 'Bugs'
                assert function_tags[1].data == 'New Tag'
                assert function_tags[1].id == '10'

                address_tags = list(_start.get_address_tags_at(bv.start + 0x1097))
                assert len(address_tags) == 1
                assert address_tags[0].type.name == 'Important'
                assert address_tags[0].data == 'New Tag'
                assert address_tags[0].id == '4'

                address_tags = list(_start.get_address_tags_at(bv.start + 0x1116))
                assert len(address_tags) == 2
                assert address_tags[0].type.name == 'Crashes'
                assert address_tags[0].data == 'New Tag'
                assert address_tags[0].id == '5'
                assert address_tags[1].type.name == 'Needs Analysis'
                assert address_tags[1].data == 'New Tag'
                assert address_tags[1].id == '6'

            binja.Settings().reset("analysis.database.suppressReanalysis")
        finally:
            self.delete_package("old_tags.bndb")

        return ret

    def test_get_paths(self):
        """Get install directory and bundled plugin directory"""
        core_platform = system()

        install_dir = binja.get_install_directory()
        if not os.path.isdir(install_dir):
            return False

        files = os.listdir(install_dir)
        if core_platform == "Darwin":
            if not 'libbinaryninjacore.dylib' in files:
                return False
        elif core_platform == "Linux":
            if not 'libbinaryninjacore.so.1' in files:
                return False
        elif core_platform == "Windows":
            if not 'binaryninjacore.dll' in files:
                return False
        else:
            return False

        plugin_dir = binja.bundled_plugin_path()
        if not os.path.isdir(plugin_dir):
            return False

        files = os.listdir(plugin_dir)
        if core_platform == "Darwin":
            if not 'libarch_x86.dylib' in files:
                return False
        elif core_platform == "Linux":
            if not 'libarch_x86.so' in files:
                return False
        elif core_platform == "Windows":
            if not 'arch_x86.dll' in files:
                return False
        else:
            return False

        return True
