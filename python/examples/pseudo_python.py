# Copyright (c) 2024 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

from binaryninja import (Architecture, BraceRequirement, DisassemblySettings, DisassemblyTextLine, Function,
                         InstructionTextToken, InstructionTextTokenType, LanguageRepresentationFunction,
                         LanguageRepresentationFunctionType, HighLevelILInstruction, HighLevelILFunction,
                         HighLevelILTokenEmitter, HighLevelILOperation, OperatorPrecedence, ScopeType,
                         SymbolDisplayType, SymbolDisplayResult, SymbolType, BoolType, VoidType, PointerType,
                         NamedTypeReferenceType, StructureType, InstructionTextTokenContext, StructureMember,
                         BinaryView, BuiltinType)
from typing import Optional
import struct


class PseudoPythonFunction(LanguageRepresentationFunction):
    comment_start_string = "# "

    def perform_init_token_emitter(self, emitter):
        # Python never allows braces, even if the user has set the option to show them
        emitter.brace_requirement = BraceRequirement.BracesNotAllowed

    def perform_begin_lines(self, instr: HighLevelILInstruction, tokens: HighLevelILTokenEmitter):
        # Ensure that the function body is indented relative to the function declaration
        tokens.increase_indent()

    def perform_get_expr_text(
            self, instr: HighLevelILInstruction, tokens: HighLevelILTokenEmitter, settings: Optional[DisassemblySettings],
            precedence: OperatorPrecedence = OperatorPrecedence.TopLevelOperatorPrecedence,
            statement: bool = False
    ):
        with tokens.expr(instr):
            if instr.operation == HighLevelILOperation.HLIL_BLOCK:
                need_separator = False
                body = instr.body
                # Emit the lines for each statement in the body
                for (idx, i) in enumerate(body):
                    # Don't display trailing return statements that don't have values
                    if (instr.as_ast and idx + 1 == len(body) and i.operation == HighLevelILOperation.HLIL_RET and
                            len(i.src) == 0 and instr.expr_index == self.hlil.root.expr_index):
                        continue

                    # If the statement is one that contains additional blocks of code, insert a scope separator
                    # to visually separate the logic.
                    has_blocks = i.operation in [HighLevelILOperation.HLIL_IF, HighLevelILOperation.HLIL_WHILE,
                                                 HighLevelILOperation.HLIL_DO_WHILE, HighLevelILOperation.HLIL_FOR,
                                                 HighLevelILOperation.HLIL_SWITCH]
                    if need_separator or (idx != 0 and has_blocks):
                        tokens.scope_separator()
                    need_separator = has_blocks

                    # Emit the lines for the statement itself
                    self.perform_get_expr_text(i, tokens, settings, OperatorPrecedence.TopLevelOperatorPrecedence, True)
                    tokens.new_line()
            elif instr.operation == HighLevelILOperation.HLIL_IF:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "if "))
                self.perform_get_expr_text(instr.condition, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, ":\n"))
                if instr.as_ast:
                    # Only display the if body when printing the full AST. When printing basic blocks in graph view,
                    # the body of the if and the else part are rendered as other nodes in the graph.
                    tokens.begin_scope(ScopeType.BlockScopeType)
                    self.perform_get_expr_text(instr.true, tokens, settings,
                                               OperatorPrecedence.TopLevelOperatorPrecedence, True)
                    tokens.end_scope(ScopeType.BlockScopeType)

                    # Else statements need to be handled as chains, since "else if" in Python should be rendered
                    # as "elif" statements.
                    if_chain = instr.false
                    while if_chain is not None and if_chain.operation not in [HighLevelILOperation.HLIL_NOP,
                                                                              HighLevelILOperation.HLIL_UNREACHABLE]:
                        if if_chain.operation == HighLevelILOperation.HLIL_IF:
                            tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "elif "))
                            self.perform_get_expr_text(if_chain.condition, tokens, settings)
                            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ":"))
                            tokens.begin_scope(ScopeType.BlockScopeType)
                            self.perform_get_expr_text(if_chain.true, tokens, settings,
                                                       OperatorPrecedence.TopLevelOperatorPrecedence, True)
                            tokens.end_scope(ScopeType.BlockScopeType)
                            if_chain = if_chain.false
                        else:
                            tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "else"))
                            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ":"))
                            tokens.begin_scope(ScopeType.BlockScopeType)
                            self.perform_get_expr_text(if_chain, tokens, settings,
                                                       OperatorPrecedence.TopLevelOperatorPrecedence, True)
                            tokens.end_scope(ScopeType.BlockScopeType)
                            break
            elif instr.operation == HighLevelILOperation.HLIL_FOR:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "for "))

                # If the for loop can be represented as a Python range function, show it that way
                dest_var = None
                if instr.init.operation == HighLevelILOperation.HLIL_VAR_INIT:
                    dest_var = instr.init.dest
                elif instr.init.operation == HighLevelILOperation.HLIL_ASSIGN and instr.init.dest.operation == HighLevelILOperation.HLIL_VAR:
                    dest_var = instr.init.dest.var
                if (dest_var is not None and
                        (instr.condition.operation in [HighLevelILOperation.HLIL_CMP_SLT,
                                                       HighLevelILOperation.HLIL_CMP_ULT]) and
                        instr.condition.left.operation == HighLevelILOperation.HLIL_VAR and
                        instr.condition.left.var == dest_var and
                        instr.update.operation == HighLevelILOperation.HLIL_ASSIGN and
                        instr.update.dest.operation == HighLevelILOperation.HLIL_VAR and
                        instr.update.dest.var == instr.condition.left.var and
                        instr.update.src.operation == HighLevelILOperation.HLIL_ADD and
                        instr.update.src.left.operation == HighLevelILOperation.HLIL_VAR and
                        instr.update.src.left.var == instr.condition.left.var):
                    step_by = (instr.update.src.right.operation != HighLevelILOperation.HLIL_CONST or
                               instr.update.src.right.constant != 1)
                    start_required = (instr.init.src.operation != HighLevelILOperation.HLIL_CONST or
                                      instr.init.src.constant != 0 or step_by)
                    tokens.append(InstructionTextToken(InstructionTextTokenType.LocalVariableToken, dest_var.name,
                                                       context=InstructionTextTokenContext.LocalVariableTokenContext,
                                                       address=instr.expr_index, value=dest_var.identifier,
                                                       size=instr.size))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, " in "))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "range"))
                    tokens.append_open_paren()
                    if start_required:
                        self.perform_get_expr_text(instr.init.src, tokens, settings)
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                    self.perform_get_expr_text(instr.condition.right, tokens, settings)
                    if step_by:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                        self.perform_get_expr_text(instr.update.src.right, tokens, settings)
                    tokens.append_close_paren()
                else:
                    # Not representable directly as a Python loop, emit it with a more HLIL-like syntax
                    if instr.init.operation != HighLevelILOperation.HLIL_NOP:
                        self.perform_get_expr_text(instr.init, tokens, settings)
                    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "; "))
                    if instr.condition.operation != HighLevelILOperation.HLIL_NOP:
                        self.perform_get_expr_text(instr.condition, tokens, settings)
                    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "; "))
                    if instr.update.operation != HighLevelILOperation.HLIL_NOP:
                        self.perform_get_expr_text(instr.update, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, ":"))
                if instr.as_ast:
                    tokens.begin_scope(ScopeType.BlockScopeType)
                    self.perform_get_expr_text(instr.body, tokens, settings,
                                               OperatorPrecedence.TopLevelOperatorPrecedence, True)
                    tokens.end_scope(ScopeType.BlockScopeType)
            elif instr.operation == HighLevelILOperation.HLIL_WHILE:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "while "))
                self.perform_get_expr_text(instr.condition, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, ":"))
                if instr.as_ast:
                    tokens.begin_scope(ScopeType.BlockScopeType)
                    self.perform_get_expr_text(instr.body, tokens, settings,
                                               OperatorPrecedence.TopLevelOperatorPrecedence, True)
                    tokens.end_scope(ScopeType.BlockScopeType)
            elif instr.operation == HighLevelILOperation.HLIL_DO_WHILE:
                if instr.as_ast:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "do"))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, ":"))
                    tokens.begin_scope(ScopeType.BlockScopeType)
                    self.perform_get_expr_text(instr.body, tokens, settings,
                                               OperatorPrecedence.TopLevelOperatorPrecedence, True)
                    tokens.end_scope(ScopeType.BlockScopeType)
                    tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "while "))
                    self.perform_get_expr_text(instr.condition, tokens, settings)
                else:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "do "))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "while "))
                    self.perform_get_expr_text(instr.condition, tokens, settings)
            elif instr.operation == HighLevelILOperation.HLIL_SWITCH:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "match "))
                self.perform_get_expr_text(instr.condition, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, ":"))
                tokens.begin_scope(ScopeType.SwitchScopeType)

                if instr.as_ast:
                    # Output each case
                    for case in instr.cases:
                        self.perform_get_expr_text(case, tokens, settings,
                                                   OperatorPrecedence.TopLevelOperatorPrecedence, True)
                        tokens.new_line()

                    # Check for default case
                    if instr.default is not None and instr.default.operation not in [HighLevelILOperation.HLIL_NOP,
                                                                                     HighLevelILOperation.HLIL_UNREACHABLE]:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "default"))
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ":"))
                        tokens.begin_scope(ScopeType.CaseScopeType)
                        self.perform_get_expr_text(instr.default, tokens, settings,
                                                   OperatorPrecedence.TopLevelOperatorPrecedence, True)
                        tokens.end_scope(ScopeType.CaseScopeType)
                    tokens.end_scope(ScopeType.SwitchScopeType)
            elif instr.operation == HighLevelILOperation.HLIL_CASE:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "case "))
                for (i, value) in enumerate(instr.values):
                    if i > 0:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " | "))
                    self.perform_get_expr_text(value, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ":"))
                tokens.begin_scope(ScopeType.CaseScopeType)
                self.perform_get_expr_text(instr.body, tokens, settings,
                                           OperatorPrecedence.TopLevelOperatorPrecedence, True)
                tokens.end_scope(ScopeType.CaseScopeType)
            elif instr.operation == HighLevelILOperation.HLIL_BREAK:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "break"))
            elif instr.operation == HighLevelILOperation.HLIL_CONTINUE:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "continue"))
            elif instr.operation == HighLevelILOperation.HLIL_CALL:
                self.perform_get_expr_text(instr.dest, tokens, settings,
                                           OperatorPrecedence.MemberAndFunctionOperatorPrecedence)
                tokens.append_open_paren()
                for (i, param) in enumerate(instr.params):
                    if i > 0:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                    self.perform_get_expr_text(param, tokens, settings)
                tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_TAILCALL:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "return "))
                self.perform_get_expr_text(instr.dest, tokens, settings,
                                           OperatorPrecedence.MemberAndFunctionOperatorPrecedence)
                tokens.append_open_paren()
                for (i, param) in enumerate(instr.params):
                    if i > 0:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                    self.perform_get_expr_text(param, tokens, settings)
                tokens.append_close_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.AnnotationToken, "  # tailcall"))
            elif instr.operation == HighLevelILOperation.HLIL_INTRINSIC:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, instr.intrinsic.name))
                tokens.append_open_paren()
                for (i, param) in enumerate(instr.params):
                    if i > 0:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                    self.perform_get_expr_text(param, tokens, settings)
                tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_SYSCALL:
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "syscall"))
                tokens.append_open_paren()
                for (i, param) in enumerate(instr.params):
                    if i > 0:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                    if i == 0 and param.operation == HighLevelILOperation.HLIL_CONST:
                        platform = self.function.platform
                        if platform is not None:
                            syscall_name = platform.get_system_call_name(param.constant)
                            if len(syscall_name) > 0:
                                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, syscall_name))
                                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " "))
                                tokens.append(InstructionTextToken(InstructionTextTokenType.AnnotationToken, "{"))
                                self.perform_get_expr_text(param, tokens, settings)
                                tokens.append(InstructionTextToken(InstructionTextTokenType.AnnotationToken, "}"))
                                continue
                    self.perform_get_expr_text(param, tokens, settings)
                tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_ZX:
                self.perform_get_expr_text(instr.src, tokens, settings)
            elif instr.operation == HighLevelILOperation.HLIL_SX:
                self.perform_get_expr_text(instr.src, tokens, settings)
            elif instr.operation == HighLevelILOperation.HLIL_IMPORT:
                # Check for import address symbol at target address, and display that if there is one
                sym = instr.function.source_function.view.get_symbol_at(instr.constant)
                if sym is not None:
                    if sym.type == SymbolType.ImportedDataSymbol or sym.type == SymbolType.ImportAddressSymbol:
                        sym = sym.imported_function_from_import_address_symbol(instr.constant)
                        if sym is not None:
                            tokens.append(
                                InstructionTextToken(InstructionTextTokenType.IndirectImportToken, sym.short_name,
                                                     value=instr.constant, address=instr.address,
                                                     size=instr.size, operand=instr.source_operand))
                            return
                # Otherwise use a generic pointer token
                tokens.append_pointer_text_token(instr, instr.constant, settings,
                                                 SymbolDisplayType.DereferenceNonDataSymbols, precedence)
            elif instr.operation == HighLevelILOperation.HLIL_ARRAY_INDEX:
                self.perform_get_expr_text(instr.src, tokens, settings,
                                           OperatorPrecedence.MemberAndFunctionOperatorPrecedence)
                tokens.append_open_bracket()
                self.perform_get_expr_text(instr.index, tokens, settings)
                tokens.append_close_bracket()
            elif instr.operation == HighLevelILOperation.HLIL_VAR_INIT:
                # Check to see if the variable appears live
                appears_dead = False
                ssa = instr.ssa_form
                if ssa is not None and ssa.operation == HighLevelILOperation.HLIL_VAR_INIT_SSA:
                    appears_dead = not self.hlil.is_ssa_var_live(ssa.dest)

                # If the variable does not appear live, show the assignment as zero confidence (grayed out)
                with tokens.force_zero_confidence(appears_dead):
                    tokens.append_var_text_token(instr.dest, instr, instr.size)
                    if instr.dest.type is not None:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ": "))
                        tokens.append(instr.dest.type.get_tokens())
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " = "))

                # For the right side of the assignment, only use zero confidence if the instruction does
                # not have any side effects
                with tokens.force_zero_confidence(appears_dead and not instr.src.has_side_effects):
                    self.perform_get_expr_text(instr.src, tokens, settings,
                                               OperatorPrecedence.AssignmentOperatorPrecedence)
            elif instr.operation == HighLevelILOperation.HLIL_VAR_DECLARE:
                tokens.append_var_text_token(instr.var, instr, instr.size)
                if instr.var.type is not None:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ": "))
                    tokens.append(instr.var.type.get_tokens())
            elif instr.operation == HighLevelILOperation.HLIL_FLOAT_CONST:
                tokens.append(InstructionTextToken(InstructionTextTokenType.FloatingPointToken, f"{instr.constant:g}"))
            elif instr.operation == HighLevelILOperation.HLIL_CONST:
                # Check for bool type. Display these as True or False. The default handling will use C style
                # booleans instead of Python style.
                if instr.size == 0 or isinstance(instr.expr_type, BoolType):
                    if instr.constant != 0:
                        tokens.append(
                            InstructionTextToken(InstructionTextTokenType.IntegerToken, "True", address=instr.address,
                                                 value=instr.constant))
                    else:
                        tokens.append(
                            InstructionTextToken(InstructionTextTokenType.IntegerToken, "False", address=instr.address,
                                                 value=instr.constant))
                else:
                    tokens.append_constant_text_token(instr, instr.constant, instr.size, settings, precedence)
            elif instr.operation == HighLevelILOperation.HLIL_CONST_PTR:
                tokens.append_pointer_text_token(instr, instr.constant, settings,
                                                 SymbolDisplayType.AddressOfDataSymbols, precedence)
            elif instr.operation == HighLevelILOperation.HLIL_CONST_DATA:
                # Constant data should be rendered according to the type of builtin function being used.
                data, builtin = instr.constant_data.data_and_builtin
                if builtin in [BuiltinType.BuiltinStrcpy, BuiltinType.BuiltinStrncpy]:
                    data = data.escape(null_terminates=True)
                    tokens.append(InstructionTextToken(InstructionTextTokenType.StringToken, f'"{data}"',
                                                       address=instr.address, value=instr.constant_data.value,
                                                       context=InstructionTextTokenContext.ConstStringDataTokenContext))
                elif builtin == BuiltinType.BuiltinMemset:
                    tokens.append_open_brace()
                    tokens.append(InstructionTextToken(InstructionTextTokenType.StringToken,
                                                       f"{instr.constant_data.value:#x}",
                                                       address=instr.address, value=instr.constant_data.value,
                                                       context=InstructionTextTokenContext.ConstDataTokenContext))
                    tokens.append_close_brace()
                else:
                    string, string_type = self.function.view.stringify_unicode_data(self.function.arch, data)
                    if string is not None:
                        wide_string_prefix = ""
                        token_context = InstructionTextTokenContext.ConstDataTokenContext
                        if builtin == BuiltinType.BuiltinWcscpy:
                            wide_string_prefix = "L"
                            token_context = InstructionTextTokenContext.ConstStringDataTokenContext
                        tokens.append(InstructionTextToken(InstructionTextTokenType.StringToken,
                                                           f'{wide_string_prefix}"{string}"',
                                                           address=instr.address, value=instr.constant_data.value,
                                                           context=token_context))
                    else:
                        data = data.escape(null_terminates=False, escape_printable=True)
                        tokens.append(InstructionTextToken(InstructionTextTokenType.StringToken, f'"{data}"',
                                                           address=instr.address, value=instr.constant_data.value,
                                                           context=InstructionTextTokenContext.ConstDataTokenContext))
            elif instr.operation == HighLevelILOperation.HLIL_EXTERN_PTR:
                # Extern pointer instructions have an offset associated with them. If this is nonzero, show this
                # as an addition or subtraction of the offset.
                parens = instr.offset != 0 and precedence >= OperatorPrecedence.AddOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                if instr.offset != 0:
                    precedence = OperatorPrecedence.SubOperatorPrecedence
                tokens.append_pointer_text_token(instr, instr.constant, settings,
                                                 SymbolDisplayType.AddressOfDataSymbols, precedence)
                if instr.offset < 0:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " - "))
                    tokens.append_integer_text_token(instr, -instr.offset, instr.size)
                elif instr.offset > 0:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " + "))
                    tokens.append_integer_text_token(instr, instr.offset, instr.size)

                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_VAR:
                tokens.append(InstructionTextToken(InstructionTextTokenType.LocalVariableToken, instr.var.name,
                                                   address=instr.expr_index, size=instr.size,
                                                   value=instr.var.identifier,
                                                   context=InstructionTextTokenContext.LocalVariableTokenContext))
            elif instr.operation == HighLevelILOperation.HLIL_ASSIGN:
                # Check to see if the variable appears live
                appears_dead = False
                if instr.dest.operation == HighLevelILOperation.HLIL_VAR:
                    ssa = instr.ssa_form
                    if ssa is not None and ssa.operation == HighLevelILOperation.HLIL_VAR_INIT_SSA:
                        appears_dead = not self.hlil.is_ssa_var_live(ssa.dest)

                # If the variable does not appear live, show the assignment as zero confidence (grayed out)
                with tokens.force_zero_confidence(appears_dead):
                    self.perform_get_expr_text(instr.dest, tokens, settings,
                                               OperatorPrecedence.AssignmentOperatorPrecedence)
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " = "))

                # For the right side of the assignment, only use zero confidence if the instruction does
                # not have any side effects
                with tokens.force_zero_confidence(appears_dead and not instr.src.has_side_effects):
                    self.perform_get_expr_text(instr.src, tokens, settings,
                                               OperatorPrecedence.AssignmentOperatorPrecedence)
            elif instr.operation == HighLevelILOperation.HLIL_ASSIGN_UNPACK:
                tokens.append_open_paren()
                for (i, dest) in enumerate(instr.dest):
                    if i > 0:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                    self.perform_get_expr_text(dest, tokens, settings)
                tokens.append_close_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " = "))
                self.perform_get_expr_text(instr.src, tokens, settings,
                                           OperatorPrecedence.AssignmentOperatorPrecedence)
            elif instr.operation == HighLevelILOperation.HLIL_STRUCT_FIELD:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.perform_get_expr_text(instr.src, tokens, settings,
                                           OperatorPrecedence.MemberAndFunctionOperatorPrecedence)
                self.append_field_text_tokens(instr.src, instr.offset, instr.member_index, instr.size, tokens)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_DEREF_FIELD:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                if instr.src.operation == HighLevelILOperation.HLIL_CONST_PTR:
                    tokens.append_pointer_text_token(instr.src, instr.src.constant, settings,
                                                     SymbolDisplayType.DisplaySymbolOnly,
                                                     OperatorPrecedence.MemberAndFunctionOperatorPrecedence)
                else:
                    self.perform_get_expr_text(instr.src, tokens, settings,
                                               OperatorPrecedence.MemberAndFunctionOperatorPrecedence)
                self.append_field_text_tokens(instr.src, instr.offset, instr.member_index, instr.size, tokens)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_DEREF:
                if instr.src.operation == HighLevelILOperation.HLIL_CONST_PTR:
                    if tokens.append_pointer_text_token(instr.src, instr.src.constant, settings,
                                                        SymbolDisplayType.DereferenceNonDataSymbols,
                                                        precedence) == SymbolDisplayResult.DataSymbolResult:
                        expr_type = instr.src.expr_type
                        if isinstance(expr_type, PointerType) and expr_type.target.width != instr.size:
                            # If dereference size doesn't match the data variable size, append a size suffix
                            suffix = {0: "", 1: ".b", 2: ".w", 4: ".d", 8: ".q", 10: ".t", 16: ".q"}
                            if instr.size in suffix:
                                suffix_str = suffix[instr.size]
                            else:
                                suffix_str = f".{instr.size}"
                            tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, suffix_str))
                else:
                    parens = precedence > OperatorPrecedence.UnaryOperatorPrecedence
                    if parens:
                        tokens.append_open_paren()
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "*"))
                    self.perform_get_expr_text(instr.src, tokens, settings,
                                               OperatorPrecedence.UnaryOperatorPrecedence)
                    if parens:
                        tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_ADDRESS_OF:
                parens = precedence > OperatorPrecedence.UnaryOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "&"))
                self.perform_get_expr_text(instr.src, tokens, settings,
                                           OperatorPrecedence.UnaryOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_CMP_E, HighLevelILOperation.HLIL_FCMP_E]:
                parens = precedence > OperatorPrecedence.EqualityOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings,
                                           OperatorPrecedence.EqualityOperatorPrecedence)
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " == "))
                self.perform_get_expr_text(instr.right, tokens, settings,
                                           OperatorPrecedence.EqualityOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_CMP_NE, HighLevelILOperation.HLIL_FCMP_NE]:
                parens = precedence > OperatorPrecedence.EqualityOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings,
                                           OperatorPrecedence.EqualityOperatorPrecedence)
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " != "))
                self.perform_get_expr_text(instr.right, tokens, settings,
                                           OperatorPrecedence.EqualityOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_CMP_SLT, HighLevelILOperation.HLIL_CMP_ULT,
                                     HighLevelILOperation.HLIL_FCMP_LT]:
                parens = precedence > OperatorPrecedence.CompareOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings,
                                           OperatorPrecedence.CompareOperatorPrecedence)
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " < "))
                self.perform_get_expr_text(instr.right, tokens, settings,
                                           OperatorPrecedence.CompareOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_CMP_SLE, HighLevelILOperation.HLIL_CMP_ULE,
                                     HighLevelILOperation.HLIL_FCMP_LE]:
                parens = precedence > OperatorPrecedence.CompareOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings,
                                           OperatorPrecedence.CompareOperatorPrecedence)
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " <= "))
                self.perform_get_expr_text(instr.right, tokens, settings,
                                           OperatorPrecedence.CompareOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_CMP_SGE, HighLevelILOperation.HLIL_CMP_UGE,
                                     HighLevelILOperation.HLIL_FCMP_GE]:
                parens = precedence > OperatorPrecedence.CompareOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings,
                                           OperatorPrecedence.CompareOperatorPrecedence)
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " >= "))
                self.perform_get_expr_text(instr.right, tokens, settings,
                                           OperatorPrecedence.CompareOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_CMP_SGT, HighLevelILOperation.HLIL_CMP_UGT,
                                     HighLevelILOperation.HLIL_FCMP_GT]:
                parens = precedence > OperatorPrecedence.CompareOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings,
                                           OperatorPrecedence.CompareOperatorPrecedence)
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, " > "))
                self.perform_get_expr_text(instr.right, tokens, settings,
                                           OperatorPrecedence.CompareOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_AND:
                if instr.size == 0:
                    # Size of zero is a boolean operation, show the boolean operator name
                    parens = (precedence >= OperatorPrecedence.BitwiseOrOperatorPrecedence or
                              precedence == OperatorPrecedence.LogicalOrOperatorPrecedence)
                    operation = "and"
                    precedence = OperatorPrecedence.LogicalAndOperatorPrecedence
                else:
                    parens = (precedence >= OperatorPrecedence.EqualityOperatorPrecedence or
                              precedence in [OperatorPrecedence.BitwiseOrOperatorPrecedence,
                                             OperatorPrecedence.BitwiseXorOperatorPrecedence])
                    operation = "&"
                    precedence = OperatorPrecedence.BitwiseAndOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens(operation, instr, tokens, settings, precedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_OR:
                if instr.size == 0:
                    # Size of zero is a boolean operation, show the boolean operator name
                    parens = (precedence >= OperatorPrecedence.BitwiseOrOperatorPrecedence or
                              precedence == OperatorPrecedence.LogicalAndOperatorPrecedence)
                    operation = "or"
                    precedence = OperatorPrecedence.LogicalOrOperatorPrecedence
                else:
                    parens = (precedence >= OperatorPrecedence.EqualityOperatorPrecedence or
                              precedence in [OperatorPrecedence.BitwiseAndOperatorPrecedence,
                                             OperatorPrecedence.BitwiseXorOperatorPrecedence])
                    operation = "|"
                    precedence = OperatorPrecedence.BitwiseOrOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens(operation, instr, tokens, settings, precedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_XOR:
                parens = (precedence >= OperatorPrecedence.EqualityOperatorPrecedence or
                          precedence in [OperatorPrecedence.BitwiseAndOperatorPrecedence,
                                         OperatorPrecedence.BitwiseOrOperatorPrecedence])
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens("^", instr, tokens, settings,
                                               OperatorPrecedence.BitwiseXorOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_ADC:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "adc"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.right, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.carry, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_SBB:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "sbb"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.right, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.carry, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_ADD_OVERFLOW:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "add_overflow"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.right, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_ADD, HighLevelILOperation.HLIL_FADD]:
                parens = (precedence > OperatorPrecedence.AddOperatorPrecedence or
                          precedence in [OperatorPrecedence.ShiftOperatorPrecedence,
                                         OperatorPrecedence.BitwiseAndOperatorPrecedence,
                                         OperatorPrecedence.BitwiseOrOperatorPrecedence,
                                         OperatorPrecedence.BitwiseXorOperatorPrecedence])
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens("+", instr, tokens, settings,
                                               OperatorPrecedence.AddOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_SUB, HighLevelILOperation.HLIL_FSUB]:
                parens = (precedence > OperatorPrecedence.AddOperatorPrecedence or
                          precedence in [OperatorPrecedence.ShiftOperatorPrecedence,
                                         OperatorPrecedence.BitwiseAndOperatorPrecedence,
                                         OperatorPrecedence.BitwiseOrOperatorPrecedence,
                                         OperatorPrecedence.BitwiseXorOperatorPrecedence])
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens("-", instr, tokens, settings,
                                               OperatorPrecedence.SubOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_MUL, HighLevelILOperation.HLIL_MULS_DP,
                                     HighLevelILOperation.HLIL_MULU_DP, HighLevelILOperation.HLIL_FMUL]:
                parens = (precedence > OperatorPrecedence.MultiplyOperatorPrecedence or
                          precedence in [OperatorPrecedence.ShiftOperatorPrecedence,
                                         OperatorPrecedence.BitwiseAndOperatorPrecedence,
                                         OperatorPrecedence.BitwiseOrOperatorPrecedence,
                                         OperatorPrecedence.BitwiseXorOperatorPrecedence])
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens("*", instr, tokens, settings,
                                               OperatorPrecedence.MultiplyOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_DIVS, HighLevelILOperation.HLIL_DIVU,
                                     HighLevelILOperation.HLIL_DIVS_DP, HighLevelILOperation.HLIL_DIVU_DP]:
                parens = (precedence > OperatorPrecedence.DivideOperatorPrecedence or
                          precedence in [OperatorPrecedence.ShiftOperatorPrecedence,
                                         OperatorPrecedence.BitwiseAndOperatorPrecedence,
                                         OperatorPrecedence.BitwiseOrOperatorPrecedence,
                                         OperatorPrecedence.BitwiseXorOperatorPrecedence])
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens("//", instr, tokens, settings,
                                               OperatorPrecedence.DivideOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_MODS, HighLevelILOperation.HLIL_MODU,
                                     HighLevelILOperation.HLIL_MODS_DP, HighLevelILOperation.HLIL_MODU_DP]:
                parens = (precedence > OperatorPrecedence.DivideOperatorPrecedence or
                          precedence in [OperatorPrecedence.ShiftOperatorPrecedence,
                                         OperatorPrecedence.BitwiseAndOperatorPrecedence,
                                         OperatorPrecedence.BitwiseOrOperatorPrecedence,
                                         OperatorPrecedence.BitwiseXorOperatorPrecedence])
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens("%", instr, tokens, settings,
                                               OperatorPrecedence.DivideOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_FDIV:
                parens = (precedence > OperatorPrecedence.DivideOperatorPrecedence or
                          precedence in [OperatorPrecedence.ShiftOperatorPrecedence,
                                         OperatorPrecedence.BitwiseAndOperatorPrecedence,
                                         OperatorPrecedence.BitwiseOrOperatorPrecedence,
                                         OperatorPrecedence.BitwiseXorOperatorPrecedence])
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens("/", instr, tokens, settings,
                                               OperatorPrecedence.DivideOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_LSL:
                parens = precedence > OperatorPrecedence.ShiftOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens("<<", instr, tokens, settings,
                                               OperatorPrecedence.ShiftOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_LSR, HighLevelILOperation.HLIL_ASR]:
                parens = precedence > OperatorPrecedence.ShiftOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.append_two_operand_tokens(">>", instr, tokens, settings,
                                               OperatorPrecedence.ShiftOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_ROL:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "rol"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.right, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_ROR:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "ror"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.right, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_RLC:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "rlc"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.right, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.carry, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_RRC:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "rrc"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.right, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.carry, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_TEST_BIT:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "test_bit"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.right, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_FLOOR:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "floor"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.src, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_CEIL:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "ceil"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.src, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_FTRUNC:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "trunc"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.src, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_FABS:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "fabs"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.src, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_FSQRT:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "sqrt"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.src, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_ROUND_TO_INT:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "round"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.src, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_FCMP_O:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "fcmp_o"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.right, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_FCMP_UO:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "fcmp_uo"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.left, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.right, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_NOT:
                parens = precedence > OperatorPrecedence.UnaryOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                if instr.size == 0:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "not "))
                else:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "~"))
                self.perform_get_expr_text(instr.src, tokens, settings,
                                           OperatorPrecedence.UnaryOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_NEG, HighLevelILOperation.HLIL_FNEG]:
                parens = precedence > OperatorPrecedence.UnaryOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "-"))
                self.perform_get_expr_text(instr.src, tokens, settings,
                                           OperatorPrecedence.UnaryOperatorPrecedence)
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_FLOAT_CONV, HighLevelILOperation.HLIL_INT_TO_FLOAT]:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "float"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.src, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_FLOAT_TO_INT, HighLevelILOperation.HLIL_BOOL_TO_INT]:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "int"))
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.src, tokens, settings)
                tokens.append_close_paren()
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_RET:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "return"))
                operands = instr.src
                if len(operands) > 0:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " "))
                if len(operands) > 1:
                    tokens.append_open_paren()
                for (i, operand) in enumerate(operands):
                    if i > 0:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                    self.perform_get_expr_text(operand, tokens, settings)
                if len(operands) > 1:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_NORET:
                tokens.append(InstructionTextToken(InstructionTextTokenType.AnnotationToken, "# no return"))
            elif instr.operation == HighLevelILOperation.HLIL_UNREACHABLE:
                tokens.append(InstructionTextToken(InstructionTextTokenType.AnnotationToken, "# unreachable"))
            elif instr.operation == HighLevelILOperation.HLIL_UNDEF:
                tokens.append(InstructionTextToken(InstructionTextTokenType.AnnotationToken, "# undefined"))
            elif instr.operation == HighLevelILOperation.HLIL_NOP:
                tokens.append(InstructionTextToken(InstructionTextTokenType.AnnotationToken, "# nop"))
            elif instr.operation == HighLevelILOperation.HLIL_BP:
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "breakpoint"))
                tokens.append_open_paren()
                tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_JUMP:
                tokens.append(InstructionTextToken(InstructionTextTokenType.AnnotationToken, "# jump -> "))
                self.perform_get_expr_text(instr.dest, tokens, settings)
            elif instr.operation == HighLevelILOperation.HLIL_TRAP:
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "trap"))
                tokens.append_open_paren()
                tokens.append_integer_text_token(instr, instr.vector, 8)
                tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_GOTO:
                tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "goto "))
                tokens.append(InstructionTextToken(InstructionTextTokenType.GotoLabelToken, instr.target.name,
                                                   instr.target.label_id))
            elif instr.operation == HighLevelILOperation.HLIL_LABEL:
                tokens.decrease_indent()
                tokens.append(InstructionTextToken(InstructionTextTokenType.GotoLabelToken, instr.target.name,
                                                   instr.target.label_id))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ":"))
                tokens.increase_indent()
            elif instr.operation == HighLevelILOperation.HLIL_LOW_PART:
                parens = precedence > OperatorPrecedence.MemberAndFunctionOperatorPrecedence
                if parens:
                    tokens.append_open_paren()
                self.perform_get_expr_text(instr.src, tokens, settings)
                suffix = {0: "", 1: ".b", 2: ".w", 4: ".d", 8: ".q", 10: ".t", 16: ".q"}
                if instr.size in suffix:
                    suffix_str = suffix[instr.size]
                else:
                    suffix_str = f".{instr.size}"
                tokens.append(InstructionTextToken(InstructionTextTokenType.StructOffsetToken, suffix_str, value=0,
                                                   size=instr.size))
                if parens:
                    tokens.append_close_paren()
            elif instr.operation == HighLevelILOperation.HLIL_SPLIT:
                tokens.append_open_paren()
                self.perform_get_expr_text(instr.high, tokens, settings)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                self.perform_get_expr_text(instr.low, tokens, settings)
                tokens.append_close_paren()
            elif instr.operation in [HighLevelILOperation.HLIL_UNIMPL, HighLevelILOperation.HLIL_UNIMPL_MEM]:
                tokens.append(InstructionTextToken(InstructionTextTokenType.AnnotationToken, "# "))
                for token in instr.tokens:
                    token.token_type = InstructionTextTokenType.AnnotationToken
                    tokens.append(token)
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.AnnotationToken,
                                                   f"# unimplemented {instr.operation.name}"))

    def append_two_operand_tokens(self, operation: str, instr: HighLevelILInstruction, tokens: HighLevelILTokenEmitter,
                                  settings: Optional[DisassemblySettings], precedence: OperatorPrecedence):
        if precedence == OperatorPrecedence.SubOperatorPrecedence:
            # Treat left side of subtraction as same level as addition. This lets
            # (a - b) - c be represented as a - b - c, but a - (b - c) does not
            # simplify at rendering
            left_precedence = OperatorPrecedence.AddOperatorPrecedence
        elif precedence == OperatorPrecedence.DivideOperatorPrecedence:
            # Treat left side of divison as same level as multiplication. This lets
            # (a / b) / c be represented as a / b / c, but a / (b / c) does not
            # simplify at rendering
            left_precedence = OperatorPrecedence.MultiplyOperatorPrecedence
        else:
            left_precedence = precedence

        self.perform_get_expr_text(instr.left, tokens, settings, left_precedence)
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, f" {operation} "))
        self.perform_get_expr_text(instr.right, tokens, settings, precedence)

    def append_field_text_tokens(self, var: HighLevelILInstruction, offset: int, member_index: int, size: int,
                                 tokens: HighLevelILTokenEmitter):
        var_type = var.expr_type
        # Follow pointer type to its target
        if isinstance(var_type, PointerType):
            var_type = var_type.target
        # Follow named type references to the target
        if isinstance(var_type, NamedTypeReferenceType):
            target_type = var_type.target(var.function.view)
            if target_type is not None:
                var_type = target_type

        has_field = False
        if isinstance(var_type, StructureType):
            # For structures, resolve field names using the type API
            class Resolver:
                def __init__(self, view: BinaryView, offset: int):
                    self.has_field = False
                    self.correct_size = False
                    self.offset = offset
                    self.view = view

                def resolve_func(self, base_name: Optional[NamedTypeReferenceType],
                                 resolved_struct: Optional[StructureType], resolved_member_index: int,
                                 struct_offset: int, adjusted_offset: int, member: StructureMember):
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperationToken, "."))
                    name_list = HighLevelILTokenEmitter.names_for_outer_structure_members(
                        self.view, var_type, var) + [member.name]
                    tokens.append(InstructionTextToken(InstructionTextTokenType.FieldNameToken, member.name,
                                                       value=struct_offset + member.offset, typeNames=name_list))
                    self.offset = adjusted_offset - member.offset
                    self.has_field = True
                    self.correct_size = member.type is not None and size == member.type.width

            resolver = Resolver(self.function.view, offset)
            result = var_type.resolve_member_or_base_member(resolver.view, offset, 0, resolver.resolve_func)
            if result and resolver.has_field and resolver.correct_size:
                # If the field was matched, we're done
                return
            has_field = resolver.has_field
            offset = resolver.offset

        # Generate offset syntax for the missing field
        suffix = {0: "", 1: ".b", 2: ".w", 4: ".d", 8: ".q", 10: ".t", 16: ".q"}
        if size in suffix:
            suffix_str = suffix[size]
        else:
            suffix_str = f".{size}"
        if (has_field or not isinstance(var_type, StructureType)) and offset == 0:
            # No offset, just display a size suffix
            offset_str = suffix_str
        else:
            # Has an offset
            offset_str = f".__offset({offset:#x}){suffix_str}"

        name_list = HighLevelILTokenEmitter.names_for_outer_structure_members(
            self.function.view, var_type, var) + [offset_str]
        tokens.append(InstructionTextToken(InstructionTextTokenType.StructOffsetToken, offset_str, value=offset,
                                           size=size, typeNames=name_list))


class PseudoPythonFunctionType(LanguageRepresentationFunctionType):
    language_name = "Pseudo Python"

    def create(self, arch: Architecture, owner: Function, hlil: HighLevelILFunction):
        return PseudoPythonFunction(self, arch, owner, hlil)

    def function_type_tokens(self, func: Function, settings: DisassemblySettings) -> DisassemblyTextLine:
        tokens = []
        tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken, "def "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.CodeSymbolToken, func.name, value=func.start))
        tokens.append(InstructionTextToken(InstructionTextTokenType.BraceToken, "("))
        for (i, param) in enumerate(func.type.parameters_with_all_locations):
            if i > 0:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
            tokens.append(InstructionTextToken(InstructionTextTokenType.ArgumentNameToken, param.name,
                                               context=InstructionTextTokenContext.LocalVariableTokenContext,
                                               address=param.location.identifier))
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ": "))
            for token in param.type.get_tokens():
                token.context = InstructionTextTokenContext.LocalVariableTokenContext
                token.address = param.location.identifier
                tokens.append(token)
        tokens.append(InstructionTextToken(InstructionTextTokenType.BraceToken, ")"))
        if func.can_return.value and func.type.return_value is not None and not isinstance(func.type.return_value, VoidType):
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " -> "))
            for token in func.type.return_value.get_tokens():
                token.context = InstructionTextTokenContext.FunctionReturnTokenContext
                tokens.append(token)
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ":"))
        return [DisassemblyTextLine(tokens, func.start)]


PseudoPythonFunctionType().register()
