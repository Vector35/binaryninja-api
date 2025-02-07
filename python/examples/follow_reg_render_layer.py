from typing import List

from PySide6.QtCore import QSettings
from binaryninja import DisassemblyTextLine, LowLevelILOperation, DisassemblyTextRenderer, \
    MediumLevelILOperation, \
    RenderLayer, BasicBlock, InstructionTextTokenType, RenderLayerDefaultEnableState, \
    PluginCommand, BinaryView, interaction, InstructionTextToken, RegisterValueType


"""
Render layer that adds annotations to follow the value of a register, for Disasm/LLIL.
- Adds "<reg> after: <value>" comments to every line that modifies your register
- Adds "<reg> at block entry: <value>" comments to every block
- Adds "<reg> at block exit: <value>" comments to every block
You can switch registers with the plugin command "Set Followed Register"
"""


class FollowRegRenderLayer(RenderLayer):
    name = "Follow Register"
    default_enable_state = RenderLayerDefaultEnableState.EnabledByDefaultRenderLayerDefaultEnableState

    def __init__(self, handle=None):
        super().__init__(handle)
        self.followed_reg = QSettings().value("layer/followed_reg", None)

    def apply_to_lines(
            self,
            block: BasicBlock,
            lines: List['DisassemblyTextLine'],
    ):
        if self.followed_reg is None:
            return lines
        if self.followed_reg not in block.arch.regs:
            return lines

        func = block.function
        arch = block.arch

        # Give our tokens a unique value so they don't highlight all the other comments
        token_value = arch.get_reg_index(self.followed_reg) ^ 0x12345678

        # ===============================================================================
        # Render the "<reg> after" comments

        for i, line in enumerate(lines):
            # Ignore non-disassembly lines
            if not any(token.type == InstructionTextTokenType.AddressSeparatorToken for token in line.tokens):
                continue

            # If the register has changed, we should render the update
            written = False
            for w in func.get_regs_written_by(line.address, arch):
                # In case this instruction only modifies a sub register of our target
                # Or in the case that we wanted to follow a sub register
                if arch.regs[w].full_width_reg == arch.regs[self.followed_reg].full_width_reg:
                    written = True
                    break

            if written:
                # Add comment tokens to existing line
                line.tokens.extend([
                    InstructionTextToken(InstructionTextTokenType.CommentToken, '  // ', token_value),
                    InstructionTextToken(InstructionTextTokenType.CommentToken, self.followed_reg, token_value),
                    InstructionTextToken(InstructionTextTokenType.CommentToken, ' after: ', token_value),
                ])

                after = func.get_reg_value_after(line.address, self.followed_reg, arch)
                if after.type == RegisterValueType.UndeterminedValue:
                    if line.il_instruction is not None:
                        instr = line.il_instruction
                    else:
                        instr_start = func.low_level_il.get_instruction_start(line.address, arch)
                        instr = func.low_level_il[instr_start]
                    if instr is not None:
                        after_possible = instr.get_possible_reg_values_after(self.followed_reg)
                        line.tokens.append(
                            InstructionTextToken(InstructionTextTokenType.CommentToken, str(after_possible), token_value)
                        )
                    else:
                        line.tokens.append(
                            InstructionTextToken(InstructionTextTokenType.CommentToken, str(after), token_value)
                        )
                else:
                    line.tokens.append(
                        InstructionTextToken(InstructionTextTokenType.CommentToken, str(after), token_value)
                    )

        block_start = block.start
        block_end = block.end
        if block.is_low_level_il:
            block_start = func.llil[block.start].address
            block_end = func.llil[block.end - 1].address

        # ===============================================================================
        # Render the before-block "<reg> at block entry" comment

        start_before = func.get_reg_value_at(block_start, self.followed_reg, arch)
        line = [
            InstructionTextToken(InstructionTextTokenType.CommentToken, '// ', token_value),
            InstructionTextToken(InstructionTextTokenType.CommentToken, self.followed_reg, token_value),
            InstructionTextToken(InstructionTextTokenType.CommentToken, ' at block entry: ', token_value),
        ]

        # Sometimes the first line is blank and we want to insert after it
        first_line = 0
        if len(lines[0].tokens) == 0:
            first_line = 1
        if start_before.type == RegisterValueType.UndeterminedValue:
            if lines[first_line].il_instruction is not None:
                instr = lines[first_line].il_instruction
            else:
                instr_start = func.low_level_il.get_instruction_start(block_start, arch)
                instr = func.low_level_il[instr_start]
            if instr is not None:
                start_before_possible = instr.get_possible_reg_values(self.followed_reg)
                line.append(
                    InstructionTextToken(InstructionTextTokenType.CommentToken, str(start_before_possible), token_value)
                )
            else:
                line.append(
                    InstructionTextToken(InstructionTextTokenType.CommentToken, str(start_before), token_value)
                )
        else:
            line.append(
                InstructionTextToken(InstructionTextTokenType.CommentToken, str(start_before), token_value)
            )

        lines.insert(first_line, DisassemblyTextLine(line, block_start))

        # ===============================================================================
        # Render the after-block "<reg> at block exit" comment

        end_after = func.get_reg_value_after(block_end, self.followed_reg, arch)
        line = [
            InstructionTextToken(InstructionTextTokenType.CommentToken, '// ', token_value),
            InstructionTextToken(InstructionTextTokenType.CommentToken, self.followed_reg, token_value),
            InstructionTextToken(InstructionTextTokenType.CommentToken, ' at block exit: ', token_value),
        ]

        # Sometimes the last line is blank and we want to insert before it
        if len(lines) > 1 and len(lines[-1].tokens) == 0:
            last_line = len(lines) - 1
        else:
            last_line = len(lines)
        if end_after.type == RegisterValueType.UndeterminedValue:
            if lines[last_line - 1].il_instruction is not None:
                instr = lines[last_line - 1].il_instruction
            else:
                instr_start = func.low_level_il.get_instruction_start(block_end, arch)
                instr = func.low_level_il[instr_start]
            if instr is not None:
                end_after_possible = instr.get_possible_reg_values_after(self.followed_reg)
                line.append(
                    InstructionTextToken(InstructionTextTokenType.CommentToken, str(end_after_possible), token_value)
                )
            else:
                line.append(
                    InstructionTextToken(InstructionTextTokenType.CommentToken, str(end_after), token_value)
                )
        else:
            line.append(
                InstructionTextToken(InstructionTextTokenType.CommentToken, str(end_after), token_value)
            )

        lines.insert(last_line, DisassemblyTextLine(line, block_end))

        return lines

    def apply_to_disassembly_block(
            self,
            block: BasicBlock,
            lines: List['DisassemblyTextLine']
    ):
        # Break this out into a helper so we don't have to write it twice
        return self.apply_to_lines(block, lines)

    def apply_to_low_level_il_block(
            self,
            block: BasicBlock,
            lines: List['DisassemblyTextLine']
    ):
        # Break this out into a helper so we don't have to write it twice
        return self.apply_to_lines(block, lines)


def set_follow_reg(bv: BinaryView):
    if bv.platform is not None:
        regs = list(bv.platform.arch.regs.keys())
        idx = interaction.get_large_choice_input("Choose", "Choose Followed Register", regs)

        # Save choice both in QSettings and on the RenderLayer object instance
        layer = RenderLayer[FollowRegRenderLayer.name]
        if idx is None:
            layer.followed_reg = None
            QSettings().remove("layer/followed_reg")
        else:
            layer.followed_reg = regs[idx]
            QSettings().setValue("layer/followed_reg", regs[idx])

    # Trigger view refresh (gross)
    for func in bv.get_functions_containing(bv.offset):
        func.reanalyze()


FollowRegRenderLayer.register()

# Using a command for this is kinda janky but currently the only option
PluginCommand.register("Set Followed Register", "Choose which register to follow for the Follow Register Render Layer", set_follow_reg)
