import json
from binaryninja import Workflow, Activity, AnalysisContext
from binaryninja.lowlevelil import *


def rewrite_action(context: AnalysisContext):
    def translate_instr(
            new_func: LowLevelILFunction,
            old_block: LowLevelILBasicBlock,
            old_instr: LowLevelILInstruction
    ) -> ExpressionIndex:
        """
        Copy and translate ``old_instr`` in ``old_block`` into ``new_func``

        :param new_func: new function to receive translated instructions
        :param old_block: original block containing old_instr
        :param old_instr: original instruction
        :return: expression index of newly created instruction in ``new_func``
        """

        if old_instr.operation == LowLevelILOperation.LLIL_PUSH:
            # push(x)
            # -----------------------
            # sp = sp - sizeof(void*)
            # *(sp) = x

            old_instr: LowLevelILPush
            # sp = sp - sizeof(void*)
            new_func.append(
                new_func.set_reg(
                    old_instr.size,
                    old_block.arch.stack_pointer,
                    new_func.sub(
                        old_instr.size,
                        new_func.reg(
                            old_instr.size,
                            old_block.arch.stack_pointer,
                            loc=ILSourceLocation.from_instruction(old_instr)
                        ),
                        new_func.const(
                            old_instr.size,
                            old_block.arch.address_size,
                            loc=ILSourceLocation.from_instruction(old_instr)
                        ),
                        loc=ILSourceLocation.from_instruction(old_instr)
                    ),
                    loc=ILSourceLocation.from_instruction(old_instr)
                )
            )
            # *(sp) = x
            return new_func.store(
                old_instr.size,
                new_func.reg(
                    old_instr.size,
                    old_block.arch.stack_pointer,
                    loc=ILSourceLocation.from_instruction(old_instr)
                ),
                old_instr.src.copy_to(new_func),
                loc=ILSourceLocation.from_instruction(old_instr)
            )
        elif old_instr.operation == LowLevelILOperation.LLIL_POP:
            # pop
            # -----------------------
            # sp = sp + sizeof(void*)
            # *(sp - sizeof(void*))

            # We need to append any helper instructions first and then return an expression
            # that replaces the ``pop`` in the original IL (since ``pop`` has a value).
            # So anything that is ``rax = pop`` becomes ``sp = sp + 8 ; rax = *(sp - 8)``

            old_instr: LowLevelILPop
            # sp = sp + sizeof(void*)
            new_func.append(
                new_func.set_reg(
                    old_instr.size,
                    old_block.arch.stack_pointer,
                    new_func.add(
                        old_instr.size,
                        new_func.reg(
                            old_instr.size,
                            old_block.arch.stack_pointer,
                            loc=ILSourceLocation.from_instruction(old_instr)
                        ),
                        new_func.const(
                            old_instr.size,
                            old_block.arch.address_size,
                            loc=ILSourceLocation.from_instruction(old_instr)
                        ),
                        loc=ILSourceLocation.from_instruction(old_instr)
                    ),
                    loc=ILSourceLocation.from_instruction(old_instr)
                )
            )
            # *(sp - sizeof(void*))
            return new_func.load(
                old_instr.size,
                new_func.sub(
                    old_instr.size,
                    new_func.reg(
                        old_instr.size,
                        old_block.arch.stack_pointer,
                        loc=ILSourceLocation.from_instruction(old_instr)
                    ),
                    new_func.const(
                        old_instr.size,
                        old_block.arch.address_size,
                        loc=ILSourceLocation.from_instruction(old_instr)
                    ),
                    loc=ILSourceLocation.from_instruction(old_instr)
                ),
                loc=ILSourceLocation.from_instruction(old_instr)
            )
        else:
            # All other instructions: copy as-is
            return old_instr.copy_to(
                new_func,
                lambda sub_instr: translate_instr(new_func, old_block, sub_instr)
            )

    # Modify the existing Lifted IL function by our translator above
    translated_func = context.lifted_il.translate(translate_instr)
    # Clean up blocks and prepare this function for the rest of analysis
    translated_func.finalize()
    # Tell the analysis to use the new form of this function
    context.lifted_il = translated_func


# Create and register the workflow for translating these instructions
wf = Workflow("core.function.metaAnalysis").clone("RewritePushPop")

# Define the custom activity configuration
wf.register_activity(Activity(
    configuration=json.dumps({
        "name": "extension.rewrite_push_pop.rewrite_action",
        "title": "Rewrite LLIL_PUSH/LLIL_POP",
        "description": "Rewrites LLIL_PUSH/LLIL_POP instructions into their component store/load/register parts, demonstrating modifying and inserting Lifted IL instructions.",
        "eligibility": {
            "auto": {
                "default": True
            }
        }
    }),
    action=rewrite_action
))

# This action is run right after generateLiftedIL so we can poke the IL before LLIL flag and stack
# adjustment resolution happens.
wf.insert_after("core.function.generateLiftedIL", ["extension.rewrite_push_pop.rewrite_action"])
wf.register()
