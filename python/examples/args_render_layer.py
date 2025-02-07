import functools
from typing import List, Mapping, Tuple, Iterator

from binaryninja import DisassemblyTextLine, LowLevelILInstruction, LowLevelILOperation, \
    TypeClass, DisassemblyTextRenderer, MediumLevelILFunction, \
    MediumLevelILCallSsa, MediumLevelILVarSsa, MediumLevelILConstBase, \
    MediumLevelILInstruction, MediumLevelILTailcallSsa, MediumLevelILOperation, \
    MediumLevelILVarPhi, log_debug, RenderLayer, BasicBlock, InstructionTextTokenType, \
    RenderLayerDefaultEnableState

"""
Render Layer that shows you where the arguments to calls are set, for Disasm/LLIL.
- Adds "Argument '<arg>' for call at <callsite>" comments to lines that set up call args
- Adds "Call at <callsite>" comments to the call sites

=========================================================================================

But how do you determine the argument to a call?
What seems like it has worked:
- You can't determine that an instruction is a parameter, you have to go from the call to its parameters
- Since trying to look up the call for an instruction is impossible, instead go through every call at once for a function (and memoize it)
- LLIL is useless for looking this up, since it has no types and the call parameters often include a list of every register
- Using MLIL, we can find all of the parameters as MLIL instructions, but we need to map them to LLIL so we can use them in the LLIL/Disasm display
- How do we map them? Turns out that's rather inconvenient:
  - Register arguments are generally pretty easy because they are just MLIL vars
  - Stack arguments somehow also work out generally, the .llil on the MLIL points to the push()
  - Constants are a mess and I just use the MLIL's address (this is often incorrect)
  - Flags are completely unhandled for now
  - Phis are handled by just looking up every var they use... probably not proper but sort of works
- This fails in a couple of scenarios though, notably __builtin_xxxxxx() functions
  - Which instruction specifies the length of a group of `mov qword [rbx+8], rax {0}` calls? I think it just picks one?
  - The `rep` instructions could actually have these params resolved (they use real registers) but in practice this doesn't work
  - Thunks are unhandled
"""


@functools.lru_cache(maxsize=64)
def get_param_sites(mlil: MediumLevelILFunction) -> Mapping[LowLevelILInstruction, List[Tuple[MediumLevelILInstruction, int]]]:
    """
    For a given function, find all LLIL instructions that are parameters to a call,
    and return a mapping for each instruction with all the calls that it maps to,
    their corresponding MLIL call instruction, and which numbered parameter they are
    in the call.

    :param mlil: MLIL function to search
    :return: Map of param sites as described above
    """
    call_sites = {}
    mlil = mlil.ssa_form

    # As a function to handle call and tailcall identically
    def collect_call_params(call_site, dest, params):
        def_sites = []
        for i, param in enumerate(params):
            llil = param.llil
            if llil is not None:
                def_sites.append((param, llil))
                continue

            match param:
                case MediumLevelILVarSsa(src=var_src):
                    def_site = mlil.get_ssa_var_definition(var_src)
                    if def_site is not None and def_site.llil is not None:
                        def_sites.append((i, def_site.llil))
                        continue
                    # Handle phis by just looking up the def sites of all their sources
                    match def_site:
                        case MediumLevelILVarPhi(src=phis):
                            for phi in phis:
                                phi_def = mlil.get_ssa_var_definition(phi)
                                if phi_def is not None and phi_def.llil is not None:
                                    def_sites.append((i, phi_def.llil))
                case MediumLevelILConstBase():
                    # This is wrong, but it works (sometimes)
                    # Oh god, have I just quoted php.net
                    def_site_idx = mlil.llil.get_instruction_start(param.address)
                    if def_site_idx is not None:
                        def_sites.append((i, mlil.llil[def_site_idx].ssa_form))
                        continue

            if len(def_sites) == 0:
                log_debug(f"Could not find def site for param {i} in call at {call_site.address:#x}")

        call_sites[call_site] = def_sites

    for instr in mlil.instructions:
        match instr:
            case MediumLevelILCallSsa(dest=dest, params=params) as call_site:
                collect_call_params(call_site, dest, params)
            case MediumLevelILTailcallSsa(dest=dest, params=params) as call_site:
                collect_call_params(call_site, dest, params)

    # Inverse args
    all_def_sites = {}
    for call_site, params in call_sites.items():
        for (param_idx, llil) in params:
            if llil not in all_def_sites:
                all_def_sites[llil] = []
            else:
                print(f"got two at {llil.instr_index} @ {llil.address:#x} -> {call_site.address:#x}")
            all_def_sites[llil].append((call_site, param_idx))

    return all_def_sites


def get_llil_arg(llil: LowLevelILInstruction) -> Iterator[Tuple[str, MediumLevelILInstruction]]:
    args = get_param_sites(llil.function.mlil)

    if llil.ssa_form in args:
        for call_site, param_idx in args[llil.ssa_form]:
            target_type = call_site.function.get_expr_type(call_site.dest.expr_index)

            # Try getting the param name from the call's type
            if target_type is not None:
                if target_type.type_class == TypeClass.PointerTypeClass:
                    target_type = target_type.target
                if target_type.type_class == TypeClass.FunctionTypeClass:
                    target_params = target_type.parameters
                    if param_idx < len(target_params):
                        param_name = target_params[param_idx].name
                        if param_name == '':
                            param_name = f"arg{param_idx+1}"
                        yield param_name, call_site
                        continue

            # Some calls have extra params that aren't reflected in their type
            yield f"arg{param_idx+1}", call_site
    return


def apply_to_lines(lines, get_instr, renderer):
    # So we don't process lines twice since we're iterating over a list as we modify it
    skip_lines = []

    # Tailcalls that don't return incorrectly mark the { Does not return } line as a call
    ignore_calls = set()

    for i, line in enumerate(lines):
        if len(line.tokens) == 0:
            continue
        if i in skip_lines:
            continue

        llil_instr = get_instr(line)
        if llil_instr is not None:
            new_lines = []
            for (arg, call) in get_llil_arg(llil_instr):
                if call.operation == MediumLevelILOperation.MLIL_TAILCALL_SSA:
                    comment = f"Argument '{arg}' for tailcall at {call.address:#x}"
                else:
                    comment = f"Argument '{arg}' for call at {call.address:#x}"
                renderer.wrap_comment(new_lines, line, comment, False, "  ",  "")
                for j, token in enumerate(line.tokens):
                    if token.type == InstructionTextTokenType.AddressSeparatorToken:
                        line.tokens = line.tokens[:j]
                        break

            # Annotate calls too so we can see them easily next to their args
            if llil_instr.address == line.address and llil_instr.address not in ignore_calls:
                if llil_instr.operation in [
                    LowLevelILOperation.LLIL_CALL,
                    LowLevelILOperation.LLIL_CALL_SSA,
                    LowLevelILOperation.LLIL_TAILCALL,
                    LowLevelILOperation.LLIL_TAILCALL_SSA
                ]:
                    ignore_calls.add(llil_instr.address)
                    if llil_instr.operation in [
                        LowLevelILOperation.LLIL_TAILCALL,
                        LowLevelILOperation.LLIL_TAILCALL_SSA
                    ]:
                        comment = f"Tailcall at {llil_instr.address:#x}"
                    else:
                        comment = f"Call at {llil_instr.address:#x}"
                    # Creating comments is a bit unwieldy at the moment
                    renderer.wrap_comment(new_lines, line, comment, False, "  ", "")
                    for j, token in enumerate(line.tokens):
                        if token.type == InstructionTextTokenType.AddressSeparatorToken:
                            line.tokens = line.tokens[:j]
                            break

            # If any of our lines changed, swap out the existing lines with the new ones
            if len(new_lines) > 0:
                lines.pop(i)
                for j, new_line in enumerate(new_lines):
                    lines.insert(i + j, new_line)
                    skip_lines.append(i + j)
    return lines


class ArgumentsRenderLayer(RenderLayer):
    name = "Annotate Call Parameters"
    default_enable_state = RenderLayerDefaultEnableState.EnabledByDefaultRenderLayerDefaultEnableState

    def apply_to_disassembly_block(
            self,
            block: BasicBlock,
            lines: List['DisassemblyTextLine']
    ):
        # Break this out into a helper so we don't have to write it twice
        renderer = DisassemblyTextRenderer(block.function)
        return apply_to_lines(lines, lambda line: block.function.get_llil_at(line.address), renderer)

    def apply_to_low_level_il_block(
            self,
            block: BasicBlock,
            lines: List['DisassemblyTextLine']
    ):
        # Break this out into a helper so we don't have to write it twice
        renderer = DisassemblyTextRenderer(block.function)
        return apply_to_lines(lines, lambda line: line.il_instruction, renderer)


ArgumentsRenderLayer.register()
