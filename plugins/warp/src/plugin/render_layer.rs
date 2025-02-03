use crate::{is_blacklisted_instruction, is_variant_instruction, relocatable_regions};
use binaryninja::basic_block::BasicBlock;
use binaryninja::disassembly::DisassemblyTextLine;
use binaryninja::function::{HighlightColor, HighlightStandardColor, NativeBlock};
use binaryninja::low_level_il::instruction::LowLevelInstructionIndex;
use binaryninja::render_layer::{register_render_layer, RenderLayer};

pub struct HighlightRenderLayer {}

impl HighlightRenderLayer {
    pub fn register() {
        register_render_layer(
            "WARP Highlight Layer",
            HighlightRenderLayer {},
            Default::default(),
        );
    }
}

impl RenderLayer for HighlightRenderLayer {
    fn apply_to_llil_block(
        &self,
        block: &BasicBlock<NativeBlock>,
        mut lines: Vec<DisassemblyTextLine>,
    ) -> Vec<DisassemblyTextLine> {
        // Highlight any LLIL instruction that will be masked by WARP.
        let function = block.function();
        // TODO: We might need to make relocatable regions configurable.
        let relocatable_regions = relocatable_regions(&function.view());
        let Ok(llil) = function.low_level_il() else {
            // Don't even think this is possible but _shrug_.
            return lines;
        };

        for line in &mut lines {
            let llil_instr_idx = LowLevelInstructionIndex(line.instruction_index);
            if let Some(llil_instr) = llil.instruction_from_index(llil_instr_idx) {
                if is_blacklisted_instruction(&llil_instr) {
                    // We have a blacklisted instruction, highlight it as orange!
                    line.highlight = HighlightColor::StandardHighlightColor {
                        color: HighlightStandardColor::OrangeHighlightColor,
                        alpha: 155,
                    };
                } else if is_variant_instruction(&relocatable_regions, &llil_instr) {
                    // We have a variant instruction, highlight it as red!
                    line.highlight = HighlightColor::StandardHighlightColor {
                        color: HighlightStandardColor::RedHighlightColor,
                        alpha: 155,
                    };
                }
            }
        }

        lines
    }
}
