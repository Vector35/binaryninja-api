use crate::{
    is_blacklisted_instruction, is_computed_variant_instruction, is_variant_instruction,
    relocatable_regions,
};
use binaryninja::basic_block::BasicBlock;
use binaryninja::disassembly::DisassemblyTextLine;
use binaryninja::flowgraph::FlowGraph;
use binaryninja::function::{HighlightColor, HighlightStandardColor, NativeBlock};
use binaryninja::low_level_il::LowLevelILRegularFunction;
use binaryninja::render_layer::{register_render_layer, RenderLayer};

// TODO: Add a render layer to show basic block GUID's?
// TODO: Add a render layer to show constraints for current function?

pub struct HighlightRenderLayer {
    blacklist: HighlightColor,
    variant: HighlightColor,
    computed_variant: HighlightColor,
}

impl HighlightRenderLayer {
    pub fn register() {
        register_render_layer(
            "WARP Highlight Layer",
            // TODO: Make the highlight colors configurable.
            HighlightRenderLayer {
                blacklist: HighlightColor::StandardHighlightColor {
                    color: HighlightStandardColor::BlackHighlightColor,
                    alpha: 155,
                },
                variant: HighlightColor::StandardHighlightColor {
                    color: HighlightStandardColor::RedHighlightColor,
                    alpha: 155,
                },
                computed_variant: HighlightColor::StandardHighlightColor {
                    color: HighlightStandardColor::OrangeHighlightColor,
                    alpha: 155,
                },
            },
            Default::default(),
        );
    }

    /// Highlights the lines that are variant or blacklisted.
    pub fn highlight_lines(
        &self,
        lifted_il: &LowLevelILRegularFunction,
        llil: &LowLevelILRegularFunction,
        lines: &mut [DisassemblyTextLine],
    ) {
        let relocatable_regions = relocatable_regions(&lifted_il.function().view());
        for line in lines {
            // We use address here instead of index since it's more reliable for other IL's.
            if let Some(lifted_il_instr) = lifted_il.instruction_at(line.address) {
                if is_blacklisted_instruction(&lifted_il_instr) {
                    line.highlight = self.blacklist;
                } else if is_variant_instruction(&relocatable_regions, &lifted_il_instr) {
                    line.highlight = self.variant;
                }
            }

            if let Some(llil_instr) = llil.instruction_at(line.address) {
                if is_computed_variant_instruction(&relocatable_regions, &llil_instr) {
                    line.highlight = self.computed_variant;
                }
            }
        }
    }
}

impl RenderLayer for HighlightRenderLayer {
    fn apply_to_flow_graph(&self, graph: &mut FlowGraph) {
        if let (Some(lifted_il), Some(llil)) = (graph.lifted_il(), graph.low_level_il()) {
            for node in &graph.nodes() {
                let mut new_lines = node.lines().to_vec();
                self.highlight_lines(&lifted_il, &llil, &mut new_lines);
                node.set_lines(new_lines);
            }
        }
    }

    fn apply_to_block(
        &self,
        block: &BasicBlock<NativeBlock>,
        mut lines: Vec<DisassemblyTextLine>,
    ) -> Vec<DisassemblyTextLine> {
        // Highlight any instruction that WARP will mask.
        let function = block.function();
        if let (Ok(lifted_il), Ok(llil)) = (function.lifted_il(), function.low_level_il()) {
            self.highlight_lines(&lifted_il, &llil, &mut lines);
        }
        lines
    }
}
