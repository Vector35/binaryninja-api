//! Customize the presentation of Linear and Graph view output.

use crate::basic_block::{BasicBlock, BasicBlockType};
use crate::disassembly::DisassemblyTextLine;
use crate::flowgraph::FlowGraph;
use crate::function::{Function, NativeBlock};
use crate::linear_view::{LinearDisassemblyLine, LinearDisassemblyLineType, LinearViewObject};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::BnStrCompatible;
use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void};
use std::ptr::NonNull;

/// The state in which the [`RenderLayer`] will be registered with.
#[repr(u32)]
pub enum RenderLayerDefaultState {
    /// Register the [`RenderLayer`] as disabled, the user must then enable it via the UI.
    ///
    /// This is the default registration value.
    Disabled = 0,
    /// Register the [`RenderLayer`] as enabled, the user must then disable it via the UI.
    Enabled = 1,
    /// Use this if you do not want the render layer to be adjustable via the UI.
    AlwaysEnabled = 2,
}

impl From<BNRenderLayerDefaultEnableState> for RenderLayerDefaultState {
    fn from(value: BNRenderLayerDefaultEnableState) -> Self {
        match value {
            BNRenderLayerDefaultEnableState::DisabledByDefaultRenderLayerDefaultEnableState => {
                Self::Disabled
            }
            BNRenderLayerDefaultEnableState::EnabledByDefaultRenderLayerDefaultEnableState => {
                Self::Enabled
            }
            BNRenderLayerDefaultEnableState::AlwaysEnabledRenderLayerDefaultEnableState => {
                Self::AlwaysEnabled
            }
        }
    }
}

impl From<RenderLayerDefaultState> for BNRenderLayerDefaultEnableState {
    fn from(value: RenderLayerDefaultState) -> Self {
        match value {
            RenderLayerDefaultState::Disabled => {
                Self::DisabledByDefaultRenderLayerDefaultEnableState
            }
            RenderLayerDefaultState::Enabled => Self::EnabledByDefaultRenderLayerDefaultEnableState,
            RenderLayerDefaultState::AlwaysEnabled => {
                Self::AlwaysEnabledRenderLayerDefaultEnableState
            }
        }
    }
}

impl Default for RenderLayerDefaultState {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Register a [`RenderLayer`] with the API.
pub fn register_render_layer<S: BnStrCompatible, T: RenderLayer>(
    name: S,
    render_layer: T,
    default_state: RenderLayerDefaultState,
) -> (&'static mut T, CoreRenderLayer) {
    let render_layer = Box::leak(Box::new(render_layer));
    let mut callback = BNRenderLayerCallbacks {
        context: render_layer as *mut _ as *mut c_void,
        applyToFlowGraph: Some(cb_apply_to_flow_graph::<T>),
        applyToLinearViewObject: Some(cb_apply_to_linear_view_object::<T>),
        freeLines: Some(cb_free_lines),
    };
    let result = unsafe {
        BNRegisterRenderLayer(
            name.into_bytes_with_nul().as_ref().as_ptr() as *const _,
            &mut callback,
            default_state.into(),
        )
    };
    let core = CoreRenderLayer::from_raw(NonNull::new(result).unwrap());
    (render_layer, core)
}

pub trait RenderLayer: Sized {
    /// Apply this Render Layer to a Flow Graph.
    fn apply_to_flow_graph(&self, graph: &mut FlowGraph) {
        for node in &graph.nodes() {
            if let Some(block) = node.basic_block(NativeBlock::new()) {
                let new_lines = self.apply_to_block(&block, node.lines().to_vec());
                node.set_lines(new_lines);
            }
        }
    }

    /// Apply this Render Layer to the lines produced by a LinearViewObject for rendering in Linear View.
    fn apply_to_linear_object(
        &self,
        object: &mut LinearViewObject,
        _prev_object: Option<&mut LinearViewObject>,
        _next_object: Option<&mut LinearViewObject>,
        lines: Vec<LinearDisassemblyLine>,
    ) -> Vec<LinearDisassemblyLine> {
        let text_to_lines =
            |function: &Function, block: &BasicBlock<NativeBlock>, text: DisassemblyTextLine| {
                LinearDisassemblyLine {
                    ty: LinearDisassemblyLineType::CodeDisassemblyLineType,
                    function: Some(function.to_owned()),
                    basic_block: Some(block.to_owned()),
                    contents: text,
                }
            };

        // Hack: HLIL bodies don't have basic blocks.
        let obj_ident = object.identifier();
        if !lines.is_empty()
            && (obj_ident.name.starts_with("HLIL") || obj_ident.name.starts_with("Language"))
        {
            // Apply to HLIL body.
            let function = lines[0]
                .function
                .to_owned()
                .expect("HLIL body has no function");
            return self.apply_to_hlil_body(&function, lines);
        }

        // Collect the "line blocks".
        // Line blocks are contiguous lines with the same backing basic block (or lack thereof).
        // Line blocks also group by line type.
        let mut line_blocks: Vec<Vec<LinearDisassemblyLine>> = Vec::new();
        for line in lines {
            let Some(last_block) = line_blocks.last_mut() else {
                // No last block, create the first block.
                line_blocks.push(vec![line]);
                continue;
            };

            let Some(last_line) = last_block.last() else {
                // No last line, create the first line.
                last_block.push(line);
                continue;
            };

            // TODO: If we want to allow a block with multiple line types we need to specifically check
            // TODO: If the last line type was Code, if it is and the last line is not we make a new block.
            if last_line.basic_block == line.basic_block && last_line.ty == line.ty {
                // Same basic block and line type, this is a part of the same line block.
                last_block.push(line);
            } else {
                // Not the same line block, create a new block.
                line_blocks.push(vec![line]);
            }
        }

        line_blocks
            .into_iter()
            .filter_map(|line_block| {
                let probe_line = line_block.first()?;
                Some((probe_line.ty, probe_line.basic_block.to_owned(), line_block))
            })
            .flat_map(|(line_ty, basic_block, lines)| {
                match (basic_block, line_ty) {
                    (Some(block), LinearDisassemblyLineType::CodeDisassemblyLineType) => {
                        // Dealing with code lines.
                        let function = block.function();
                        let text_lines = lines.into_iter().map(|line| line.contents).collect();
                        let new_text_lines = self.apply_to_block(&block, text_lines);
                        new_text_lines
                            .into_iter()
                            .map(|line| text_to_lines(&function, &block, line))
                            .collect()
                    }
                    _ => {
                        // Dealing with misc lines.
                        self.apply_to_misc_lines(
                            object,
                            _prev_object.as_deref(),
                            _next_object.as_deref(),
                            lines,
                        )
                    }
                }
            })
            .collect()
    }

    /// Apply this Render Layer to a single Basic Block of Disassembly lines.
    ///
    /// Modify the lines to change the presentation of the block.
    fn apply_to_disassembly_block(
        &self,
        _block: &BasicBlock<NativeBlock>,
        lines: Vec<DisassemblyTextLine>,
    ) -> Vec<DisassemblyTextLine> {
        lines
    }

    /// Apply this Render Layer to a single Basic Block of Low Level IL lines.
    ///
    /// Modify the lines to change the presentation of the block.
    fn apply_to_llil_block(
        &self,
        _block: &BasicBlock<NativeBlock>,
        lines: Vec<DisassemblyTextLine>,
    ) -> Vec<DisassemblyTextLine> {
        lines
    }

    /// Apply this Render Layer to a single Basic Block of Medium Level IL lines.
    ///
    /// Modify the lines to change the presentation of the block.
    fn apply_to_mlil_block(
        &self,
        _block: &BasicBlock<NativeBlock>,
        lines: Vec<DisassemblyTextLine>,
    ) -> Vec<DisassemblyTextLine> {
        lines
    }

    /// Apply this Render Layer to a single Basic Block of High Level IL lines.
    ///
    /// Modify the lines to change the presentation of the block.
    ///
    /// This function will NOT apply to High Level IL bodies as displayed in Linear View!
    /// Those are handled by [`RenderLayer::apply_to_hlil_body`] instead as they do not
    /// have a [`BasicBlock`] associated with them.
    fn apply_to_hlil_block(
        &self,
        _block: &BasicBlock<NativeBlock>,
        lines: Vec<DisassemblyTextLine>,
    ) -> Vec<DisassemblyTextLine> {
        lines
    }

    /// Apply this Render Layer to the entire body of a High Level IL function.
    ///
    /// Modify the lines to change the presentation of the block.
    ///
    /// This function only applies to Linear View, and not to Graph View! If you want to
    /// handle Graph View too, you will need to use [`RenderLayer::apply_to_hlil_block`] and handle
    /// the lines one block at a time.
    fn apply_to_hlil_body(
        &self,
        _function: &Function,
        lines: Vec<LinearDisassemblyLine>,
    ) -> Vec<LinearDisassemblyLine> {
        lines
    }

    // TODO: We might want to just go ahead and pass the line type.
    /// Apply to lines generated by Linear View that are not part of a function.
    ///
    /// Modify the lines to change the presentation of the block.
    fn apply_to_misc_lines(
        &self,
        _object: &mut LinearViewObject,
        _prev_object: Option<&LinearViewObject>,
        _next_object: Option<&LinearViewObject>,
        lines: Vec<LinearDisassemblyLine>,
    ) -> Vec<LinearDisassemblyLine> {
        lines
    }

    /// Apply this Render Layer to all IL blocks and disassembly blocks.
    ///
    /// If not implemented this will handle calling the view specific apply functions:
    ///
    /// - [`RenderLayer::apply_to_disassembly_block`]
    /// - [`RenderLayer::apply_to_llil_block`]
    /// - [`RenderLayer::apply_to_mlil_block`]
    /// - [`RenderLayer::apply_to_hlil_block`]
    ///
    /// Modify the lines to change the presentation of the block.
    fn apply_to_block(
        &self,
        block: &BasicBlock<NativeBlock>,
        lines: Vec<DisassemblyTextLine>,
    ) -> Vec<DisassemblyTextLine> {
        match block.block_type() {
            BasicBlockType::Native => self.apply_to_disassembly_block(block, lines),
            BasicBlockType::LowLevelIL => self.apply_to_llil_block(block, lines),
            BasicBlockType::MediumLevelIL => self.apply_to_mlil_block(block, lines),
            BasicBlockType::HighLevelIL => self.apply_to_hlil_block(block, lines),
        }
    }
}

#[repr(transparent)]
pub struct CoreRenderLayer {
    pub(crate) handle: NonNull<BNRenderLayer>,
}

impl CoreRenderLayer {
    pub fn from_raw(handle: NonNull<BNRenderLayer>) -> Self {
        Self { handle }
    }

    pub fn render_layers() -> Array<CoreRenderLayer> {
        let mut count = 0;
        let result = unsafe { BNGetRenderLayerList(&mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn render_layer_by_name<S: BnStrCompatible>(name: S) -> Option<CoreRenderLayer> {
        let name_raw = name.into_bytes_with_nul();
        let result = unsafe { BNGetRenderLayerByName(name_raw.as_ref().as_ptr() as *const c_char) };
        NonNull::new(result).map(Self::from_raw)
    }

    pub fn default_state(&self) -> RenderLayerDefaultState {
        let raw = unsafe { BNGetRenderLayerDefaultEnableState(self.handle.as_ptr()) };
        RenderLayerDefaultState::from(raw)
    }

    pub fn apply_to_flow_graph(&self, graph: &FlowGraph) {
        unsafe { BNApplyRenderLayerToFlowGraph(self.handle.as_ptr(), graph.handle) }
    }

    pub fn apply_to_linear_view_object(
        &self,
        object: &LinearViewObject,
        prev_object: Option<&LinearViewObject>,
        next_object: Option<&LinearViewObject>,
        lines: Vec<LinearDisassemblyLine>,
    ) -> Vec<LinearDisassemblyLine> {
        let mut lines_raw: Vec<_> = lines
            .into_iter()
            // NOTE: Freed after the core call
            .map(LinearDisassemblyLine::into_raw)
            .collect();

        let prev_object_ptr = prev_object
            .map(|o| o.handle)
            .unwrap_or(std::ptr::null_mut());
        let next_object_ptr = next_object
            .map(|o| o.handle)
            .unwrap_or(std::ptr::null_mut());

        let mut new_lines = std::ptr::null_mut();
        let mut new_line_count = 0;

        unsafe {
            BNApplyRenderLayerToLinearViewObject(
                self.handle.as_ptr(),
                object.handle,
                prev_object_ptr,
                next_object_ptr,
                lines_raw.as_mut_ptr(),
                lines_raw.len(),
                &mut new_lines,
                &mut new_line_count,
            )
        };

        for line in lines_raw {
            LinearDisassemblyLine::free_raw(line);
        }

        let raw: Array<LinearDisassemblyLine> =
            unsafe { Array::new(new_lines, new_line_count, ()) };
        raw.to_vec()
    }
}

impl CoreArrayProvider for CoreRenderLayer {
    type Raw = *mut BNRenderLayer;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CoreRenderLayer {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeRenderLayerList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // TODO: Because handle is a NonNull we should prob make Self::Raw that as well...
        let handle = NonNull::new(*raw).unwrap();
        CoreRenderLayer::from_raw(handle)
    }
}

unsafe extern "C" fn cb_apply_to_flow_graph<T: RenderLayer>(
    ctxt: *mut c_void,
    graph: *mut BNFlowGraph,
) {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    // SAFETY: We do not own the flowgraph, do not take it as Ref.
    let mut flow_graph = FlowGraph::from_raw(graph);
    ctxt.apply_to_flow_graph(&mut flow_graph);
}

unsafe extern "C" fn cb_apply_to_linear_view_object<T: RenderLayer>(
    ctxt: *mut c_void,
    object: *mut BNLinearViewObject,
    prev: *mut BNLinearViewObject,
    next: *mut BNLinearViewObject,
    in_lines: *mut BNLinearDisassemblyLine,
    in_line_count: usize,
    out_lines: *mut *mut BNLinearDisassemblyLine,
    out_line_count: *mut usize,
) {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    // SAFETY: We do not own the flowgraph, do not take it as Ref.
    let mut object = LinearViewObject::from_raw(object);
    let mut prev_object = if !prev.is_null() {
        Some(LinearViewObject::from_raw(prev))
    } else {
        None
    };
    let mut next_object = if !next.is_null() {
        Some(LinearViewObject::from_raw(next))
    } else {
        None
    };

    let raw_lines = std::slice::from_raw_parts(in_lines, in_line_count);
    // NOTE: The caller is owned of the inLines.
    let lines: Vec<_> = raw_lines
        .iter()
        .map(|line| LinearDisassemblyLine::from_raw(line))
        .collect();

    let new_lines = ctxt.apply_to_linear_object(
        &mut object,
        prev_object.as_mut(),
        next_object.as_mut(),
        lines,
    );

    unsafe {
        *out_line_count = new_lines.len();
        let boxed_new_lines: Box<[_]> = new_lines
            .into_iter()
            // NOTE: Freed by cb_free_lines
            .map(LinearDisassemblyLine::into_raw)
            .collect();
        // NOTE: Dropped by cb_free_lines
        *out_lines = Box::leak(boxed_new_lines).as_mut_ptr();
    }
}

unsafe extern "C" fn cb_free_lines(
    _ctxt: *mut c_void,
    lines: *mut BNLinearDisassemblyLine,
    line_count: usize,
) {
    let lines_ptr = std::ptr::slice_from_raw_parts_mut(lines, line_count);
    let boxed_lines = Box::from_raw(lines_ptr);
    for line in boxed_lines {
        LinearDisassemblyLine::free_raw(line);
    }
}
