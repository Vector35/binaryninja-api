use binaryninja::binary_view::BinaryView;
use binaryninja::disassembly::{InstructionTextToken, InstructionTextTokenKind};
use binaryninja::file_metadata::SessionId;
use binaryninja::linear_view::{LinearDisassemblyLine, LinearViewObject};
use binaryninja::object_destructor::ObjectDestructor;
use binaryninja::render_layer::{register_render_layer, RenderLayer, RenderLayerDefaultState};
use std::collections::HashMap;
use std::sync::RwLock;

pub mod state;

#[derive(Default)]
struct DebugLineRenderLayer {
    data: RwLock<HashMap<SessionId, state::DebugLineState>>,
}

impl DebugLineRenderLayer {
    pub fn map_line_info(
        &self,
        view: &BinaryView,
        mut line: LinearDisassemblyLine,
    ) -> LinearDisassemblyLine {
        let addr = line.contents.address;
        if let Some(info) = self.line_info(view, addr) {
            // We only want to add the line number for lines that display an address.
            if line.contents.tokens.first().is_some_and(|t| {
                t.kind == InstructionTextTokenKind::AddressDisplay { address: addr }
            }) {
                line.contents.tokens.insert(
                    0,
                    InstructionTextToken::new(" ", InstructionTextTokenKind::AddressSeparator),
                );
                line.contents.tokens.insert(
                    0,
                    InstructionTextToken::new(
                        info.to_string(),
                        InstructionTextTokenKind::AddressDisplay { address: addr },
                    ),
                );
            }
        }
        line
    }

    pub fn line_info(&self, view: &BinaryView, address: u64) -> Option<state::DebugLineInfo> {
        let lock = self.data.read().ok()?;
        let state = lock.get(&view.file().session_id())?;
        state.line_info(address)
    }

    // TODO: This is manual probing rn, would prefer to not do like this.
    fn probe_state(&self, view: &BinaryView) {
        let session_id = view.file().session_id();
        let mut lock = self.data.write().unwrap();
        if !lock.contains_key(&session_id) {
            if let Ok(state) = state::DebugLineState::new(view) {
                lock.insert(session_id, state);
            }
        }
    }
}

impl RenderLayer for DebugLineRenderLayer {
    fn apply_to_linear_object(
        &self,
        _object: &mut LinearViewObject,
        _prev_object: Option<&mut LinearViewObject>,
        _next_object: Option<&mut LinearViewObject>,
        lines: Vec<LinearDisassemblyLine>,
    ) -> Vec<LinearDisassemblyLine> {
        let view = match lines.first() {
            Some(first_line) => first_line.function.as_ref().map(|f| f.view()),
            None => return lines,
        };

        if let Some(view) = view {
            self.probe_state(&view);
            let lines = lines
                .into_iter()
                .map(|line| self.map_line_info(&view, line))
                .collect();
            lines
        } else {
            lines
        }
    }
}

impl ObjectDestructor for DebugLineRenderLayer {
    fn destruct_view(&self, view: &BinaryView) {
        let mut lock = self.data.write().unwrap();
        lock.remove(&view.file().session_id());
    }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CorePluginInit() -> bool {
    binaryninja::tracing_init!();

    register_render_layer(
        "Debug Lines",
        DebugLineRenderLayer::default(),
        RenderLayerDefaultState::Disabled,
    );

    true
}
