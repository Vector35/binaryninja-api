use binaryninja::basic_block::BasicBlock;
use binaryninja::binary_view::BinaryViewExt;
use binaryninja::disassembly::{DisassemblyOption, DisassemblySettings, DisassemblyTextLine};
use binaryninja::function::NativeBlock;
use binaryninja::headless::Session;
use binaryninja::linear_view::LinearViewObject;
use binaryninja::render_layer::{register_render_layer, CoreRenderLayer, RenderLayer};
use rstest::{fixture, rstest};
use std::path::PathBuf;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_render_layer_register(_session: &Session) {
    struct EmptyRenderLayer;
    impl RenderLayer for EmptyRenderLayer {}
    register_render_layer("Test Render Layer", EmptyRenderLayer, Default::default());
    CoreRenderLayer::render_layer_by_name("Test Render Layer").expect("Failed to get render layer");
}

#[rstest]
fn test_render_layer_linear_view(_session: &Session) {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");

    struct NopRenderLayer;
    impl RenderLayer for NopRenderLayer {
        fn apply_to_disassembly_block(
            &self,
            _block: &BasicBlock<NativeBlock>,
            lines: Vec<DisassemblyTextLine>,
        ) -> Vec<DisassemblyTextLine> {
            println!("Nothing added to disassembly block");
            lines
        }
    }
    let (_, nop_render_layer) =
        register_render_layer("Nop Render Layer", NopRenderLayer, Default::default());

    // Create linear view object stuff
    let settings = DisassemblySettings::new();
    settings.set_option(DisassemblyOption::ShowAddress, false);
    settings.set_option(DisassemblyOption::WaitForIL, true);
    settings.set_option(DisassemblyOption::IndentHLILBody, false);
    settings.set_option(DisassemblyOption::ShowCollapseIndicators, false);
    settings.set_option(DisassemblyOption::ShowFunctionHeader, false);

    let linear_view = LinearViewObject::disassembly(&view, &settings);
    let mut cursor = linear_view.create_cursor();
    // Seek to the start of the function `__crt_strtox::is_overflow_condition<uint64_t>`
    cursor.seek_to_address(view.original_image_base() + 0x26240);
    let current_object = cursor.current_object();
    let current_lines = cursor.lines().to_vec();

    let new_lines = nop_render_layer.apply_to_linear_view_object(
        &current_object,
        None,
        None,
        current_lines.clone(),
    );

    // These should 100% be in the same order. If not that is a bug.

    for (i, (current_line, new_line)) in current_lines.iter().zip(new_lines.iter()).enumerate() {
        if current_line != new_line {
            assert_eq!(current_line, new_line, "Line mismatch at index {}", i);
        }
    }

    struct AddRenderLayer;
    impl RenderLayer for AddRenderLayer {
        fn apply_to_disassembly_block(
            &self,
            _block: &BasicBlock<NativeBlock>,
            mut lines: Vec<DisassemblyTextLine>,
        ) -> Vec<DisassemblyTextLine> {
            println!("Adding to disassembly block");
            lines.push(DisassemblyTextLine::from("heyyyyy"));
            lines
        }
    }
    let (_, adding_render_layer) =
        register_render_layer("Add Render Layer", AddRenderLayer, Default::default());

    // Calling lines() again should now have the render layer applied.
    cursor.add_render_layer(&adding_render_layer);
    let new_current_lines = cursor.lines().to_vec();
    // Assert that new_current_lines is one longer than current_lines (we added a line)
    assert_eq!(new_current_lines.len(), current_lines.len() + 1);

    // Remove the render layer and make sure that the line is no longer present.
    cursor.remove_render_layer(&adding_render_layer);
    let new_new_current_lines = cursor.lines().to_vec();
    assert_eq!(new_new_current_lines.len(), current_lines.len());
}
