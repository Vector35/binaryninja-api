use binaryninja::binary_view::{BinaryViewBase, BinaryViewExt};
use binaryninja::disassembly::{DisassemblyOption, DisassemblySettings, DisassemblyTextRenderer};
use binaryninja::function::Function;
use binaryninja::tracing::TracingLogListener;

fn disassemble(func: &Function) {
    let settings = DisassemblySettings::new();
    settings.set_option(DisassemblyOption::ShowAddress, false);
    settings.set_option(DisassemblyOption::WaitForIL, true);
    settings.set_option(DisassemblyOption::IndentHLILBody, false);
    settings.set_option(DisassemblyOption::ShowCollapseIndicators, false);
    settings.set_option(DisassemblyOption::ShowFunctionHeader, false);

    let text_renderer = DisassemblyTextRenderer::from_function(func, Some(&settings));
    for basic_block in &func.basic_blocks() {
        for instr_addr in basic_block.iter() {
            // NOTE: If you want the annotations as well you can call text_renderer.disassembly_text
            if let Some((text, _len)) = text_renderer.instruction_text(instr_addr) {
                // TODO: This only ever appears to return a single string?
                let text_string: Vec<_> = text.iter().map(|t| t.to_string()).collect();
                tracing::info!("{}", text_string.join(""));
            }
        }
    }
}

pub fn main() {
    tracing_subscriber::fmt::init();
    let _listener = TracingLogListener::new().register();

    let filename = std::env::args().nth(1).expect("No filename provided");

    // This loads all the core architecture, platform, etc plugins
    let headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    tracing::info!("Loading binary...");
    let bv = headless_session
        .load(&filename)
        .expect("Couldn't open file!");

    tracing::info!("File:  `{}`", bv.file());
    tracing::info!("File size: `{:#x}`", bv.len());
    tracing::info!("Function count: {}", bv.functions().len());

    for func in &bv.functions() {
        disassemble(func.as_ref());
    }
}
