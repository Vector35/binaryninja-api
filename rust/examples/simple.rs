use binaryninja::architecture::Architecture;
use binaryninja::binary_view::{BinaryViewBase, BinaryViewExt};
use binaryninja::tracing::TracingLogListener;

fn main() {
    tracing_subscriber::fmt::init();
    let _listener = TracingLogListener::new().register();

    // This loads all the core architecture, platform, etc plugins
    let headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    tracing::info!("Loading binary...");
    let bv = headless_session
        .load("/bin/cat")
        .expect("Couldn't open `/bin/cat`");

    tracing::info!("File:  `{}`", bv.file());
    tracing::info!("File size: `{:#x}`", bv.len());
    tracing::info!("Function count: {}", bv.functions().len());

    for func in &bv.functions() {
        println!("{}:", func.symbol());
        for basic_block in &func.basic_blocks() {
            // TODO : This is intended to be refactored to be more nice to work with soon(TM)
            for addr in basic_block.as_ref() {
                if let Some((_, tokens)) = func.arch().instruction_text(
                    bv.read_buffer(addr, func.arch().max_instr_len())
                        .unwrap()
                        .get_data(),
                    addr,
                ) {
                    let line = tokens
                        .iter()
                        .map(|token| token.to_string())
                        .collect::<String>();
                    println!("{addr}    {line}");
                }
            }
        }
    }
}
